// Package proxies 处理订阅获取、去重及随机乱序，处理节点重命名
package proxies

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/samber/lo"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"github.com/sinspired/subs-check/utils"
	"gopkg.in/yaml.v3"
)

var (
	IsSysProxyAvailable bool
	IsGhProxyAvailable  bool
)

func GetProxies() ([]map[string]any, int, int, error) {
	// 初始化系统代理和 githubproxy
	IsSysProxyAvailable = utils.GetSysProxy()
	IsGhProxyAvailable = utils.GetGhProxy()

	// 解析本地与远程订阅清单
	subUrls, localNum, remoteNum, historyNum := resolveSubUrls()
	args := []any{}
	if localNum > 0 {
		args = append(args, "本地", localNum)
	}
	if remoteNum > 0 {
		args = append(args, "远程", remoteNum)
	}
	if historyNum > 0 {
		args = append(args, "历史", historyNum)
	}
	args = append(args, "总计", len(subUrls))
	slog.Info("订阅链接数量", args...)

	// 仅在有值时打印
	if IsSysProxyAvailable {
		slog.Info("", "-system-proxy", config.GlobalConfig.SystemProxy)
	}
	if IsGhProxyAvailable {
		slog.Info("", "-github-proxy", config.GlobalConfig.GithubProxy)
	}

	if len(config.GlobalConfig.NodeType) > 0 {
		slog.Info("只筛选用户设置的协议", "type", config.GlobalConfig.NodeType)
	}

	var wg sync.WaitGroup
	proxyChan := make(chan map[string]any, 1)                              // 缓冲通道存储解析的代理
	concurrentLimit := make(chan struct{}, config.GlobalConfig.Concurrent) // 限制并发数

	// 启动收集结果的协程（将之前成功节点和其他订阅分别收集以便将之前成功节点放前面）
	var succedProxies []map[string]any
	var historyProxies []map[string]any
	var syncProxies []map[string]any

	done := make(chan struct{})
	go func() {
		for proxy := range proxyChan {
			switch {
			case proxy["sub_from_history"] == true:
				historyProxies = append(historyProxies, proxy)
			case proxy["sub_was_succeed"] == true:
				succedProxies = append(succedProxies, proxy)
			default:
				syncProxies = append(syncProxies, proxy)
			}
		}
		done <- struct{}{}
	}()

	// 启动工作协程
	for _, subURL := range subUrls {
		wg.Add(1)
		concurrentLimit <- struct{}{} // 获取令牌

		// 精确判断：必须是回环地址，且 URL 明确包含端口，端口等于 config.GlobalConfig.ListenPort，且 path 以 /all.yaml 或 /all.yml 结尾
		isSuccedProxiesURL := false
		isHistoryProxiesURL := false

		if d, err := u.Parse(subURL); err == nil {
			host := d.Hostname()
			port := d.Port() // 如果 URL 没有显式端口，这里会是空字符串

			// 把配置里的 ListenPort 转换成端口数字
			requiredListenPort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.ListenPort, ":"))
			requiredSubStorePort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.SubStorePort, ":"))

			isLocal := isLocal(host)

			if isLocal && port != "" && (port == requiredListenPort || port == requiredSubStorePort) {
				if strings.HasSuffix(d.Path, "/all.yaml") || strings.HasSuffix(d.Path, "/all.yml") {
					isSuccedProxiesURL = true
				}
				if strings.HasSuffix(d.Path, "/history.yaml") || strings.HasSuffix(d.Path, "/history.yml") {
					isHistoryProxiesURL = true
				}
			}
		}

		go func(url string, wasSucced, wasHistory bool) {
			defer wg.Done()
			defer func() { <-concurrentLimit }() // 释放令牌

			data, err := GetDateFromSubs(url)
			if err != nil {
				slog.Error(fmt.Sprintf("%v", err))
				return
			}

			var tag string
			if d, err := u.Parse(url); err == nil {
				tag = d.Fragment
			}

			var con map[string]any
			err = yaml.Unmarshal(data, &con)
			if err != nil {
				proxyList, err := convert.ConvertsV2Ray(data)
				if err != nil {
					slog.Error(fmt.Sprintf("解析proxy错误: %v", err), "url", url)
					return
				}
				slog.Debug(fmt.Sprintf("获取订阅链接: %s，有效节点数量: %d", url, len(proxyList)))
				for _, proxy := range proxyList {
					// 只测试指定协议
					if t, ok := proxy["type"].(string); ok {
						if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
							continue
						}
					}

					// 为每个节点添加订阅链接来源信息和备注
					proxy["sub_url"] = url
					proxy["sub_tag"] = tag
					proxy["sub_was_succeed"] = wasSucced
					proxy["sub_from_history"] = wasHistory
					proxyChan <- proxy
				}

				return
			}

			proxyInterface, ok := con["proxies"]
			if !ok || proxyInterface == nil {
				slog.Warn(fmt.Sprintf("订阅链接为空: %s", url))
				return
			}

			proxyList, ok := proxyInterface.([]any)
			if !ok {
				return
			}
			slog.Debug(fmt.Sprintf("获取订阅链接: %s，有效节点数量: %d", url, len(proxyList)))
			for _, proxy := range proxyList {
				if proxyMap, ok := proxy.(map[string]any); ok {
					if t, ok := proxyMap["type"].(string); ok {
						// 只测试指定协议
						if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
							continue
						}
						// 虽然支持mihomo支持下划线，但是这里为了规范，还是改成横杠
						// todo: 不知道后边还有没有这类问题
						switch t {
						case "hysteria2", "hy2":
							if _, ok := proxyMap["obfs_password"]; ok {
								proxyMap["obfs-password"] = proxyMap["obfs_password"]
								delete(proxyMap, "obfs_password")
							}
						}
					}
					// 为每个节点添加订阅链接来源信息和备注
					proxyMap["sub_url"] = url
					proxyMap["sub_tag"] = tag
					proxyMap["sub_was_succeed"] = wasSucced
					proxyMap["sub_from_history"] = wasHistory
					proxyChan <- proxyMap
				}
			}

		}(subURL, isSuccedProxiesURL, isHistoryProxiesURL)
	}

	// 等待所有工作协程完成
	wg.Wait()
	close(proxyChan)
	<-done // 等待收集完成
	// 释放运行时内存
	runtime.GC()

	// 构建 succed 节点的 server 集合
	succedSet := make(map[string]struct{}, len(succedProxies))
	for _, p := range succedProxies {
		proxyKey := generateProxyKey(p)
		succedSet[proxyKey] = struct{}{}
	}

	// 去重 historyProxies，同时统计数量
	dedupedHistory := make([]map[string]any, 0)
	for _, p := range historyProxies {
		proxyKey := generateProxyKey(p)
		// 如果在 succedSet 中，说明已经在 succedProxies 里了，跳过
		if _, exists := succedSet[proxyKey]; exists {
			continue
		}
		succedSet[proxyKey] = struct{}{} // 加入集合，防止 history 内部重复

		dedupedHistory = append(dedupedHistory, p)
	}

	historyProxies = dedupedHistory

	// 统计数量
	succedCount := len(succedProxies)
	historyCount := len(historyProxies)

	// 拼接最终节点列表（保持顺序）
	mihomoProxies := append(append(succedProxies, historyProxies...), syncProxies...)

	for _, p := range mihomoProxies {
		delete(p, "sub_was_succeed")  // 删除旧的标记
		delete(p, "sub_from_history") // 删除旧的标记
	}

	succedProxies = nil
	historyProxies = nil
	for i := range syncProxies {
		syncProxies[i] = nil // 移除 map 引用
	}
	syncProxies = nil
	runtime.GC() // 提示 GC 回收

	// 返回时用去重后的历史数量
	return mihomoProxies, succedCount, historyCount, nil
}

// from 3k
// resolveSubUrls 合并本地与远程订阅清单并去重（去重时忽略 fragment）
func resolveSubUrls() ([]string, int, int, int) {
	// 计数
	var localNum, remoteNum, historyNum int
	localNum = len(config.GlobalConfig.SubUrls)

	urls := make([]string, 0, len(config.GlobalConfig.SubUrls))
	urls = append(urls, config.GlobalConfig.SubUrls...)

	if len(config.GlobalConfig.SubUrlsRemote) != 0 {
		for _, subURLRemote := range config.GlobalConfig.SubUrlsRemote {
			warped := utils.WarpURL(subURLRemote, IsGhProxyAvailable)
			if remote, err := fetchRemoteSubUrls(warped); err != nil {
				slog.Warn("获取远程订阅清单失败，已忽略", "err", err)
			} else {
				remoteNum += len(remote)
				urls = append(urls, remote...)
			}
		}
	}

	requiredListenPort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.ListenPort, ":"))
	localLastSucced := fmt.Sprintf("http://127.0.0.1:%s/all.yaml", requiredListenPort)
	localHistory := fmt.Sprintf("http://127.0.0.1:%s/history.yaml", requiredListenPort)

	// 如果用户设置了保留成功节点，则把本地的 all.yaml 和 history.yaml 放到最前面（如果存在的话）
	if config.GlobalConfig.KeepSuccessProxies {
		saver, err := method.NewLocalSaver()
		if err == nil {
			if !filepath.IsAbs(saver.OutputPath) {
				// 处理用户写相对路径的问题
				saver.OutputPath = filepath.Join(saver.BasePath, saver.OutputPath)
			}
			localLastSuccedFile := filepath.Join(saver.OutputPath, "all.yaml")
			localHistoryFile := filepath.Join(saver.OutputPath, "history.yaml")

			if _, err := os.Stat(localLastSuccedFile); err == nil {
				historyNum++
				urls = append([]string{localLastSucced + "#KeepSucceed"}, urls...)
			}
			if _, err := os.Stat(localHistoryFile); err == nil {
				historyNum++
				urls = append([]string{localHistory + "#KeepHistory"}, urls...)
			}
		}
	}

	// 去重并过滤本地 URL（忽略 fragment）
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, s := range urls {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}

		key := s
		if d, err := u.Parse(s); err == nil {
			d.Fragment = ""
			key = d.String()

			// 如果不保留成功节点，过滤掉本地 all.yaml 和 history.yaml
			if !config.GlobalConfig.KeepSuccessProxies &&
				(key == localLastSucced || key == localHistory) {
				continue
			}
		}

		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out, localNum, remoteNum, historyNum
}

// fetchRemoteSubUrls 从远程地址读取订阅URL清单
// 支持两种格式：
// 1) 纯文本，按换行分隔，支持以 # 开头的注释与空行
// 2) YAML/JSON 的字符串数组
func fetchRemoteSubUrls(listURL string) ([]string, error) {
	if listURL == "" {
		return nil, errors.New("empty list url")
	}
	data, err := GetDateFromSubs(listURL)
	if err != nil {
		return nil, err
	}
	// 优先尝试解析为字符串数组（YAML/JSON兼容）
	var arr []string
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	// 回退为按行解析
	res := make([]string, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res = append(res, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func GetDateFromSubs(rawURL string) ([]byte, error) {
	// 内部类型：单次尝试计划
	type tryPlan struct {
		url      string
		useProxy bool // true: 使用系统代理; false: 明确禁用代理
		via      string
	}

	// 配置项与默认值
	maxRetries := config.GlobalConfig.SubUrlsReTry
	if maxRetries <= 0 {
		maxRetries = 1
	}
	retryInterval := config.GlobalConfig.SubUrlsRetryInterval
	if retryInterval <= 0 {
		retryInterval = 1
	}
	timeout := config.GlobalConfig.SubUrlsTimeout
	if timeout <= 0 {
		timeout = 10
	}

	// 占位符候选：今日 + 昨日（仅当存在占位符时）
	candidates := buildCandidateURLs(rawURL)

	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}

		for _, cand := range candidates {
			// 构建尝试顺序：
			// 1) 原始链接 + 系统代理（若可用），否则直连
			// 2) GitHub 代理直连（仅当 WarpURL 确实发生变化且可用）
			plans := make([]tryPlan, 0, 2)

			normalized := ensureScheme(cand)

			// 只要用户配置了系统代理，或探测为可用，都先走系统代理
			if IsSysProxyAvailable {
				plans = append(plans, tryPlan{url: normalized, useProxy: true, via: "sys-proxy"})
			} else {
				plans = append(plans, tryPlan{url: normalized, useProxy: false, via: "direct"})
			}

			gh := utils.WarpURL(normalized, IsGhProxyAvailable)
			if IsGhProxyAvailable && gh != normalized {
				plans = append(plans, tryPlan{url: gh, useProxy: false, via: "ghproxy-direct"})
			}

			for _, p := range plans {
				body, err, terminal := fetchOnce(p.url, p.useProxy, timeout)
				if err == nil {
					return body, nil
				}
				lastErr = err
				if terminal {
					// 明确错误（如 404/401）直接终止所有重试
					return nil, lastErr
				}
			}
		}
	}

	return nil, fmt.Errorf("重试%d次后失败: %v", maxRetries, lastErr)
}

// buildCandidateURLs 生成候选链接：
// - 如果存在日期占位符，返回 [今日, 昨日]
// - 否则返回 [原始]
func buildCandidateURLs(u string) []string {
	if !hasDatePlaceholder(u) {
		return []string{u}
	}
	now := time.Now()
	yest := now.AddDate(0, 0, -1)
	today := replaceDatePlaceholders(u, now)
	yesterday := replaceDatePlaceholders(u, yest)
	slog.Debug("检测到日期占位符，将尝试今日和昨日日期")
	return []string{today, yesterday}
}

// hasDatePlaceholder 粗略检查是否包含任意日期占位符
func hasDatePlaceholder(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "{ymd}") || strings.Contains(ls, "{y}") ||
		strings.Contains(ls, "{m}") || strings.Contains(ls, "{d}") ||
		strings.Contains(ls, "{y-m-d}") || strings.Contains(ls, "{y_m_d}")
}

// replaceDatePlaceholders 按时间替换日期占位符，大小写不敏感
func replaceDatePlaceholders(s string, t time.Time) string {
	// 统一处理多种格式
	reMap := map[*regexp.Regexp]string{
		regexp.MustCompile(`(?i)\{Ymd\}`):   t.Format("20060102"),
		regexp.MustCompile(`(?i)\{Y-m-d\}`): t.Format("2006-01-02"),
		regexp.MustCompile(`(?i)\{Y_m_d\}`): t.Format("2006_01_02"),
		regexp.MustCompile(`(?i)\{Y\}`):     t.Format("2006"),
		regexp.MustCompile(`(?i)\{m\}`):     t.Format("01"),
		regexp.MustCompile(`(?i)\{d\}`):     t.Format("02"),
	}
	out := s
	for re, val := range reMap {
		out = re.ReplaceAllString(out, val)
	}
	return out
}

// ensureScheme 如果缺少协议，默认补为 http:// 或 https://（针对常见 host 做合理推断）
func ensureScheme(u string) string {
	s := strings.TrimSpace(u)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	// 本地/内网使用 http
	if strings.HasPrefix(s, "127.0.0.1:") || strings.HasPrefix(strings.ToLower(s), "localhost:") || strings.HasPrefix(s, "0.0.0.0:") || strings.HasPrefix(s, "[::1]:") {
		return "http://" + s
	}
	// GitHub/raw 默认 https
	if strings.HasPrefix(s, "raw.githubusercontent.com/") || strings.HasPrefix(s, "github.com/") {
		return "https://" + s
	}
	// 默认 http
	return "http://" + s
}

// fetchOnce 执行一次请求；返回 (body, err, terminal)
// terminal=true 表示不应继续重试（如 404/401 等明确错误）
func fetchOnce(target string, useProxy bool, timeoutSec int) ([]byte, error, bool) {
	parsed, err := u.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("解析URL失败: %w", err), false
	}

	req, err := http.NewRequest("GET", parsed.String(), nil)
	if err != nil {
		return nil, err, false
	}
	req.Header.Set("User-Agent", "clash.meta")

	// 本地 KeepSuccess / KeepHistory 请求需要附加 header 与 query
	frag := parsed.Fragment
	isKeep := strings.Contains(strings.ToLower(frag), "success") || strings.Contains(strings.ToLower(frag), "succeed") || strings.Contains(strings.ToLower(frag), "history")
	host := parsed.Hostname()
	isLocal := isLocal(host)
	if isLocal && isKeep {
		q := req.URL.Query()
		if q.Get("from_subs_check") == "" {
			q.Set("from_subs_check", "true")
			req.URL.RawQuery = q.Encode()
		}
		req.Header.Set("X-From-Subs-Check", "true")
		req.Header.Set("X-API-Key", config.GlobalConfig.APIKey)
	}

	// HTTP Client
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	if useProxy {
		// 优先使用用户显式配置的系统代理，其次回退到环境变量
		if p := strings.TrimSpace(config.GlobalConfig.SystemProxy); p != "" {
			if pu, perr := u.Parse(p); perr == nil {
				client.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
			} else {
				client.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
			}
		} else {
			client.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
		}
	} else {
		client.Transport = &http.Transport{Proxy: nil}
	}

	resp, err := client.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return nil, fmt.Errorf("订阅: %s 请求超时 [代理: %v]", req.URL.String(), useProxy), false
		}
		return nil, fmt.Errorf("订阅: %s 请求失败: %v", req.URL.String(), err), false
	}
	// 确保及时关闭，避免泄露
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound, http.StatusGone, http.StatusUnavailableForLegalReasons:
			// 明确失效，直接终止
			return nil, fmt.Errorf("\u001b[31m订阅链接已失效！\u001b[0m %s [代理: %v, 状态码: %d]", req.URL.String(), useProxy, resp.StatusCode), true
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, fmt.Errorf("订阅: %s 权限不足或需要认证 (状态码: %d)", req.URL.String(), resp.StatusCode), true
		default:
			return nil, fmt.Errorf("订阅: %s 状态码: %d", req.URL.String(), resp.StatusCode), false
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取订阅链接: %s 数据错误: %v", req.URL.String(), err), false
	}
	return body, nil, false
}

// 生成唯一 key，按 server、port、type 三个字段
func generateProxyKey(p map[string]any) string {
	server := strings.TrimSpace(fmt.Sprint(p["server"]))
	port := strings.TrimSpace(fmt.Sprint(p["port"]))
	typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(p["type"])))
	servername := strings.ToLower(strings.TrimSpace(fmt.Sprint(p["servername"])))

	password := strings.TrimSpace(fmt.Sprint(p["password"]))
	if password == "" {
		password = strings.TrimSpace(fmt.Sprint(p["uuid"]))
	}

	// 如果全部字段都为空，则把整个 map 以简短形式作为 fallback key（避免丢失）
	if server == "" && port == "" && typ == "" && servername == "" && password == "" {
		// 尽量稳定地生成字符串
		return fmt.Sprintf("raw:%v", p)
	}
	// 使用 '|' 分隔构建 key
	return server + "|" + port + "|" + typ + "|" + servername + "|" + password
}

// isLocal 判断是否为本地地址
func isLocal(host string) bool {
	return host == "127.0.0.1" || strings.EqualFold(host, "localhost") || host == "0.0.0.0" || host == "::1" || strings.Contains(host, ".local") || !strings.Contains(host, ".")
}
