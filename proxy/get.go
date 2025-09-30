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

func GetProxies() ([]map[string]any, int, int, error) {
	// 解析本地与远程订阅清单
	subUrls := resolveSubUrls()
	slog.Info("订阅链接数量", "本地", len(config.GlobalConfig.SubUrls), "远程", len(config.GlobalConfig.SubUrlsRemote), "总计", len(subUrls))

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
	for _, subUrl := range subUrls {
		wg.Add(1)
		concurrentLimit <- struct{}{} // 获取令牌

		warpUrl := utils.WarpUrl(subUrl)

		// 精确判断：必须是回环地址，且 URL 明确包含端口，端口等于 config.GlobalConfig.ListenPort，且 path 以 /all.yaml 或 /all.yml 结尾
		isSuccedProxiesUrl := false
		isHistoryProxiesUrl := false

		if d, err := u.Parse(warpUrl); err == nil {
			host := d.Hostname()
			port := d.Port() // 如果 URL 没有显式端口，这里会是空字符串

			// 把配置里的 ListenPort 转换成端口数字
			requiredListenPort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.ListenPort, ":"))
			requiredSubStorePort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.SubStorePort, ":"))

			if (host == "127.0.0.1" || host == "localhost" || host == "0.0.0.0" || host == "::1") &&
				port != "" && (port == requiredListenPort || port == requiredSubStorePort) {
				if strings.HasSuffix(d.Path, "/all.yaml") || strings.HasSuffix(d.Path, "/all.yml") {
					isSuccedProxiesUrl = true
				}
				if strings.HasSuffix(d.Path, "/history.yaml") || strings.HasSuffix(d.Path, "/history.yml") {
					isHistoryProxiesUrl = true
				}
			}
		}

		go func(url string, wasSucced, wasHistory bool) {
			defer wg.Done()
			defer func() { <-concurrentLimit }() // 释放令牌

			data, err := GetDateFromSubs(url)
			if err != nil {
				slog.Error(fmt.Sprintf("获取订阅链接错误跳过: %v", err))
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
				// 释放运行时内存
				data = nil
				proxyList = nil

				return
			}

			proxyInterface, ok := con["proxies"]
			if !ok || proxyInterface == nil {
				slog.Error(fmt.Sprintf("订阅链接没有proxies: %s", url))
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
			// 释放运行时内存
			data = nil
			proxyList = nil

		}(warpUrl, isSuccedProxiesUrl, isHistoryProxiesUrl)
	}

	// 等待所有工作协程完成
	wg.Wait()
	close(proxyChan)
	<-done // 等待收集完成

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

	// 释放不再需要的内存
	proxyChan = nil
	succedSet = nil
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
// resolveSubUrls 合并本地与远程订阅清单并去重
// resolveSubUrls 合并本地与远程订阅清单并去重（去重时忽略 fragment）
func resolveSubUrls() []string {
	urls := make([]string, 0, len(config.GlobalConfig.SubUrls))
	urls = append(urls, config.GlobalConfig.SubUrls...)

	if len(config.GlobalConfig.SubUrlsRemote) != 0 {
		for _, d := range config.GlobalConfig.SubUrlsRemote {
			if remote, err := fetchRemoteSubUrls(utils.WarpUrl(d)); err != nil {
				slog.Warn("获取远程订阅清单失败，已忽略", "err", err)
			} else {
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
				urls = append([]string{localLastSucced + "#KeepSucced"}, urls...)
			}
			if _, err := os.Stat(localHistoryFile); err == nil {
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
		if d, err := u.Parse(utils.WarpUrl(s)); err == nil {
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
	return out
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

func GetDateFromSubs(subUrl string) ([]byte, error) {
	maxRetries := config.GlobalConfig.SubUrlsReTry
	// 重试间隔
	retryInterval := config.GlobalConfig.SubUrlsRetryInterval
	if retryInterval == 0 {
		retryInterval = 1
	}
	// 超时时间
	timeout := config.GlobalConfig.SubUrlsTimeout
	if timeout == 0 {
		timeout = 10
	}
	var lastErr error

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}

		// 解析 URL 字符串
		u, err := u.Parse(subUrl)
		if err != nil {
			lastErr = fmt.Errorf("解析URL失败: %w", err)
			continue
		}

		// 只要 fragment 非空
		isKeepSuccess := u.Fragment != ""

		// 构建请求
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			lastErr = err
			continue
		}

		// 根据判断结果添加请求头或查询参数
		if isKeepSuccess {
			q := req.URL.Query()
			if q.Get("from_subs_check") == "" {
				q.Set("from_subs_check", "true")
				req.URL.RawQuery = q.Encode()
			}
			req.Header.Set("X-From-Subs-Check", "true")
		}

		req.Header.Set("User-Agent", "clash.meta")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("订阅链接: %s 返回状态码: %d", req.URL.String(), resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("读取订阅链接: %s 数据错误: %v", req.URL.String(), err)
			continue
		}
		return body, nil
	}

	return nil, fmt.Errorf("重试%d次后失败: %v", maxRetries, lastErr)
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
