// Package proxies 处理订阅获取、去重及随机乱序，处理节点重命名
package proxies

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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
	// ErrIgnore 用作内部特殊标记，表示某些情况下无需记录日志的“非错误”返回
	ErrIgnore = errors.New("error-ignore")
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
	proxyChan := make(chan map[string]any, 1) // 缓冲通道存储解析的代理

	getSubsConcurrent := min(config.GlobalConfig.Concurrent, 100)
	concurrentLimit := make(chan struct{}, getSubsConcurrent) // 限制并发数

	// 启动收集结果的协程（将之前成功节点和其他订阅分别收集以便将之前成功节点放前面）
	var succedProxies []map[string]any
	var historyProxies []map[string]any
	var syncProxies []map[string]any

	// 记录成功解析出节点的订阅链接（去重）
	validSubs := make(map[string]struct{})
	// 统计每个订阅链接解析出的节点数量
	subNodeCounts := make(map[string]int)

	done := make(chan struct{})
	go func() {
		for proxy := range proxyChan {
			// 收到任一节点即标记该订阅链接为有效
			if su, ok := proxy["sub_url"].(string); ok && su != "" {
				validSubs[su] = struct{}{}
				subNodeCounts[su]++
			}
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
				if !errors.Is(err, ErrIgnore) {
					slog.Error(fmt.Sprintf("%v", err))
				}
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
					// 如果转换失败,进行一次提取
					links := extractV2RayLinks(data)
					if len(links) == 0 {
						// 尝试将无协议的 ip:port 列表按 URL 猜测协议头，再交给 ConvertsV2Ray 解析
						if guessed := convertUnStandandTextViaConvert(url, data); len(guessed) > 0 {
							for _, proxy := range guessed {
								if t, ok := proxy["type"].(string); ok {
									if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
										continue
									}
								}
								proxy["sub_url"] = url
								proxy["sub_tag"] = tag
								proxy["sub_was_succeed"] = wasSucced
								proxy["sub_from_history"] = wasHistory
								proxyChan <- proxy
							}
							return
						}
						return
					}
					// 将提取到的链接按换行拼接，走 V2Ray 转换逻辑
					extractedData := []byte(strings.Join(links, "\n"))
					proxyList, err = convert.ConvertsV2Ray(extractedData)
					if err != nil {
						slog.Error(fmt.Sprintf("解析提取的V2Ray链接错误: %v", err), "url", url)
						return
					}
					slog.Debug(fmt.Sprintf("获取订阅链接(文本提取): %s，有效节点数量: %d", url, len(proxyList)))
				}
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

			// 1) mihomo/clash 风格：proxies
			proxyInterface, ok := con["proxies"]
			if !ok || proxyInterface == nil {
				// 2) sing-box 风格：outbounds
				if outIf, ok := con["outbounds"]; ok && outIf != nil {
					if outList, ok := outIf.([]any); ok && len(outList) > 0 {
						converted := convertSingBoxOutbounds(outList)
						if len(converted) > 0 {
							slog.Debug(fmt.Sprintf("从sing-box outbounds解析: %s，有效节点数量: %d", url, len(converted)))
							for _, proxy := range converted {
								// 只测试指定协议
								if t, ok := proxy["type"].(string); ok {
									if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
										continue
									}
								}
								// 附加来源信息
								proxy["sub_url"] = url
								proxy["sub_tag"] = tag
								proxy["sub_was_succeed"] = wasSucced
								proxy["sub_from_history"] = wasHistory
								proxyChan <- proxy
							}
							return
						}
					}
				}

				// 3) 免费代理 JSON 列表风格：{"http":["ip:port",...], "socks5":[...], "socks4":[...]}
				if converted := convertUnStandandJsonViaConvert(con); len(converted) > 0 {
					slog.Debug(fmt.Sprintf("从free-proxies JSON(加协议头→ConvertsV2Ray)解析: %s，有效节点数量: %d", url, len(converted)))
					for _, proxy := range converted {
						if t, ok := proxy["type"].(string); ok {
							if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
								continue
							}
						}
						proxy["sub_url"] = url
						proxy["sub_tag"] = tag
						proxy["sub_was_succeed"] = wasSucced
						proxy["sub_from_history"] = wasHistory
						proxyChan <- proxy
					}
					return
				}

				// 在判断订阅链接为空前，尝试从已解析内容中提取以 v2ray 系列协议开头的链接
				links := extractV2RayLinks(con)

				if len(links) > 0 {
					// 将提取到的链接按换行拼接，走 V2Ray 转换逻辑
					extractedData := []byte(strings.Join(links, "\n"))
					proxyList, err := convert.ConvertsV2Ray(extractedData)
					if err != nil {
						slog.Error(fmt.Sprintf("解析提取的V2Ray链接错误: %v", err), "url", url)
						return
					}
					slog.Debug(fmt.Sprintf("从订阅中提取V2Ray链接: %s，有效节点数量: %d", url, len(proxyList)))
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

				// 结构化提取失败时，回退到对原始文本进行正则提取
				fallbackLinks := extractV2RayLinks(data)
				if len(fallbackLinks) > 0 {
					extractedData := []byte(strings.Join(fallbackLinks, "\n"))
					proxyList, err := convert.ConvertsV2Ray(extractedData)
					if err != nil {
						slog.Error(fmt.Sprintf("解析回退文本中提取的V2Ray链接错误: %v", err), "url", url)
						return
					}

					// 最终回退：将按 URL 猜测协议头处理纯文本/数组
					if guessed := convertUnStandandTextViaConvert(url, data); len(guessed) > 0 {
						for _, proxy := range guessed {
							if t, ok := proxy["type"].(string); ok {
								if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
									continue
								}
							}
							proxy["sub_url"] = url
							proxy["sub_tag"] = tag
							proxy["sub_was_succeed"] = wasSucced
							proxy["sub_from_history"] = wasHistory
							proxyChan <- proxy
						}
						return
					}
					slog.Debug(fmt.Sprintf("从订阅原始文本中提取V2Ray链接: %s，有效节点数量: %d", url, len(proxyList)))
					for _, proxy := range proxyList {
						if t, ok := proxy["type"].(string); ok {
							if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
								continue
							}
						}
						proxy["sub_url"] = url
						proxy["sub_tag"] = tag
						proxy["sub_was_succeed"] = wasSucced
						proxy["sub_from_history"] = wasHistory
						proxyChan <- proxy
					}
					return
				}

				slog.Warn(fmt.Sprintf("订阅链接为空: %s", url))
				return
			}

			proxyList, ok := proxyInterface.([]any)
			if !ok {
				return
			}
			// 若 proxies 是字符串数组（ip:port），按 URL 猜测协议头后统一走 ConvertsV2Ray
			{
				strArr := make([]string, 0, len(proxyList))
				for _, it := range proxyList {
					if s, ok := it.(string); ok {
						s = strings.TrimSpace(s)
						if s != "" {
							strArr = append(strArr, s)
						}
					}
				}
				if len(strArr) > 0 {
					con2 := map[string]any{guessSchemeByURL(url): strArr}
					converted := convertUnStandandJsonViaConvert(con2)
					if len(converted) > 0 {
						slog.Debug(fmt.Sprintf("proxies为字符串数组，已按URL猜测协议转换: %s，数量: %d", url, len(converted)))
						for _, proxy := range converted {
							if t, ok := proxy["type"].(string); ok {
								if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
									continue
								}
							}
							proxy["sub_url"] = url
							proxy["sub_tag"] = tag
							proxy["sub_was_succeed"] = wasSucced
							proxy["sub_from_history"] = wasHistory
							proxyChan <- proxy
						}
						return
					}
				}
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

	// 如开启订阅链接筛选，保存有效订阅链接到本地文件
	if true && config.GlobalConfig.SubURLsStats {
		list := make([]string, 0, len(validSubs))
		for su := range validSubs {
			list = append(list, su)
		}
		sort.Strings(list)
		// 以父级键 sub-urls 包装，生成如下结构：
		// sub-urls:
		//   - url1
		//   - url2
		wrapped := map[string]any{
			"sub-urls": list,
		}
		if data, err := yaml.Marshal(wrapped); err != nil {
			slog.Warn("序列化有效订阅链接失败", "err", err)
		} else if err := method.SaveToStats(data, "subs-valid.yaml"); err != nil {
			slog.Warn("保存有效订阅链接失败", "err", err)
		}

		// 保存每个订阅链接的节点统计到 subs-stats.yaml（按数量降序）
		type pair struct {
			URL   string
			Count int
		}
		pairs := make([]pair, 0, len(subNodeCounts))
		for u, c := range subNodeCounts {
			pairs = append(pairs, pair{URL: u, Count: c})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].Count == pairs[j].Count {
				return pairs[i].URL < pairs[j].URL
			}
			return pairs[i].Count > pairs[j].Count
		})
		// 保存为合法 YAML：每行一个条目，键为 URL，值为 count
		// 例如：
		// - "https://example.com/sub.txt": 123
		var sb strings.Builder
		sb.WriteString("订阅链接:\n")
		for _, p := range pairs {
			sb.WriteString(fmt.Sprintf("- %q: %d\n", p.URL, p.Count))
		}
		if err := method.SaveToStats([]byte(sb.String()), "subs-stats.yaml"); err != nil {
			slog.Warn("保存订阅统计失败", "err", err)
		}
	}

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
				if !errors.Is(err, ErrIgnore) {
					slog.Warn("获取远程订阅清单失败，已忽略", "err", err)
				}
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

type SubUrls struct {
	SubUrls []string `yaml:"sub-urls" json:"sub-urls"`
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

	// 1) 优先尝试解析为对象形式 (sub-urls: [...])
	var obj SubUrls
	if err := yaml.Unmarshal(data, &obj); err == nil && len(obj.SubUrls) > 0 {
		return obj.SubUrls, nil
	}

	// 2) 尝试解析为数组形式 ([...])
	var arr []string
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	// 3) 回退为按行解析 (纯文本)
	res := make([]string, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if after, ok := strings.CutPrefix(line, "-"); ok {
			line = strings.TrimSpace(after)
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
	candidates, hasDatePlaceholder := buildCandidateURLs(rawURL)

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
					if hasDatePlaceholder {
						return nil, ErrIgnore
					}

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
func buildCandidateURLs(u string) ([]string, bool) {
	if !hasDatePlaceholder(u) {
		return []string{u}, false
	}
	now := time.Now()
	yest := now.AddDate(0, 0, -1)
	today := replaceDatePlaceholders(u, now)
	yesterday := replaceDatePlaceholders(u, yest)
	slog.Debug("检测到日期占位符，将尝试今日和昨日日期")
	return []string{today, yesterday}, true
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
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

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

// 支持的 V2Ray/代理链接协议前缀（小写匹配）
var v2raySchemePrefixes = []string{
	"vmess://",
	"vless://",
	"trojan://",
	"ss://",
	"ssr://",
	// hysteria 系列
	"hysteria://",
	"hysteria2://",
	"hy2://",
	// tuic 系列
	"tuic://",
	"tuic5://",
	// socks 系列（部分订阅可能会混入）
	"socks://",
	"socks5://",
	"socks5h://",
	// 其他扩展协议（尽量兼容）
	"anytls://",
}

// 从任意已反序列化的数据结构中递归提取 V2Ray/代理链接
func extractV2RayLinks(v any) []string {
	links := make([]string, 0, 8)
	var walk func(any)
	walk = func(x any) {
		switch vv := x.(type) {
		case nil:
			return
		case string:
			links = append(links, extractV2RayLinksFromTextInternal(vv)...)
		case []byte:
			links = append(links, extractV2RayLinksFromTextInternal(string(vv))...)
		case []any:
			for _, it := range vv {
				walk(it)
			}
		case map[string]any:
			for _, it := range vv {
				walk(it)
			}
		}
	}
	walk(v)
	return normalizeExtractedLinks(uniqueStrings(links))
}

func uniqueStrings(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// 使用正则从纯文本中提取 V2Ray/代理链接
var (
	v2rayRegexOnce         sync.Once
	v2rayLinkRegexCompiled *regexp.Regexp
)

func getV2RayLinkRegex() *regexp.Regexp {
	v2rayRegexOnce.Do(func() {
		// 由前缀动态构建 scheme 正则，避免重复维护
		names := make([]string, 0, len(v2raySchemePrefixes))
		seen := make(map[string]struct{}, len(v2raySchemePrefixes))
		for _, p := range v2raySchemePrefixes {
			scheme := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(p), "://"))
			if scheme == "" {
				continue
			}
			if _, ok := seen[scheme]; ok {
				continue
			}
			seen[scheme] = struct{}{}
			names = append(names, regexp.QuoteMeta(scheme))
		}
		pattern := `(?i)\b(` + strings.Join(names, `|`) + `)://[^\s"'<>\)\]]+`
		v2rayLinkRegexCompiled = regexp.MustCompile(pattern)
	})
	return v2rayLinkRegexCompiled
}

func extractV2RayLinksFromTextInternal(s string) []string {
	if s == "" {
		return nil
	}
	re := getV2RayLinkRegex()
	matches := re.FindAllString(s, -1)
	return matches
}

// 规范化提取到的链接：
// - 去除首尾空白
// - 去除首尾引号 " ' `
// - 去除行首常见列表符号（- * • 等）
// - 去除行尾常见分隔符（, ， ; ；）
func normalizeExtractedLinks(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		// 去掉包裹引号
		t = strings.Trim(t, "\"'`")
		// 去掉行首的列表符号
		for {
			tt := strings.TrimLeft(t, " -\t\u00A0\u2003\u2002\u2009\u3000•*·")
			if tt == t {
				break
			}
			t = tt
		}
		// 去掉行尾常见分隔符
		t = strings.TrimRight(t, ",，;；")
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return uniqueStrings(out)
}

// 将 sing-box outbounds 转为 mihomo/clash 兼容的 proxies
func convertSingBoxOutbounds(outbounds []any) []map[string]any {
	res := make([]map[string]any, 0, len(outbounds))

	aggregators := map[string]struct{}{
		"selector": {},
		"urltest":  {},
		"direct":   {},
		"block":    {},
		"dns":      {},
	}

	for _, ob := range outbounds {
		m, ok := ob.(map[string]any)
		if !ok {
			continue
		}

		typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(m["type"])))
		if _, skip := aggregators[typ]; skip {
			continue
		}

		conv := make(map[string]any)
		// 映射基本字段
		server := strings.TrimSpace(fmt.Sprint(m["server"]))
		if server == "" {
			// 有的会写在 "server_address" 之类，尽量兼容
			if s := strings.TrimSpace(fmt.Sprint(m["server_address"])); s != "" {
				server = s
			}
		}
		conv["server"] = server
		conv["port"] = toIntPort(m["server_port"]) // mihomo 期望 "port"

		if tag := strings.TrimSpace(fmt.Sprint(m["tag"])); tag != "" {
			conv["name"] = tag
		}

		// 类型映射
		switch typ {
		case "shadowsocks":
			conv["type"] = "ss"
			if method := strings.TrimSpace(fmt.Sprint(m["method"])); method != "" {
				conv["cipher"] = method
			}
			if pwd := strings.TrimSpace(fmt.Sprint(m["password"])); pwd != "" {
				conv["password"] = pwd
			}
		case "vmess":
			conv["type"] = "vmess"
			if uuid := strings.TrimSpace(fmt.Sprint(m["uuid"])); uuid != "" {
				conv["uuid"] = uuid
			}
			if aid := strings.TrimSpace(fmt.Sprint(m["alter_id"])); aid != "" {
				conv["alterId"] = aid
			}
			// 默认 cipher 交给底层，或设为 auto
			conv["cipher"] = "auto"
		case "vless":
			conv["type"] = "vless"
			if uuid := strings.TrimSpace(fmt.Sprint(m["uuid"])); uuid != "" {
				conv["uuid"] = uuid
			}
			if flow := strings.TrimSpace(fmt.Sprint(m["flow"])); flow != "" {
				conv["flow"] = flow
			}
		case "trojan":
			conv["type"] = "trojan"
			if pwd := strings.TrimSpace(fmt.Sprint(m["password"])); pwd != "" {
				conv["password"] = pwd
			}
		case "hysteria2", "hy2":
			conv["type"] = "hysteria2"
			if pwd := strings.TrimSpace(fmt.Sprint(m["password"])); pwd != "" {
				conv["password"] = pwd
			}
			// sing-box 常见 obfs 写法：obfs {password}
			if obfs, ok := m["obfs"].(map[string]any); ok {
				if p := strings.TrimSpace(fmt.Sprint(obfs["password"])); p != "" {
					conv["obfs-password"] = p
				}
			}
		default:
			// 其他类型先按原样尝试，底层 mihomo 可能支持
			conv["type"] = typ
		}

		// 传输层（ws/grpc）
		if tr, ok := m["transport"].(map[string]any); ok {
			if t := strings.ToLower(strings.TrimSpace(fmt.Sprint(tr["type"]))); t != "" {
				switch t {
				case "ws":
					conv["network"] = "ws"
					wsopts := make(map[string]any)
					if p := strings.TrimSpace(fmt.Sprint(tr["path"])); p != "" {
						wsopts["path"] = p
					}
					if h, ok := tr["headers"].(map[string]any); ok {
						// 直接透传 headers
						wsopts["headers"] = h
					}
					if len(wsopts) > 0 {
						conv["ws-opts"] = wsopts
					}
				case "grpc":
					conv["network"] = "grpc"
					gops := make(map[string]any)
					if sn := strings.TrimSpace(fmt.Sprint(tr["service_name"])); sn != "" {
						gops["grpc-service-name"] = sn
					} else if sn := strings.TrimSpace(fmt.Sprint(tr["serviceName"])); sn != "" {
						gops["grpc-service-name"] = sn
					}
					if len(gops) > 0 {
						conv["grpc-opts"] = gops
					}
				}
			}
		}

		// TLS / Reality
		if tlsm, ok := m["tls"].(map[string]any); ok {
			conv["tls"] = true
			if sn := strings.TrimSpace(fmt.Sprint(tlsm["server_name"])); sn != "" {
				conv["servername"] = sn
			}
			if r, ok := tlsm["reality"].(map[string]any); ok {
				if en, ok := r["enabled"].(bool); ok && en {
					ro := make(map[string]any)
					if pk := strings.TrimSpace(fmt.Sprint(r["public_key"])); pk != "" {
						ro["public-key"] = pk
					}
					if sid := strings.TrimSpace(fmt.Sprint(r["short_id"])); sid != "" {
						ro["short-id"] = sid
					}
					if len(ro) > 0 {
						conv["reality-opts"] = ro
					}
				}
			}
		}

		res = append(res, conv)
	}

	return res
}

func toIntPort(v any) int {
	if v == nil {
		return 0
	}
	switch vv := v.(type) {
	case int:
		return vv
	case int64:
		return int(vv)
	case float64:
		return int(vv)
	case string:
		if vv == "" {
			return 0
		}
		if n, err := strconv.Atoi(vv); err == nil {
			return n
		}
	}
	return 0
}

// 支持解析免费代理 JSON 列表结构
// 形如：{"http":["ip:port",...], "https":[...], "socks5":[...], "socks4":[...]}
// 返回 mihomo/clash 兼容节点，仅包含 http 与 socks5；socks4 暂不支持（底层不兼容），将忽略。
func convertUnStandandJsonViaConvert(con map[string]any) []map[string]any {
	if len(con) == 0 {
		return nil
	}

	links := make([]string, 0, 256)

	// 收集不同类型 → 拼接相应协议头
	collect := func(kind string, arr any) {
		vals := make([]string, 0)
		switch vv := arr.(type) {
		case []any:
			for _, it := range vv {
				if s, ok := it.(string); ok {
					vals = append(vals, strings.TrimSpace(s))
				}
			}
		case []string:
			for _, s := range vv {
				vals = append(vals, strings.TrimSpace(s))
			}
		}
		for _, hp := range vals {
			if hp == "" {
				continue
			}
			host, portStr := splitHostPortLoose(hp)
			if host == "" || portStr == "" {
				continue
			}
			if _, err := strconv.Atoi(portStr); err != nil {
				continue
			}
			switch strings.ToLower(kind) {
			case "http":
				links = append(links, fmt.Sprintf("http://%s:%s", host, portStr))
			case "https":
				links = append(links, fmt.Sprintf("https://%s:%s", host, portStr))
			case "socks5":
				links = append(links, fmt.Sprintf("socks5://%s:%s", host, portStr))
			case "socks5h":
				links = append(links, fmt.Sprintf("socks5h://%s:%s", host, portStr))
			case "socks4":
				links = append(links, fmt.Sprintf("socks4://%s:%s", host, portStr))
			case "socks":
				// 默认为 socks5
				links = append(links, fmt.Sprintf("socks://%s:%s", host, portStr))
			case "mieru":
				links = append(links, fmt.Sprintf("mieru://%s:%s", host, portStr))
			case "anytls":
				links = append(links, fmt.Sprintf("anytls://%s:%s", host, portStr))
			// 下列协议一般需要额外参数，若上游真提供对应 key，则尝试构造，但多数会被 ConvertsV2Ray 忽略
			case "tuic":
				links = append(links, fmt.Sprintf("tuic://%s:%s", host, portStr))
			case "shadowsocks":
				links = append(links, fmt.Sprintf("shadowsocks://%s:%s", host, portStr))
			case "vmess":
				links = append(links, fmt.Sprintf("vmess://%s:%s", host, portStr))
			case "vless":
				links = append(links, fmt.Sprintf("vless://%s:%s", host, portStr))
			case "trojan":
				links = append(links, fmt.Sprintf("trojan://%s:%s", host, portStr))
			case "hysteria2":
				links = append(links, fmt.Sprintf("hysteria2://%s:%s", host, portStr))
			default:
				links = append(links, fmt.Sprintf("http://%s:%s", host, portStr))
			}
		}
	}

	if v, ok := con["http"]; ok && v != nil {
		collect("http", v)
	}
	if v, ok := con["https"]; ok && v != nil {
		collect("https", v)
	}
	if v, ok := con["socks5"]; ok && v != nil {
		collect("socks5", v)
	}
	if v, ok := con["socks5h"]; ok && v != nil {
		collect("socks5h", v)
	}
	if v, ok := con["socks4"]; ok && v != nil {
		collect("socks4", v)
	}
	if v, ok := con["socks"]; ok && v != nil {
		collect("socks", v)
	}
	if v, ok := con["mieru"]; ok && v != nil {
		collect("mieru", v)
	}
	// socks4 暂不处理

	if len(links) == 0 {
		return nil
	}

	data := []byte(strings.Join(links, "\n"))
	proxyList, err := convert.ConvertsV2Ray(data)
	if err != nil || len(proxyList) == 0 {
		return nil
	}
	return proxyList
}

// 更宽松的 host:port 分割，优先使用 net.SplitHostPort，失败则回退到最后一个冒号分割
func splitHostPortLoose(hp string) (string, string) {
	if hp == "" {
		return "", ""
	}
	if strings.Contains(hp, ":") {
		if h, p, err := net.SplitHostPort(hp); err == nil {
			return h, p
		}
		idx := strings.LastIndex(hp, ":")
		if idx > 0 && idx < len(hp)-1 {
			return hp[:idx], hp[idx+1:]
		}
	}
	return hp, ""
}

// 根据 URL 进行协议猜测：优先匹配 socks5/https/http 关键字，默认 http
func guessSchemeByURL(raw string) string {
	u, err := u.Parse(raw)
	if err != nil {
		return "http"
	}
	base := strings.ToLower(filepath.Base(u.Path))
	name := base
	if dot := strings.Index(base, "."); dot > 0 {
		name = base[:dot]
	}
	// 更全面的关键词匹配
	if strings.Contains(name, "socks5h") {
		return "socks5h"
	}
	if strings.Contains(name, "socks5") {
		return "socks5"
	}
	if strings.Contains(name, "socks4") {
		return "socks4"
	}
	if strings.Contains(name, "socks") {
		return "socks"
	}
	if strings.Contains(name, "mieru") {
		return "mieru"
	}
	if strings.Contains(name, "anytls") {
		return "anytls"
	}
	if strings.Contains(name, "https") || strings.Contains(name, "http2") {
		return "https"
	}
	if strings.Contains(name, "http") {
		return "http"
	}
	return "http"
}

// 将无协议的纯文本/JSON数组 ip:port 列表，按 URL 猜测协议头后交给 ConvertsV2Ray
func convertUnStandandTextViaConvert(rawURL string, data []byte) []map[string]any {
	// 优先尝试 JSON 数组
	var arr []string
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		kind := guessSchemeByURL(rawURL)
		con := map[string]any{kind: arr}
		return convertUnStandandJsonViaConvert(con)
	}

	// 其次当作纯文本换行分隔
	lines := make([]string, 0, 128)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 去掉可能的列表符号
		line = strings.TrimLeft(line, "- ")
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil
	}
	kind := guessSchemeByURL(rawURL)
	con := map[string]any{kind: lines}
	return convertUnStandandJsonViaConvert(con)
}
