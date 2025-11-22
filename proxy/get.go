// get.go
package proxies

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/samber/lo"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"github.com/sinspired/subs-check/utils"
)

var (
	// ErrIgnore 标记无需记录日志的非致命错误
	ErrIgnore = errors.New("error-ignore")
)

// ProxyNode 定义通用节点结构类型
type ProxyNode map[string]any

type SubUrls struct {
	SubUrls []string `yaml:"sub-urls" json:"sub-urls"`
}

// GetProxies 主入口：获取、解析、去重及统计代理节点
func GetProxies() ([]map[string]any, int, int, error) {
	// 初始化环境与日志
	initEnvironment()

	// 解析订阅清单
	subUrls, localNum, remoteNum, historyNum := resolveSubUrls()
	logSubscriptionStats(len(subUrls), localNum, remoteNum, historyNum)

	// 数据管道
	proxyChan := make(chan ProxyNode, 100)

	// 统计与收集容器
	var (
		succedProxies  []ProxyNode
		historyProxies []ProxyNode
		syncProxies    []ProxyNode
		validSubs      = make(map[string]struct{})
		subNodeCounts  = make(map[string]int)
		wg             sync.WaitGroup
	)

	// 启动结果收集协程
	done := make(chan struct{})
	go func() {
		defer close(done)
		for proxy := range proxyChan {
			if su, ok := proxy["sub_url"].(string); ok && su != "" {
				validSubs[su] = struct{}{}
				subNodeCounts[su]++
			}
			// 分类存储
			switch {
			case proxy["sub_from_history"] == true:
				historyProxies = append(historyProxies, proxy)
			case proxy["sub_was_succeed"] == true:
				succedProxies = append(succedProxies, proxy)
			default:
				syncProxies = append(syncProxies, proxy)
			}
		}
	}()

	// 并发抓取
	concurrency := min(config.GlobalConfig.Concurrent, 100)
	sem := make(chan struct{}, concurrency)

	listenPort := strings.TrimPrefix(config.GlobalConfig.ListenPort, ":")
	subStorePort := strings.TrimPrefix(config.GlobalConfig.SubStorePort, ":")

	for _, subURL := range subUrls {
		wg.Add(1)
		sem <- struct{}{} // 获取令牌

		// 分析是否为本地特殊文件
		isSucced, isHistory, tag := identifyLocalSubType(subURL, listenPort, subStorePort)

		go func(u, t string, succ, hist bool) {
			defer wg.Done()
			defer func() { <-sem }()
			processSubscription(u, t, succ, hist, proxyChan)
		}(subURL, tag, isSucced, isHistory)
	}

	wg.Wait()
	close(proxyChan)
	<-done // 等待收集完成

	// 内存清理与去重合并
	runtime.GC()
	finalProxies, succedCount, historyCount := deduplicateAndMerge(succedProxies, historyProxies, syncProxies)

	// 保存统计
	saveStats(validSubs, subNodeCounts)

	return finalProxies, succedCount, historyCount, nil
}

// processSubscription 单个订阅的处理流程
func processSubscription(urlStr, tag string, wasSucced, wasHistory bool, out chan<- ProxyNode) {
	// 1. 下载
	data, err := FetchSubsData(urlStr)
	if err != nil {
		if !errors.Is(err, ErrIgnore) {
			// 根据错误类型打印错误消息
			logFatal(err, urlStr)
		}
		return
	}

	// 2. 解析
	nodes, err := parseSubscriptionData(data, urlStr)
	if err != nil {
		// 回退策略：尝试正则暴力提取
		nodes = fallbackExtractV2Ray(data, urlStr)
		if len(nodes) == 0 {
			slog.Warn("解析失败或为空列表", "URL", urlStr, "error", err)
			return
		}
	}

	// 3. 过滤与发送
	count := 0
	filterTypes := config.GlobalConfig.NodeType

	for _, node := range nodes {
		// 类型过滤
		if t, ok := node["type"].(string); ok && len(filterTypes) > 0 {
			if !lo.Contains(filterTypes, t) {
				continue
			}
		}

		// 规范化与元数据附加
		normalizeNode(node)
		node["sub_url"] = urlStr
		node["sub_tag"] = tag
		node["sub_was_succeed"] = wasSucced
		node["sub_from_history"] = wasHistory

		out <- node
		count++
	}

	slog.Debug("Parsed subscription", "URL", urlStr, "valid_nodes", count)
}

// parseSubscriptionData 智能分发解析器
func parseSubscriptionData(data []byte, subURL string) ([]ProxyNode, error) {
	// 优先尝试 YAML/JSON 结构化解析
	var generic any
	if err := yaml.Unmarshal(data, &generic); err == nil {

		switch val := generic.(type) {
		case map[string]any:
			// Clash 格式
			if proxies, ok := val["proxies"]; ok {
				slog.Info("提取clash格式")
				return parseClashProxies(proxies)
			}
			// Sing-Box 格式
			if outbounds, ok := val["outbounds"]; ok {
				slog.Info("提取singbox格式")
				return parseSingBoxOutbounds(outbounds)
			}
			// 非标准 JSON (协议名为 Key)
			if nodes := convertUnStandandJsonViaConvert(val); len(nodes) > 0 {
				slog.Info("解析到非标准 JSON格式的订阅")
				return convertToProxyNodes(nodes), nil
			}
		case []any:
			if len(val) == 0 {
				return nil, nil
			}

			// 1. 字符串数组 (链接列表 或 IP:Port 列表)
			if _, ok := val[0].(string); ok {
				slog.Info("解析到字符串数组 (链接列表 或 IP:Port 列表)")
				return parseStringList(val, subURL)
			}

			// 2. 对象数组 (Shadowsocks JSON配置等)
			if _, ok := val[0].(map[string]any); ok {
				slog.Info("解析到通用JSON对象数组 (Shadowsocks/SIP008等)")
				return convertGeneralJsonArray(val), nil
			}
		}
	}

	// 其次尝试 Base64/V2Ray 标准转换
	if nodes, err := convert.ConvertsV2Ray(data); err == nil && len(nodes) > 0 {
		slog.Info("v2ray格式")
		return convertToProxyNodes(nodes), nil
	}

	// 针对 "局部合法、全局非法" 的多段 proxies 文件
	if nodes := extractAndParseProxies(data); len(nodes) > 0 {
		slog.Debug("通过多端解析，获取到代理节点", "count", len(nodes))
		return nodes, nil
	}

	// 尝试自定义 Bracket KV 格式 ([Type]Name=...)
	if nodes := parseBracketKVProxies(data); len(nodes) > 0 {
		slog.Info("Bracket KV 格式")
		return convertToProxyNodes(nodes), nil
	}

	// 尝试 V2Ray Core JSON (按行)
	if nodes := parseV2RayJsonLines(data); len(nodes) > 0 {
		slog.Info("识别到 V2Ray JSON Lines 格式", "count", len(nodes))
		return nodes, nil
	}

	// 最后尝试按行猜测 (纯文本 IP:Port)
	if nodes := convertUnStandandTextViaConvert(subURL, data); len(nodes) > 0 {
		slog.Info("按行猜测")
		return nodes, nil
	}

	return nil, fmt.Errorf("未知格式")
}

// parseStringList 处理字符串列表
func parseStringList(list []any, subURL string) ([]ProxyNode, error) {
	var strList []string
	var finalNodes []ProxyNode

	// 1. 遍历列表，分离 WireGuard 和其他文本
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)

		// 拦截 WireGuard
		if strings.HasPrefix(s, "wireguard://") || strings.HasPrefix(s, "wg://") {
			slog.Info("处理wireguard协议")
			if node := ParseWireGuardURI(s); node != nil {
				finalNodes = append(finalNodes, ProxyNode(node))
			}
		} else {
			strList = append(strList, s)
		}
	}

	// 如果没有其他字符串，直接返回已解析的 WG 节点
	if len(strList) == 0 {
		return finalNodes, nil
	}

	// 2. 处理剩余字符串列表
	joined := strings.Join(strList, "\n")

	// 路径 A: 尝试作为 V2Ray 链接 (vmess://...)
	if nodes, err := convert.ConvertsV2Ray([]byte(joined)); err == nil && len(nodes) > 0 {
		finalNodes = append(finalNodes, convertToProxyNodes(nodes)...)
		return finalNodes, nil
	}

	// 路径 B: 尝试作为 IP:Port 列表，需猜测协议
	scheme := guessSchemeByURL(subURL)
	// 构造 { "scheme": ["ip:port"] } 结构交给通用转换器
	otherNodes := convertToProxyNodes(convertUnStandandJsonViaConvert(map[string]any{scheme: strList}))

	if len(otherNodes) > 0 {
		finalNodes = append(finalNodes, otherNodes...)
	}

	return finalNodes, nil
}

// fallbackExtractV2Ray 正则提取兜底
func fallbackExtractV2Ray(data []byte, subURL string) []ProxyNode {
	decodedData := TryDecodeBase64(data)
	links := extractV2RayLinks(decodedData)
	if len(links) == 0 {
		return nil
	}

	var finalNodes []ProxyNode

	slog.Info("开始处理提取到的链接", "count", len(links))

	for _, link := range links {
		link = strings.TrimSpace(link)

		// 1. 处理 WireGuard
		if strings.HasPrefix(link, "wireguard://") || strings.HasPrefix(link, "wg://") {
			if node := ParseWireGuardURI(link); node != nil {
				node["sub_url"] = subURL
				finalNodes = append(finalNodes, ProxyNode(node))
			}
			continue
		}

		// 2. 处理 SSR (使用手动解析，比 Mihomo 更稳)
		if strings.HasPrefix(link, "ssr://") {
			if node := ParseSSRURI(link); node != nil {
				node["sub_url"] = subURL
				finalNodes = append(finalNodes, ProxyNode(node))
			}
			continue
		}

		// 3. 其他标准协议 (vmess, ss, hy2) 逐个转换
		// 这样互不影响
		fixedLink := fixupProxyLink(link)
		if nodes, err := convert.ConvertsV2Ray([]byte(fixedLink)); err == nil && len(nodes) > 0 {
			converted := convertToProxyNodes(nodes)
			for _, n := range converted {
				n["sub_url"] = subURL
				finalNodes = append(finalNodes, n)
			}
		}
	}

	slog.Info("链接解析统计", "total_success", len(finalNodes))
	return finalNodes
}

// FetchSubsData 获取数据 (包含重试、占位符处理、代理策略)
func FetchSubsData(rawURL string) ([]byte, error) {
	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}
	conf := config.GlobalConfig
	maxRetries := max(1, conf.SubUrlsReTry)
	timeout := max(10, conf.SubUrlsTimeout)

	candidates, hasPlaceholder := buildCandidateURLs(rawURL)
	var lastErr error

	// 定义请求策略
	type strategy struct {
		useProxy bool
		urlFunc  func(string) string
	}

	strategies := []strategy{}
	isLocalURL := utils.IsLocalURL(rawURL)

	if isLocalURL {
		strategies = append(strategies, strategy{
			false,
			func(s string) string { return utils.WarpURL(ensureScheme(s), true) },
		})
	} else {
		if utils.IsSysProxyAvailable {
			strategies = append(strategies, strategy{
				true,
				func(s string) string { return utils.WarpURL(ensureScheme(s), true) },
			})
		}

		if utils.IsGhProxyAvailable {
			strategies = append(strategies, strategy{
				false,
				func(s string) string { return utils.WarpURL(ensureScheme(s), true) },
			})
		}
	}

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(max(1, conf.SubUrlsRetryInterval)) * time.Second)
		}

		for _, candidate := range candidates {
			for _, strat := range strategies {
				targetURL := strat.urlFunc(candidate)
				// 如果 Warp 之后 URL 没变（例如非 Github 链接），且策略是为了试 GhProxy，则跳过
				if strat.urlFunc != nil && targetURL == candidate && len(strategies) > 2 {
					continue
				}

				body, err, fatal := fetchOnce(targetURL, strat.useProxy, timeout)
				if err == nil {
					return body, nil
				}
				lastErr = err

				// 遇到 404 等致命错误且没有日期占位符时，直接终止
				if fatal && !hasPlaceholder {
					return nil, err
				}
			}
		}
		// 如果有日期占位符，且一轮尝试都失败，通常意味着猜测的日期不对，直接忽略，不记录 Error 日志
		if hasPlaceholder {
			return nil, ErrIgnore
		}
	}

	return nil, fmt.Errorf("多次重试失败: %v", lastErr)
}

// 辅助函数

func initEnvironment() {
	slog.Info("获取系统代理和Github代理状态")
	utils.IsSysProxyAvailable = utils.GetSysProxy()
	utils.IsGhProxyAvailable = utils.GetGhProxy()
	if utils.IsSysProxyAvailable {
		slog.Info("", "-system-proxy", config.GlobalConfig.SystemProxy)
	}
	if utils.IsGhProxyAvailable {
		slog.Info("", "-github-proxy", config.GlobalConfig.GithubProxy)
	}
}

func parseClashProxies(v any) ([]ProxyNode, error) {
	if list, ok := v.([]any); ok {
		return convertToProxyNodes(convertList(list)), nil
	}
	return nil, errors.New("invalid clash proxies format")
}

func parseSingBoxOutbounds(v any) ([]ProxyNode, error) {
	if list, ok := v.([]any); ok {
		return convertSingBoxOutbounds(list), nil
	}
	return nil, errors.New("invalid sing-box outbounds format")
}

func convertList(in []any) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, i := range in {
		if m, ok := i.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func convertToProxyNodes(list []map[string]any) []ProxyNode {
	if list == nil {
		return nil
	}
	res := make([]ProxyNode, len(list))
	for i, v := range list {
		res[i] = ProxyNode(v)
	}
	return res
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
		slog.Info("获取远程订阅列表")
		for _, subURLRemote := range config.GlobalConfig.SubUrlsRemote {
			warped := utils.WarpURL(subURLRemote, utils.IsGhProxyAvailable)
			if remote, err := fetchRemoteSubUrls(warped); err != nil {
				if !errors.Is(err, ErrIgnore) {
					// 根据错误类型打印错误消息
					logFatal(err, subURLRemote)
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
		if d, err := url.Parse(s); err == nil {
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

// fetchOnce 执行单次 HTTP 请求
func fetchOnce(target string, useProxy bool, timeoutSec int) ([]byte, error, bool) {
	// 构造 Request
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err, false
	}
	req.Header.Set("User-Agent", "clash.meta")

	// 特殊处理本地请求头
	if isLocalRequest(req.URL) {
		req.Header.Set("X-From-Subs-Check", "true")
		req.Header.Set("X-API-Key", config.GlobalConfig.APIKey)
		q := req.URL.Query()
		q.Set("from_subs_check", "true")
		req.URL.RawQuery = q.Encode()
	}

	// 构造 Client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           nil, // 默认直连
	}

	if useProxy {
		if p := config.GlobalConfig.SystemProxy; p != "" {
			if pu, err := url.Parse(p); err == nil {
				transport.Proxy = http.ProxyURL(pu)
			} else {
				transport.Proxy = http.ProxyFromEnvironment
			}
		} else {
			transport.Proxy = http.ProxyFromEnvironment
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err, false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		fatal := resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 410
		return nil, fmt.Errorf("%d", resp.StatusCode), fatal
	}

	body, err := io.ReadAll(resp.Body)
	return body, err, false
}

// fetchRemoteSubUrls 从远程地址读取订阅URL清单
// 支持两种格式：
// 1) 纯文本，按换行分隔，支持以 # 开头的注释与空行
// 2) YAML/JSON 的字符串数组
func fetchRemoteSubUrls(listURL string) ([]string, error) {
	if listURL == "" {
		return nil, errors.New("远程列表为空")
	}
	data, err := FetchSubsData(listURL)
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

	// 2.5) 解析为通用 map，尝试从 Clash/Mihomo 配置中提取 proxy-providers.*.url
	var generic map[string]any
	if err := yaml.Unmarshal(data, &generic); err == nil && len(generic) > 0 {
		if urls := extractClashProviderURLs(generic); len(urls) > 0 {
			return urls, nil
		}
	}

	// 3) 回退为按行解析 (纯文本) + 快速 URL 校验
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
		line = strings.Trim(line, "\"'")

		// 必须显式包含协议，仅接受 http/https
		if parsed, perr := url.Parse(line); perr == nil {
			scheme := strings.ToLower(parsed.Scheme)
			if (scheme == "http" || scheme == "https") && parsed.Host != "" {
				res = append(res, line)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
