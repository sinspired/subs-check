package proxies

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
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

// initEnvironment 初始化代理环境变量
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

// logSubscriptionStats 打印订阅数量统计
func logSubscriptionStats(total, local, remote, history int) {
	args := []any{}
	if local > 0 {
		args = append(args, "本地", local)
	}
	if remote > 0 {
		args = append(args, "远程", remote)
	}
	if history > 0 {
		args = append(args, "历史", history)
	}
	if total < local+remote+history {
		args = append(args, "总计[去重]", total)
	} else {
		args = append(args, "总计", total)
	}

	slog.Info("订阅数量", args...)

	if len(config.GlobalConfig.NodeType) > 0 {
		val := fmt.Sprintf("[%s]", strings.Join(config.GlobalConfig.NodeType, ","))
		slog.Info("代理协议筛选", slog.String("Type", val))
	}
}

// GetProxies 主入口：获取、解析、去重及统计代理节点
func GetProxies() ([]map[string]any, int, int, int, error) {
	// 初始化代理环境变量
	initEnvironment()

	// 获取远程订阅列表
	subUrls, localNum, remoteNum, historyNum := resolveSubUrls()
	logSubscriptionStats(len(subUrls), localNum, remoteNum, historyNum)

	proxyChan := make(chan ProxyNode, 5000)

	// 定义优先级常量
	const (
		PrioNormal  = 0
		PrioHistory = 1
		PrioSuccess = 2
	)

	var (
		wg sync.WaitGroup

		// 统计计数（原始数量）
		rawCount = 0

		// === 使用 Map 暂存最佳节点，替代 Slice ===
		// Key: 节点指纹
		// Value: 节点数据
		bestNodes = make(map[string]ProxyNode, 20000)

		// 记录已存储节点的优先级，用于比较
		nodePrio = make(map[string]int, 20000)

		// 订阅统计
		subNodeCounts = make(map[string]int)
		validSubs     = make(map[string]struct{})
	)

	// GC 阈值，每20万个节点进行一次GC，避免内存无限上涨
	const gcInterval = 200000
	pendingGCNum := 0

	// 处理获取节点，消费 proxyChan
	done := make(chan struct{})
	go func() {
		defer close(done)

		for proxy := range proxyChan {
			rawCount++
			pendingGCNum++

			// 流式 GC 控制
			if pendingGCNum >= gcInterval {
				// 在 GC 导致停顿前记录日志
				slog.Debug("触发流式内存清理", "当前已处理总数", rawCount)
				// 循环内GC
				runtime.GC()
				// 归还内存
				// 否则百万级节点池内存将持续增加
				debug.FreeOSMemory()
				pendingGCNum = 0
			}

			// 1. 统计订阅源
			if su, ok := proxy["sub_url"].(string); ok && su != "" {
				validSubs[su] = struct{}{}
				subNodeCounts[su]++
			}

			// 2. 计算当前节点的优先级
			currentPrio := PrioNormal
			if proxy["sub_was_succeed"] == true {
				currentPrio = PrioSuccess
			} else if proxy["sub_from_history"] == true {
				currentPrio = PrioHistory
			}

			// 3. 生成指纹
			key := GenerateProxyKey(proxy)

			// 4. 优先级竞争逻辑 (替代 DeduplicateAndMerge)
			if existPrio, exists := nodePrio[key]; exists {
				// 如果已存在，且新节点优先级更高，则覆盖（升级）
				if currentPrio > existPrio {
					bestNodes[key] = proxy
					nodePrio[key] = currentPrio
				}
				// 如果优先级相同或更低，直接丢弃（GC 会自动回收该 proxy）
			} else {
				// 如果不存在，直接存入
				bestNodes[key] = proxy
				nodePrio[key] = currentPrio
			}
		}
	}()

	// 获取订阅节点，生成proxyChan
	concurrency := min(config.GlobalConfig.Concurrent, 50)
	sem := make(chan struct{}, concurrency)
	listenPort := strings.TrimPrefix(config.GlobalConfig.ListenPort, ":")
	subStorePort := strings.TrimPrefix(config.GlobalConfig.SubStorePort, ":")

	for _, subURL := range subUrls {
		wg.Add(1)
		sem <- struct{}{}
		isSucced, isHistory, tag := identifyLocalSubType(subURL, listenPort, subStorePort)
		go func(u, t string, succ, hist bool) {
			defer wg.Done()
			defer func() { <-sem }()
			processSubscription(u, t, succ, hist, proxyChan)
		}(subURL, tag, isSucced, isHistory)
	}

	wg.Wait()
	close(proxyChan)
	<-done

	// 最终 GC 清理临时垃圾
	runtime.GC()
	debug.FreeOSMemory()

	// 将 Map 转为 Slice，并统计最终的分类数量
	finalProxies := make([]map[string]any, 0, len(bestNodes))
	finalSuccCount := 0
	finalHistCount := 0

	for key, node := range bestNodes {
		prio := nodePrio[key]

		// 统计逻辑：根据最终留下的那个节点的优先级计数
		switch prio {
		case PrioSuccess:
			finalSuccCount++
		case PrioHistory:
			finalHistCount++
		}

		// 清理元数据
		cleanMetadata(node)

		// 这里的显式转换是为了满足返回值类型 []map[string]any
		finalProxies = append(finalProxies, map[string]any(node))
	}

	// 释放 Map 内存（虽然函数返回后也会释放）
	bestNodes = nil
	nodePrio = nil

	saveStats(validSubs, subNodeCounts)
	// 打印去重统计日志
	slog.Info("节点解析",
		"原始", rawCount,
		"去重", len(finalProxies),
		"丢弃", rawCount-len(finalProxies),
	)
	return finalProxies, rawCount, finalSuccCount, finalHistCount, nil
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
		slog.Debug("解析代理节点成功", "node", node)
		// 类型过滤
		if len(filterTypes) > 0 {
			if t, ok := node["type"].(string); ok && !lo.Contains(filterTypes, t) {
				continue
			}
		}

		// 统一清洗节点字段，注入默认值
		NormalizeNode(node)

		node["sub_url"] = urlStr
		node["sub_tag"] = tag
		node["sub_was_succeed"] = wasSucced
		node["sub_from_history"] = wasHistory

		out <- node
		count++
	}

	slog.Debug("订阅解析完成", "URL", urlStr, "有效节点", count)
}

// parseSubscriptionData 智能分发解析器
func parseSubscriptionData(data []byte, subURL string) ([]ProxyNode, error) {
	// 优先尝试带注释的 Sing-Box 配置
	if nodes := ParseSingBoxWithMetadata(data); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "Sing-Box(Metadata)")
		return nodes, nil
	}

	// 尝试 YAML/JSON 结构化解析
	var generic any
	if err := yaml.Unmarshal(data, &generic); err == nil {
		switch val := generic.(type) {
		case map[string]any:
			// Clash 格式
			if proxies, ok := val["proxies"].([]any); ok {
				slog.Debug("解析成功", "订阅", subURL, "格式", "Mihomo/Clash")
				return convertListToNodes(proxies), nil
			}
			// Sing-Box 纯 JSON 格式
			if outbounds, ok := val["outbounds"].([]any); ok {
				slog.Debug("解析成功", "订阅", subURL, "格式", "Sing-Box(JSON)")
				return ConvertSingBoxOutbounds(outbounds), nil
			}
			// 非标准 JSON (协议名为 Key, e.g. {"vless": [...], "hysteria": [...]})
			if nodes := ConvertProtocolMap(val); len(nodes) > 0 {
				slog.Debug("解析成功", "订阅", subURL, "格式", "Non-Standard JSON", "数量", len(nodes))
				return nodes, nil
			}
		case []any:
			if len(val) == 0 {
				return nil, nil
			}
			if _, ok := val[0].(string); ok {
				slog.Debug("解析成功", "订阅", subURL, "格式", "String List")
				strList := make([]string, 0, len(val))
				for _, v := range val {
					if s, ok := v.(string); ok {
						strList = append(strList, s)
					}
				}
				return ParseProxyLinksAndConvert(strList, subURL), nil
			}
			if _, ok := val[0].(map[string]any); ok {
				slog.Debug("解析成功", "订阅", subURL, "格式", "General JSON List")
				return ConvertGeneralJsonArray(val), nil
			}
		}
	}

	// 尝试 Base64/V2Ray 标准转换
	if nodes, err := convert.ConvertsV2Ray(data); err == nil && len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "Base64/V2Ray", "数量", len(nodes))
		return ToProxyNodes(nodes), nil
	}

	// 针对 "局部合法、全局非法" 的多段 proxies 文件
	if nodes := ExtractAndParseProxies(data); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "Multipart Proxies", "数量", len(nodes))
		return nodes, nil
	}

	// 尝试逐行 YAML 流式解析
	if nodes := ParseYamlFlowList(data); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "YAML Flow List", "数量", len(nodes))
		return nodes, nil
	}

	// 尝试 Surge/Surfboard 格式
	if bytes.Contains(data, []byte("=")) && (bytes.Contains(data, []byte("[VMess]")) || bytes.Contains(data, []byte(", 20"))) {
		if nodes := ParseSurfboardProxies(data); len(nodes) > 0 {
			slog.Debug("解析成功", "订阅", subURL, "格式", "Surfboard/Surge", "数量", len(nodes))
			return nodes, nil
		}
	}

	// 尝试 V2Ray Core JSON
	if nodes := ParseV2RayJsonLines(data); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "V2Ray JSON Lines", "数量", len(nodes))
		return nodes, nil
	}

	// 尝试自定义 Bracket KV 格式 ([Type]Name=...)
	if nodes := ParseBracketKVProxies(data); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "Bracket KV", "数量", len(nodes))
		return nodes, nil
	}

	// 最后尝试按行猜测
	if nodes := parseRawLines(data, subURL); len(nodes) > 0 {
		slog.Debug("解析成功", "订阅", subURL, "格式", "Raw Lines (Guess)", "数量", len(nodes))
		return nodes, nil
	}

	return nil, fmt.Errorf("未知格式")
}

// parseRawLines 读取纯文本行并交给统一解析器
func parseRawLines(data []byte, subURL string) []ProxyNode {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, strings.TrimLeft(line, "- "))
		}
	}
	if len(lines) == 0 {
		return nil
	}

	return ParseProxyLinksAndConvert(lines, subURL)
}

// fallbackExtractV2Ray 正则提取兜底
func fallbackExtractV2Ray(data []byte, subURL string) []ProxyNode {
	decodedData := TryDecodeBase64(data)
	slog.Debug("base64解码", "decode", string(decodedData))
	links := ExtractV2RayLinks(decodedData)
	if len(links) == 0 {
		return nil
	}
	slog.Debug("正则提取链接", "数量", len(links), "URL", subURL)

	return ParseProxyLinksAndConvert(links, subURL)
}

func convertListToNodes(list []any) []ProxyNode {
	res := make([]ProxyNode, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			res = append(res, ProxyNode(m))
		}
	}
	return res
}

// FetchSubsData 获取数据 (包含重试、占位符处理、代理策略)
func FetchSubsData(rawURL string) ([]byte, error) {
	// 清洗 URL
	rawURL = CleanURL(rawURL)

	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}

	slog.Debug("正在下载订阅", "URL", rawURL)

	conf := config.GlobalConfig
	maxRetries := max(1, conf.SubUrlsReTry)
	timeout := max(10, conf.SubUrlsTimeout)

	// 处理为标准的GitHub raw地址
	rawURL = NormalizeGitHubRawURL(rawURL)

	candidates, hasPlaceholder := buildCandidateURLs(rawURL)
	var lastErr error

	// 定义请求策略
	type strategy struct {
		useProxy bool
		urlFunc  func(string) string
	}

	strategies := []strategy{}

	warpFunc := func(s string) string { return utils.WarpURL(EnsureScheme(s), true) }
	originFunc := func(s string) string { return EnsureScheme(s) }

	if utils.IsLocalURL(rawURL) {
		strategies = append(strategies, strategy{false, warpFunc})
	} else {
		// 1. 系统代理 (External utils)
		if utils.IsSysProxyAvailable {
			strategies = append(strategies, strategy{true, originFunc})
		}
		// 2. Github 代理 (External utils)
		if utils.IsGhProxyAvailable {
			strategies = append(strategies, strategy{false, warpFunc})
		}
		// 3. 直连兜底
		strategies = append(strategies, strategy{false, originFunc})
	}

	// UA 列表池
	var uaList = []string{
		convert.RandUserAgent(),
		"mihomo/1.18.3",
		"clash.meta",
		"curl/8.16.0",
	}

	for i := range maxRetries {
		ua := uaList[i%len(uaList)]
		if i > 0 {
			time.Sleep(time.Duration(max(1, conf.SubUrlsRetryInterval)) * time.Second)
		}

		for _, candidate := range candidates {
			triedInThisLoop := make(map[string]struct{})

			for _, strat := range strategies {
				targetURL := strat.urlFunc(candidate)

				key := fmt.Sprintf("%s|%v", targetURL, strat.useProxy)
				if _, tried := triedInThisLoop[key]; tried {
					continue
				}
				triedInThisLoop[key] = struct{}{}

				// 保持 Debug，过于频繁的尝试详情不需要 Info
				slog.Debug("尝试下载", "Target", targetURL, "Proxy", strat.useProxy)

				body, err, fatal := fetchOnce(targetURL, strat.useProxy, timeout, ua)
				if err == nil {
					return body, nil
				}
				lastErr = err

				if fatal && !hasPlaceholder {
					return nil, err
				}
			}
		}
		if hasPlaceholder {
			return nil, ErrIgnore
		}
	}

	return nil, fmt.Errorf("%d次重试后失败: %v", maxRetries, lastErr)
}

var (
	// clientMap 用于缓存不同代理策略的 HTTP Client
	// key: "direct" 或 proxyUrl (e.g. "http://127.0.0.1:7890")
	clientMap  = make(map[string]*http.Client)
	clientLock sync.RWMutex
)

// getClient 根据代理地址获取复用的 Client
func getClient(proxyAddr string) *http.Client {
	clientLock.RLock()
	client, ok := clientMap[proxyAddr]
	clientLock.RUnlock()

	if ok {
		return client
	}

	clientLock.Lock()
	defer clientLock.Unlock()

	// 双重检查
	if client, ok = clientMap[proxyAddr]; ok {
		return client
	}

	// 创建新的 Transport
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,              // 全局最大空闲连接
		MaxIdleConnsPerHost: 20,               // 每个 Host 最大空闲连接
		IdleConnTimeout:     90 * time.Second, // 空闲超时
		DisableKeepAlives:   false,            // 开启长连接复用
	}

	// 设置代理
	if proxyAddr != "direct" {
		if u, err := url.Parse(proxyAddr); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	} else {
		transport.Proxy = nil
	}

	// 创建 Client
	// timeout := max(10, config.GlobalConfig.SubUrlsTimeout)
	// 设置一个较大的超时，以在调用时控制超时
	newClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	clientMap[proxyAddr] = newClient
	return newClient
}

// fetchOnce 执行单次 HTTP 请求 (使用连接池)
func fetchOnce(target string, useProxy bool, timeoutSec int, ua string) ([]byte, error, bool) {
	// 1. 确定 Client Key
	proxyKey := "direct"
	if useProxy {
		if p := config.GlobalConfig.SystemProxy; p != "" {
			proxyKey = p // 使用代理地址作为 Key
		}
	}

	// 2. 获取复用的 Client
	client := getClient(proxyKey)

	// 3. 创建带超时的连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)

	defer cancel()

	// 4. 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err, false
	}
	if len(ua) <= 1 {
		ua = convert.RandUserAgent()
	}
	req.Header.Set("User-Agent", ua)

	// 4. 处理本地请求特殊 Header
	if isLocalRequest(req.URL) {
		req.Header.Set("X-From-Subs-Check", "true")
		req.Header.Set("X-API-Key", config.GlobalConfig.APIKey)
		q := req.URL.Query()
		q.Set("from_subs_check", "true")
		req.URL.RawQuery = q.Encode()
	}

	// 5. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, err, false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// 读取并丢弃 Body，有助于复用 TCP 连接（Keep-Alive）
		io.Copy(io.Discard, resp.Body)
		slog.Debug("错误", "url", req.URL, "代理", useProxy, "状态码", resp.StatusCode, "UA", req.UserAgent())
		fatal := resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 410
		return nil, fmt.Errorf("%d", resp.StatusCode), fatal
	}

	body, err := io.ReadAll(resp.Body)
	return body, err, false
}

// resolveSubUrls 合并本地与远程订阅清单并去重
func resolveSubUrls() ([]string, int, int, int) {
	var localNum, remoteNum, historyNum int
	localNum = len(config.GlobalConfig.SubUrls)

	urls := make([]string, 0, len(config.GlobalConfig.SubUrls))
	urls = append(urls, config.GlobalConfig.SubUrls...)

	if len(config.GlobalConfig.SubUrlsRemote) != 0 {
		slog.Info("获取远程订阅列表")
		for _, subURLRemote := range config.GlobalConfig.SubUrlsRemote {
			// 处理为标准的raw地址
			subURLRemote = NormalizeGitHubRawURL(subURLRemote)
			warped := utils.WarpURL(subURLRemote, utils.IsGhProxyAvailable)
			if remote, err := fetchRemoteSubUrls(warped); err != nil {
				if !errors.Is(err, ErrIgnore) {
					logFatal(err, subURLRemote)
				}
			} else {
				remoteNum += len(remote)
				urls = append(urls, remote...)
			}
		}
	}else{
		slog.Info("获取订阅列表")
	}

	requiredListenPort := strings.TrimSpace(strings.TrimPrefix(config.GlobalConfig.ListenPort, ":"))
	localLastSucced := fmt.Sprintf("http://127.0.0.1:%s/all.yaml", requiredListenPort)
	localHistory := fmt.Sprintf("http://127.0.0.1:%s/history.yaml", requiredListenPort)

	// 如果用户设置了保留成功节点，则把本地的 all.yaml 和 history.yaml 放到最前面
	if config.GlobalConfig.KeepSuccessProxies {
		saver, err := method.NewLocalSaver()
		if err == nil {
			if !filepath.IsAbs(saver.OutputPath) {
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

// fetchRemoteSubUrls 从远程地址读取订阅URL清单
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

// identifyLocalSubType 识别本地订阅源类型
func identifyLocalSubType(subURL, listenPort, storePort string) (isLatest, isHistory bool, tag string) {
	u, err := url.Parse(subURL)
	if err != nil {
		return false, false, ""
	}

	tag = u.Fragment
	port := u.Port()

	// 必须是本地地址
	if !utils.IsLocalURL(subURL) {
		return false, false, tag
	}

	// 端口必须匹配当前服务端口或存储端口
	if port != listenPort && port != storePort {
		return false, false, tag
	}

	// 路径分类
	path := u.Path
	isLatest = strings.HasSuffix(path, "/all.yaml") || strings.HasSuffix(path, "/all.yml")
	isHistory = strings.HasSuffix(path, "/history.yaml") || strings.HasSuffix(path, "/history.yml")

	return isLatest, isHistory, tag
}

func cleanMetadata(p ProxyNode) {
	delete(p, "sub_was_succeed")
	delete(p, "sub_from_history")
}

// saveStats 保存统计信息
func saveStats(validSubs map[string]struct{}, subNodeCounts map[string]int) {
	if !config.GlobalConfig.SubURLsStats {
		return
	}

	// 1. 保存有效链接列表
	list := lo.Keys(validSubs)
	sort.Strings(list)
	wrapped := map[string]any{"sub-urls": list}
	if data, err := yaml.Marshal(wrapped); err == nil {
		_ = method.SaveToStats(data, "subs-valid.yaml")
	}

	// 2. 保存数量统计
	type pair struct {
		URL   string
		Count int
	}
	pairs := make([]pair, 0, len(subNodeCounts))
	for u, c := range subNodeCounts {
		pairs = append(pairs, pair{u, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].URL < pairs[j].URL
		}
		return pairs[i].Count > pairs[j].Count
	})

	var sb strings.Builder
	sb.WriteString("订阅链接:\n")
	for _, p := range pairs {
		sb.WriteString(fmt.Sprintf("- %q: %d\n", p.URL, p.Count))
	}
	_ = method.SaveToStats([]byte(sb.String()), "subs-stats.yaml")
}

// buildCandidateURLs 生成候选链接
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

func hasDatePlaceholder(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "{ymd}") || strings.Contains(ls, "{y}") ||
		strings.Contains(ls, "{m}") || strings.Contains(ls, "{d}") ||
		strings.Contains(ls, "{y-m-d}") || strings.Contains(ls, "{y_m_d}")
}

func replaceDatePlaceholders(s string, t time.Time) string {
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

func isLocalRequest(u *url.URL) bool {
	return utils.IsLocalURL(u.Hostname()) &&
		(strings.Contains(u.Fragment, "Keep") || strings.Contains(u.Path, "history") || strings.Contains(u.Path, "all"))
}

// extractClashProviderURLs 从 Clash/Mihomo 配置中提取 proxy-providers 的 url
func extractClashProviderURLs(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := []string{"proxy-providers", "proxy_providers", "proxyproviders"}
	out := make([]string, 0, 8)
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		providers, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for _, prov := range providers {
			pm, ok := prov.(map[string]any)
			if !ok {
				continue
			}
			if u, ok := pm["url"].(string); ok {
				u = strings.TrimSpace(u)
				if u != "" {
					out = append(out, u)
				}
			}
		}
	}
	return out
}

func logFatal(err error, urlStr string) {
	if code, convErr := strconv.Atoi(err.Error()); convErr == nil {
		// err 是数字字符串，按状态码处理
		var msg string
		switch code {
		case 400:
			msg = "\033[31m错误请求\033[0m"
		case 401, 403:
			msg = "\033[31m无权限访问\033[0m"
		case 404:
			msg = "\033[31m订阅失效\033[0m"
		case 405:
			msg = "方法不被允许"
		case 408:
			msg = "请求超时"
		case 410:
			msg = "\033[31m资源已永久删除\033[0m"
		case 429:
			msg = "\033[33m请求过多，被限流\033[0m"
		case 500, 502, 503, 504:
			msg = "\033[31m服务端/网关错误\033[0m"
		default:
			msg = "请求失败"
		}
		// 对失效订阅加上删除线效果
		if code == 404 || code == 401 || code == 410 {
			urlStr = fmt.Sprintf("\033[9m%s\033[29m", urlStr)
		}
		slog.Error(msg, "URL", urlStr, "status", code)

	} else {
		// 普通错误
		slog.Error("获取失败", "URL", urlStr, "error", err)
	}
}

// NormalizeGitHubRawURL 将 GitHub 的 blob 或 raw 页面链接转换为 raw.githubusercontent.com 直链
func NormalizeGitHubRawURL(urlStr string) string {
	// 如果不是 github.com 的链接，或者已经是 raw.githubusercontent.com，直接返回
	if !strings.Contains(urlStr, "github.com") || strings.Contains(urlStr, "raw.githubusercontent.com") {
		return urlStr
	}

	// 移除可能存在的 www. 前缀，统一处理
	urlStr = strings.Replace(urlStr, "www.github.com", "github.com", 1)

	// 检查是否包含 /blob/ 或 /raw/
	// GitHub 结构通常是: github.com/{user}/{repo}/[blob|raw]/{branch}/{path}
	// 目标结构是: raw.githubusercontent.com/{user}/{repo}/{branch}/{path}

	if strings.Contains(urlStr, "/blob/") {
		urlStr = strings.Replace(urlStr, "github.com", "raw.githubusercontent.com", 1)
		urlStr = strings.Replace(urlStr, "/blob/", "/", 1)
	} else if strings.Contains(urlStr, "/raw/") {
		urlStr = strings.Replace(urlStr, "github.com", "raw.githubusercontent.com", 1)
		urlStr = strings.Replace(urlStr, "/raw/", "/", 1)
	}

	return urlStr
}

// CleanURL 清洗 URL，移除首尾空白及尾部常见的误复制标点符号
func CleanURL(raw string) string {
	// 1. 去除首尾的标准空白符 (空格, 换行, Tab)
	s := strings.TrimSpace(raw)

	// 2. 定义尾部需要剔除的“垃圾字符”集合
	// "  : 双引号
	// '  : 单引号
	// `  : 反引号 (Markdown常用)
	// ,  : 逗号
	// ;  : 分号
	// .  : 句号 (虽然URL允许结尾有点，但在订阅链接场景下通常是句尾误复制)
	// )  : 右括号 (Markdown链接常用)
	// ]  : 右方括号
	// }  : 右大括号
	// >  : 大于号 (Email/引用常用)
	cutset := "\"'`,;.)]}>" + "`"

	// 3. 循环移除尾部所有属于 cutset 的字符，直到遇到非 cutset 字符为止
	return strings.TrimRight(s, cutset)
}
