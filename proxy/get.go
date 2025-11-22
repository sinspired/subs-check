// get.go
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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// ProxyNode 定义通用节点结构类型，方便类型断言
type ProxyNode map[string]any

type SubUrls struct {
	SubUrls []string `yaml:"sub-urls" json:"sub-urls"`
}

// GetProxies 主入口：获取、解析、去重代理节点
func GetProxies() ([]map[string]any, int, int, error) {
	// 1. 初始化环境
	initEnvironment()

	// 2. 解析所有订阅 URL (本地 + 远程 + 历史)
	subUrls, localNum, remoteNum, historyNum := resolveSubUrls()
	logSubscriptionStats(len(subUrls), localNum, remoteNum, historyNum)

	// 3. 并发控制与数据收集通道
	proxyChan := make(chan ProxyNode, 100)
	done := make(chan struct{})

	// 结果收集容器
	var (
		succedProxies  []ProxyNode
		historyProxies []ProxyNode
		syncProxies    []ProxyNode
		validSubs      = make(map[string]struct{})
		subNodeCounts  = make(map[string]int)
	)

	// 启动收集协程
	go func() {
		defer close(done)
		for proxy := range proxyChan {
			if su, ok := proxy["sub_url"].(string); ok && su != "" {
				validSubs[su] = struct{}{}
				subNodeCounts[su]++
			}
			// 分类存储以便后续排序
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

	// 4. 并发拉取与解析
	runConcurrentFetch(subUrls, proxyChan)
	close(proxyChan) // 关闭通道，通知收集协程结束
	<-done           // 等待收集完成

	// 5. 内存清理与去重合并
	runtime.GC()
	finalProxies, succedCount, historyCount := deduplicateAndMerge(succedProxies, historyProxies, syncProxies)

	// 6. 保存统计信息
	saveStats(validSubs, subNodeCounts)

	return finalProxies, succedCount, historyCount, nil
}

// initEnvironment 初始化代理检测
func initEnvironment() {
	IsSysProxyAvailable = utils.GetSysProxy()
	IsGhProxyAvailable = utils.GetGhProxy()
	if IsSysProxyAvailable {
		slog.Info("System Proxy Detected", "proxy", config.GlobalConfig.SystemProxy)
	}
	if IsGhProxyAvailable {
		slog.Info("Github Proxy Detected", "proxy", config.GlobalConfig.GithubProxy)
	}
	if len(config.GlobalConfig.NodeType) > 0 {
		slog.Info("Filter enabled", "types", config.GlobalConfig.NodeType)
	}
}

// runConcurrentFetch并发执行抓取任务
func runConcurrentFetch(subUrls []string, proxyChan chan<- ProxyNode) {
	var wg sync.WaitGroup
	concurrency := min(config.GlobalConfig.Concurrent, 100)
	sem := make(chan struct{}, concurrency)

	listenPort := strings.TrimPrefix(config.GlobalConfig.ListenPort, ":")
	subStorePort := strings.TrimPrefix(config.GlobalConfig.SubStorePort, ":")

	for _, subURL := range subUrls {
		wg.Add(1)
		sem <- struct{}{} // 获取令牌

		// 预判断特殊 URL 属性
		isSucced, isHistory, tag := analyzeURLAttributes(subURL, listenPort, subStorePort)

		go func(urlStr, tagStr string, succed, history bool) {
			defer wg.Done()
			defer func() { <-sem }()

			processSubscription(urlStr, tagStr, succed, history, proxyChan)
		}(subURL, tag, isSucced, isHistory)
	}
	wg.Wait()
}

// processSubscription 单个订阅的处理流程：下载 -> 识别 -> 解析 -> 过滤 -> 发送
func processSubscription(urlStr, tag string, wasSucced, wasHistory bool, out chan<- ProxyNode) {
	// 1. 下载数据
	data, err := FetchSubscriptionData(urlStr)
	if err != nil {
		if !errors.Is(err, ErrIgnore) {
			slog.Error("Fetch failed", "URL", urlStr, "error", err)
		}
		return
	}

	// 2. 智能解析
	nodes, err := parseSubscriptionData(data, urlStr)
	if err != nil {
		// 如果解析失败，尝试最后的一招：正则暴力提取 V2Ray 链接
		nodes = fallbackExtractV2Ray(data, urlStr)
		if len(nodes) == 0 {
			slog.Warn("Parse failed or empty", "URL", urlStr, "error", err)
			return
		}
	}

	// 3. 过滤、标记并发送
	count := 0
	filterTypes := config.GlobalConfig.NodeType
	for _, node := range nodes {
		// 类型过滤
		if t, ok := node["type"].(string); ok && len(filterTypes) > 0 {
			if !lo.Contains(filterTypes, t) {
				continue
			}
		}

		// 规范化处理 (如 hysteria2 混淆密码字段)
		normalizeNode(node)

		// 附加元数据
		node["sub_url"] = urlStr
		node["sub_tag"] = tag
		node["sub_was_succeed"] = wasSucced
		node["sub_from_history"] = wasHistory

		out <- node
		count++
	}

	slog.Debug("Parsed subscription", "URL", urlStr, "valid_nodes", count)
}

// ==========================================
// 核心解析逻辑
// ==========================================

// parseSubscriptionData 根据内容特征分发解析器
func parseSubscriptionData(data []byte, subURL string) ([]ProxyNode, error) {
	// 尝试解析为 YAML/JSON 通用结构
	var genericContainer any
	if err := yaml.Unmarshal(data, &genericContainer); err == nil {
		// 1. 判断是否为 Clash 配置 (包含 proxies 字段)
		if m, ok := genericContainer.(map[string]any); ok {
			if proxies, found := m["proxies"]; found {
				return parseClashProxies(proxies)
			}
			// 2. 判断是否为 Sing-Box 配置 (包含 outbounds 字段)
			if outbounds, found := m["outbounds"]; found {
				return parseSingBoxOutbounds(outbounds)
			}
			// 3. 判断是否为非标准 JSON 列表 (key 为协议名)
			if nodes := convertUnStandandJsonViaConvert(m); len(nodes) > 0 {
				// FIX: 使用 convertToProxyNodes 进行类型转换
				return convertToProxyNodes(nodes), nil
			}
		}

		// 4. 判断是否为纯字符串数组
		if arr, ok := genericContainer.([]any); ok {
			return parseStringList(arr, subURL)
		}
	}

	// 5. 尝试 Base64 / V2Ray 标准转换
	if nodes, err := convert.ConvertsV2Ray(data); err == nil && len(nodes) > 0 {
		return convertToProxyNodes(nodes), nil
	}

	// 6. 尝试自定义 Bracket KV 格式
	if nodes := parseBracketKVProxies(data); len(nodes) > 0 {
		// FIX: 使用 convertToProxyNodes 进行类型转换
		return convertToProxyNodes(nodes), nil
	}

	// 7. 尝试按行猜测协议
	if nodes := convertUnStandandTextViaConvert(subURL, data); len(nodes) > 0 {
		return nodes, nil
	}

	return nil, fmt.Errorf("unknown subscription format")
}

// parseClashProxies 解析 Clash 格式
func parseClashProxies(proxies any) ([]ProxyNode, error) {
	list, ok := proxies.([]any)
	if !ok {
		return nil, errors.New("proxies is not a list")
	}
	result := make([]ProxyNode, 0, len(list))
	for _, item := range list {
		if node, ok := item.(map[string]any); ok {
			result = append(result, node)
		}
	}
	return result, nil
}

// parseSingBoxOutbounds 解析 Sing-Box 格式并转换为 Clash 格式
func parseSingBoxOutbounds(outbounds any) ([]ProxyNode, error) {
	list, ok := outbounds.([]any)
	if !ok {
		return nil, errors.New("outbounds is not a list")
	}
	return convertSingBoxOutbounds(list), nil
}

// parseStringList 解析字符串列表，可能是 V2Ray Links 或 ip:port
func parseStringList(list []any, subURL string) ([]ProxyNode, error) {
	strList := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			strList = append(strList, s)
		}
	}
	if len(strList) == 0 {
		return nil, nil
	}

	// 尝试作为 V2Ray 链接解析
	joined := strings.Join(strList, "\n")
	if nodes, err := convert.ConvertsV2Ray([]byte(joined)); err == nil && len(nodes) > 0 {
		return convertToProxyNodes(nodes), nil
	}

	// 尝试作为 ip:port 列表解析 (猜测协议)
	scheme := guessSchemeByURL(subURL)
	con := map[string]any{scheme: strList}

	// FIX: 使用 convertToProxyNodes 转换结果
	nodes := convertUnStandandJsonViaConvert(con)
	return convertToProxyNodes(nodes), nil
}

// fallbackExtractV2Ray 最后的手段：正则提取
func fallbackExtractV2Ray(data []byte, subURL string) []ProxyNode {
	// 提取所有可能的链接
	links := extractV2RayLinks(data)

	if len(links) == 0 {
		return nil
	}

	// 预处理链接，标准化 hy:// 为 hysteria://
	// convert.ConvertsV2Ray 可能不识别 hy:// 前缀
	normalizedLinks := make([]string, 0, len(links))
	for _, link := range links {
		if strings.HasPrefix(link, "hy://") {
			link = strings.Replace(link, "hy://", "hysteria://", 1)
		}
		normalizedLinks = append(normalizedLinks, link)
	}

	// 转换提取到的链接
	joined := strings.Join(normalizedLinks, "\n")
	nodes, err := convert.ConvertsV2Ray([]byte(joined))
	if err != nil {
		// 如果转换失败，尝试按 URL 猜测协议处理这些纯文本
		// 注意：这里传入 joined (已经包含了标准化后的链接)
		return convertUnStandandTextViaConvert(subURL, []byte(joined))
	}
	return convertToProxyNodes(nodes)
}

// normalizeNode 规范化节点字段
func normalizeNode(node ProxyNode) {
	if t, ok := node["type"].(string); ok {
		// 修正 Hysteria2 字段名
		if t == "hysteria2" || t == "hy2" {
			if val, exists := node["obfs_password"]; exists {
				node["obfs-password"] = val
				delete(node, "obfs_password")
			}
		}
	}
}

// convertToProxyNodes 将 []map[string]any 转换为 []ProxyNode
func convertToProxyNodes(list []map[string]any) []ProxyNode {
	if list == nil {
		return nil
	}
	res := make([]ProxyNode, len(list))
	for i, v := range list {
		res[i] = ProxyNode(v) // 显式类型转换
	}
	return res
}

// ==========================================
// 辅助工具与逻辑
// ==========================================

// deduplicateAndMerge 去重并合并结果
func deduplicateAndMerge(succed, history, sync []ProxyNode) ([]map[string]any, int, int) {
	succedSet := make(map[string]struct{})
	finalList := make([]map[string]any, 0, len(succed)+len(history)+len(sync))

	// 1. 添加并记录 Success 节点
	for _, p := range succed {
		cleanMetadata(p)
		finalList = append(finalList, p)
		succedSet[generateProxyKey(p)] = struct{}{}
	}
	succedCount := len(succed)

	// 2. 添加 History 节点 (去重：不在 Success 中)
	histCount := 0
	for _, p := range history {
		key := generateProxyKey(p)
		if _, exists := succedSet[key]; !exists {
			cleanMetadata(p)
			finalList = append(finalList, p)
			succedSet[key] = struct{}{} // 避免 History 内部重复
			histCount++
		}
	}

	// 3. 添加 Sync 节点
	for _, p := range sync {
		cleanMetadata(p)
		finalList = append(finalList, p)
	}

	return finalList, succedCount, histCount
}

func cleanMetadata(p ProxyNode) {
	delete(p, "sub_was_succeed")
	delete(p, "sub_from_history")
}

// analyzeURLAttributes 分析 URL 是否为本地历史/成功文件
func analyzeURLAttributes(subURL, listenPort, storePort string) (isSucced, isHistory bool, tag string) {
	uParsed, err := url.Parse(subURL)
	if err != nil {
		return
	}
	tag = uParsed.Fragment

	host := uParsed.Hostname()
	port := uParsed.Port()

	if !isLocal(host) {
		return
	}

	// 端口匹配检查
	if port != listenPort && port != storePort {
		return
	}

	if strings.HasSuffix(uParsed.Path, "/all.yaml") || strings.HasSuffix(uParsed.Path, "/all.yml") {
		isSucced = true
	}
	if strings.HasSuffix(uParsed.Path, "/history.yaml") || strings.HasSuffix(uParsed.Path, "/history.yml") {
		isHistory = true
	}
	return
}

// FetchSubscriptionData 获取订阅数据，处理重试、代理和日期占位符
func FetchSubscriptionData(rawURL string) ([]byte, error) {
	// 配置项
	maxRetries := max(1, config.GlobalConfig.SubUrlsReTry)
	retryInterval := max(1, config.GlobalConfig.SubUrlsRetryInterval)
	timeout := max(10, config.GlobalConfig.SubUrlsTimeout)

	// 生成候选 URL (处理 {ymd} 等占位符)
	candidates, hasPlaceholder := buildCandidateURLs(rawURL)
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}

		for _, urlStr := range candidates {
			// 策略 1: 系统代理 (如果配置)
			if IsSysProxyAvailable {
				body, err, fatal := fetchOnce(ensureScheme(urlStr), true, timeout)
				if err == nil {
					return body, nil
				}
				lastErr = err
				if fatal && !hasPlaceholder {
					return nil, err
				}
			} else {
				// 策略 2: 直连
				body, err, fatal := fetchOnce(ensureScheme(urlStr), false, timeout)
				if err == nil {
					return body, nil
				}
				lastErr = err
				if fatal && !hasPlaceholder {
					return nil, err
				}
			}

			// 策略 3: Github Proxy (如果适用且不同)
			if IsGhProxyAvailable {
				ghUrl := utils.WarpURL(ensureScheme(urlStr), true)
				if ghUrl != urlStr {
					body, err, _ := fetchOnce(ghUrl, false, timeout)
					if err == nil {
						return body, nil
					}
					lastErr = errors.Join(lastErr, err)
				}
			}
		}
		// 如果有日期占位符且第一次循环所有候选都失败，不再重试日期组合，直接报忽略
		if hasPlaceholder {
			return nil, ErrIgnore
		}
	}

	return nil, fmt.Errorf("retries exhausted: %v", lastErr)
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
		fatal := resp.StatusCode == 404 || resp.StatusCode == 410 || resp.StatusCode == 401
		return nil, fmt.Errorf("http status %d", resp.StatusCode), fatal
	}

	body, err := io.ReadAll(resp.Body)
	return body, err, false
}

// ==========================================
// 辅助函数 (Helpers)
// ==========================================

func isLocalRequest(u *url.URL) bool {
	return isLocal(u.Hostname()) &&
		(strings.Contains(u.Fragment, "Keep") || strings.Contains(u.Path, "history") || strings.Contains(u.Path, "all"))
}

func logSubscriptionStats(total, local, remote, history int) {
	args := []any{}
	if local > 0 {
		args = append(args, "Local", local)
	}
	if remote > 0 {
		args = append(args, "Remote", remote)
	}
	if history > 0 {
		args = append(args, "History", history)
	}
	args = append(args, "Total", total)
	slog.Info("Subscription Stats", args...)
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

// convertSingBoxOutbounds 核心转换逻辑封装
func convertSingBoxOutbounds(outbounds []any) []ProxyNode {
	res := make([]ProxyNode, 0, len(outbounds))
	ignoredTypes := map[string]struct{}{"selector": {}, "urltest": {}, "direct": {}, "block": {}, "dns": {}}

	for _, ob := range outbounds {
		m, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		typ := strings.ToLower(fmt.Sprint(m["type"]))
		if _, skip := ignoredTypes[typ]; skip {
			continue
		}

		// 基础字段映射
		conv := ProxyNode{
			"server": lo.CoalesceOrEmpty(fmt.Sprint(m["server"]), fmt.Sprint(m["server_address"])),
			"port":   toIntPort(m["server_port"]),
			"name":   fmt.Sprint(m["tag"]),
		}

		// 类型特定映射
		switch typ {
		case "shadowsocks":
			conv["type"] = "ss"
			conv["cipher"] = m["method"]
			conv["password"] = m["password"]
		case "vmess":
			conv["type"] = "vmess"
			conv["uuid"] = m["uuid"]
			conv["alterId"] = m["alter_id"]
			conv["cipher"] = "auto"
		case "vless":
			conv["type"] = "vless"
			conv["uuid"] = m["uuid"]
			conv["flow"] = m["flow"]
		case "trojan":
			conv["type"] = "trojan"
			conv["password"] = m["password"]
		case "hysteria2", "hy2":
			conv["type"] = "hysteria2"
			conv["password"] = m["password"]
			if obfs, ok := m["obfs"].(map[string]any); ok {
				conv["obfs-password"] = obfs["password"]
			}
		case "hysteria", "hy":
			conv["type"] = "hysteria"
			conv["password"] = m["password"]
			if obfs, ok := m["obfs"].(map[string]any); ok {
				conv["obfs-password"] = obfs["password"]
			}
		case "tuic":
			conv["type"] = "tuic"
			conv["uuid"] = m["uuid"]
			conv["password"] = m["password"]
			conv["congestion-controller"] = m["congestion_controller"]
		default:
			conv["type"] = typ
		}

		// 传输层处理 (Transport)
		if tr, ok := m["transport"].(map[string]any); ok {
			trType := strings.ToLower(fmt.Sprint(tr["type"]))
			switch trType {
			case "ws":
				conv["network"] = "ws"
				conv["ws-opts"] = map[string]any{
					"path":    tr["path"],
					"headers": tr["headers"],
				}
			case "grpc":
				conv["network"] = "grpc"
				conv["grpc-opts"] = map[string]any{
					"grpc-service-name": lo.CoalesceOrEmpty(fmt.Sprint(tr["service_name"]), fmt.Sprint(tr["serviceName"])),
				}
			}
		}

		// TLS 处理
		if tlsMap, ok := m["tls"].(map[string]any); ok {
			conv["tls"] = true
			conv["servername"] = tlsMap["server_name"]
			conv["skip-cert-verify"] = tlsMap["insecure"]
			if reality, ok := tlsMap["reality"].(map[string]any); ok && reality["enabled"] == true {
				conv["reality-opts"] = map[string]any{
					"public-key": reality["public_key"],
					"short-id":   reality["short_id"],
				}
			}
		}

		res = append(res, conv)
	}
	return res
}

// convertUnStandandTextViaConvert 处理纯文本/数组 ip:port 列表
func convertUnStandandTextViaConvert(rawURL string, data []byte) []ProxyNode {
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

	scheme := guessSchemeByURL(rawURL)

	// FIX: 先获取 []map[string]any，再转换为 []ProxyNode
	nodes := convertUnStandandJsonViaConvert(map[string]any{scheme: lines})
	return convertToProxyNodes(nodes)
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
