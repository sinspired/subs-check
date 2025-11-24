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
	"regexp"
	"runtime"
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
	// 下面这些函数来自外部包 github.com/sinspired/subs-check/utils，保留 utils. 前缀
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
		args = append(args, "总计(去重)", total)
	} else {
		args = append(args, "总计", total)
	}

	slog.Info("订阅链接数量", args...)

	if len(config.GlobalConfig.NodeType) > 0 {
		val := fmt.Sprintf("[%s]", strings.Join(config.GlobalConfig.NodeType, ","))
		slog.Info("代理协议筛选", slog.String("Type", val))
	}
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

	// 并发抓取控制
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
		if len(filterTypes) > 0 {
			if t, ok := node["type"].(string); ok && !lo.Contains(filterTypes, t) {
				continue
			}
		}

		// 规范化与元数据附加
		NormalizeNode(node)

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
	// 优先尝试带注释的 Sing-Box 配置
	// 因为它包含 # 注释，直接用标准 Unmarshal 会失败，所以最先尝试清洗解析
	if nodes := ParseSingBoxWithMetadata(data); len(nodes) > 0 {
		slog.Debug("识别到 Sing-Box 配置 (含元数据)")
		return nodes, nil
	}

	// 尝试 YAML/JSON 结构化解析
	var generic any
	if err := yaml.Unmarshal(data, &generic); err == nil {
		switch val := generic.(type) {
		case map[string]any:
			// Clash 格式
			if proxies, ok := val["proxies"].([]any); ok {
				slog.Debug("提取clash格式")
				return convertListToNodes(proxies), nil
			}
			// Sing-Box 纯 JSON 格式
			if outbounds, ok := val["outbounds"].([]any); ok {
				slog.Debug("提取singbox格式")
				return ConvertSingBoxOutbounds(outbounds), nil
			}
			// 非标准 JSON (协议名为 Key, e.g. {"vless": [...], "hysteria": [...]})
			if nodes := ConvertProtocolMap(val); len(nodes) > 0 {
				slog.Debug("解析到非标准 JSON格式的订阅")
				return nodes, nil
			}
		case []any:
			if len(val) == 0 {
				return nil, nil
			}
			if _, ok := val[0].(string); ok {
				slog.Debug("解析到字符串数组 (链接列表)")
				strList := make([]string, 0, len(val))
				for _, v := range val {
					if s, ok := v.(string); ok {
						strList = append(strList, s)
					}
				}
				return ParseProxyLinksAndConvert(strList, subURL), nil
			}
			if _, ok := val[0].(map[string]any); ok {
				slog.Debug("解析到通用JSON对象数组 (Shadowsocks/SIP008等)")
				return ConvertGeneralJsonArray(val), nil
			}
		}
	}

	// 尝试 Base64/V2Ray 标准转换
	if nodes, err := convert.ConvertsV2Ray(data); err == nil && len(nodes) > 0 {
		return ToProxyNodes(nodes), nil
	}

	// 针对 "局部合法、全局非法" 的多段 proxies 文件
	if nodes := ExtractAndParseProxies(data); len(nodes) > 0 {
		slog.Debug("通过多段解析，获取到代理节点", "count", len(nodes))
		return nodes, nil
	}

	// 尝试逐行 YAML 流式解析 (这是上一步增加的容错逻辑)
	if nodes := ParseYamlFlowList(data); len(nodes) > 0 {
		return nodes, nil
	}

	// 尝试 Surge/Surfboard 格式
	if bytes.Contains(data, []byte("=")) && (bytes.Contains(data, []byte("[VMess]")) || bytes.Contains(data, []byte(", 20"))) {
		if nodes := ParseSurfboardProxies(data); len(nodes) > 0 {
			slog.Debug("Surfboard/Surge 格式", "count", len(nodes))
			return nodes, nil
		}
	}

	// 5. 尝试自定义 Bracket KV 格式 ([Type]Name=...)
	
	if nodes := ParseBracketKVProxies(data); len(nodes) > 0 {
		slog.Debug("Bracket KV 格式")
		return nodes, nil
	}

	// 尝试 V2Ray Core JSON
	if nodes := ParseV2RayJsonLines(data); len(nodes) > 0 {
		slog.Debug("识别到 V2Ray JSON Lines 格式", "count", len(nodes))
		return nodes, nil
	}

	// 最后尝试按行猜测
	if nodes := parseRawLines(data, subURL); len(nodes) > 0 {
		slog.Debug("按行猜测")
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
	links := ExtractV2RayLinks(decodedData)
	if len(links) == 0 {
		return nil
	}
	slog.Debug("开始处理提取到的链接", "count", len(links))

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
	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}
	conf := config.GlobalConfig
	maxRetries := max(1, conf.SubUrlsReTry)
	timeout := max(10, conf.SubUrlsTimeout)

	if strings.Contains(rawURL, "github.com") && strings.Contains(rawURL, "/blob/") {
		// 把 github.com/.../blob/... 转换为 raw.githubusercontent.com/.../...
		rawURL = strings.Replace(rawURL, "github.com/", "raw.githubusercontent.com/", 1)
		rawURL = strings.Replace(rawURL, "/blob/", "/", 1)
	}

	candidates, hasPlaceholder := buildCandidateURLs(rawURL)
	var lastErr error

	// 定义请求策略
	type strategy struct {
		useProxy bool
		urlFunc  func(string) string
	}

	strategies := []strategy{}

	isLocalURL := utils.IsLocalURL(rawURL)

	warpFunc := func(s string) string { return utils.WarpURL(EnsureScheme(s), true) }

	if isLocalURL {
		strategies = append(strategies, strategy{false, warpFunc})
	} else {
		// 1. 系统代理 (External utils)
		if utils.IsSysProxyAvailable {
			strategies = append(strategies, strategy{true, warpFunc})
		}
		// 2. Github 代理 (External utils)
		if utils.IsGhProxyAvailable {
			strategies = append(strategies, strategy{false, warpFunc})
		}
		// 3. 直连兜底
		strategies = append(strategies, strategy{false, warpFunc})
	}

	for i := range maxRetries {
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

				body, err, fatal := fetchOnce(targetURL, strat.useProxy, timeout)
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

	return nil, fmt.Errorf("多次重试失败: %v", lastErr)
}

// fetchOnce 执行单次 HTTP 请求
func fetchOnce(target string, useProxy bool, timeoutSec int) ([]byte, error, bool) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err, false
	}
	req.Header.Set("User-Agent", "clash.meta")

	if isLocalRequest(req.URL) {
		req.Header.Set("X-From-Subs-Check", "true")
		req.Header.Set("X-API-Key", config.GlobalConfig.APIKey)
		q := req.URL.Query()
		q.Set("from_subs_check", "true")
		req.URL.RawQuery = q.Encode()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           nil,
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

// resolveSubUrls 合并本地与远程订阅清单并去重
func resolveSubUrls() ([]string, int, int, int) {
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

// deduplicateAndMerge 去重并合并结果
func deduplicateAndMerge(succed, history, sync []ProxyNode) ([]map[string]any, int, int) {
	succedSet := make(map[string]struct{})
	finalList := make([]map[string]any, 0, len(succed)+len(history)+len(sync))

	// 1. 添加并记录 Success 节点
	for _, p := range succed {
		cleanMetadata(p)
		finalList = append(finalList, p)
		succedSet[GenerateProxyKey(p)] = struct{}{}
	}
	succedCount := len(succed)

	// 2. 添加 History 节点 (去重：不在 Success 中)
	histCount := 0
	for _, p := range history {
		key := GenerateProxyKey(p)
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
