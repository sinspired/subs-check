// utils.go
package proxies

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/samber/lo"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"github.com/sinspired/subs-check/utils"
)

// 协议映射表：Key 为常见的缩写或别名，Value 为标准协议头或标识
var protocolSchemes = map[string]string{
	// Hysteria
	"hysteria2": "hysteria2://", "hy2": "hysteria2://",
	"hysteria": "hysteria://", "hy": "hysteria://",
	// Standard
	"http": "http://", "https": "https://",
	"socks5": "socks5://", "socks5h": "socks5h://", "socks4": "socks4://", "socks": "socks://",
	// V2Ray / Others
	"vmess": "vmess://", "vless": "vless://",
	"trojan":      "trojan://",
	"shadowsocks": "ss://", "ss": "ss://",
	"tuic": "tuic://", "tuic5": "tuic://",
	"juicity":   "juicity://",
	"wireguard": "wg://", "wg": "wg://",
	"mieru":  "mieru://",
	"anytls": "anytls://",
}

// v2raySchemePrefixes 用于正则提取
var v2raySchemePrefixes = []string{
	"vmess://", "vless://", "trojan://", "ss://", "ssr://",
	"hysteria://", "hysteria2://", "hy2://", "hy://",
	"tuic://", "tuic5://", "juicity://",
	"wg://", "wireguard://",
	"socks://", "socks5://", "socks5h://",
	"anytls://", "mieru://",
}

var (
	v2rayRegexOnce         sync.Once
	v2rayLinkRegexCompiled *regexp.Regexp
)

// ======================
// 转换与解析核心工具
// ======================

// convertUnStandandJsonViaConvert 将非标准 JSON (Key为协议) 转换为标准节点
// 支持形如：{"http":["ip:port"], "hy2":["..."]}
func convertUnStandandJsonViaConvert(con map[string]any) []map[string]any {
	if len(con) == 0 {
		return nil
	}

	var links []string

	// 遍历 Map，查找已知协议
	for key, val := range con {
		prefix, isKnown := protocolSchemes[strings.ToLower(key)]
		if !isKnown {
			continue
		}

		// 提取列表内容
		var items []string
		switch v := val.(type) {
		case []string:
			items = v
		case []any:
			for _, s := range v {
				if str, ok := s.(string); ok {
					items = append(items, strings.TrimSpace(str))
				}
			}
		}

		// 格式化链接
		for _, item := range items {
			if item == "" {
				continue
			}
			// 1. 如果本身已经是完整链接 (包含 ://)，仅做标准化修复
			if strings.Contains(item, "://") {
				links = append(links, fixupProxyLink(item))
				continue
			}

			// 2. 否则，拼接 IP:Port
			host, port := splitHostPortLoose(item)
			if host == "" || port == "" {
				continue
			}
			if _, err := strconv.Atoi(port); err != nil {
				continue
			}

			links = append(links, fmt.Sprintf("%s%s:%s", prefix, host, port))
		}
	}

	if len(links) == 0 {
		return nil
	}

	// 统一交由 Mihomo/Clash 转换器处理
	data := []byte(strings.Join(links, "\n"))
	if nodes, err := convert.ConvertsV2Ray(data); err == nil {
		return nodes
	}
	return nil
}

// convertUnStandandTextViaConvert 处理纯文本行，按 URL 猜测协议
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
	slog.Info("按行读取数据", "line", len(lines))

	scheme := guessSchemeByURL(rawURL)
	// 复用 JSON 转换逻辑
	nodes := convertUnStandandJsonViaConvert(map[string]any{scheme: lines})
	return convertToProxyNodes(nodes)
}

// fixupProxyLink 修复非标准链接头，使其符合 Mihomo 标准
func fixupProxyLink(link string) string {
	// Hysteria: hy:// -> hysteria://
	if strings.HasPrefix(link, "hy://") {
		return strings.Replace(link, "hy://", "hysteria://", 1)
	}
	return link
}

// guessSchemeByURL 根据 URL 文件名猜测协议，默认为 http
func guessSchemeByURL(raw string) string {
	uParsed, err := url.Parse(raw)
	if err != nil {
		return "http"
	}

	filename := strings.ToLower(filepath.Base(uParsed.Path))
	// 移除扩展名
	if idx := strings.Index(filename, "."); idx > 0 {
		filename = filename[:idx]
	}

	// 遍历已知协议表进行匹配 (优先匹配长词，如 hysteria2)
	// 由于 map 无序，这里为了精准度，可以按长度排序或手动检测关键高频词
	// 为保持高效，手动检测常见词
	for key := range protocolSchemes {
		if strings.Contains(filename, key) {
			return key
		}
	}

	if strings.Contains(filename, "https") || strings.Contains(filename, "http2") {
		return "https"
	}
	return "http"
}

// ======================
// 基础工具函数
// ======================

func ensureScheme(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return s
	}
	// 本地环境默认 HTTP
	if utils.IsLocalURL(strings.Split(s, ":")[0]) {
		return "http://" + s
	}
	// Github 默认 HTTPS
	if strings.HasPrefix(s, "raw.githubusercontent.com/") || strings.HasPrefix(s, "github.com/") {
		return "https://" + s
	}
	return "http://" + s
}

func splitHostPortLoose(hp string) (string, string) {
	if hp == "" {
		return "", ""
	}
	if host, port, err := net.SplitHostPort(hp); err == nil {
		return host, port
	}
	// 回退逻辑：取最后一个冒号
	if idx := strings.LastIndex(hp, ":"); idx > 0 && idx < len(hp)-1 {
		return hp[:idx], hp[idx+1:]
	}
	return hp, ""
}

// ======================
// 正则与提取工具
// ======================

func getV2RayLinkRegex() *regexp.Regexp {
	v2rayRegexOnce.Do(func() {
		var schemes []string
		seen := make(map[string]struct{})
		for _, p := range v2raySchemePrefixes {
			s := strings.TrimSuffix(strings.ToLower(p), "://")
			if _, ok := seen[s]; !ok && s != "" {
				seen[s] = struct{}{}
				schemes = append(schemes, regexp.QuoteMeta(s))
			}
		}
		// 构造类似 `(?i)\b(vmess|vless|...):/\/[^\s"'<>\)\]]+` 的正则
		pattern := `(?i)\b(` + strings.Join(schemes, `|`) + `)://[^\s"'<>\)\]]+`
		v2rayLinkRegexCompiled = regexp.MustCompile(pattern)
	})
	return v2rayLinkRegexCompiled
}

func extractV2RayLinks(v any) []string {
	var links []string

	// 递归提取函数
	var walk func(any)
	walk = func(x any) {
		switch vv := x.(type) {
		case string:
			links = append(links, extractLinksFromStr(vv)...)
		case []byte:
			links = append(links, extractLinksFromStr(string(vv))...)
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
	return normalizeExtractedLinks(lo.Uniq(links))
}

func extractLinksFromStr(s string) []string {
	if s == "" {
		return nil
	}
	return getV2RayLinkRegex().FindAllString(s, -1)
}

func normalizeExtractedLinks(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		t = strings.Trim(t, "\"'`")
		t = strings.TrimRight(t, ",，;；")
		if t != "" {
			out = append(out, t)
		}
	}
	return lo.Uniq(out)
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

// 解析形如：
// [Type] Name = type, server, port, k=v, ...
// 的自定义文本格式为 mihomo/clash 兼容的 proxy map
func parseBracketKVProxies(data []byte) []map[string]any {
	res := make([]map[string]any, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 仅处理包含 '=' 的行
		eq := strings.Index(line, "=")
		if eq <= 0 || eq >= len(line)-1 {
			continue
		}
		left := strings.TrimSpace(line[:eq])
		right := strings.TrimSpace(line[eq+1:])

		// 提取名称，去掉左侧前缀的 [Type]
		name := left
		if strings.HasPrefix(left, "[") {
			if r := strings.Index(left, "]"); r >= 0 {
				name = strings.TrimSpace(left[r+1:])
			}
		}

		// 拆分逗号参数：type, server, port, k=v...
		rawParts := strings.Split(right, ",")
		parts := make([]string, 0, len(rawParts))
		for _, p := range rawParts {
			pp := strings.TrimSpace(p)
			if pp != "" {
				parts = append(parts, pp)
			}
		}
		if len(parts) < 3 {
			continue
		}

		typ := strings.ToLower(parts[0])
		server := parts[1]
		portStr := parts[2]
		port, perr := strconv.Atoi(strings.TrimSpace(portStr))
		if perr != nil || port <= 0 {
			continue
		}

		m := make(map[string]any)
		m["name"] = name
		m["server"] = strings.TrimSpace(server)
		m["port"] = port
		switch typ {
		case "shadowsocks":
			m["type"] = "ss"
		case "ss":
			m["type"] = "ss"
		case "trojan":
			m["type"] = "trojan"
		case "vmess":
			m["type"] = "vmess"
		case "vless":
			m["type"] = "vless"
		case "hysteria2", "hy2":
			m["type"] = "hysteria2"
		case "hysteria", "hy":
			m["type"] = "hysteria"
		default:
			// 未知类型跳过
			continue
		}

		// 可选参数解析
		var wsOpts map[string]any
		for _, kv := range parts[3:] {
			idx := strings.Index(kv, "=")
			if idx <= 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[:idx]))
			val := strings.TrimSpace(kv[idx+1:])
			val = strings.Trim(val, "\"'")

			switch key {
			case "username", "uuid":
				if m["type"] == "vmess" || m["type"] == "vless" {
					m["uuid"] = val
				}
			case "password", "passwd":
				m["password"] = val
			case "encrypt-method", "method", "cipher":
				if m["type"] == "ss" {
					m["cipher"] = val
				}
			case "sni", "servername":
				m["servername"] = val
			case "skip-cert-verify", "skip_cert_verify":
				if b, ok := parseBoolLoose(val); ok {
					m["skip-cert-verify"] = b
				}
			case "udp-relay", "udp":
				if b, ok := parseBoolLoose(val); ok {
					m["udp"] = b
				}
			case "tfo":
				if b, ok := parseBoolLoose(val); ok {
					m["tfo"] = b
				}
			case "tls":
				if b, ok := parseBoolLoose(val); ok {
					m["tls"] = b
				}
			case "ws":
				if b, ok := parseBoolLoose(val); ok && b {
					m["network"] = "ws"
				}
			case "ws-path", "wspath", "path":
				if wsOpts == nil {
					wsOpts = map[string]any{}
				}
				wsOpts["path"] = val
				if _, ok := m["network"]; !ok {
					m["network"] = "ws"
				}
			case "ws-headers", "wsheader":
				if val != "" {
					// 形如 Host:example.com 或 key:value
					k, v := parseHeaderKV(val)
					if k != "" {
						if wsOpts == nil {
							wsOpts = map[string]any{}
						}
						h := map[string]any{k: v}
						wsOpts["headers"] = h
					}
				}
			case "vmess-aead", "tls13":
				// 忽略或留作以后扩展
			default:
				// 未识别键忽略
			}
		}
		if wsOpts != nil {
			m["ws-opts"] = wsOpts
		}

		// 基础必需项校验（尽力）
		valid := true
		switch m["type"] {
		case "ss":
			if m["cipher"] == nil || m["password"] == nil {
				valid = false
			}
		case "trojan":
			if m["password"] == nil {
				valid = false
			}
		case "vmess", "vless":
			if m["uuid"] == nil {
				valid = false
			}
		}
		if !valid {
			continue
		}

		res = append(res, m)
	}
	return res
}

func parseBoolLoose(s string) (bool, bool) {
	ls := strings.ToLower(strings.TrimSpace(s))
	switch ls {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func parseHeaderKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx <= 0 {
		return "", ""
	}
	k := strings.TrimSpace(s[:idx])
	v := strings.TrimSpace(s[idx+1:])
	return k, v
}

// 针对格式: - {name: xxx, server: xxx, ...}
// extractAndParseProxies 提取文件中所有离散的 proxies 块并解析
func extractAndParseProxies(data []byte) []ProxyNode {
	var allNodes []ProxyNode
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var buffer bytes.Buffer
	inProxiesBlock := false
	blockCount := 0 // 统计块的数量

	// 辅助函数：解析缓冲区中的 YAML 块
	parseBuffer := func() {
		if buffer.Len() == 0 {
			return
		}
		// 构造一个临时的结构来接收解析结果
		var container struct {
			Proxies []map[string]any `yaml:"proxies"`
		}

		// 使用 goccy/go-yaml 解析这段合法的片段
		if err := yaml.Unmarshal(buffer.Bytes(), &container); err == nil && len(container.Proxies) > 0 {
			blockCount++ // 成功解析一个块
			countBefore := len(allNodes)

			// 转换并添加到总列表
			for _, p := range container.Proxies {
				// 标准化处理 (处理 ws-path, port 类型等)
				normalized := normalizeFlatFields(p)
				allNodes = append(allNodes, ProxyNode(normalized))
			}

			slog.Debug("解析单个proxies块成功",
				"BlockIndex", blockCount,
				"NewNodes", len(allNodes)-countBefore,
			)
		}
		buffer.Reset()
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 1. 检测是否进入 proxies 块
		// 必须是以 "proxies:" 开头
		if strings.HasPrefix(line, "proxies:") {
			// 如果之前已经在一个块里，先结算之前的
			if inProxiesBlock {
				parseBuffer()
			}
			inProxiesBlock = true
			buffer.WriteString(line + "\n")
			continue
		}

		// 2. 处理块内的行
		if inProxiesBlock {
			// 遇到空行或注释，为了保持格式，建议保留（或忽略均可，这里保留）
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				buffer.WriteString(line + "\n")
				continue
			}

			// 判断缩进：如果行首有空格或Tab，视作块内容
			hasIndent := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")

			if hasIndent {
				buffer.WriteString(line + "\n")
			} else {
				// 遇到无缩进的非空行 (例如 "port: 7890") -> 块结束
				inProxiesBlock = false
				parseBuffer()

				// 【特殊情况】当前行本身就是下一个 "proxies:" 的开始（极少见但防御性处理）
				if strings.HasPrefix(line, "proxies:") {
					inProxiesBlock = true
					buffer.WriteString(line + "\n")
				}
			}
		}
	}

	// 循环结束后，处理最后一个块
	if inProxiesBlock {
		parseBuffer()
	}

	// 打印最终统计
	if blockCount > 0 {
		slog.Info("分块解析完成", "总Block数量", blockCount, "总节点数量", len(allNodes))
	}

	return allNodes
}

// normalizeFlatFields 将非标准的扁平字段映射为 Clash 标准结构
func normalizeFlatFields(m map[string]any) map[string]any {
	// 1. 强力修复 Port 类型
	if p, ok := m["port"]; ok {
		m["port"] = toIntPort(p)
	}

	// 2. 处理 Flow Style 中的扁平化 ws 配置
	// 示例: { ..., ws-path: /abc, ws-headers: {...} } -> { ws-opts: { path: /abc ... } }
	var wsPath, wsHeaders any
	hasWsFields := false

	// 提取
	if v, ok := m["ws-path"]; ok {
		wsPath = v
		delete(m, "ws-path") // 删除旧键
		hasWsFields = true
	}
	if v, ok := m["ws-headers"]; ok {
		wsHeaders = v
		delete(m, "ws-headers") // 删除旧键
		hasWsFields = true
	}

	// 合并
	if hasWsFields {
		wsOpts := make(map[string]any)
		// 如果原本就有 ws-opts (混合情况)，先取出来
		if existing, ok := m["ws-opts"].(map[string]any); ok {
			wsOpts = existing
		}

		if wsPath != nil {
			wsOpts["path"] = wsPath
		}
		if wsHeaders != nil {
			wsOpts["headers"] = wsHeaders
		}
		m["ws-opts"] = wsOpts

		// 确保 network 字段被设置
		if _, ok := m["network"]; !ok {
			m["network"] = "ws"
		}
	}

	// 3. 处理其他布尔值字符串 (例如 "true" 字符串转 bool)
	normalizeBool(m, "tls")
	normalizeBool(m, "udp")
	normalizeBool(m, "skip-cert-verify")
	normalizeBool(m, "allow-insecure")

	return m
}

// toIntPort 极其宽容的端口转换函数
func toIntPort(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case uint:
		return int(val)
	case uint32:
		return int(val)
	case uint64:
		return int(val) // goccy/go-yaml 经常解析成这个
	case float32:
		return int(val)
	case float64:
		return int(val) // 标准 json 解析成这个
	case string:
		// 尝试解析 "443" 或 "443.0"
		clean := strings.Split(val, ".")[0] // 去掉可能的小数点
		if i, err := strconv.Atoi(clean); err == nil {
			return i
		}
	}
	return 0
}

func normalizeBool(m map[string]any, key string) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			lower := strings.ToLower(s)
			switch lower {
			case "true", "1":
				m[key] = true
			case "false", "0":
				m[key] = false
			}
		}
	}
}

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
	if total < local+remote {
		args = append(args, "总计（去重）", total)
	} else {
		args = append(args, "总计", total)
	}

	slog.Info("订阅链接数量", args...)

	if len(config.GlobalConfig.NodeType) > 0 {
		val := fmt.Sprintf("[%s]", strings.Join(config.GlobalConfig.NodeType, ","))

		slog.Info("代理协议筛选", slog.String("Type", val))
	}
}

// identifyLocalSubType 识别本地订阅源类型
// 仅当 URL 是本地地址且端口匹配时才返回分类结果，否则返回全 false/""
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

	// 3. 添加 Sync 节点 (此处不做严格去重，或者依赖后续处理，按原逻辑保留)
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

func isLocalRequest(u *url.URL) bool {
	return utils.IsLocalURL(u.Hostname()) &&
		(strings.Contains(u.Fragment, "Keep") || strings.Contains(u.Path, "history") || strings.Contains(u.Path, "all"))
}

// 从 Clash/Mihomo 配置中提取 proxy-providers 的 url 字段
func extractClashProviderURLs(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	// 支持的可能命名
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
		switch code {
		case 400:
			slog.Error("\033[31m错误请求\033[0m", "订阅", urlStr, "status", code)

		case 401, 403:
			slog.Error("\033[31m无权限访问\033[0m", "URL", fmt.Sprintf("\033[9m%s\033[29m", urlStr), "status", code)

		case 404:
			slog.Error("\033[31m订阅失效\033[0m", "订阅", fmt.Sprintf("\033[9m%s\033[29m", urlStr), "status", code)

		case 405:
			slog.Error("方法不被允许", "URL", urlStr, "status", code)

		case 408:
			slog.Error("请求超时", "URL", urlStr, "status", code)

		case 410:
			slog.Error("\033[31m资源已永久删除\033[0m", "订阅", fmt.Sprintf("\033[9m%s\033[29m", urlStr), "status", code)

		case 429:
			slog.Error("\033[33m请求过多，被限流\033[0m", "URL", urlStr, "status", code)

		case 500:
			slog.Error("\033[31m服务器内部错误\033[0m", "URL", urlStr, "status", code)
		case 502:
			slog.Error("\033[31m网关错误\033[0m", "URL", urlStr, "status", code)
		case 503:
			slog.Error("\033[31m服务不可用\033[0m", "URL", urlStr, "status", code)
		case 504:
			slog.Error("\033[31m网关超时\033[0m", "URL", urlStr, "status", code)

		default:
			slog.Error("请求失败", "URL", urlStr, "status", code)
		}
	} else {
		// 普通错误
		slog.Error("获取失败", "URL", urlStr, "error", err)
	}
}

// convertGeneralJsonArray 处理通用对象数组，识别特定客户端的格式 (如 Shadowsocks 导出配置)
func convertGeneralJsonArray(list []any) []ProxyNode {
	var nodes []ProxyNode

	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		// 识别 Shadowsocks 传统导出格式
		// 特征: 包含 "server_port", "password", "method", "server"
		if _, hasPort := m["server_port"]; hasPort {
			if _, hasMethod := m["method"]; hasMethod {
				node := make(ProxyNode)

				// 必须字段映射
				node["type"] = "ss"
				node["server"] = m["server"]
				node["port"] = toIntPort(m["server_port"]) // 使用之前增强过的 toIntPort
				node["cipher"] = m["method"]
				node["password"] = m["password"]

				// 名称映射 (remarks -> name)
				if remarks, ok := m["remarks"].(string); ok && remarks != "" {
					node["name"] = remarks
				} else {
					// 如果没有备注，生成一个默认名字
					node["name"] = fmt.Sprintf("ss-%s:%v", m["server"], m["server_port"])
				}

				// 插件处理 (plugin)
				if plugin, ok := m["plugin"].(string); ok && plugin != "" {
					node["plugin"] = plugin
					if pluginOpts, ok := m["plugin_opts"].(string); ok {
						node["plugin-opts"] = pluginOpts // 注意：有些客户端导出的 opts 是字符串而非对象
					}
				}

				// 简单的有效性检查
				if node["server"] != nil && node["port"] != 0 && node["cipher"] != nil {
					nodes = append(nodes, node)
				}
				continue
			}
		}

		// 可以在这里扩展其他非标准 JSON 对象的识别逻辑 (例如 SIP008 等)
	}

	return nodes
}

// ParseWireGuardURI 解析 wireguard:// 链接
func ParseWireGuardURI(link string) map[string]any {
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	// 1. 基础信息映射
	// 用户名部分即为 Private Key
	privateKey := u.User.Username()
	
	node := map[string]any{
		"type":        "wireguard",
		"name":        strings.TrimPrefix(u.Fragment, "#"),
		"server":      u.Hostname(),
		"port":        toIntPort(u.Port()),
		"private-key": privateKey,
		"udp":         true, // WireGuard 必须是 UDP
	}

	// 2. 解析 Query 参数
	q := u.Query()

	// Public Key
	if pub := q.Get("publickey"); pub != "" {
		// 注意：Clash 配置中通常叫 peer-public-key 或 public-key (取决于版本，Mihomo通用 peer-public-key)
		// 但为了兼容性，通常放在根目录下叫 public-key 即可（代表对端的公钥）
		node["public-key"] = pub 
	}
	
	// Pre-Shared Key
	if psk := q.Get("presharedkey"); psk != "" {
		node["pre-shared-key"] = psk
	}

	// MTU
	if mtu := q.Get("mtu"); mtu != "" {
		if m, err := strconv.Atoi(mtu); err == nil {
			node["mtu"] = m
		}
	}

	// Local Address (IP)
	// URL 里通常是 address=172.16.0.2/32
	if addr := q.Get("address"); addr != "" {
		// Clash 配置通常只需要 IP，不需要 CIDR 后缀，但保留也通常兼容
		// 如果需要严格清洗：
		if idx := strings.Index(addr, "/"); idx > 0 {
			node["ip"] = addr[:idx]
		} else {
			node["ip"] = addr
		}
		// 如果有 ipv6 可以在这里进一步处理，但你的例子里主要是 ipv4
	}

	// Reserved (Cloudflare WARP 专用)
	// URL 格式: reserved=108,161,21
	// Clash 格式: reserved: [108, 161, 21] (数组)
	if reservedStr := q.Get("reserved"); reservedStr != "" {
		parts := strings.Split(reservedStr, ",")
		var reservedInts []int
		for _, p := range parts {
			// URL 可能包含 %2C 等编码，url.Parse 已经解了一次，Split 后 trim 一下保险
			p = strings.TrimSpace(p)
			if i, err := strconv.Atoi(p); err == nil {
				reservedInts = append(reservedInts, i)
			}
		}
		if len(reservedInts) > 0 {
			node["reserved"] = reservedInts
		}
	}

	return node
}

// TryDecodeBase64 尝试将数据进行 Base64 解码
// 如果解码成功且结果看起来是文本，返回解码后的数据
// 否则返回原始数据
func TryDecodeBase64(data []byte) []byte {
	// 移除首尾空白字符
	s := string(bytes.TrimSpace(data))
	if len(s) == 0 {
		return data
	}

	// 定义可能的解码器
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			// 简单的启发式检查：解码后如果是乱码（二进制），可能并不是我们想要的订阅文本
			// 订阅通常是 UTF-8 文本
			if utf8.Valid(decoded) {
				return decoded
			}
		}
	}

	// 如果所有解码尝试都失败，或者解码后不是有效文本，假设它已经是明文
	return data
}