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
	"strconv"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/samber/lo"
	"github.com/sinspired/subs-check/utils"
)

// 协议映射表：Key 为常见的缩写或别名，Value 为标准协议头
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
	"shadowsocks": "ss://", "ss": "ss://", "ssr": "ssr://",
	"tuic": "tuic://", "tuic5": "tuic://",
	"juicity":   "juicity://",
	"wireguard": "wireguard://", "wg": "wg://",
	"mieru":  "mieru://",
	"anytls": "anytls://",
}

var (
	v2rayRegexOnce         sync.Once
	v2rayLinkRegexCompiled *regexp.Regexp
)

// --------核心解析入口--------

// ParseProxyLinksAndConvert 统一处理链接列表
// 能够同时处理 WireGuard, SSR (手动解析) 和 V2Ray/Clash 支持的标准协议 (调用 Mihomo)
// subURL 用于在猜测协议时提供上下文 (例如文件名包含 hysteria)
func ParseProxyLinksAndConvert(links []string, subURL string) []ProxyNode {
	var finalNodes []ProxyNode
	var batchLinks []string

	// 获取文件名推测的协议（作为上下文参考）
	fileGuessedScheme := guessSchemeByURL(subURL)

	for _, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}

		// 1. 优先处理手动解析的协议 (WG, SSR)
		if strings.HasPrefix(link, "wireguard://") || strings.HasPrefix(link, "wg://") {
			if node := ParseWireGuardURI(link); node != nil {
				finalNodes = append(finalNodes, ProxyNode(node))
			}
			continue
		}

		if strings.HasPrefix(link, "ssr://") {
			if node := ParseSSRURI(link); node != nil {
				finalNodes = append(finalNodes, ProxyNode(node))
			}
			continue
		}

		// 2. 标准化链接 或 智能扩展 IP:Port
		if strings.Contains(link, "://") {
			// 已有协议头，进行简单修复
			batchLinks = append(batchLinks, FixupProxyLink(link))
		} else {
			// 处理纯 IP:Port 或域名:Port
			host, port := SplitHostPortLoose(link)

			// 简单的合法性校验，防止将普通文本误判为节点
			if host != "" && port != "" {
				if _, err := strconv.Atoi(port); err == nil {
					prefix, isKnown := protocolSchemes[fileGuessedScheme]

					// 如果文件名暗示了明确的非 HTTP 协议 (如 vmess)，则只添加该协议
					// 如果是 http/https 或 未知，则进入更激进的猜测逻辑
					if isKnown && fileGuessedScheme != "http" && fileGuessedScheme != "https" {
						batchLinks = append(batchLinks, fmt.Sprintf("%s%s:%s", prefix, host, port))
					} else {
						//同时生成 HTTPS 和 HTTP ===
						// 1. 总是尝试 HTTPS (type: http, tls: true)
						// 即使文件名是 http，也可能是 https
						batchLinks = append(batchLinks, fmt.Sprintf("https://%s:%s", host, port))

						// 2. 总是尝试 HTTP (type: http, tls: false)
						// 以前只限制 80/8080，现在放开，因为很多代理跑在非标端口
						batchLinks = append(batchLinks, fmt.Sprintf("http://%s:%s", host, port))

						// 3. 总是尝试 SOCKS5
						batchLinks = append(batchLinks, fmt.Sprintf("socks5://%s:%s", host, port))
					}
				}
			}
		}
	}

	// 3. 批量转换剩余链接
	if len(batchLinks) > 0 {
		// 这里去重一下，避免因为逻辑重叠产生重复链接
		batchLinks = lo.Uniq(batchLinks)

		data := []byte(strings.Join(batchLinks, "\n"))
		if nodes, err := convert.ConvertsV2Ray(data); err == nil {
			finalNodes = append(finalNodes, ToProxyNodes(nodes)...)
		}
	}

	return finalNodes
}

// ConvertProtocolMap 处理非标准 JSON ({"vless": [...], "hysteria": [...]})
func ConvertProtocolMap(con map[string]any) []ProxyNode {
	var allLinks []string

	// 遍历 Map，查找已知协议
	for key, val := range con {
		prefix, isKnown := protocolSchemes[strings.ToLower(key)]
		if !isKnown {
			continue
		}

		// 提取列表内容
		var items []string
		if v, ok := val.([]string); ok {
			items = v
		} else if vAny, ok := val.([]any); ok {
			for _, s := range vAny {
				if str, ok := s.(string); ok {
					items = append(items, str)
				}
			}
		}

		// 格式化链接
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}

			if strings.Contains(item, "://") {
				allLinks = append(allLinks, FixupProxyLink(item))
			} else {
				// 拼接协议头
				host, port := SplitHostPortLoose(item)
				if host != "" && port != "" {
					allLinks = append(allLinks, prefix+host+":"+port)
				}
			}
		}
	}

	if len(allLinks) == 0 {
		return nil
	}

	// 这里 subURL 传空即可，因为协议已经在 key 中确定并拼接好了
	return ParseProxyLinksAndConvert(allLinks, "")
}

// ToProxyNodes 将 Mihomo 的转换结果 []map[string]any 转换为 []ProxyNode 并进行标准化
func ToProxyNodes(list []map[string]any) []ProxyNode {
	if list == nil {
		return nil
	}
	res := make([]ProxyNode, len(list))
	for i, v := range list {
		// 立即进行标准化，防止后续处理遇到类型不一致问题
		NormalizeNode(v)
		res[i] = ProxyNode(v)
	}
	return res
}

// --------节点标准化与清洗--------

// NormalizeNode 统一清洗节点字段，注入默认值
// 将各种非标准或类型不确定的字段转换为 Clash/Mihomo 标准格式
func NormalizeNode(m map[string]any) {
	// 1. 端口标准化 (确保是 int)
	if p, ok := m["port"]; ok {
		m["port"] = ToIntPort(p)
	}

	// 2. 布尔值标准化 (防止 panic bug)
	normalizeBool(m, "tls")
	normalizeBool(m, "udp")
	normalizeBool(m, "skip-cert-verify")
	normalizeBool(m, "tfo")
	normalizeBool(m, "allow-insecure")
	normalizeBool(m, "xudp")
	normalizeBool(m, "reuse-addr")
	normalizeBool(m, "disable-sni")

	// 3. 协议特定修正与默认值注入
	if t, ok := m["type"].(string); ok {
		t = strings.ToLower(t)
		m["type"] = t

		switch t {
		case "trojan":
			m["tls"] = true
		case "https":
			// 只有明确写为 type: https 时，才强制转换并开启 TLS
			m["type"] = "http"
			m["tls"] = true
		case "http":
			// 标准 HTTP 代理，不做强制 TLS 设置
			// 除非端口是 443 且未指定 TLS，否则保持原样或默认 false
			if _, hasTls := m["tls"]; !hasTls {
				// 启发式：如果是 443 端口，大概率是 HTTPS
				if p := ToIntPort(m["port"]); p == 443 {
					m["tls"] = true
				} else {
					m["tls"] = false
				}
			}
		case "hysteria2", "hy2":
			if val, exists := m["obfs_password"]; exists {
				m["obfs-password"] = val
				delete(m, "obfs_password")
			}
		case "vmess", "vless":
			if val, ok := m["security"].(string); ok && strings.ToLower(val) == "tls" {
				m["tls"] = true
			}
		}
	}

	// 4. 处理扁平化的 WS 字段
	normalizeWsFields(m)
}

func normalizeWsFields(m map[string]any) {
	var wsPath, wsHeaders any
	hasWsFields := false

	// 提取扁平字段
	if v, ok := m["ws-path"]; ok {
		wsPath = v
		delete(m, "ws-path")
		hasWsFields = true
	}
	if v, ok := m["ws-headers"]; ok {
		wsHeaders = v
		delete(m, "ws-headers")
		hasWsFields = true
	}

	// 如果存在，合并入 ws-opts
	if hasWsFields {
		wsOpts := make(map[string]any)
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
		// 确保 network 被标记为 ws
		if _, ok := m["network"]; !ok {
			m["network"] = "ws"
		}
	}
}

// normalizeBool 强制将 map 中的特定字段转换为 bool 类型
// 规避 Mihomo decoder 在处理 uint 转 bool 时的 panic bug
func normalizeBool(m map[string]any, key string) {
	val, ok := m[key]
	if !ok {
		return
	}

	switch v := val.(type) {
	case bool:
		// 已经是 bool，无需处理
		return
	case string:
		lower := strings.ToLower(v)
		switch lower {
		case "true", "1":
			m[key] = true
		case "false", "0":
			m[key] = false
		default:
			// 无法识别的字符串
			// 这里保守起见，保持原样或设为 false，防止 decoder 报错
			delete(m, key)
		}
	case int:
		m[key] = v != 0
	case int8:
		m[key] = v != 0
	case int16:
		m[key] = v != 0
	case int32:
		m[key] = v != 0
	case int64:
		m[key] = v != 0
	case uint:
		// 将 uint 转换为 bool，避免进入 Mihomo 的错误分支
		m[key] = v != 0
	case uint8:
		m[key] = v != 0
	case uint16:
		m[key] = v != 0
	case uint32:
		m[key] = v != 0
	case uint64:
		m[key] = v != 0
	case float32:
		m[key] = v != 0
	case float64:
		// JSON 解析数字通常是 float64
		m[key] = v != 0
	default:
		// 其他无法转换的类型，直接删除该字段，避免传给 Mihomo 导致未知错误
		delete(m, key)
	}
}

// FixupProxyLink 修复非标准链接头
func FixupProxyLink(link string) string {
	// 常见错误：hy:// 应为 hysteria://
	if strings.HasPrefix(link, "hy://") {
		return strings.Replace(link, "hy://", "hysteria://", 1)
	}
	return link
}

// ToIntPort 极其宽容的端口转换函数
func ToIntPort(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		// 尝试解析 "443" 或 "443.0"
		clean := strings.Split(val, ".")[0]
		if i, err := strconv.Atoi(clean); err == nil {
			return i
		}
	}
	// 尝试强转其他数值类型 (int64, uint 等)
	if i, err := strconv.Atoi(fmt.Sprintf("%v", v)); err == nil {
		return i
	}
	return 0
}

// --------基础工具--------

func EnsureScheme(s string) string {
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

func SplitHostPortLoose(hp string) (string, string) {
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

// guessSchemeByURL 根据 URL 文件名猜测协议
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

	// 遍历已知协议表进行匹配
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

// TryDecodeBase64 尝试 Base64 解码，失败则返回原数据
func TryDecodeBase64(data []byte) []byte {
	s := string(bytes.TrimSpace(data))
	if len(s) == 0 {
		return data
	}

	encodings := []*base64.Encoding{
		base64.RawURLEncoding, // SSR 最常用
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}

	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			// 简单的启发式检查：如果解码后全是乱码（非文本），可能不是正确的解码
			// 但这里只要不报错就认为成功
			return decoded
		}
	}
	return data
}

// --------正则提取逻辑--------

func ExtractV2RayLinks(data []byte) []string {
	var links []string
	v2rayRegexOnce.Do(func() {
		// 动态构建正则，匹配所有已知协议头
		schemes := []string{}
		seen := map[string]bool{}
		for _, p := range protocolSchemes {
			s := strings.TrimSuffix(strings.ToLower(p), "://")
			if !seen[s] && s != "" {
				schemes = append(schemes, regexp.QuoteMeta(s))
				seen[s] = true
			}
		}
		// 模式: 单词边界 + 协议 + :// + 非空白/引号/括号字符
		pattern := `(?i)\b(` + strings.Join(schemes, `|`) + `)://[^\s"'<>\)\]]+`
		v2rayLinkRegexCompiled = regexp.MustCompile(pattern)
	})

	rawStr := string(data)
	links = v2rayLinkRegexCompiled.FindAllString(rawStr, -1)

	// 简单清洗结果
	out := make([]string, 0, len(links))
	for _, s := range links {
		t := strings.TrimSpace(s)
		t = strings.Trim(t, "\"'`")
		t = strings.TrimRight(t, ",，;；")
		if t != "" {
			out = append(out, t)
		}
	}
	return lo.Uniq(out)
}

// --------特定格式转换器--------

// ConvertSingBoxOutbounds 将 Sing-Box 的 outbounds 转换为 Clash 代理节点
func ConvertSingBoxOutbounds(outbounds []any) []ProxyNode {
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

		conv := ProxyNode{
			"server": lo.CoalesceOrEmpty(fmt.Sprint(m["server"]), fmt.Sprint(m["server_address"])),
			"port":   ToIntPort(m["server_port"]),
			"name":   fmt.Sprint(m["tag"]),
		}

		// 协议特定字段映射
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
		case "tuic":
			conv["type"] = "tuic"
			conv["uuid"] = m["uuid"]
			conv["password"] = m["password"]
			conv["congestion-controller"] = m["congestion_controller"]
		default:
			conv["type"] = typ
		}

		// 传输层处理
		if tr, ok := m["transport"].(map[string]any); ok {
			trType := strings.ToLower(fmt.Sprint(tr["type"]))
			if trType == "ws" {
				conv["network"] = "ws"
				conv["ws-opts"] = map[string]any{"path": tr["path"], "headers": tr["headers"]}
			}
			if trType == "grpc" {
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

		NormalizeNode(conv)
		res = append(res, conv)
	}
	return res
}

// ConvertGeneralJsonArray 处理通用对象数组 (主要是 Shadowsocks 导出的配置文件)
func ConvertGeneralJsonArray(list []any) []ProxyNode {
	var nodes []ProxyNode
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		// 识别特征: server_port, method, password
		if _, hasPort := m["server_port"]; hasPort {
			if _, hasMethod := m["method"]; hasMethod {
				node := ProxyNode{
					"type":        "ss",
					"server":      m["server"],
					"port":        ToIntPort(m["server_port"]),
					"cipher":      m["method"],
					"password":    m["password"],
					"plugin":      m["plugin"],
					"plugin-opts": m["plugin_opts"],
				}

				if name, ok := m["remarks"].(string); ok && name != "" {
					node["name"] = name
				} else {
					node["name"] = fmt.Sprintf("ss-%s:%v", m["server"], m["server_port"])
				}

				NormalizeNode(node)
				nodes = append(nodes, node)
			}
		}
	}
	return nodes
}

// ParseWireGuardURI 解析 wireguard:// 链接
func ParseWireGuardURI(link string) map[string]any {
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	node := map[string]any{
		"type":        "wireguard",
		"name":        strings.TrimPrefix(u.Fragment, "#"),
		"server":      u.Hostname(),
		"port":        ToIntPort(u.Port()),
		"private-key": u.User.Username(),
		"udp":         true,
	}

	q := u.Query()
	if pub := q.Get("publickey"); pub != "" {
		node["public-key"] = pub
	}
	if psk := q.Get("presharedkey"); psk != "" {
		node["pre-shared-key"] = psk
	}
	if mtu := q.Get("mtu"); mtu != "" {
		node["mtu"] = ToIntPort(mtu)
	}
	if addr := q.Get("address"); addr != "" {
		node["ip"] = strings.Split(addr, "/")[0]
	}

	if res := q.Get("reserved"); res != "" {
		var reserved []int
		for _, p := range strings.Split(res, ",") {
			// 处理可能的 URL 编码
			if i, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				reserved = append(reserved, i)
			}
		}
		if len(reserved) > 0 {
			node["reserved"] = reserved
		}
	}
	return node
}

// ParseSSRURI 解析 ssr:// 链接 (Base64解码 + 参数提取)
func ParseSSRURI(link string) map[string]any {
	content := strings.TrimPrefix(link, "ssr://")
	// 清理末尾可能的备注标记
	if idx := strings.Index(content, "#"); idx > 0 {
		content = content[:idx]
	}

	decoded := string(TryDecodeBase64([]byte(strings.TrimSpace(content))))
	parts := strings.SplitN(decoded, "/?", 2)

	// 格式: host:port:protocol:method:obfs:password_base64
	fields := strings.Split(parts[0], ":")
	if len(fields) < 6 {
		return nil
	}

	n := len(fields)
	node := map[string]any{
		"type":     "ss", // 兼容性处理
		"server":   strings.Join(fields[:n-5], ":"),
		"port":     ToIntPort(fields[n-5]),
		"cipher":   fields[n-3],
		"password": string(TryDecodeBase64([]byte(fields[n-1]))),
		"protocol": fields[n-4],
		"obfs":     fields[n-2],
	}

	if len(parts) > 1 {
		for _, pair := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				val := string(TryDecodeBase64([]byte(kv[1])))
				switch kv[0] {
				case "remarks":
					node["name"] = val
				case "obfsparam":
					node["obfs-param"] = val
				case "protoparam":
					node["protocol-param"] = val
				}
			}
		}
	}
	// 默认名称
	if node["name"] == nil || node["name"] == "" {
		node["name"] = fmt.Sprintf("ssr-%v", node["server"])
	}
	return node
}

// ParseBracketKVProxies 解析自定义格式: [Type] Name = key=val, ...
func ParseBracketKVProxies(data []byte) []ProxyNode {
	var nodes []ProxyNode
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		left, right := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// 解析名称
		name := left
		if idx := strings.Index(left, "]"); idx > 0 {
			name = strings.TrimSpace(left[idx+1:])
		}

		args := strings.Split(right, ",")
		if len(args) < 3 {
			continue
		}

		node := map[string]any{
			"name":   name,
			"type":   strings.ToLower(args[0]),
			"server": strings.TrimSpace(args[1]),
			"port":   ToIntPort(args[2]),
		}
		if node["type"] == "shadowsocks" {
			node["type"] = "ss"
		}

		// 解析 KV 参数
		for _, kv := range args[3:] {
			if k, v, ok := strings.Cut(kv, "="); ok {
				key := strings.ToLower(strings.TrimSpace(k))
				val := strings.TrimSpace(v)

				switch key {
				case "username", "uuid":
					node["uuid"] = val
				case "password", "passwd":
					node["password"] = val
				case "method", "cipher":
					node["cipher"] = val
				case "sni", "servername":
					node["servername"] = val
				case "udp", "tfo", "tls", "skip-cert-verify":
					m := map[string]any{key: val}
					normalizeBool(m, key)
					node[key] = m[key]
				case "ws":
					if val == "true" {
						node["network"] = "ws"
					}
				case "ws-path":
					node["ws-path"] = val // 后续NormalizeNode处理
				case "ws-headers":
					node["ws-headers"] = val // 后续NormalizeNode处理
				}
			}
		}

		NormalizeNode(node)
		nodes = append(nodes, ProxyNode(node))
	}
	return nodes
}

// ParseSurfboardProxies 解析 Surge/Surfboard 格式
// 复用 ParseBracketKVProxies 的逻辑
func ParseSurfboardProxies(data []byte) []ProxyNode {
	return ParseBracketKVProxies(data)
}

// ExtractAndParseProxies 提取分散的 proxies: 块并解析
func ExtractAndParseProxies(data []byte) []ProxyNode {
	var nodes []ProxyNode
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var buffer bytes.Buffer
	inBlock := false

	// 解析缓冲区的辅助函数
	parseBuf := func() {
		if buffer.Len() == 0 {
			return
		}
		var c struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		// 尝试解析 YAML
		if err := yaml.Unmarshal(buffer.Bytes(), &c); err == nil {
			for _, p := range c.Proxies {
				NormalizeNode(p)
				nodes = append(nodes, ProxyNode(p))
			}
		}
		buffer.Reset()
	}

	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)

		// 块开始
		if strings.HasPrefix(line, "proxies:") {
			if inBlock {
				parseBuf()
			}
			inBlock = true
			buffer.WriteString(line + "\n")
			continue
		}

		if inBlock {
			// 保持块内容收集：空行、注释、或有缩进的行
			if trim == "" || strings.HasPrefix(trim, "#") {
				buffer.WriteString(line + "\n")
			} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				buffer.WriteString(line + "\n")
			} else {
				// 缩进结束，块结束
				inBlock = false
				parseBuf()
			}
		}
	}
	// 处理文件末尾的块
	if inBlock {
		parseBuf()
	}
	return nodes
}

// ParseV2RayJsonLines 解析 V2Ray Core 的 Outbound JSON (按行)
// 这是一个简化的实现，提取核心字段
func ParseV2RayJsonLines(data []byte) []ProxyNode {
	var nodes []ProxyNode
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, "outbound") {
			continue
		}

		var out map[string]any
		if yaml.Unmarshal([]byte(line), &out) != nil {
			continue
		}

		// 提取 protocol
		protocol, _ := out["protocol"].(string)

		// 提取 settings.vnext
		settings, _ := out["settings"].(map[string]any)
		vnext, _ := settings["vnext"].([]any)
		if len(vnext) == 0 {
			continue
		}

		serverConf, _ := vnext[0].(map[string]any)
		address := fmt.Sprint(serverConf["address"])
		port := ToIntPort(serverConf["port"])

		users, _ := serverConf["users"].([]any)
		if len(users) == 0 {
			continue
		}
		userConf, _ := users[0].(map[string]any)
		uuid := fmt.Sprint(userConf["id"])

		// 构建基础节点
		node := ProxyNode{
			"name":   lo.CoalesceOrEmpty(fmt.Sprint(out["tag"]), "v2ray-json"),
			"server": address,
			"port":   port,
			"uuid":   uuid,
		}

		// 协议映射
		switch protocol {
		case "vmess":
			node["type"] = "vmess"
			node["alterId"] = ToIntPort(userConf["alterId"])
			node["cipher"] = "auto"
		case "vless":
			node["type"] = "vless"
			if flow, ok := userConf["flow"].(string); ok {
				node["flow"] = flow
			}
		default:
			continue // 暂不支持其他协议
		}

		// 提取 StreamSettings
		if stream, ok := out["streamSettings"].(map[string]any); ok {
			node["network"] = stream["network"]
			if sec := fmt.Sprint(stream["security"]); sec == "tls" {
				node["tls"] = true
				if tlsSet, ok := stream["tlsSettings"].(map[string]any); ok {
					node["servername"] = tlsSet["serverName"]
				}
			}
			// WS Settings
			if wsSet, ok := stream["wsSettings"].(map[string]any); ok {
				node["ws-opts"] = map[string]any{
					"path":    wsSet["path"],
					"headers": wsSet["headers"],
				}
			}
		}

		NormalizeNode(node)
		nodes = append(nodes, node)
	}
	return nodes
}

// ParseYamlFlowList 逐行解析 YAML 流式列表 (容错模式)
// 专门处理格式错误或缩进错误的 Clash 格式列表，例如：
// - {name: ...}
func ParseYamlFlowList(data []byte) []ProxyNode {
	var nodes []ProxyNode
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// 这里的 buffer 用于 scanner，防止单行过长导致 panic
	// 默认 64k 对于 flow yaml 通常足够，如果遇到超长行可能会需要调整，但一般代理配置不会单行超 64k
	scanner.Buffer(make([]byte, 2048*1024), 1024*1024)

	for scanner.Scan() {
		lineBytes := bytes.TrimSpace(scanner.Bytes())

		if len(lineBytes) == 0 {
			continue
		}

		// 1. 结构特征检查：必须包含 key-value 分隔符 ":" 以及 flow 格式的特征 "{", "}"
		if !bytes.Contains(lineBytes, []byte(":")) {
			continue
		}
		// 依赖 '{' 和 '}' 来判断是否为 flow 格式
		if !bytes.Contains(lineBytes, []byte("{")) || !bytes.Contains(lineBytes, []byte("}")) {
			continue
		}

		// 2. 核心字段预检 (The CPU Saver)
		// 绝大多数有效代理节点都必须包含 "server" (ss/trojan/shadowsocks) 或 "uuid" (vmess/vless)
		// 这一步能过滤掉绝大多数无效行（如注释、metadata、纯配置项），极大降低 yaml.Unmarshal 的调用频率
		if !bytes.Contains(lineBytes, []byte("server")) && !bytes.Contains(lineBytes, []byte("uuid")) {
			continue
		}

		// 3. 格式归一化：处理行首可能的 "- "
		cleanBytes := lineBytes
		if bytes.HasPrefix(cleanBytes, []byte("-")) {
			cleanBytes = bytes.TrimSpace(cleanBytes[1:])
		}

		// 再次确认是对象结构 "{ ... }"
		if !bytes.HasPrefix(cleanBytes, []byte("{")) {
			// 如果去掉了 "-" 后不是以 "{" 开头，说明可能是 "- name: xxx" 这种 block 格式
			// 或者格式错乱。这里只处理标准的 flow json/yaml 对象
			continue
		}

		// 4. 构造合法的 YAML 列表项字符串
		// 只有通过了上述所有检查，才进行 string 转换和拼接，这是必要的开销
		// 构造形式： "- { ... }"
		yamlLine := "- " + string(cleanBytes)

		var tempNodes []map[string]any
		// 执行昂贵的 Unmarshal
		if err := yaml.Unmarshal([]byte(yamlLine), &tempNodes); err == nil && len(tempNodes) > 0 {
			for _, m := range tempNodes {
				NormalizeNode(m)
				// 解析后再次校验关键字段，确保数据的完整性
				if _, hasServer := m["server"]; hasServer {
					nodes = append(nodes, ProxyNode(m))
				}
			}
		} else {
			// TODO: 如果标准解析失败（例如引号嵌套错误），尝试简单的正则提取修复
		}
	}

	if len(nodes) > 0 {
		slog.Debug("使用逐行 YAML 容错解析成功", "count", len(nodes))
	}

	return nodes
}

// ParseSingBoxWithMetadata 解析带注释元数据的 Sing-Box 配置文件
// 处理形如 #profile-title: ... 开头，主体为 JSON 的文件
func ParseSingBoxWithMetadata(data []byte) []ProxyNode {
	// 快速特征检测：必须包含 outbounds 关键字
	if !bytes.Contains(data, []byte("outbounds")) {
		return nil
	}

	// 1. 清洗注释行
	var cleanBuf bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// 忽略以 # 开头的行 (元数据)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		cleanBuf.WriteString(line + "\n")
	}

	// 2. 解析 JSON/YAML
	var config map[string]any
	// 使用 yaml.Unmarshal 因为它兼容 JSON 且容错性更好
	if err := yaml.Unmarshal(cleanBuf.Bytes(), &config); err != nil {
		return nil
	}

	// 3. 提取 outbounds 并转换
	if outbounds, ok := config["outbounds"].([]any); ok {
		return ConvertSingBoxOutbounds(outbounds)
	}

	return nil
}
