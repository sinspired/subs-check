//utils.go
package proxies

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	u "net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
)

// 使用正则从纯文本中提取 V2Ray/代理链接
var (
	v2rayRegexOnce         sync.Once
	v2rayLinkRegexCompiled *regexp.Regexp
)

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
	"hy://",
	// tuic 系列
	"tuic://",
	"tuic5://",
	// juicity
	"juicity://",
	// wireguard
	"wg://",
	"wireguard://",
	// socks 系列
	"socks://",
	"socks5://",
	"socks5h://",
	// naive
	"naive+https://",
	// 其他扩展协议
	"anytls://",
	"mieru://",
}

// isLocal 判断是否为本地地址
func isLocal(host string) bool {
	return host == "127.0.0.1" || strings.EqualFold(host, "localhost") || host == "0.0.0.0" || host == "::1" || strings.Contains(host, ".local") || !strings.Contains(host, ".")
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

// toIntPort 端口转换为整数
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
	// 关键词匹配
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
	if strings.Contains(name, "hysteria2") || strings.Contains(name, "hy2") {
		return "hysteria2"
	}
	if strings.Contains(name, "hysteria") || strings.Contains(name, "hy") {
		return "hysteria"
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

// 支持解析免费代理 JSON 列表结构
// 形如：{"http":["ip:port",...], "https":[...], "socks5":[...], "socks4":[...]}
// 返回 mihomo/clash 兼容节点，仅包含 http 与 socks5；socks4 暂不支持（底层不兼容），将忽略。
// convertUnStandandJsonViaConvert
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
			
			// 如果字符串本身已经是包含协议的链接（例如 hy://ip:port），直接使用，不做拼接
			// 简单的判断是否包含 ://
			if strings.Contains(hp, "://") {
				// 做简单的标准化替换
				if strings.HasPrefix(hp, "hy://") {
					hp = strings.Replace(hp, "hy://", "hysteria://", 1)
				}
				links = append(links, hp)
				continue
			}

			host, portStr := splitHostPortLoose(hp)
			if host == "" || portStr == "" {
				continue
			}
			if _, err := strconv.Atoi(portStr); err != nil {
				continue
			}

			// 拼接协议头
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
				links = append(links, fmt.Sprintf("socks://%s:%s", host, portStr))
			case "mieru":
				links = append(links, fmt.Sprintf("mieru://%s:%s", host, portStr))
			case "anytls":
				links = append(links, fmt.Sprintf("anytls://%s:%s", host, portStr))
			case "tuic":
				links = append(links, fmt.Sprintf("tuic://%s:%s", host, portStr))
			case "shadowsocks", "ss":
				links = append(links, fmt.Sprintf("ss://%s:%s", host, portStr)) // ss 通常需要 base64，这里仅作尝试
			case "vmess":
				links = append(links, fmt.Sprintf("vmess://%s:%s", host, portStr))
			case "vless":
				links = append(links, fmt.Sprintf("vless://%s:%s", host, portStr))
			case "trojan":
				links = append(links, fmt.Sprintf("trojan://%s:%s", host, portStr))
			case "hysteria2", "hy2":
				links = append(links, fmt.Sprintf("hysteria2://%s:%s", host, portStr))
			case "hysteria", "hy":
				// hy:// 是非标准的，转换为标准 hysteria://
				links = append(links, fmt.Sprintf("hysteria://%s:%s", host, portStr))
			case "juicity":
				links = append(links, fmt.Sprintf("juicity://%s:%s", host, portStr))
			case "wireguard", "wg":
				links = append(links, fmt.Sprintf("wg://%s:%s", host, portStr))
			default:
				links = append(links, fmt.Sprintf("http://%s:%s", host, portStr))
			}
		}
	}

	// 补全遗漏的键检查
	checkKeys := []struct {
		Key  string
		Type string // 如果为空，则使用 Key 本身
	}{
		{"hysteria2", ""}, {"hy2", "hysteria2"},
		{"hysteria", ""}, {"hy", "hysteria"},
		{"socks5", ""}, {"socks5h", ""}, {"socks4", ""}, {"socks", ""},
		{"http", ""}, {"https", ""},
		{"mieru", ""}, {"anytls", ""},
		{"tuic", ""},
		{"shadowsocks", "shadowsocks"}, {"ss", "shadowsocks"},
		{"vmess", ""}, {"vless", ""}, {"trojan", ""},
		{"juicity", ""}, {"wireguard", "wireguard"}, {"wg", "wireguard"},
	}

	for _, item := range checkKeys {
		if v, ok := con[item.Key]; ok && v != nil {
			targetType := item.Key
			if item.Type != "" {
				targetType = item.Type
			}
			collect(targetType, v)
		}
	}

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

func parseHeaderKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx <= 0 {
		return "", ""
	}
	k := strings.TrimSpace(s[:idx])
	v := strings.TrimSpace(s[idx+1:])
	return k, v
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
