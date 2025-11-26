package proxies

import (
	"fmt"
	"strconv"
	"strings"
)

// GenerateProxyKey 生成代理节点的唯一指纹
func GenerateProxyKey(p map[string]any) string {
	var sb strings.Builder
	// 预估长度，稍微加大一点以容纳复杂协议
	sb.Grow(192)

	// 1. 基础三元组: Type|Server|Port
	// Type 归一化为小写，防止 "Vmess" 和 "vmess" 被视为不同
	if v, ok := p["type"]; ok {
		if s, ok := v.(string); ok {
			sb.WriteString(strings.ToLower(s))
		} else {
			fmt.Fprint(&sb, v)
		}
	}
	sb.WriteByte('|')

	writeString(&sb, p, "server")
	sb.WriteByte('|')

	if v, ok := p["port"]; ok {
		switch val := v.(type) {
		case int:
			sb.WriteString(strconv.Itoa(val))
		case string:
			sb.WriteString(val)
		case float64:
			// 处理 JSON 解析可能出现的 float64
			sb.WriteString(strconv.Itoa(int(val)))
		default:
			// 只有极少数奇怪类型才回退到反射
			fmt.Fprint(&sb, val)
		}
	}
	sb.WriteByte('|')

	// 2. 身份凭证 (Credentials)
	// 不同协议使用不同的认证方式，为防止冲突，我们尽可能写入所有存在的凭证字段
	// 使用短前缀节省内存

	// Password (通用: SS, Trojan, VLESS, VMess, Hysteria2, SSH, TUIC, HTTP, Socks)
	writeStringWithPrefix(&sb, p, "password", "pw:")
	// UUID (VMess, VLESS, TUIC)
	writeStringWithPrefix(&sb, p, "uuid", "id:")
	// Username (SSH, HTTP, Socks, Mieru)
	writeStringWithPrefix(&sb, p, "username", "usr:")
	// Token (TUIC)
	writeStringWithPrefix(&sb, p, "token", "tok:")
	// PSK (Snell)
	writeStringWithPrefix(&sb, p, "psk", "psk:")
	// Auth-Str (Hysteria 1)
	writeStringWithPrefix(&sb, p, "auth-str", "auth:")
	// Private Key (WireGuard, SSH) - 它是客户端身份的核心
	writeStringWithPrefix(&sb, p, "private-key", "pk:")
	// Public Key (WireGuard) - 它是服务端身份的核心
	writeStringWithPrefix(&sb, p, "public-key", "pub:")

	sb.WriteByte('|')

	// 3. TLS/SNI/Host 归一化
	// 即使协议不同，TLS 开关状态也是核心区别
	if v, ok := p["tls"]; ok {
		if isTrue(v) {
			sb.WriteString("tls:1|")
		} else {
			sb.WriteString("tls:0|")
		}
	}

	// SNI 归一化：sni > servername > obfs-opts.host (Snell)
	// 只要有一个存在，就写入 "sni:xxx|"
	if !writeStringWithPrefix(&sb, p, "sni", "sni:") {
		if !writeStringWithPrefix(&sb, p, "servername", "sni:") {
			// Snell 特殊处理: obfs-opts: { host: bing.com }
			if opts, ok := p["obfs-opts"].(map[string]any); ok {
				writeStringWithPrefix(&sb, opts, "host", "sni:")
			}
		}
	}

	// 4. 传输层与网络 (Network / Transport)
	// VMess/Trojan/VLESS 使用 "network"
	writeStringWithPrefix(&sb, p, "network", "net:")
	// Mieru 使用 "transport"
	writeStringWithPrefix(&sb, p, "transport", "net:")

	// 5. 传输层细节 (Path, ServiceName, Reality)
	if opts, ok := p["ws-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "path", "ws:")
		// Headers 里的 Host 有时也作为区分依据，但通常 SNI 已经覆盖了
	}
	if opts, ok := p["grpc-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "grpc-service-name", "grpc:")
	}
	if opts, ok := p["reality-opts"].(map[string]any); ok {
		// Reality 的公钥决定了它伪装的目标，必须区分
		writeStringWithPrefix(&sb, opts, "public-key", "rea:")
		// short-id 也可以区分，但通常 pub key 变了 short-id 也会变
		writeStringWithPrefix(&sb, opts, "short-id", "sid:")
	}

	// 6. 协议特定细节 (Shadowsocks, SSR, Hysteria, Snell)

	// Cipher (SS, SSR, VMess)
	writeStringWithPrefix(&sb, p, "cipher", "cip:")

	// SS Plugin / Obfs
	if !writeStringWithPrefix(&sb, p, "plugin", "plg:") {
		// SSR / Hysteria Obfs
		writeStringWithPrefix(&sb, p, "obfs", "obfs:")
	}

	// SS Plugin Opts (Mode)
	if opts, ok := p["plugin-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "mode", "plg-m:")
	}

	// Snell Obfs Opts (Mode) - Snell 的混淆模式
	if opts, ok := p["obfs-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "mode", "obfs-m:")
	}

	// SSR Protocol
	writeStringWithPrefix(&sb, p, "protocol", "proto:")

	// VLESS Flow (XTLS)
	writeStringWithPrefix(&sb, p, "flow", "flow:")

	// Hysteria 2 Obfs Password
	writeStringWithPrefix(&sb, p, "obfs-password", "hy2pw:")

	// TUIC / WireGuard 特殊字段
	writeStringWithPrefix(&sb, p, "udp-relay-mode", "udp-m:")
	writeStringWithPrefix(&sb, p, "ip", "ip:") // WireGuard endpoint IP different from server domain?
	writeStringWithPrefix(&sb, p, "ipv6", "v6:")

	return sb.String()
}

// --- 辅助函数 ---

// writeString 写入值
func writeString(sb *strings.Builder, m map[string]any, key string) bool {
	val, ok := m[key]
	if !ok || val == nil {
		return false
	}
	// Fast path for string
	if s, ok := val.(string); ok {
		if s == "" {
			return false
		}
		sb.WriteString(s)
		return true
	}
	// Fallback
	s := fmt.Sprint(val)
	if s == "" {
		return false
	}
	sb.WriteString(s)
	return true
}

// writeStringWithPrefix 带前缀写入
func writeStringWithPrefix(sb *strings.Builder, m map[string]any, key, prefix string) bool {
	val, ok := m[key]
	if !ok || val == nil {
		return false
	}
	// Fast path for string
	if s, ok := val.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		sb.WriteString(prefix)
		sb.WriteString(s)
		sb.WriteByte('|')
		return true
	}
	// Fallback for non-string (int, float, etc)
	s := fmt.Sprint(val)
	if s == "" {
		return false
	}
	sb.WriteString(prefix)
	sb.WriteString(s)
	sb.WriteByte('|')
	return true
}

// isTrue 判断布尔真值
func isTrue(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case string:
		return val == "true" || val == "TRUE" || val == "1"
	}
	return false
}
