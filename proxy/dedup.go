package proxies

import (
	"fmt"
	"strings"
)

// GenerateProxyKey 生成代理节点的唯一指纹
// 降低内存分配，避免 strings.Split/Join/fmt.Sprintf
func GenerateProxyKey(p map[string]any) string {
	var sb strings.Builder
	// 预估长度，避免扩容
	sb.Grow(128)

	// 1. 基础三元组: Type|Server|Port
	writeString(&sb, p, "type")
	sb.WriteByte('|')
	writeString(&sb, p, "server")
	sb.WriteByte('|')
	if v, ok := p["port"]; ok {
		fmt.Fprint(&sb, v)
	}
	sb.WriteByte('|')

	// 2. 核心凭证
	if !writeString(&sb, p, "password") {
		if !writeString(&sb, p, "uuid") {
			if !writeString(&sb, p, "psk") {
				if !writeString(&sb, p, "auth-str") {
					writeString(&sb, p, "private-key")
				}
			}
		}
	}
	sb.WriteByte('|')

	// 3. TLS/SNI (修复逻辑)
	// 必须区分 true 和 false
	if v, ok := p["tls"]; ok {
		if isTrue(v) {
			sb.WriteString("tls:1|")
		} else {
			// 显式记录 false，防止与 true 混淆
			sb.WriteString("tls:0|")
		}
	}

	// 优先 sni，其次 servername
	if !writeStringWithPrefix(&sb, p, "sni", "sni:") {
		writeStringWithPrefix(&sb, p, "servername", "sni:")
	}

	// 4. Network & Transport
	if writeStringWithPrefix(&sb, p, "network", "net:") {
		sb.WriteByte('|')
	}

	// 5. 嵌套参数
	if opts, ok := p["ws-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "path", "ws:")
	} else if opts, ok := p["grpc-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "grpc-service-name", "grpc:")
	}

	if opts, ok := p["reality-opts"].(map[string]any); ok {
		writeStringWithPrefix(&sb, opts, "public-key", "rea:")
	}

	// 6. SS/SSR/Hysteria 特有字段

	// Cipher: 如果 p["cipher"] 存在且非空，直接写入 "cip:xxxx|"
	writeStringWithPrefix(&sb, p, "cipher", "cip:")

	// Plugin / Obfs: 如果写入 plugin 成功，就不再尝试 obfs；否则尝试 obfs
	if !writeStringWithPrefix(&sb, p, "plugin", "plg:") {
		writeStringWithPrefix(&sb, p, "obfs", "obfs:")
	}

	// VLESS Flow
	writeStringWithPrefix(&sb, p, "flow", "flow:")

	// Hysteria2 Obfs Password
	writeStringWithPrefix(&sb, p, "obfs-password", "hy2pw:")

	return sb.String()
}

// 辅助函数
func writeString(sb *strings.Builder, m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			sb.WriteString(s)
			return true
		}
		s := fmt.Sprint(v)
		if s != "" {
			sb.WriteString(s)
			return true
		}
	}
	return false
}

// writeStringWithPrefix 带前缀写入，例如 "sni:example.com|"
// 1. 优先使用类型断言处理 string，零分配。
// 2. 只有非 string 类型才使用 fmt.Sprint。
// 3. 返回 bool 表示是否写入了内容，方便用于 if/else 链式判断。
func writeStringWithPrefix(sb *strings.Builder, m map[string]any, key, prefix string) bool {
	val, ok := m[key]
	if !ok || val == nil {
		return false
	}

	// Fast Path: 绝大多数情况都是 string
	if s, ok := val.(string); ok {
		if s == "" {
			return false
		}
		// strings.TrimSpace 返回的是原字符串的切片引用，不会分配新内存
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}

		sb.WriteString(prefix)
		sb.WriteString(s)
		sb.WriteByte('|')
		return true
	}

	// Slow Path: 处理 int, float, bool 等边缘情况
	s := fmt.Sprint(val)
	if s == "" {
		return false
	}
	sb.WriteString(prefix)
	sb.WriteString(s)
	sb.WriteByte('|')
	return true
}

func isTrue(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case string:
		// 简单的大小写处理，不需要 ToLower 分配新字符串
		// 大部分情况是 "true" 或 "1"
		return val == "true" || val == "TRUE" || val == "1"
	}
	return false
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}
