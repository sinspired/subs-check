package proxies

import (
	"testing"
)

// 假设 protocolSchemes 和 sortedProtocolKeys 已经在其他地方定义并初始化
// 这里我们只测试 guessSchemeByURL 的逻辑

func TestGuessSchemeByURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		// 基础协议识别
		{"http://example.com/vless.yaml", "vless"},
		{"https://cdn.site/hysteria.json", "hysteria"},
		{"trojan.txt", "trojan"},
		{"shadowsocks.conf", "shadowsocks"},

		// 特殊规则
		{"http://foo/bar/http2.yaml", "https"}, // http2 → https
		{"https://abc/all.json", "all"},        // 文件名包含 all → all

		// 带 query/fragment
		{"https://cdn.site/vless.yaml?token=123", "vless"},
		{"https://cdn.site/trojan.txt#section", "trojan"},

		// 无法识别
		{"https://example.com/unknown.txt", ""},
		{"https://example.com/", ""},
	}

	for _, tt := range tests {
		got := guessSchemeByURL(tt.raw)
		if got != tt.want {
			t.Errorf("guessSchemeByURL(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
