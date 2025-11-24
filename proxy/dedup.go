package proxies

import (
	"fmt"
	"runtime"
	"strings"
)

// DeduplicateProxies 对代理列表进行去重
func DeduplicateProxies(proxies []map[string]any) []map[string]any {
	seenKeys := make(map[string]bool)
	// 预分配切片容量，避免多次扩容
	result := make([]map[string]any, 0, len(proxies))

	for _, proxy := range proxies {
		// 基础校验：没有 server 地址的直接跳过
		// 使用 getString 兼容 server 字段可能非 string 的极端情况
		server := getString(proxy, "server")
		if server == "" {
			continue
		}

		// 生成高精度指纹
		key := GenerateProxyKey(proxy)

		if !seenKeys[key] {
			seenKeys[key] = true
			result = append(result, proxy)
		}
	}

	// 收集代理节点阶段结束
	// 进行一次内存回收，降低前期运行时内存
	for i := range proxies {
		proxies[i] = nil
	}
	// 显式触发 GC
	runtime.GC()

	return result
}

// GenerateProxyKey 生成代理节点的唯一指纹
func GenerateProxyKey(p map[string]any) string {
	// 基础五元组特征
	server := getString(p, "server")
	port := getString(p, "port")
	typ := strings.ToLower(getString(p, "type"))

	// 统一凭证处理 (Password / UUID / PSK / PrivateKey / AuthStr)
	password := getString(p, "password")
	if password == "" {
		password = getString(p, "uuid")
	}
	if password == "" {
		password = getString(p, "psk") // Snell
	}
	if password == "" {
		password = getString(p, "auth-str") // Hysteria
	}
	if password == "" {
		password = getString(p, "private-key") // WireGuard/SSH
	}

	// 构建基础键值
	keyBuilder := []string{typ, server, port, password}

	// 1. TLS/SNI 区分 (HTTP, Socks5, VMess, VLESS, Trojan, etc.)
	// 某些协议(如Trojan)强制TLS，但其他协议可选。SNI不同也视为不同节点。
	if val, ok := p["tls"]; ok {
		keyBuilder = append(keyBuilder, fmt.Sprintf("tls:%v", val))
	}

	// 优先取 sni，如果没有取 servername，都没有则忽略
	if val := getString(p, "sni"); val != "" {
		keyBuilder = append(keyBuilder, "sni:"+val)
	} else if val := getString(p, "servername"); val != "" {
		keyBuilder = append(keyBuilder, "sni:"+val)
	}

	// 2. 传输层 Network 区分 (VMess, VLESS, Trojan)
	// 同一个端口可能是 TCP, WS, GRPC, HTTPUpgrade
	if net := getString(p, "network"); net != "" {
		keyBuilder = append(keyBuilder, "net:"+net)
	}

	// 3. 传输层细节参数 (WS Path, GRPC ServiceName)
	// 即使是 WS，不同的 path 也是不同的节点
	if opts, ok := p["ws-opts"].(map[string]any); ok {
		if path := getString(opts, "path"); path != "" {
			keyBuilder = append(keyBuilder, "ws-path:"+path)
		}
	}
	if opts, ok := p["grpc-opts"].(map[string]any); ok {
		if service := getString(opts, "grpc-service-name"); service != "" {
			keyBuilder = append(keyBuilder, "grpc-service:"+service)
		}
	}

	// 4. 现实协议 (Reality) 区分
	// VLESS/VMess/Trojan 即使 server/uuid 一样，publicKey 不同就是完全不同的目标
	if opts, ok := p["reality-opts"].(map[string]any); ok {
		if pub := getString(opts, "public-key"); pub != "" {
			keyBuilder = append(keyBuilder, "reality-pub:"+pub)
		}
	}

	// 5. Shadowsocks/SSR 区分
	// 同样的 server/port/password，使用不同的加密算法(cipher)或混淆(plugin/obfs)是不兼容的
	if cipher := getString(p, "cipher"); cipher != "" {
		keyBuilder = append(keyBuilder, "cipher:"+cipher)
	}
	if plugin := getString(p, "plugin"); plugin != "" {
		keyBuilder = append(keyBuilder, "plugin:"+plugin)
		// 获取 plugin-opts 里的关键参数，如 mode
		if opts, ok := p["plugin-opts"].(map[string]any); ok {
			if mode := getString(opts, "mode"); mode != "" {
				keyBuilder = append(keyBuilder, "plugin-mode:"+mode)
			}
		}
	}
	// SSR 特有
	if proto := getString(p, "protocol"); proto != "" {
		keyBuilder = append(keyBuilder, "proto:"+proto)
	}
	// SSR Obfs
	if obfs := getString(p, "obfs"); obfs != "" {
		// SSR 的 obfs 和 Hysteria 的 obfs 虽然字段名一样，但因为前面的 'typ' 已经区分了协议，
		// 所以这里直接拼进去也不会冲突
		keyBuilder = append(keyBuilder, "obfs:"+obfs)
	}

	// 6. VLESS 特有 Flow (XTLS Vision 等)
	if flow := getString(p, "flow"); flow != "" {
		keyBuilder = append(keyBuilder, "flow:"+flow)
	}

	// 7. Hysteria 2 特有 Obfs-password
	// 注意：Hysteria2 也有 obfs 字段，上面的 SSR 判断通常也会覆盖到，
	// 但 Hysteria2 还有一个 obfs-password
	if obfsPw := getString(p, "obfs-password"); obfsPw != "" {
		keyBuilder = append(keyBuilder, "hy2-obfspw:"+obfsPw)
	}

	// 如果是全空配置（极少见的兜底）
	if len(keyBuilder) == 4 && server == "" && port == "" {
		return fmt.Sprintf("raw:%v", p)
	}

	return strings.Join(keyBuilder, "|")
}

// 辅助函数：安全获取字符串并去除空格
// 处理 int 类型的端口号被自动转为 string
func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}
