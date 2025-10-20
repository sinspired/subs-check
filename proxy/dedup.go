package proxies

import (
	"fmt"
	"runtime"
)

func DeduplicateProxies(proxies []map[string]any) []map[string]any {
	seenKeys := make(map[string]bool)
	result := make([]map[string]any, 0, len(proxies))

	for _, proxy := range proxies {
		server, _ := proxy["server"].(string)
		if server == "" {
			continue
		}
		servername, _ := proxy["servername"].(string)

		proxyType, _ := proxy["type"].(string)

		password, _ := proxy["password"].(string)
		if password == "" {
			password, _ = proxy["uuid"].(string)
		}

		key := fmt.Sprintf("[%s]%s:%v:%s:%s", proxyType, server, proxy["port"], servername, password)
		if !seenKeys[key] {
			seenKeys[key] = true
			result = append(result, proxy)
		}
	}

	// 收集代理节点阶段结束
	// 进行一次内存回收，降低前期运行时内存: 10%
	for i := range proxies {
		proxies[i] = nil // 移除 map 引用
	}
	runtime.GC()  // 提示 GC 回收

	return result
}
