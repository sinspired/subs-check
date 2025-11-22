package utils

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/sinspired/subs-check/config"
)

var (
	IsSysProxyAvailable bool
	IsGhProxyAvailable  bool
)

// IsLocalURL 判断给定的 URL 是否指向本地/局域网地址
func IsLocalURL(URL string) (bool) {
	// 解析 URL（支持 http://、https://、ws:// 等，也支持不带 scheme 的如 localhost:8080）
	u, err := url.Parse(strings.ToLower(URL))
	if err != nil {
		// 如果解析失败，尝试加上 http:// 再试一次（兼容用户直接传 hostname:port）
		if u2, err2 := url.Parse("http://" + URL); err2 == nil {
			u = u2
		} else {
			return false
		}
	}

	host := u.Hostname() // 自动提取主机名部分，去掉端口

	// 处理常见本地标识
	if host == "" ||
		host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == "0.0.0.0" ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".lan") ||
		!strings.Contains(host, ".") { // 裸主机名如 mypc、MY-PC
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// 无法解析为IP，但可能是内网域名如 my-router.home 等
		// 可以选择进一步解析，但大多数情况直接返回 false 或保守视为非本地
		return false
	}

	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast()
}

// GetSysProxy 检测系统代理是否可用，并设置环境变量
func GetSysProxy() bool {
	commonProxies := []string{
		"http://127.0.0.1:7890",
		"http://127.0.0.1:7891",
		"http://127.0.0.1:1080",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:10808",
		"http://127.0.0.1:10809",
		"http://127.0.0.1:3067",
		"http://127.0.0.1:2080",
		"http://127.0.0.1:1194",
		"http://127.0.0.1:1082",
		"http://127.0.0.1:12334",
		"http://127.0.0.1:12335",
	}

	// 清理所有可能的代理环境变量
	UnsetAllProxyEnvVars()

	// 优先使用配置文件中的代理，其次检测常见端口
	proxy := findAvailableSysProxy(config.GlobalConfig.SystemProxy, commonProxies)
	if proxy != "" {

		// 设置 HTTP 和 HTTPS 代理
		os.Setenv("HTTP_PROXY", proxy)
		os.Setenv("HTTPS_PROXY", proxy)
		os.Setenv("http_proxy", proxy)
		os.Setenv("https_proxy", proxy)
		os.Setenv("ALL_PROXY", proxy)

		// 更新配置中的代理
		config.GlobalConfig.SystemProxy = proxy
		slog.Debug("系统代理", "proxy", proxy)
		IsSysProxyAvailable = true
		return true
	}

	// 如果没有找到可用代理，清理所有代理环境变量
	UnsetAllProxyEnvVars()
	slog.Debug("未找到可用代理，清除代理环境变量")
	IsSysProxyAvailable = false
	return false
}

// UnsetAllProxyEnvVars 清理所有可能的代理环境变量
func UnsetAllProxyEnvVars() {
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy"} {
		os.Unsetenv(key)
	}
}

// GetGhProxy 检测 github 代理是否可用，并设置可用的 github 代理
func GetGhProxy() bool {
	GhProxy := config.GlobalConfig.GithubProxy
	GhProxyGroup := config.GlobalConfig.GithubProxyGroup

	if GhProxy == "" && GhProxyGroup == nil {
		slog.Debug("未配置 githubproxy，将不使用 githubproxy")
		IsGhProxyAvailable = false
		return false
	}

	// 先检测单个 GhProxy
	if GhProxy != "" {
		if ok, normalized := checkGhProxyAvailable(GhProxy); ok {
			config.GlobalConfig.GithubProxy = normalized
			slog.Debug("GitHub代理", "normalized", normalized)
			IsGhProxyAvailable = true
			return true
		}
	}

	// 并发检测 GhProxyGroup
	if len(GhProxyGroup) > 0 {
		slog.Debug("开始并发检测 GhProxyGroup 内的代理")

		type result struct {
			proxy string
			ok    bool
			cost  time.Duration
		}

		resultCh := make(chan result, len(GhProxyGroup))
		var wg sync.WaitGroup

		for _, proxy := range GhProxyGroup {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				start := time.Now()
				ok, normalized := checkGhProxyAvailable(p)
				cost := time.Since(start)
				resultCh <- result{proxy: normalized, ok: ok, cost: cost}
			}(proxy)
		}

		// 等待所有 goroutine 完成后关闭通道
		go func() {
			wg.Wait()
			close(resultCh)
		}()

		// 找到最快可用的代理
		var best result
		best.cost = time.Hour // 初始设为一个很大的值
		for r := range resultCh {
			if r.ok && r.cost < best.cost {
				best = r
			}
		}

		if best.ok {
			config.GlobalConfig.GithubProxy = best.proxy
			if best.cost.Milliseconds() < 1000 {
				cost := fmt.Sprintf("%dms", best.cost.Milliseconds())
				slog.Info("最佳GitHub代理", "URL", best.proxy, "耗时", cost)
			} else {
				cost := fmt.Sprintf("%.2fs", best.cost.Seconds())
				slog.Info("最佳GitHub代理", "URL", best.proxy, "耗时", cost)
			}
			IsGhProxyAvailable = true
			return true
		}
	}

	slog.Debug("未找到可用的 GitHubProxy，将不使用 GitHubProxy")
	IsGhProxyAvailable = false
	return false
}

// checkGhProxyAvailable 检查指定的 githubproxy是否可用,并返回处理后的地址
func checkGhProxyAvailable(githubProxy string) (bool, string) {
	// proxyBase 例如: "https://ghproxy.com/"
	if !strings.HasSuffix(githubProxy, "/") {
		githubProxy = githubProxy + "/"
	}

	if !strings.HasPrefix(githubProxy, "http://") && !strings.HasPrefix(githubProxy, "https://") {
		githubProxy = "https://" + githubProxy
	}

	testTarget := "https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore"
	testURL := githubProxy + testTarget

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, // 禁用系统代理，确保直连测试
		},
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false, githubProxy
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, githubProxy
	}

	// 读取完整响应体，确保下载完成
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return false, githubProxy
	}

	return true, githubProxy
}

// isSysProxyAvailable 并发检测代理是否可用
// 要求 Google 204 和 GitHub Raw 两个检测目标都成功
func isSysProxyAvailable(proxy string) bool {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	// 检测目标列表
	testURLs := []struct {
		url        string
		expectCode int
	}{
		{"https://www.google.com/generate_204", http.StatusNoContent},                           // 204
		{"https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore", http.StatusOK}, // 200
	}

	var wg sync.WaitGroup
	results := make(chan bool, len(testURLs))

	// 并发检测
	for _, t := range testURLs {
		wg.Add(1)
		go func(target string, expect int) {
			defer wg.Done()
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				results <- false
				return
			}
			req.Header.Set("User-Agent", convert.RandUserAgent())
			resp, err := client.Do(req)
			if err != nil {
				results <- false
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body) // 确保读完
			results <- (resp.StatusCode == expect)
		}(t.url, t.expectCode)
	}

	// 等待所有检测完成
	wg.Wait()
	close(results)

	// 必须全部成功
	for ok := range results {
		if !ok {
			return false
		}
	}
	return true
}

// findAvailableSysProxy 优先检测配置文件中的代理，不可用则并发检测常见端口
func findAvailableSysProxy(configProxy string, candidates []string) string {
	// Step 1: 优先检测配置文件中的代理
	if configProxy != "" && isSysProxyAvailable(configProxy) {
		return configProxy
	}

	// Step 2: 并发检测候选代理
	resultCh := make(chan string, 1)
	var wg sync.WaitGroup

	for _, proxy := range candidates {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			if isSysProxyAvailable(p) {
				select {
				case resultCh <- p: // 只取第一个可用的
				default:
				}
			}
		}(proxy)
	}

	// 等待所有 goroutine 完成后关闭 channel
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 返回第一个可用代理
	if proxy, ok := <-resultCh; ok {
		return proxy
	}
	return ""
}
