package utils

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/sinspired/subs-check/config"
)

// GetSysProxy 检测系统代理是否可用，并设置环境变量
func GetSysProxy() bool {
	commonProxies := []string{
		"http://127.0.0.1:7890",
		"http://127.0.0.1:7891",
		"http://127.0.0.1:1080",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:10808",
		"http://127.0.0.1:10809",
	}

	// 优先使用配置文件中的代理，其次检测常见端口
	proxy := findAvailableSysProxy(config.GlobalConfig.SysProxy, commonProxies)
	if proxy != "" {
		os.Setenv("HTTP_PROXY", proxy)
		os.Setenv("HTTPS_PROXY", proxy)
		slog.Info("使用代理", "proxy", proxy)
		return true
	}

	slog.Debug("未找到可用代理，将不设置代理")
	return false
}

// GetSysProxy 检测系统代理是否可用，并设置环境变量
func GetGhProxy() bool {
	GhProxy := config.GlobalConfig.GithubProxy
	if config.GlobalConfig.GithubProxy == "" {
		slog.Debug("未配置 githubproxy，将不使用 githubproxy")
		return false
	}
	checkGhProxyAvailable := checkGhProxyAvailable(GhProxy)
	GhProxy = config.GlobalConfig.GithubProxy
	if checkGhProxyAvailable {
		slog.Info("githubproxy 可用", "githubproxy", GhProxy)
		return true
	} else {
		slog.Debug("githubproxy 不可用，将不使用 githubproxy", "githubproxy", GhProxy)
		return false
	}
}

// checkGhProxyAvailable 检查指定的 githubproxy 是否可用
func checkGhProxyAvailable(githubProxy string) bool {
	// proxyBase 例如: "https://ghproxy.com/"
	if !strings.HasSuffix(githubProxy, "/") {
		githubProxy = githubProxy + "/"
	}

	if !strings.HasPrefix(githubProxy, "http://") && !strings.HasPrefix(githubProxy, "https://") {
		githubProxy = "https://" + githubProxy
	}

	config.GlobalConfig.GithubProxy = githubProxy

	testTarget := "https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore"
	testURL := githubProxy + testTarget

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, // 禁用系统代理，确保直连测试
		},
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// 简单读取部分内容，确保不是空响应
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return n > 0
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
		Timeout:   3 * time.Second,
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
			resp, err := client.Get(target)
			if err != nil {
				results <- false
				return
			}
			defer resp.Body.Close()
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
