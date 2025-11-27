// Package platform 解锁检测平台
package platform

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/sinspired/subs-check/config"
)

var CfCdnApis = []string{
	"https://4.ipw.cn",
	"https://www.cloudflare.com",
	"https://api.ipify.org",
	"https://iplark.com",
	"https://ifconfig.co",
	"https://api.ip2location.io",
	"https://api.ip.sb",
	"https://realip.cc",
	"https://ipapi.co",
	"https://free.freeipapi.com",
	"https://api.myip.com",
	"https://api.ipbase.com",
	"https://api.ipquery.io",
}

// cfCommonHeaders 请求头，避免被 ban
func cfCommonHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      convert.RandUserAgent(),
		"Accept-Language": "en-US,en;q=0.5",
		// "Accept":             "*/*",
		"Sec-Ch-Ua":          "\"Chromium\";v=\"122\", \"Google Chrome\";v=\"122\", \"Not A(Brand\";v=\"99\"",
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": "\"Windows\"",
		"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Connection":         "close",
	}
}

// CheckCloudflare 检测当前客户端是否可以访问 Cloudflare CDN
func CheckCloudflare(httpClient *http.Client) (cloudflare bool, cfRelayLoc string, cfRelayIP string) {

	ok, err := checkCFEndpoint(httpClient, "https://cp.cloudflare.com/generate_204", 204)
	if err == nil && ok {
		slog.Debug("Cloudflare 可达")
		return true, "", ""
	}

	ok, err = checkCFEndpoint(httpClient, "https://cloudflare.com", 200)
	if err == nil && ok {
		slog.Debug("Cloudflare 可达")
		return true, "", ""
	}

	// cfRelayLoc, cfRelayIP = GetCFTrace(httpClient)

	// if cfRelayLoc != "" && cfRelayIP != "" {
	// 	slog.Debug(fmt.Sprintf("Cloudflare CDN 检测成功: loc=%s, ip=%s", cfRelayLoc, cfRelayIP))
	// 	return true, cfRelayLoc, cfRelayIP
	// }

	return false, "", ""
}

// GetCFTrace 获取 Cloudflare Trace 的 loc 和 ip,并设置 10s 超时
func GetCFTrace(httpClient *http.Client) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return FetchCFTraceFirstConcurrent(httpClient, ctx, cancel)
}

// shuffle 返回一个新切片，元素是原切片的随机乱序版本
func shuffle(in []string) []string {
	out := append([]string(nil), in...)
	rand.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})

	return out
}

// FetchCFTraceFirstConcurrent 并发处理 FetchCFCDNTrace
func FetchCFTraceFirstConcurrent(httpClient *http.Client, ctx context.Context, cancel context.CancelFunc) (string, string) {
	type result struct {
		loc string
		ip  string
	}

	// 乱序 + 截取前3, 减轻网络负载
	apis := shuffle(CfCdnApis)
	if len(apis) > 3 {
		apis = apis[:3]
	}

	resultChan := make(chan result, 1)
	var once sync.Once
	var wg sync.WaitGroup

	retries := config.GlobalConfig.SubUrlsReTry

	for _, baseURL := range apis {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			for range retries {
				select {
				case <-ctx.Done():
					return
				default:
				}
				loc, ip := FetchCFTrace(httpClient, ctx, url)
				if loc != "" && ip != "" {
					once.Do(func() {
						resultChan <- result{loc, ip}
						cancel()
					})
					return
				}
			}
		}(baseURL)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	select {
	case r := <-resultChan:
		return r.loc, r.ip
	case <-ctx.Done():
		return "", ""
	}
}

// FetchCFTrace 从cloudflare 的cdn-cgi/trace API获取CDN节点位置
func FetchCFTrace(httpClient *http.Client, ctx context.Context, baseURL string) (string, string) {
	url := fmt.Sprintf("%s/cdn-cgi/trace", baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", ""
	}

	for key, value := range cfCommonHeaders() {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}

	var loc, ip string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimPrefix(line, "loc=")
		}
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		}
	}
	return loc, ip
}

// checkCFEndpoint 检查指定的 Cloudflare 端点是否可达，并返回是否成功和错误信息
func checkCFEndpoint(httpClient *http.Client, url string, expectedStatus int) (bool, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, err
	}

	for key, value := range cfCommonHeaders() {
		req.Header.Set(key, value)
	}

	transport := httpClient.Transport
	if transport == nil {
		transport = &http.Transport{}
	}
	if t, ok := transport.(*http.Transport); ok {
		sni := req.URL.Hostname()
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
		}
		httpClient.Transport = t
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		errStr := err.Error()

		// 检测是否为典型的 Cloudflare 拒绝自身加速请求的错误
		//  strings.Contains(errStr, "EOF") ||
		// 	strings.Contains(errStr, "tls:") ||
		// 	strings.Contains(errStr, "ws closed: 1005") ||
		// 	strings.Contains(errStr, "connection reset") ||

		if strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "tls:") ||
			strings.Contains(errStr, "connection reset") {
			slog.Debug("Cloudflare 连接异常，但可能可以访问，暂时返回 true", "error", errStr)
			return true, nil
		}
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		if resp.StatusCode == 403 {
			slog.Debug("放行状态码", "code", resp.StatusCode)
			return true, nil
		} else {
			slog.Warn("cloudflare.com 返回非预期状态码", "code", resp.StatusCode)
		}
		return false, nil
	}
	return true, nil
}
