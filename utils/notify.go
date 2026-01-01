package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sinspired/subs-check/config"
)

type NotifyRequest struct {
	URLs  string `json:"urls"`
	Body  string `json:"body"`
	Title string `json:"title"`
}

// Notify 发送通知请求，支持通过指定代理发送
func Notify(req NotifyRequest, proxy string) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("构建请求体失败: %w", err)
	}

	transport := &http.Transport{}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return fmt.Errorf("代理地址无效: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	httpReq, err := http.NewRequest("POST", config.GlobalConfig.AppriseAPIServer, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("构建请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("通知失败，状态码: %d, 响应: %s", resp.StatusCode, string(b))
	}

	return nil
}

// sendWithRetry 通过多种代理方式重试发送通知
func sendWithRetry(req NotifyRequest, name string) {
	proxyChain := []string{
		"", // 优先尝试直连
		func() string {
			if IsSysProxyAvailable {
				return config.GlobalConfig.SystemProxy
			}
			return ""
		}(),
		func() string {
			if GetSysProxy() {
				return config.GlobalConfig.SystemProxy
			}
			return ""
		}(),
		"socks5://test:test@51.75.126.18:1080", 
	}

	var lastErr error
	for i, p := range proxyChain {
		if lastErr := Notify(req, p); lastErr == nil {
			stage := []string{"ok", "代理", "代理变化", "兜底"}[i]
			slog.Info(fmt.Sprintf("%s 通知发送成功 [%s]", name, stage))
			return
		}
	}

	slog.Error(fmt.Sprintf("%s 发送通知失败: %v", name, lastErr))
}

// broadcastNotify 广播通知到所有配置的目标
func broadcastNotify(buildBody func(u string) NotifyRequest) {
	if config.GlobalConfig.AppriseAPIServer == "" {
		return
	}
	if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("请配置通知目标: recipient-url")
		return
	}

	for _, u := range config.GlobalConfig.RecipientURL {
		req := buildBody(u)
		name := strings.SplitN(u, "://", 2)[0]
		sendWithRetry(req, name)
	}
}

// GetCurrentTime 获取当前时间的字符串表示
func GetCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// SendNotify 发送节点可用数量通知
func SendNotify(length int) {
	broadcastNotify(func(u string) NotifyRequest {
		return NotifyRequest{
			URLs:  u,
			Body:  fmt.Sprintf("✅ 可用节点：%d\n🕒 %s", length, GetCurrentTime()),
			Title: config.GlobalConfig.NotifyTitle,
		}
	})
}

// SendNotifyGeoDBUpdate 发送 GeoDB 更新通知
func SendNotifyGeoDBUpdate(version string) {
	broadcastNotify(func(u string) NotifyRequest {
		return NotifyRequest{
			URLs:  u,
			Body:  fmt.Sprintf("✅ 已更新到：%s\n🕒 %s", version, GetCurrentTime()),
			Title: "🔔 MaxMind数据库状态",
		}
	})
}

// SendNotifySelfUpdate 发送自更新通知
func SendNotifySelfUpdate(current, latest string) {
	broadcastNotify(func(u string) NotifyRequest {
		return NotifyRequest{
			URLs:  u,
			Body:  fmt.Sprintf("✅ %s -> %s\n🕒 %s", current, latest, GetCurrentTime()),
			Title: "🔔 subs-check 自动更新",
		}
	})
}

// SendNotifyDetectLatestRelease 发送检测到新版本通知
func SendNotifyDetectLatestRelease(current, latest string, isDockerOrGui bool, downloadURL string) {
	broadcastNotify(func(u string) NotifyRequest {
		var body string
		if isDockerOrGui {
			body = fmt.Sprintf("🏷 %s\n🔗 请及时更新 %s\n🕒 %s", latest, downloadURL, GetCurrentTime())
		} else {
			body = fmt.Sprintf("🏷 %s\n✏️ 请编辑 config.yaml 开启自动更新\n📄 update: true\n🕒 %s", latest, GetCurrentTime())
		}

		return NotifyRequest{
			URLs:  u,
			Body:  body,
			Title: "📦 subs-check 发现新版本",
		}
	})
}
