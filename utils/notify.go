package utils

import (
	"bytes"
	"context"
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

// NotifyKind 表示通知类型
type NotifyKind int

const (
	NotifyNodeStatus  NotifyKind = iota // 节点状态
	NotifyGeoDBUpdate                   // GeoDB 更新
	NotifySelfUpdate                    // 程序自更新
	NotifyNewRelease                    // 新版本通知
)

const (
	notifyTimeout = 10 * time.Second // 通知请求超时时间

	FallbackProxy = "socks5://test:test@51.75.126.18:1080"                                                     // 兜底代理
	RepoURL       = "https://github.com/sinspired/subs-check-pro"                                                  // 仓库地址
	ClickURL      = "https://github.com/sinspired/subs-check-pro/releases/latest"                                  // 点击跳转链接
	IconURL       = "https://raw.githubusercontent.com/sinspired/subs-check-pro/main/app/static/icon/icon-512.png" // 通用图标 URL
)

// NotifyRequest 表示通知请求体
type NotifyRequest struct {
	URLs  string `json:"urls"`
	Body  string `json:"body"`
	Title string `json:"title"`
}

// newClient 创建 HTTP 客户端，支持可选代理
func newClient(proxy string) (*http.Client, error) {
	tr := &http.Transport{}
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("代理地址无效: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Transport: tr, Timeout: notifyTimeout}, nil
}

// Notify 发送单次通知请求
func Notify(req NotifyRequest, proxy string) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("构建请求体失败: %w", err)
	}

	client, err := newClient(proxy)
	if err != nil {
		return err
	}

	apiServer := config.GlobalConfig.AppriseAPIServer
	if apiServer == "" {
		return fmt.Errorf("通知服务器地址未配置")
	}

	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		apiServer,
		bytes.NewReader(body),
	)
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
		bs, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("通知失败, 状态码: %d, 响应: %s", resp.StatusCode, strings.TrimSpace(string(bs)))
	}

	return nil
}

// sendWithRetry 带重试逻辑的通知发送
func sendWithRetry(req NotifyRequest, name string) {
	proxies := []string{""} // 直连优先

	if IsSysProxyAvailable {
		proxies = append(proxies, config.GlobalConfig.SystemProxy)
	}
	if GetSysProxy() {
		proxies = append(proxies, config.GlobalConfig.SystemProxy)
	}
	if FallbackProxy != "" {
		proxies = append(proxies, FallbackProxy)
	}

	var lastErr error
	for _, p := range proxies {
		if err := Notify(req, p); err == nil {
			if p != "" {
				slog.Info("通知发送成功", "目标", name, "方法", "代理")
			} else {
				slog.Info("通知发送成功", "目标", name)
			}
			return
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		slog.Error("通知发送最终失败", "目标", name, "错误", lastErr)
	}
}

// decorateURL 根据服务类型和通知类型装饰 URL
func decorateURL(raw string, kind NotifyKind) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()

	switch u.Scheme {
	case "bark", "barks":
		q.Set("icon", IconURL)
		q.Set("image", IconURL)
		q.Set("copy", RepoURL)
		q.Set("click", RepoURL)
		switch kind {
		case NotifyNewRelease:
			q.Set("group", "release")
			q.Set("category", "新版本通知")
			if ClickURL != "" {
				q.Set("click", ClickURL)
			}
		case NotifyNodeStatus:
			q.Set("group", "node")
			q.Set("category", "节点状态更新")
		case NotifyGeoDBUpdate:
			q.Set("group", "geodb")
			q.Set("category", "数据库更新")
		case NotifySelfUpdate:
			q.Set("group", "selfupdate")
			q.Set("category", "程序更新")
		}

	case "discord":
		if IconURL != "" {
			q.Set("avatar", "yes")
			q.Set("avatar_url", IconURL)
		}
		switch kind {
		case NotifyNewRelease:
			q.Set("footer", "新版本通知")
		case NotifyNodeStatus:
			q.Set("footer", "节点状态更新")
		}
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// broadcastNotify 广播通知到所有接收者
func broadcastNotify(kind NotifyKind, title, body string) {
    apiServer := config.GlobalConfig.AppriseAPIServer
    if apiServer == "" {
        return
    }
	if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("请配置通知目标: recipient-url")
		return
	}

	for _, u := range config.GlobalConfig.RecipientURL {
		req := NotifyRequest{
			URLs:  decorateURL(u, kind),
			Body:  body,
			Title: title,
		}
		name := strings.SplitN(u, "://", 2)[0]
		sendWithRetry(req, name)
	}
}

// GetCurrentTime 返回当前时间字符串
func GetCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// SendNotifyCheckResult 发送节点检查结果通知
func SendNotifyCheckResult(length int) {
	title := config.GlobalConfig.NotifyTitle
	body := fmt.Sprintf("✅ 可用节点：%d\n🕒 %s", length, GetCurrentTime())
	broadcastNotify(NotifyNodeStatus, title, body)
}

// SendNotifyGeoDBUpdate 发送 GeoDB 更新通知
func SendNotifyGeoDBUpdate(version string) {
	title := "🔔 MaxMind GeoDB 更新"
	body := fmt.Sprintf("✅ 已更新到：%s\n🕒 %s", version, GetCurrentTime())
	broadcastNotify(NotifyGeoDBUpdate, title, body)
}

// SendNotifySelfUpdate 发送程序自更新通知
func SendNotifySelfUpdate(current, latest string) {
	title := "🔔 subs-check 自动更新"
	body := fmt.Sprintf("✅ %s -> %s\n🕒 %s", current, latest, GetCurrentTime())
	broadcastNotify(NotifySelfUpdate, title, body)
}

// SendNotifyDetectLatestRelease 发送新版本通知
func SendNotifyDetectLatestRelease(current, latest string, isDockerOrGui bool, downloadURL string) {
	title := "📦 subs-check 发现新版本"
	var body string
	if isDockerOrGui {
		body = fmt.Sprintf("🏷 %s\n🔗 %s\n🕒 %s", latest, downloadURL, GetCurrentTime())
	} else {
		body = fmt.Sprintf("🏷 %s\n✏️ 请编辑 config.yaml 开启自动更新\n📄 update: true\n🕒 %s", latest, GetCurrentTime())
	}
	broadcastNotify(NotifyNewRelease, title, body)
}
