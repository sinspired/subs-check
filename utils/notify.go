package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sinspired/subs-check/config"
)

// NotifyRequest 定义发送通知的请求结构
type NotifyRequest struct {
	URLs  string `json:"urls"`  // 通知目标的 URL（如 mailto://、discord://）
	Body  string `json:"body"`  // 通知内容
	Title string `json:"title"` // 通知标题（可选）
}

// Notify 发送通知
func Notify(request NotifyRequest) error {
	// 构建请求体
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("构建请求体失败: %w", err)
	}

	// 发送请求
	resp, err := http.Post(config.GlobalConfig.AppriseAPIServer, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("通知失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return nil
}

func SendNotify(length int) {
	if config.GlobalConfig.AppriseAPIServer == "" {
		return
	} else if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("没有配置通知目标")
		return
	}

	for _, url := range config.GlobalConfig.RecipientURL {
		request := NotifyRequest{
			URLs: url,
			Body: fmt.Sprintf("✅ 可用节点：%d\n🕒 %s",
				length,
				GetCurrentTime()),
			Title: config.GlobalConfig.NotifyTitle,
		}
		var err error
		for i := 0; i < config.GlobalConfig.SubUrlsReTry; i++ {
			err = Notify(request)
			if err == nil {
				slog.Info(fmt.Sprintf("%s 通知发送成功", strings.SplitN(url, "://", 2)[0]))
				break
			}
		}
		if err != nil {
			slog.Error(fmt.Sprintf("%s 发送通知失败: %v", strings.SplitN(url, "://", 2)[0], err))
		}
	}
}

func GetCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func SendNotifyGeoDBUpdate(version string) {
	if config.GlobalConfig.AppriseAPIServer == "" {
		return
	} else if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("没有配置通知目标")
		return
	}

	for _, url := range config.GlobalConfig.RecipientURL {
		request := NotifyRequest{
			URLs: url,
			Body: fmt.Sprintf("✅ 已更新到：%s\n🕒 %s",
				version,
				GetCurrentTime()),
			Title: "🔔 MaxMind数据库状态",
		}
		var err error
		for i := 0; i < config.GlobalConfig.SubUrlsReTry; i++ {
			err = Notify(request)
			if err == nil {
				slog.Info(fmt.Sprintf("%s MaxMind数据库更新通知发送成功", strings.SplitN(url, "://", 2)[0]))
				break
			}
		}
		if err != nil {
			slog.Error(fmt.Sprintf("%s MaxMind数据库更新发送通知失败: %v", strings.SplitN(url, "://", 2)[0], err))
		}
	}
}

// SendNotifySelfUpdate 版本更新通知
func SendNotifySelfUpdate(current string, lastest string) {
	if config.GlobalConfig.AppriseAPIServer == "" {
		return
	} else if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("没有配置通知目标")
		return
	}

	for _, url := range config.GlobalConfig.RecipientURL {
		request := NotifyRequest{
			URLs: url,
			Body: fmt.Sprintf("✅ %s\n🕒 %s",
				current+" -> "+lastest,
				GetCurrentTime()),
			Title: "🔔 subs-check 自动更新",
		}
		var err error
		for i := 0; i < config.GlobalConfig.SubUrlsReTry; i++ {
			err = Notify(request)
			if err == nil {
				slog.Info(fmt.Sprintf("%s 版本更新 通知发送成功", strings.SplitN(url, "://", 2)[0]))
				break
			}
		}
		if err != nil {
			slog.Error(fmt.Sprintf("%s 版本更新 发送通知失败: %v", strings.SplitN(url, "://", 2)[0], err))
		}
	}
}

// SendNotifyDetectLatestRelease 版本更新通知
func SendNotifyDetectLatestRelease(current string, lastest string, isDockerOrGui bool, downloadURL string) {
	if config.GlobalConfig.AppriseAPIServer == "" {
		return
	} else if len(config.GlobalConfig.RecipientURL) == 0 {
		slog.Error("没有配置通知目标")
		return
	}

	for _, url := range config.GlobalConfig.RecipientURL {
		var request NotifyRequest
		if isDockerOrGui {

			request = NotifyRequest{
				URLs: url,
				Body: fmt.Sprintf("🏷 %s\n🔗 请及时更新%s\n🕒 %s",
					lastest, downloadURL,
					GetCurrentTime()),
				Title: "📦 subs-check 发现新版本",
			}
		} else {
			request = NotifyRequest{
				URLs: url,
				Body: fmt.Sprintf("🏷 %s\n✏️ 请编辑config.yaml，开启更新\n📄 update: true\n🕒 %s",
					lastest,
					GetCurrentTime()),
				Title: "📦 subs-check 发现新版本",
			}
		}

		var err error
		for i := 0; i < config.GlobalConfig.SubUrlsReTry; i++ {
			err = Notify(request)
			if err == nil {
				slog.Info(fmt.Sprintf("%s 版本检测 通知发送成功", strings.SplitN(url, "://", 2)[0]))
				break
			}
		}
		if err != nil {
			slog.Error(fmt.Sprintf("%s 版本检测 发送通知失败: %v", strings.SplitN(url, "://", 2)[0], err))
		}
	}
}
