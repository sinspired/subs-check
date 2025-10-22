// Package utils 工具类包
package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sinspired/subs-check/config"
)

type sub struct {
	Name                   string           `json:"name"`
	Remark                 string           `json:"remark"`
	Source                 string           `json:"source"`
	IgnoreFailedRemoteFile string           `json:"ignoreFailedRemoteFile,omitempty"`
	Process                []map[string]any `json:"process"`
	Tag                    []string         `json:"tag,omitempty"`
	Content                string           `json:"content"`
}

// Arguments 脚本参数
type Arguments struct {
	Name string `json:"name"` // 订阅名称：sub
	Type string `json:"type"` // 订阅类型：0：单条订阅；1：组合订阅
}

// args 支持可选的 arguments
type args struct {
	Content   string                 `json:"content"`
	Mode      string                 `json:"mode"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type Operator struct {
	Args     args   `json:"args"`
	Disabled bool   `json:"disabled"`
	Type     string `json:"type"`
}

// file 结构体扩展，兼容 mihomo 和 singbox
type file struct {
	Name                   string     `json:"name"`
	Remark                 string     `json:"remark,omitempty"`
	Icon                   string     `json:"icon,omitempty"`
	IsIconColor            bool       `json:"isIconColor,omitempty"`
	Source                 string     `json:"source"`
	SourceType             string     `json:"sourceType"`
	SourceName             string     `json:"sourceName"`
	Process                []Operator `json:"process"`
	Type                   string     `json:"type"` // "mihomoProfile" or "file"
	URL                    string     `json:"url,omitempty"`
	IgnoreFailedRemoteFile string     `json:"ignoreFailedRemoteFile,omitempty"`
	Tag                    []string   `json:"tag,omitempty"`
}

type fileResult struct {
	Data   file   `json:"data"`
	Status string `json:"status"`
}

const (
	SubName    = "sub"
	MihomoName = "mihomo"
)

// 用来判断用户是否在运行时更改了覆写订阅的url
var mihomoOverwriteURL string

// BaseURL 基础URL配置
var BaseURL string

// newDefaultSub 返回默认sub
func newDefaultSub(data []byte) sub {
	return sub{
		Content: string(data),
		Name:    SubName,
		Remark:  "默认订阅 (无分流规则)",
		Tag:     []string{"Subs-Check", "已检测"},
		Source:  "local",
		Process: []map[string]any{
			{
				"type": "Quick Setting Operator",
			},
		},
	}
}

// MihomoFile 定义mihomo文件
func newMihomoFile() file {
	return file{
		Name:        MihomoName,
		Remark:      "默认 Mihomo 订阅 (带分流规则)",
		Tag:         []string{"Subs-Check", "已检测"},
		Icon:        "",
		IsIconColor: true,
		Source:      "local",
		SourceType:  "subscription",
		SourceName:  "sub",
		Process: []Operator{
			{
				Type: "Script Operator",
				Args: args{
					Content: WarpURL(config.GlobalConfig.MihomoOverwriteURL, GetGhProxy()),
					Mode:    "link",
					Arguments: map[string]any{
						"name": "sub",
						"type": "0",
					},
				},
				Disabled: false,
			},
		},
		Type:                   "mihomoProfile",
		URL:                    "",
		IgnoreFailedRemoteFile: "enabled",
	}
}

// newSingboxFile 返回singbox文件
func newSingboxFile(name, jsURL, jsonURL string) file {
	return file{
		Name:        name,
		Remark:      "默认 Sing-Box 订阅 (带分流规则)",
		Tag:         []string{"Subs-Check", "已检测"},
		Icon:        "https://singbox.app/wp-content/uploads/2025/06/cropped-logo-278x300.webp",
		IsIconColor: true,
		Source:      "remote",
		SourceType:  "subscription",
		SourceName:  "SUB",
		Process: []Operator{
			{
				Type: "Script Operator",
				Args: args{
					Content: jsURL,
					Mode:    "link",
					Arguments: map[string]any{
						"name": "sub",
						"type": "0",
					},
				},
				Disabled: false,
			},
		},
		Type:                   "file",
		URL:                    jsonURL,
		IgnoreFailedRemoteFile: "enabled",
	}
}

func UpdateSubStore(yamlData []byte) {
	// 调试的时候等一等node启动
	if os.Getenv("SUB_CHECK_SKIP") != "" && config.GlobalConfig.SubStorePort != "" {
		time.Sleep(time.Second * 1)
	}
	// 处理用户输入的格式
	config.GlobalConfig.SubStorePort = formatPort(config.GlobalConfig.SubStorePort)
	// 设置基础URL
	BaseURL = fmt.Sprintf("http://127.0.0.1%s", config.GlobalConfig.SubStorePort)
	if config.GlobalConfig.SubStorePath != "" {
		BaseURL = fmt.Sprintf("%s%s", BaseURL, config.GlobalConfig.SubStorePath)
	}

	// 创建默认订阅实例
	defaultSub := newDefaultSub(yamlData)

	if err := defaultSub.checkSub(); err != nil {
		slog.Debug(fmt.Sprintf("检查sub配置文件失败: %v, 正在创建中...", err))
		if err := defaultSub.createSub(); err != nil {
			slog.Error(fmt.Sprintf("创建sub配置文件失败: %v", err))
			return
		}
	}

	// 创建或更新mihomo文件
	if config.GlobalConfig.MihomoOverwriteURL == "" {
		slog.Error("mihomo覆写订阅url未设置")
		return
	}

	// 定义mihomo文件
	mihomoFile := newMihomoFile()

	if err := mihomoFile.checkFile(); err != nil {
		slog.Debug(fmt.Sprintf("检查mihomo配置文件失败: %v, 正在创建中...", err))
		if err := mihomoFile.createFile(); err != nil {
			slog.Error(fmt.Sprintf("创建mihomo配置文件失败: %v", err))
			return
		}
		mihomoOverwriteURL = config.GlobalConfig.MihomoOverwriteURL
	}
	if err := defaultSub.updateSub(); err != nil {
		slog.Error(fmt.Sprintf("更新sub配置文件失败: %v", err))
		return
	}
	if config.GlobalConfig.MihomoOverwriteURL != mihomoOverwriteURL {
		if err := mihomoFile.updateFile(); err != nil {
			slog.Error(fmt.Sprintf("更新mihomo配置文件失败: %v", err))
			return
		}
		mihomoOverwriteURL = config.GlobalConfig.MihomoOverwriteURL
		slog.Debug("mihomo覆写订阅url已更新")
	}

	// TODO: 创建singbox文件
	slog.Info("substore更新完成")
}
func (sub sub) checkSub() error {
	resp, err := http.Get(fmt.Sprintf("%s/api/sub/%s", BaseURL, sub.Name))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var fileResult fileResult
	err = json.Unmarshal(body, &fileResult)
	if err != nil {
		return err
	}
	if fileResult.Status != "success" {
		return fmt.Errorf("获取sub配置文件失败")
	}
	return nil
}
func (sub sub) createSub() error {
	// sub-store 上传默认限制1MB
	json, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/subs", BaseURL), "application/json", bytes.NewBuffer(json))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("创建sub配置文件失败,错误码:%d", resp.StatusCode)
	}
	return nil
}

func (sub sub) updateSub() error {
	json, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/api/sub/%s", BaseURL, SubName),
		bytes.NewBuffer(json))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("更新sub配置文件失败,错误码:%d", resp.StatusCode)
	}
	return nil
}

// 如果用户监听了局域网IP，后续会请求失败
func formatPort(port string) string {
	if strings.Contains(port, ":") {
		parts := strings.Split(port, ":")
		return ":" + parts[len(parts)-1]
	}
	return ":" + port
}

// WarpURL 添加github代理前缀
func WarpURL(url string, isGhProxyAvailable bool) string {
	url = formatTimePlaceholders(url, time.Now())

	// 如果url中以https://raw.githubusercontent.com开头，那么就使用github代理
	if strings.HasPrefix(url, "https://raw.githubusercontent.com") && isGhProxyAvailable {
		return config.GlobalConfig.GithubProxy + url
	}
	return url
}

// 动态时间占位符
// 支持在链接中使用时间占位符，会自动替换成当前日期/时间:
// - `{Y}` - 四位年份 (2023)
// - `{m}` - 两位月份 (01-12)
// - `{d}` - 两位日期 (01-31)
// - `{Ymd}` - 组合日期 (20230131)
// - `{Y_m_d}` - 下划线分隔 (2023_01_31)
// - `{Y-m-d}` - 横线分隔 (2023-01-31)
func formatTimePlaceholders(url string, t time.Time) string {
	replacer := strings.NewReplacer(
		"{Y}", t.Format("2006"),
		"{m}", t.Format("01"),
		"{d}", t.Format("02"),
		"{Ymd}", t.Format("20060102"),
		"{Y_m_d}", t.Format("2006_01_02"),
		"{Y-m-d}", t.Format("2006-01-02"),
	)
	return replacer.Replace(url)
}

func (f file) checkFile() error {
	resp, err := http.Get(fmt.Sprintf("%s/api/wholeFile/%s", BaseURL, f.Name))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var fileResult fileResult
	err = json.Unmarshal(body, &fileResult)
	if err != nil {
		return err
	}
	if fileResult.Status != "success" {
		return fmt.Errorf("获取%s配置文件失败", f.Name)
	}
	return nil
}

func (f file) createFile() error {
	jsonData, err := json.Marshal(f)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/files", BaseURL), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("创建%s配置文件失败,错误码:%d", f.Name, resp.StatusCode)
	}
	return nil
}

func (f file) updateFile() error {
	json, err := json.Marshal(f)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/api/file/%s", BaseURL, f.Name),
		bytes.NewBuffer(json))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("更新mihomo配置文件失败,错误码:%d", resp.StatusCode)
	}
	return nil
}
