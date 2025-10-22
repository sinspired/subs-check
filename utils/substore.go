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
	Name                   string     `json:"name"`
	Remark                 string     `json:"remark"`
	Source                 string     `json:"source"`
	IgnoreFailedRemoteFile string     `json:"ignoreFailedRemoteFile,omitempty"`
	Process                []Operator `json:"process"`
	Tag                    []string   `json:"tag,omitempty"`
	Content                string     `json:"content"`
	Icon                   string     `json:"icon,omitempty"`
	IsIconColor            bool       `json:"isIconColor,omitempty"`
}

// Arguments 脚本参数
type Arguments struct {
	Name string `json:"name"` // 订阅名称：sub
	Type string `json:"type"` // 订阅类型：0：单条订阅；1：组合订阅
}

// args 支持可选的 arguments
type args struct {
	Content   string    `json:"content"` // 覆写地址，mihomo支持yaml覆写
	Mode      string    `json:"mode"`
	Arguments Arguments `json:"arguments,omitempty"`
}

type Operator struct {
	Args     args   `json:"args"`
	Disabled bool   `json:"disabled"`
	Type     string `json:"type"`
}

// file 结构体，兼容 mihomo 和 singbox
type file struct {
	Name                   string     `json:"name"`
	Remark                 string     `json:"remark,omitempty"` // 备注信息
	Icon                   string     `json:"icon,omitempty"`
	IsIconColor            bool       `json:"isIconColor,omitempty"`
	Source                 string     `json:"source"`     // "local" or "remote"
	SourceType             string     `json:"sourceType"` // "subscription" or "collection"
	SourceName             string     `json:"sourceName"` // 单条订阅 或 组合订阅 的名称
	Process                []Operator `json:"process"`
	Type                   string     `json:"type"`          // "mihomoProfile" or "file"
	URL                    string     `json:"url,omitempty"` // 脚本操作链接
	IgnoreFailedRemoteFile string     `json:"ignoreFailedRemoteFile,omitempty"`
	Tag                    []string   `json:"tag,omitempty"`
}

type resourceResult struct {
	Status string `json:"status"`
}

const (
	SubName     = "sub"
	MihomoName  = "mihomo"
	SingboxName = "singbox"
)

var (
	LatestSingboxVersion = "1.12"
	OldSingboxVersion    = "1.11"
)

const (
	latestSingboxJSON = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json"
	latestSingboxJS   = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.js"
	// 当前ios支持的最新singbox版本:1.11
	OldSingboxJSON = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.json"
	OldSingboxJS   = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.js"
)

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
		Process: []Operator{
			{
				Type:     "Quick Setting Operator",
				Disabled: false,
			},
		},
	}
}

// newMihomoFile 定义mihomo文件
func newMihomoFile() file {
	overwriteURL := config.GlobalConfig.MihomoOverwriteURL
	if overwriteURL == "" {
		overwriteURL = "http://127.0.0.1:8199/sub/ACL4SSR_Online_Full.yaml" // 默认值
	}
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
					Content: WarpURL(overwriteURL, GetGhProxy()),
					Mode:    "link",
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
	jsURL = WarpURL(jsURL, GetGhProxy())
	jsURL += "#name=sub&type=0#noCache"
	jsonURL = WarpURL(jsonURL, GetGhProxy())
	jsonURL += "#noCache"

	version := strings.Split(name, "-")[1]
	remark := "默认 Sing-Box 订阅 (带分流规则)"
	if version != "" {
		remark = fmt.Sprintf("默认 Sing-Box-%s 订阅 (带分流规则)", version)

	}

	// icon := "https://singbox.app/wp-content/uploads/2025/06/cropped-logo-278x300.webp"
	icon := WarpURL("https://raw.githubusercontent.com/SagerNet/sing-box/main/docs/assets/icon.svg", GetGhProxy())

	icon = WarpURL(icon, GetGhProxy())
	return file{
		Name:        name,
		Remark:      remark,
		Tag:         []string{"Subs-Check", "已检测"},
		Icon:        icon,
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
					Arguments: Arguments{
						Name: "sub",
						Type: "0",
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

// UpdateSubStore 更新sub-store
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

	// 处理 sub 订阅
	endpoint := "sub"
	if err := checkResource(endpoint, defaultSub.Name); err != nil {
		slog.Debug(fmt.Sprintf("检查 %s 配置文件失败: %v, 正在创建中...", defaultSub.Name, err))
		if err := createResource(endpoint, defaultSub, defaultSub.Name); err != nil {
			slog.Error(fmt.Sprintf("创建 %s 配置文件失败: %v", defaultSub.Name, err))
			return
		}
	}
	if err := updateResource(endpoint, defaultSub, SubName); err != nil {
		slog.Error(fmt.Sprintf("更新 %s 配置文件失败: %v", defaultSub.Name, err))
		return
	}

	// 定义 mihomo 文件
	mihomoFile := newMihomoFile()
	if err := mihomoFile.updateSubStoreFile(); err != nil {
		slog.Info("mihomo 订阅更新失败")
	}

	// 处理最新版本和旧版本的singbox订阅
	if config.GlobalConfig.SingboxLatest.Version != "" {
		LatestSingboxVersion = config.GlobalConfig.SingboxLatest.Version
	}
	if config.GlobalConfig.SingboxOld.Version != "" {
		OldSingboxVersion = config.GlobalConfig.SingboxOld.Version
	}
	processSingboxFile(&config.GlobalConfig.SingboxLatest, latestSingboxJS, latestSingboxJSON, LatestSingboxVersion)
	processSingboxFile(&config.GlobalConfig.SingboxOld, OldSingboxJS, OldSingboxJSON, OldSingboxVersion)

	slog.Info("substore更新完成")
}

// processSingboxFile 处理 singbox 订阅
func processSingboxFile(sbc *config.SingBoxConfig, defaultJS, defaultJSON, singboxVersion string) {
	var js, jsonStr string
	if len(sbc.JS) > 0 && len(sbc.JSON) > 0 {
		js = sbc.JS[0]
		jsonStr = sbc.JSON[0]
	} else {
		js = defaultJS
		jsonStr = defaultJSON
	}
	name := SingboxName + "-" + singboxVersion

	file := newSingboxFile(name, js, jsonStr)
	if err := file.updateSubStoreFile(); err != nil {
		slog.Info(fmt.Sprintf("%s 订阅更新失败", file.Name))
	}
}

// checkResource 检查资源是否存在
func checkResource(endpoint, name string) error {
	url := fmt.Sprintf("%s/api/%s/%s", BaseURL, endpoint, name)
	if endpoint == "wholeFile" {
		url = fmt.Sprintf("%s/api/%s/%s", BaseURL, endpoint, name)
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var result resourceResult
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	if result.Status != "success" {
		return fmt.Errorf("获取 %s 资源失败", name)
	}
	return nil
}

// createResource 创建资源
func createResource(endpoint string, data any, name string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/%ss", BaseURL, endpoint)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("创建 %s 资源失败, 错误码: %d", name, resp.StatusCode)
	}
	return nil
}

// updateResource 更新资源
func updateResource(endpoint string, data any, name string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/%s/%s", BaseURL, endpoint, name)
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("更新 %s 资源失败, 错误码: %d", name, resp.StatusCode)
	}
	return nil
}

// updateSubStoreFile 检查资源,创建,更新sub-store
func (f file) updateSubStoreFile() error {
	if f.Name == MihomoName {
		if f.Process[0].Args.Content == "" {
			return fmt.Errorf("未设置覆写文件")
		}
	} else if f.Process[0].Args.Content == "" || f.URL == "" {
		return fmt.Errorf("未设置覆写文件或规则文件")
	}

	endpoint := "file"
	if err := checkResource("wholeFile", f.Name); err != nil {
		slog.Debug(fmt.Sprintf("检查 %s 配置文件失败: %v, 正在创建中...", f.Name, err))
		if err := createResource(endpoint, f, f.Name); err != nil {
			slog.Error(fmt.Sprintf("创建 %s 配置文件失败: %v", f.Name, err))
			return err
		}
	}

	if err := updateResource(endpoint, f, f.Name); err != nil {
		slog.Error(fmt.Sprintf("更新 %s 配置文件失败: %v", f.Name, err))
		return err
	}

	slog.Info(fmt.Sprintf("%s 订阅已更新", f.Name))
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
