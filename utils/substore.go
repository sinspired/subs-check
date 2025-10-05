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
	Content string           `json:"content"`
	Name    string           `json:"name"`
	Remark  string           `json:"remark"`
	Source  string           `json:"source"`
	Process []map[string]any `json:"process"`
}

type args struct {
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

type Operator struct {
	Args     args   `json:"args"`
	Disabled bool   `json:"disabled"`
	Type     string `json:"type"`
}

type file struct {
	Name       string     `json:"name"`
	Process    []Operator `json:"process"`
	Remark     string     `json:"remark"`
	Source     string     `json:"source"`
	SourceName string     `json:"sourceName"`
	SourceType string     `json:"sourceType"`
	Type       string     `json:"type"`
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
var mihomoOverwriteUrl string

// 基础URL配置
var BaseURL string

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

	if err := checkSub(); err != nil {
		slog.Debug(fmt.Sprintf("检查sub配置文件失败: %v, 正在创建中...", err))
		if err := createSub(yamlData); err != nil {
			slog.Error(fmt.Sprintf("创建sub配置文件失败: %v", err))
			return
		}
	}
	if config.GlobalConfig.MihomoOverwriteUrl == "" {
		slog.Error("mihomo覆写订阅url未设置")
		return
	}
	if err := checkfile(); err != nil {
		slog.Debug(fmt.Sprintf("检查mihomo配置文件失败: %v, 正在创建中...", err))
		if err := createfile(); err != nil {
			slog.Error(fmt.Sprintf("创建mihomo配置文件失败: %v", err))
			return
		}
		mihomoOverwriteUrl = config.GlobalConfig.MihomoOverwriteUrl
	}
	if err := updateSub(yamlData); err != nil {
		slog.Error(fmt.Sprintf("更新sub配置文件失败: %v", err))
		return
	}
	if config.GlobalConfig.MihomoOverwriteUrl != mihomoOverwriteUrl {
		if err := updatefile(); err != nil {
			slog.Error(fmt.Sprintf("更新mihomo配置文件失败: %v", err))
			return
		}
		mihomoOverwriteUrl = config.GlobalConfig.MihomoOverwriteUrl
		slog.Debug("mihomo覆写订阅url已更新")
	}
	slog.Info("substore更新完成")
}
func checkSub() error {
	resp, err := http.Get(fmt.Sprintf("%s/api/sub/%s", BaseURL, SubName))
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
func createSub(data []byte) error {
	// sub-store 上传默认限制1MB
	sub := sub{
		Content: string(data),
		Name:    "sub",
		Remark:  "subs-check专用,勿动",
		Source:  "local",
		Process: []map[string]any{
			{
				"type": "Quick Setting Operator",
			},
		},
	}
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

func updateSub(data []byte) error {

	sub := sub{
		Content: string(data),
		Name:    "sub",
		Remark:  "subs-check专用,勿动",
		Source:  "local",
		Process: []map[string]any{
			{
				"type": "Quick Setting Operator",
			},
		},
	}
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

func checkfile() error {
	resp, err := http.Get(fmt.Sprintf("%s/api/wholeFile/%s", BaseURL, MihomoName))
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
		return fmt.Errorf("获取mihomo配置文件失败")
	}
	return nil
}
func createfile() error {
	file := file{
		Name: MihomoName,
		Process: []Operator{
			{
				Args: args{
					Content: WarpUrl(config.GlobalConfig.MihomoOverwriteUrl, GetGhProxy()),
					Mode:    "link",
				},
				Disabled: false,
				Type:     "Script Operator",
			},
		},
		Remark:     "subs-check专用,勿动",
		Source:     "local",
		SourceName: "sub",
		SourceType: "subscription",
		Type:       "mihomoProfile",
	}
	json, err := json.Marshal(file)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/files", BaseURL), "application/json", bytes.NewBuffer(json))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("创建mihomo配置文件失败,错误码:%d", resp.StatusCode)
	}
	return nil
}

func updatefile() error {
	file := file{
		Name: MihomoName,
		Process: []Operator{
			{
				Args: args{
					Content: WarpUrl(config.GlobalConfig.MihomoOverwriteUrl, GetGhProxy()),
					Mode:    "link",
				},
				Disabled: false,
				Type:     "Script Operator",
			},
		},
		Remark:     "subs-check专用,勿动",
		Source:     "local",
		SourceName: "sub",
		SourceType: "subscription",
		Type:       "mihomoProfile",
	}
	json, err := json.Marshal(file)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/api/file/%s", BaseURL, MihomoName),
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

// 如果用户监听了局域网IP，后续会请求失败
func formatPort(port string) string {
	if strings.Contains(port, ":") {
		parts := strings.Split(port, ":")
		return ":" + parts[len(parts)-1]
	}
	return ":" + port
}

func WarpUrl(url string, isGhProxyAvailable bool) string {
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
