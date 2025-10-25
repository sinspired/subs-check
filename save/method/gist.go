package method

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"log/slog"

	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

var (
	gistAPIURL     = "https://api.github.com/gists"
	gistMaxRetries = 3
	gistRetryDelay = 2 * time.Second
)

// GistFile 表示 Gist 文件的结构
type GistFile struct {
	Content string `json:"content"`
}

// GistPayload 表示创建 Gist 的请求结构
type GistPayload struct {
	Description string              `json:"description"`
	Public      bool                `json:"public"`
	Files       map[string]GistFile `json:"files"`
}

// GistUploader 处理 GitHub Gist 上传的结构体
type GistUploader struct {
	client   *http.Client
	token    string
	id       string
	isPublic bool
}

// NewGistUploader 创建新的 Gist 上传器
func NewGistUploader() *GistUploader {
	if config.GlobalConfig.GithubAPIMirror != "" {
		gistAPIURL = config.GlobalConfig.GithubAPIMirror + "/gists"
	}

	useProxy := utils.GetSysProxy()

	transport := &http.Transport{}
	if useProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &GistUploader{
		client:   client,
		token:    config.GlobalConfig.GithubToken,
		id:       config.GlobalConfig.GithubGistID,
		isPublic: false,
	}
}

// UploadToGist 上传数据到 Gist 的入口函数
func UploadToGist(yamlData []byte, filename string) error {
	uploader := NewGistUploader()
	return uploader.Upload(yamlData, filename)
}

// ValiGistConfig 验证Gist配置
func ValiGistConfig() error {
	if config.GlobalConfig.GithubToken == "" {
		return fmt.Errorf("github token未配置")
	}
	if config.GlobalConfig.GithubGistID == "" {
		return fmt.Errorf("gist id未配置")
	}
	return nil
}

// Upload 执行上传操作
func (g *GistUploader) Upload(yamlData []byte, filename string) error {
	if err := g.validateInput(yamlData, filename); err != nil {
		return err
	}

	payload := GistPayload{
		Description: "Configuration",
		Public:      g.isPublic,
		Files: map[string]GistFile{
			filename: {
				Content: string(yamlData),
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON编码失败: %w", err)
	}

	return g.uploadWithRetry(jsonData, filename)
}

// validateInput 验证输入参数
func (g *GistUploader) validateInput(yamlData []byte, filename string) error {
	if len(yamlData) == 0 {
		return fmt.Errorf("yaml数据为空")
	}
	if filename == "" {
		return fmt.Errorf("文件名不能为空")
	}
	if g.token == "" {
		return fmt.Errorf("github token未配置")
	}
	return nil
}

// uploadWithRetry 带重试机制的上传
func (g *GistUploader) uploadWithRetry(jsonData []byte, filename string) error {
	var lastErr error

	for attempt := 0; attempt < gistMaxRetries; attempt++ {
		if err := g.doUpload(jsonData); err != nil {
			lastErr = err
			slog.Error(fmt.Sprintf("gist上传失败(尝试 %d/%d) %v", attempt+1, gistMaxRetries, err))
			time.Sleep(gistRetryDelay)
			continue
		}
		slog.Info("gist上传成功", "filename", filename)
		return nil
	}

	return fmt.Errorf("gist上传失败，已重试%d次: %w", gistMaxRetries, lastErr)
}

// doUpload 执行单次上传
func (g *GistUploader) doUpload(jsonData []byte) error {
	req, err := g.createRequest(jsonData)
	if err != nil {
		return err
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	return g.checkResponse(resp)
}

// createRequest 创建HTTP请求
func (g *GistUploader) createRequest(jsonData []byte) (*http.Request, error) {
	url := gistAPIURL + "/" + g.id
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	return req, nil
}

// checkResponse 检查响应结果
func (g *GistUploader) checkResponse(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("读取响应失败(状态码: %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("上传失败(状态码: %d): %s", resp.StatusCode, string(body))
	}
	return nil
}
