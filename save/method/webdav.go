package method

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"log/slog"

	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

var (
	webdavMaxRetries = 3
	webdavRetryDelay = 2 * time.Second
)

// WebDAVUploader 处理 WebDAV 上传的结构体
type WebDAVUploader struct {
	client   *http.Client
	baseURL  string
	username string
	password string
}

// NewWebDAVUploader 创建新的 WebDAV 上传器
func NewWebDAVUploader() *WebDAVUploader {
	useProxy := utils.GetSysProxy()

	transport := &http.Transport{}
	if useProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &WebDAVUploader{
		client:   client,
		baseURL:  config.GlobalConfig.WebDAVURL,
		username: config.GlobalConfig.WebDAVUsername,
		password: config.GlobalConfig.WebDAVPassword,
	}
}

// UploadToWebDAV 上传数据到 WebDAV 的入口函数
func UploadToWebDAV(yamlData []byte, filename string) error {
	uploader := NewWebDAVUploader()
	return uploader.Upload(yamlData, filename)
}

// ValiWebDAVConfig 验证WebDAV配置
func ValiWebDAVConfig() error {
	if config.GlobalConfig.WebDAVURL == "" {
		return fmt.Errorf("webdav URL未配置")
	}
	if config.GlobalConfig.WebDAVUsername == "" {
		return fmt.Errorf("webdav 用户名未配置")
	}
	if config.GlobalConfig.WebDAVPassword == "" {
		return fmt.Errorf("webdav 密码未配置")
	}
	return nil
}

// Upload 执行上传操作
func (w *WebDAVUploader) Upload(yamlData []byte, filename string) error {
	if err := w.validateInput(yamlData, filename); err != nil {
		return err
	}

	return w.uploadWithRetry(yamlData, filename)
}

// validateInput 验证输入参数
func (w *WebDAVUploader) validateInput(yamlData []byte, filename string) error {
	if len(yamlData) == 0 {
		return fmt.Errorf("yaml数据为空")
	}
	if filename == "" {
		return fmt.Errorf("文件名不能为空")
	}
	if w.baseURL == "" {
		return fmt.Errorf("webdav URL未配置")
	}
	return nil
}

// uploadWithRetry 带重试机制的上传
func (w *WebDAVUploader) uploadWithRetry(yamlData []byte, filename string) error {
	var lastErr error

	for attempt := 0; attempt < webdavMaxRetries; attempt++ {
		if err := w.doUpload(yamlData, filename); err != nil {
			lastErr = err
			slog.Error(fmt.Sprintf("webdav上传失败(尝试 %d/%d) %v", attempt+1, webdavMaxRetries, err))
			time.Sleep(webdavRetryDelay)
			continue
		}
		slog.Info("webdav上传成功", "filename", filename)
		return nil
	}

	return fmt.Errorf("webdav上传失败，已重试%d次: %w", webdavMaxRetries, lastErr)
}

// doUpload 执行单次上传
func (w *WebDAVUploader) doUpload(yamlData []byte, filename string) error {
	req, err := w.createRequest(yamlData, filename)
	if err != nil {
		return err
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	return w.checkResponse(resp)
}

// createRequest 创建HTTP请求
func (w *WebDAVUploader) createRequest(yamlData []byte, filename string) (*http.Request, error) {
	baseURL := w.baseURL
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	url := baseURL + filename

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(yamlData))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.SetBasicAuth(w.username, w.password)
	req.Header.Set("Content-Type", "application/x-yaml")
	return req, nil
}

// checkResponse 检查响应结果
func (w *WebDAVUploader) checkResponse(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("读取响应失败(状态码: %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("上传失败(状态码: %d): %s", resp.StatusCode, string(body))
	}
	return nil
}
