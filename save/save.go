// Package save 保存检测结果
package save

import (
	"fmt"
	proxyutils "github.com/sinspired/subs-check/proxy"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/sinspired/subs-check/check"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"github.com/sinspired/subs-check/utils"
)

// ProxyCategory 定义代理分类
type ProxyCategory struct {
	Name    string
	Proxies []map[string]any
	Filter  func(result check.Result) bool
}

// ConfigSaver 处理配置保存的结构体
type ConfigSaver struct {
	results    []check.Result
	categories []ProxyCategory
	saveMethod func([]byte, string) error
}

// NewConfigSaver 创建新的配置保存器
func NewConfigSaver(results []check.Result) *ConfigSaver {
	return &ConfigSaver{
		results:    results,
		saveMethod: chooseSaveMethod(),
		categories: []ProxyCategory{
			{
				Name:    "all.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result check.Result) bool { return true },
			},
			{
				Name:    "mihomo.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result check.Result) bool { return true },
			},
			{
				Name:    "base64.txt",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result check.Result) bool { return true },
			},
			{
				Name:    "history.yaml", // 新增
				Proxies: make([]map[string]any, 0),
				Filter:  func(result check.Result) bool { return true }, // 这里可加条件
			},
		},
	}
}

// SaveConfig 保存配置的入口函数
func SaveConfig(results []check.Result) {
	tmp := config.GlobalConfig.SaveMethod
	config.GlobalConfig.SaveMethod = "local"
	// 奇技淫巧，保存到本地一份，因为我没想道其他更好的方法同时保存
	{
		saver := NewConfigSaver(results)
		if err := saver.Save(); err != nil {
			slog.Error(fmt.Sprintf("保存配置失败: %v", err))
		}
	}

	if tmp == "local" {
		return
	}
	config.GlobalConfig.SaveMethod = tmp
	// 如果其他配置验证失败，还会保存到本地一次
	{
		saver := NewConfigSaver(results)
		if err := saver.Save(); err != nil {
			slog.Error(fmt.Sprintf("保存配置失败: %v", err))
		}
	}
}

// Save 执行保存操作
func (cs *ConfigSaver) Save() error {
	// 分类处理代理
	cs.categorizeProxies()

	// 保存各个类别的代理
	for _, category := range cs.categories {
		if err := cs.saveCategory(category); err != nil {
			slog.Error(fmt.Sprintf("保存到%s失败: %v", config.GlobalConfig.SaveMethod, err))
			continue
		}
	}

	return nil
}

// categorizeProxies 将代理按类别分类
func (cs *ConfigSaver) categorizeProxies() {
	for _, result := range cs.results {
		for i := range cs.categories {
			if cs.categories[i].Filter(result) {
				cs.categories[i].Proxies = append(cs.categories[i].Proxies, result.Proxy)
			}
		}
	}
}

// saveCategory 保存单个类别的代理
func (cs *ConfigSaver) saveCategory(category ProxyCategory) error {
	if len(category.Proxies) == 0 {
		slog.Warn(fmt.Sprintf("yaml节点为空，跳过保存: %s, saveMethod: %s", category.Name, config.GlobalConfig.SaveMethod))
		return nil
	}
	if category.Name == "history.yaml" {
		saver, err := method.NewLocalSaver()
		if err != nil {
			return fmt.Errorf("本地存储初始化失败，无法启用历史记录功能: %w", err)
		}
		if !filepath.IsAbs(saver.OutputPath) {
			// 处理用户写相对路径的问题
			saver.OutputPath = filepath.Join(saver.BasePath, saver.OutputPath)
		}

		// 读取已有文件
		existing := make([]map[string]any, 0)

		outputPath := saver.OutputPath
		filepath := filepath.Join(outputPath, category.Name)
		// 读取原有历史记录
		data, err := ReadFileIfExists(filepath)
		if err == nil && len(data) > 0 {
			var parsed map[string][]map[string]any
			if err := yaml.Unmarshal(data, &parsed); err == nil {
				existing = parsed["proxies"]
			}
		}

		// 合并去重
		merged := mergeUniqueProxies(existing, category.Proxies)

		// 序列化
		yamlData, err := yaml.Marshal(map[string]any{
			"proxies": merged,
		})
		if err != nil {
			return fmt.Errorf("序列化yaml %s 失败: %w", category.Name, err)
		}

		// 保存（这里直接覆盖写入，因为 merged 已经包含旧数据，相当于逻辑上的“追加”）
		if err := cs.saveMethod(yamlData, category.Name); err != nil {
			return fmt.Errorf("保存 %s 失败: %w", category.Name, err)
		}
		return nil
	}
	if category.Name == "all.yaml" {
		yamlData, err := yaml.Marshal(map[string]any{
			"proxies": category.Proxies,
		})
		if err != nil {
			return fmt.Errorf("序列化yaml %s 失败: %w", category.Name, err)
		}
		if err := cs.saveMethod(yamlData, category.Name); err != nil {
			return fmt.Errorf("保存 %s 失败: %w", category.Name, err)
		}
		// 只在 all.yaml 和 local时，更新substore
		if config.GlobalConfig.SaveMethod == "local" && config.GlobalConfig.SubStorePort != "" {
			utils.UpdateSubStore(yamlData)
		}
		return nil
	}
	if category.Name == "mihomo.yaml" && config.GlobalConfig.SubStorePort != "" {
		resp, err := http.Get(fmt.Sprintf("%s/api/file/%s", utils.BaseURL, utils.MihomoName))
		if err != nil {
			return fmt.Errorf("获取mihomo file请求失败: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("读取mihomo file失败: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("获取mihomo file失败, 状态码: %d, 错误信息: %s", resp.StatusCode, body)
		}
		if err := cs.saveMethod(body, category.Name); err != nil {
			return fmt.Errorf("保存 %s 失败: %w", category.Name, err)
		}
		return nil
	}
	if category.Name == "base64.txt" && config.GlobalConfig.SubStorePort != "" {
		// http://127.0.0.1:8299/download/sub?target=V2Ray
		resp, err := http.Get(fmt.Sprintf("%s/download/%s?target=V2Ray", utils.BaseURL, utils.SubName))
		if err != nil {
			return fmt.Errorf("获取base64.txt请求失败: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("读取base64.txt失败: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("获取base64.txt失败，状态码: %d, 错误信息: %s", resp.StatusCode, body)
		}
		if err := cs.saveMethod(body, category.Name); err != nil {
			return fmt.Errorf("保存 %s 失败: %w", category.Name, err)
		}
		return nil
	}

	return nil
}

// chooseSaveMethod 根据配置选择保存方法
func chooseSaveMethod() func([]byte, string) error {
	switch config.GlobalConfig.SaveMethod {
	case "r2":
		if err := method.ValiR2Config(); err != nil {
			return func(b []byte, s string) error { return fmt.Errorf("r2配置不完整: %v", err) }
		}
		uploader := method.NewR2Uploader()

		return func(yamlData []byte, filename string) error {
			return uploader.Upload(yamlData, filename)
		}
	case "gist":
		if err := method.ValiGistConfig(); err != nil {
			return func(b []byte, s string) error { return fmt.Errorf("gist配置不完整: %v", err) }
		}
		uploader := method.NewGistUploader()

		return func(yamlData []byte, filename string) error {
			return uploader.Upload(yamlData, filename)
		}
	case "webdav":
		if err := method.ValiWebDAVConfig(); err != nil {
			return func(b []byte, s string) error { return fmt.Errorf("webDAV配置不完整: %v", err) }
		}
		// 创建单例 uploader，避免多次调用 NewWebDAVUploader() 和 utils.GetSysProxy()
		uploader := method.NewWebDAVUploader()
		return func(yamlData []byte, filename string) error {
			return uploader.Upload(yamlData, filename)
		}
	case "local":
		return method.SaveToLocal
	case "s3": // New case for MinIO
		if err := method.ValiS3Config(); err != nil {
			return func(b []byte, s string) error { return fmt.Errorf("S3配置不完整: %v", err) }
		}
		return method.UploadToS3
	default:
		return func(b []byte, s string) error {
			return fmt.Errorf("未知的保存方法或其他方法配置错误: %v", config.GlobalConfig.SaveMethod)
		}
	}
}

func mergeUniqueProxies(existing, newProxies []map[string]any) []map[string]any {
	seen := make(map[string]bool)
	result := make([]map[string]any, 0, len(existing)+len(newProxies))

	// 先加旧的
	for _, p := range existing {
		delete(p, "sub_was_succeed")  // 删除旧的标记
		delete(p, "sub_from_history") // 删除旧的标记
		key := proxyutils.GenerateProxyKey(p)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	// 再加新的
	for _, p := range newProxies {
		delete(p, "sub_was_succeed")  // 删除旧的标记
		delete(p, "sub_from_history") // 删除旧的标记
		key := proxyutils.GenerateProxyKey(p)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result
}

func ReadFileIfExists(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return os.ReadFile(path)
}
