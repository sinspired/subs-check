package method

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

const (
	outputDirName = "output"
	fileMode      = 0644
	dirMode       = 0755
)

// LocalSaver 处理本地文件保存的结构体
type LocalSaver struct {
	BasePath   string
	OutputPath string
}

// NewLocalSaver 创建新的本地保存器
func NewLocalSaver() (*LocalSaver, error) {
	basePath := utils.GetExecutablePath()
	if basePath == "" {
		return nil, fmt.Errorf("获取可执行文件路径失败")
	}

	var outputPath string
	if config.GlobalConfig.OutputDir != "" {
		outputPath = config.GlobalConfig.OutputDir
	} else {
		outputPath = filepath.Join(basePath, outputDirName)
	}

	return &LocalSaver{
		BasePath:   basePath,
		OutputPath: outputPath,
	}, nil
}

// SaveToLocal 保存配置到本地文件
func SaveToLocal(yamlData []byte, filename string) error {
	saver, err := NewLocalSaver()
	if err != nil {
		return fmt.Errorf("创建本地保存器失败: %w", err)
	}

	return saver.Save(yamlData, filename)
}

// Save 执行保存操作
func (ls *LocalSaver) Save(yamlData []byte, filename string) error {
	// 确保输出目录存在
	if err := ls.ensureOutputDir(); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 验证输入参数
	if err := ls.validateInput(yamlData, filename); err != nil {
		return err
	}

	// 构建文件路径并保存
	filepath := filepath.Join(ls.OutputPath, filename)

	if err := os.WriteFile(filepath, yamlData, fileMode); err != nil {
		return fmt.Errorf("写入文件失败 [%s]: %w", filename, err)
	}
	slog.Info("保存本地成功", "filepath", filepath)

	return nil
}

// ensureOutputDir 确保输出目录存在
func (ls *LocalSaver) ensureOutputDir() error {
	if _, err := os.Stat(ls.OutputPath); os.IsNotExist(err) {
		if err := os.MkdirAll(ls.OutputPath, dirMode); err != nil {
			return fmt.Errorf("创建目录失败 [%s]: %w", ls.OutputPath, err)
		}
	}
	return nil
}

// validateInput 验证输入参数
func (ls *LocalSaver) validateInput(yamlData []byte, filename string) error {
	if len(yamlData) == 0 {
		return fmt.Errorf("yaml数据为空")
	}

	if filename == "" {
		return fmt.Errorf("filename不能为空")
	}

	// 检查文件名是否包含非法字符
	if filepath.Base(filename) != filename {
		return fmt.Errorf("filename包含非法字符: %s", filename)
	}

	return nil
}
