package method

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

// StatsSaver 处理本地文件保存的结构体
type StatsSaver struct {
	BasePath   string
	StatsPath string
}

// NewStatsSaver 创建新的本地保存器
func NewStatsSaver() (*StatsSaver, error) {
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

	statsPath := filepath.Join(outputPath, "stats")
	return &StatsSaver{
		BasePath:   basePath,
		StatsPath: statsPath,
	}, nil
}

// SaveToStats保存配置到本地文件
func SaveToStats(yamlData []byte, filename string) error {
	saver, err := NewStatsSaver()
	if err != nil {
		return fmt.Errorf("创建本地保存器失败: %w", err)
	}

	return saver.Save(yamlData, filename)
}

// Save 执行保存操作
func (ls *StatsSaver) Save(yamlData []byte, filename string) error {
	// 确保输出目录存在
	if err := ls.ensureStatsDir(); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 验证输入参数
	if err := ls.validateInput(yamlData, filename); err != nil {
		return err
	}

	// 构建文件路径并保存
	filepath := filepath.Join(ls.StatsPath, filename)

	if err := os.WriteFile(filepath, yamlData, fileMode); err != nil {
		return fmt.Errorf("写入文件失败 [%s]: %w", filename, err)
	}
	slog.Info("保存订阅统计信息", "filepath", filepath)

	return nil
}

// ensureStatsDir 确保输出目录存在
func (ls *StatsSaver) ensureStatsDir() error {
	if _, err := os.Stat(ls.StatsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(ls.StatsPath, dirMode); err != nil {
			return fmt.Errorf("创建目录失败 [%s]: %w", ls.StatsPath, err)
		}
	}
	return nil
}

// validateInput 验证输入参数
func (ls *StatsSaver) validateInput(yamlData []byte, filename string) error {
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
