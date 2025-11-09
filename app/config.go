package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sinspired/subs-check/assets"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
	"gopkg.in/yaml.v3"
)

// initConfigPath 初始化配置文件路径
func (app *App) initConfigPath() error {
	if app.configPath == "" {
		execPath := utils.GetExecutablePath()
		configDir := filepath.Join(execPath, "config")

		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("创建配置目录失败: %w", err)
		}

		app.configPath = filepath.Join(configDir, "config.yaml")
	}
	return nil
}

// loadConfig 加载配置文件
func (app *App) loadConfig() error {
	yamlFile, err := os.ReadFile(app.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return app.createDefaultConfig()
		}
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 为避免旧配置残留，反序列化到新的实例，然后替换全局配置
	newConfig := new(config.Config)
	if err := yaml.Unmarshal(yamlFile, newConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	*config.GlobalConfig = *newConfig

	slog.Info("配置文件读取成功")
	return nil
}

// createDefaultConfig 创建默认配置文件
func (app *App) createDefaultConfig() error {
	slog.Info("配置文件不存在，创建默认配置文件")

	if err := os.WriteFile(app.configPath, []byte(config.DefaultConfigTemplate), 0644); err != nil {
		return fmt.Errorf("写入默认配置文件失败: %w", err)
	}

	slog.Info("默认配置文件创建成功")
	slog.Info(fmt.Sprintf("请编辑配置文件: %s", app.configPath))
	os.Exit(0)
	return nil
}

// initConfigWatcher 初始化配置文件监听
func (app *App) initConfigWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建文件监听器失败: %w", err)
	}

	app.watcher = watcher

	// 防抖定时器，防止vscode等软件先临时创建文件在覆盖，会产生两次write事件
	var debounceTimer *time.Timer
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if absPath, _ := filepath.Abs(app.configPath); event.Name != absPath {
					continue
				}
				// 兼容容器外修改
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					// 如果定时器存在，重置它
					if debounceTimer != nil {
						debounceTimer.Stop()
					}

					// 创建新的定时器，延迟100ms执行
					debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
						slog.Info("配置文件发生变化，正在重新加载")
						oldCronExpr := config.GlobalConfig.CronExpression
						oldInterval := app.interval

						oldUpdateSwitcher := config.GlobalConfig.EnableSelfUpdate
						oldCronCheckUpdateExpr := config.GlobalConfig.CronCheckUpdate
						oldSubStorePath := config.GlobalConfig.SubStorePath

						if err := app.loadConfig(); err != nil {
							slog.Error(fmt.Sprintf("重新加载配置文件失败: %v", err))
							return
						}

						if config.GlobalConfig.APIKey == "" {
							if apiKey := os.Getenv("API_KEY"); apiKey != "" {
								config.GlobalConfig.APIKey = apiKey
							} else {
								if initAPIKey != "" {
									config.GlobalConfig.APIKey = GenerateSimpleKey(10)
									slog.Warn("未设置api-key，key，已随机生成", "api-key", config.GlobalConfig.APIKey)
								} else {
									config.GlobalConfig.APIKey = geneAPIKey
									slog.Debug("保留首次运行自动生成的API key", "api-key", config.GlobalConfig.APIKey)
								}
							}
						}

						// 去掉开头斜杠以进行比对
						oldSubStorePath = strings.TrimPrefix(oldSubStorePath, "/")
						config.GlobalConfig.SubStorePath = strings.TrimPrefix(config.GlobalConfig.SubStorePath, "/")

						// 如果sub-store路径变化，重启sub-store服务
						if config.GlobalConfig.SubStorePath == "" {
							if subStorePath := os.Getenv("SUB_STORE_PATH"); subStorePath != "" {
								config.GlobalConfig.SubStorePath = subStorePath
							} else {
								if assets.InitSubStorePath != "" {
									slog.Warn("sub-store路径发生变化，正在重启sub-store服务")
									config.GlobalConfig.SubStorePath = GenerateSimpleKey(20)
									slog.Info("已随机生成", "sub-store-path", config.GlobalConfig.SubStorePath)

									if app.cancel != nil {
										app.cancel()
										app.ctx, app.cancel = context.WithCancel(context.Background())
									}
									assets.RunSubStoreService(app.ctx)
								} else {
									config.GlobalConfig.SubStorePath = assets.InitSubStorePath
									slog.Debug("保留首次运行自动生成的sub-store路径", "sub-store-path", config.GlobalConfig.SubStorePath)
								}
							}
						} else if oldSubStorePath != config.GlobalConfig.SubStorePath {
							slog.Warn("sub-store路径发生变化，正在重启sub-store服务")
							if app.cancel != nil {
								app.cancel()
								app.ctx, app.cancel = context.WithCancel(context.Background())
							}
							assets.RunSubStoreService(app.ctx)
						}

						// 检查cron表达式或检测间隔是否变化
						if oldCronExpr != config.GlobalConfig.CronExpression ||
							oldInterval != config.GlobalConfig.CheckInterval {

							app.interval = func() int {
								if config.GlobalConfig.CheckInterval <= 0 {
									return 1
								}
								return config.GlobalConfig.CheckInterval
							}()
							slog.Warn("检测设置发生变化，重新配置定时器")

							// 使用setTimer方法重新设置定时器
							app.setTimer()
						}

						if oldCronCheckUpdateExpr != config.GlobalConfig.CronCheckUpdate || oldUpdateSwitcher != config.GlobalConfig.EnableSelfUpdate {
							slog.Warn("版本更新设置发生变化，重新设置定时更新任务")
							app.SetupUpdateTasks()
						}
					})
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error(fmt.Sprintf("配置文件监听错误: %v", err))
			}
		}
	}()

	// 开始监听配置文件目录
	if err := watcher.Add(filepath.Dir(app.configPath)); err != nil {
		return fmt.Errorf("添加配置文件监听失败: %w", err)
	}

	slog.Info("配置文件监听已启动")
	return nil
}
