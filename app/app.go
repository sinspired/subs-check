package app

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/robfig/cron/v3"
	"github.com/sinspired/subs-check/app/monitor"
	"github.com/sinspired/subs-check/assets"
	"github.com/sinspired/subs-check/check"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save"
	"github.com/sinspired/subs-check/utils"
)

// App 结构体用于管理应用程序状态
type App struct {
	ctx        context.Context
	cancel     context.CancelFunc
	configPath string
	interval   int
	watcher    *fsnotify.Watcher
	checkChan  chan struct{} // 触发检测的通道
	checking   atomic.Bool   // 检测状态标志
	ticker     *time.Ticker
	done       chan struct{} // 用于结束ticker goroutine的信号
	cron       *cron.Cron    // crontab调度器
	version    string
	originVersion string
	httpServer *http.Server
	stopCh     <-chan struct{}
}

// New 创建新的应用实例
// 注意：不再在这里调用 flag.Parse() 或定义 flags，全部由 main 负责。
func New(originVersion string, version string, configPath string) *App {
	ctx, cancel := context.WithCancel(context.Background())

	return &App{
		ctx:           ctx,
		cancel:        cancel,
		configPath:    configPath,
		checkChan:     make(chan struct{}),
		done:          make(chan struct{}),
		version:       version,
		originVersion: originVersion,
	}
}

// Initialize 初始化应用程序
func (app *App) Initialize() error {
	// 初始化配置文件路径
	if err := app.initConfigPath(); err != nil {
		return fmt.Errorf("初始化配置文件路径失败: %w", err)
	}

	// 加载配置文件
	if err := app.loadConfig(); err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}

	// 初始化配置文件监听
	if err := app.initConfigWatcher(); err != nil {
		return fmt.Errorf("初始化配置文件监听失败: %w", err)
	}

	// 从配置文件中读取代理，设置代理
	if config.GlobalConfig.SystemProxy != "" {
		os.Setenv("HTTP_PROXY", config.GlobalConfig.SystemProxy)
		os.Setenv("HTTPS_PROXY", config.GlobalConfig.SystemProxy)
	}

	app.interval = config.GlobalConfig.CheckInterval

	if config.GlobalConfig.ListenPort != "" {
		if err := app.initHttpServer(); err != nil {
			return fmt.Errorf("初始化HTTP服务器失败: %w", err)
		}
	}

	if config.GlobalConfig.SubStorePort != "" {
		if runtime.GOOS == "linux" && runtime.GOARCH == "386" {
			slog.Warn("node不支持Linux 32位系统，不启动sub-store服务")
		} else {
			// 使用 app.ctx 启动 sub-store，让其可被取消
			go assets.RunSubStoreService(app.ctx)
			// 短暂等待，保证 sub-store 启动日志按预期顺序输出
			time.Sleep(500 * time.Millisecond)
		}
	}

	// 启动内存监控
	monitor.StartMemoryMonitor()

	// 注册退出前清理逻辑（兜底）
	utils.BeforeExitHook = func() {
		NodeAlive, err := assets.FindNode()
		if err == nil && NodeAlive {
			slog.Warn("强制退出前，尝试清理 node 子进程")
			if err := assets.KillNode(); err != nil {
				slog.Error("强制清理 node 失败", "err", err)
			}
			slog.Warn("程序未正常退出，强制停止")
		}
	}

	// 注册 ShutdownHook（第二次 Ctrl+C 立即调用）
	utils.ShutdownHook = func() {
		slog.Warn("立即退出程序")
		app.Shutdown()
	}

	// 设置信号处理器
	app.stopCh = utils.SetupSignalHandler(&check.ForceClose, &app.checking)

	// 每周日 0 点自动更新 GeoLite2 数据库
	weeklyCron := cron.New()
	_, err := weeklyCron.AddFunc("0 0 * * 0", func() {
		slog.Info("更新 GeoLite2 数据库...")
		if err := assets.UpdateGeoLite2DB(); err != nil {
			slog.Error(fmt.Sprintf("更新 GeoLite2 数据库失败: %v", err))
		}
	})
	if err != nil {
		slog.Error(fmt.Sprintf("注册 GeoLite2 数据库更新任务失败: %v", err))
	} else {
		weeklyCron.Start()
	}

	// 检查版本更新
	// TODO: 定时检查更新,接受配置设置
	enableSelfUpdate := config.GlobalConfig.EnableSelfUpdate
	updateOnStartup := config.GlobalConfig.UpdateOnStartup
	cronCheckUpdate := config.GlobalConfig.CronCheckUpdate

	// 是否从GUI发出的调用
	START_FROM_GUI := (os.Getenv("START_FROM_GUI") != "")

	// 是否运行在docker
	isDocker := isDocker()

	// 程序启动时更新
	if !START_FROM_GUI && enableSelfUpdate && updateOnStartup && !isDocker {
		updateDone := make(chan struct{})
		go func() {
			app.CheckUpdateAndRestart()
			close(updateDone)
		}()
		<-updateDone // 等待后台更新完成
	} else {
		// 启动时总是检查版本号,提示手动更新
		detectDone := make(chan struct{})
		go func() {
			app.detectLatestRelease()
			close(detectDone)
		}()
		<-detectDone // 等待后台版本检查完成
	}

	//设置定时更新任务
	updateCron := cron.New()
	if cronCheckUpdate != "" {
		_, err = updateCron.AddFunc(cronCheckUpdate, func() {
			if !START_FROM_GUI && enableSelfUpdate && !app.checking.Load() && !isDocker{
				slog.Info("定时检查版本更新...")
				updateDone := make(chan struct{})
				go func() {
					app.CheckUpdateAndRestart()
					close(updateDone)
				}()
				<-updateDone // 等待后台更新完成
			} else if !app.checking.Load() {
				// 不在检测代理期间,检查版本号,提示手动更新
				detectDone := make(chan struct{})
				go func() {
					app.detectLatestRelease()
					close(detectDone)
				}()
				<-detectDone // 等待后台版本检查完成
			}
		})
		if err != nil {
			slog.Error(fmt.Sprintf("注册 定时检查版本更新 定时任务失败: %v", err))
		} else {
			updateCron.Start()
		}
	} else {
		// 未设置cronCheckUpdate的情况下,给出一个默认值
		// 每周日 0 点自动检查版本更新
		_, err = updateCron.AddFunc("0 0 * * 0", func() {
			if !START_FROM_GUI && enableSelfUpdate && !app.checking.Load() && !isDocker{
				slog.Info("定时检查版本更新...")
				updateDone := make(chan struct{})
				go func() {
					app.CheckUpdateAndRestart()
					close(updateDone)
				}()
				<-updateDone // 等待后台更新完成
			} else if !app.checking.Load() {
				// 不在检测代理期间,检查版本号,提示手动更新
				detectDone := make(chan struct{})
				go func() {
					app.detectLatestRelease()
					close(detectDone)
				}()
				<-detectDone // 等待后台版本检查完成
			}
		})
		if err != nil {
			slog.Error(fmt.Sprintf("注册 定时检查版本更新 定时任务失败: %v", err))
		} else {
			updateCron.Start()
		}
	}

	return nil
}

// Run 运行应用程序主循环
func (app *App) Run() {
	defer func() {
		if app.watcher != nil {
			_ = app.watcher.Close()
		}
		if app.ticker != nil {
			app.ticker.Stop()
		}
		if app.cron != nil {
			app.cron.Stop()
		}
	}()

	app.setTimer()

	if config.GlobalConfig.CronExpression != "" {
		slog.Warn("使用cron表达式，首次启动不立即执行检测")
	} else {
		app.triggerCheck()
	}

	// 并发处理 checkChan
	go func() {
		for range app.checkChan {
			go app.triggerCheck()
		}
	}()

	// 阻塞等待 stopCh 被关闭
	<-app.stopCh
	app.Shutdown()
}

// setTimer 根据配置设置定时器
func (app *App) setTimer() {
	// 停止现有定时器
	if app.ticker != nil {
		// 应该先发送停止信号，防止被=nil后panic
		close(app.done)                // 发送停止信号
		app.done = make(chan struct{}) // 创建新通道
		app.ticker.Stop()
		app.ticker = nil
	}

	// 停止现有cron
	if app.cron != nil {
		app.cron.Stop()
		app.cron = nil
	}

	// 检查是否设置了cron表达式
	if config.GlobalConfig.CronExpression != "" {
		slog.Info(fmt.Sprintf("使用cron表达式: %s", config.GlobalConfig.CronExpression))
		app.cron = cron.New()
		_, err := app.cron.AddFunc(config.GlobalConfig.CronExpression, func() {
			app.triggerCheck()
		})
		if err != nil {
			app.cron.Stop()
			slog.Error(fmt.Sprintf("cron表达式 '%s' 解析失败: %v，将使用检查间隔时间",
				config.GlobalConfig.CronExpression, err))
			// 使用间隔时间
			app.useIntervalTimer()
		} else {
			app.cron.Start()
		}
	} else {
		// 使用间隔时间
		app.useIntervalTimer()
	}
}

// useIntervalTimer 使用间隔时间模式运行
func (app *App) useIntervalTimer() {
	// 初始化定时器
	app.ticker = time.NewTicker(time.Duration(app.interval) * time.Minute)
	done := app.done
	// 启动一个goroutine监听定时器事件
	go func() {
		for {
			select {
			case <-app.ticker.C:
				app.triggerCheck()
			case <-done:
				return // 收到停止信号，退出goroutine
			}
		}
	}()
}

// TriggerCheck 供外部调用的触发检测方法
func (app *App) TriggerCheck() {
	select {
	case app.checkChan <- struct{}{}:
		slog.Info("手动触发检测")
	default:
		slog.Warn("已有检测正在进行，忽略本次触发")
	}
}

// triggerCheck 内部检测方法
func (app *App) triggerCheck() {
	// 如果已经在检测中，直接返回
	if !app.checking.CompareAndSwap(false, true) {
		slog.Warn("已有检测正在进行，跳过本次检测")
		return
	}
	defer app.checking.Store(false)

	if err := app.checkProxies(); err != nil {
		slog.Error(fmt.Sprintf("检测代理失败: %v", err))
		// 不在这里直接退出进程，因为在正常运行中检测失败不应结束程序
	}

	// 检测完成后显示下次检查时间
	if app.ticker != nil {
		// 使用间隔时间模式
		app.ticker.Reset(time.Duration(app.interval) * time.Minute)
		nextCheck := time.Now().Add(time.Duration(app.interval) * time.Minute)
		slog.Info(fmt.Sprintf("下次检查时间: %s", nextCheck.Format("2006-01-02 15:04:05")))
	} else if app.cron != nil {
		// 使用cron模式
		entries := app.cron.Entries()
		if len(entries) > 0 {
			nextTime := entries[0].Next
			slog.Info(fmt.Sprintf("下次检查时间: %s", nextTime.Format("2006-01-02 15:04:05")))
		}
	}
	debug.FreeOSMemory()
}

// checkProxies 执行代理检测
func (app *App) checkProxies() error {
	slog.Info("开始准备检测代理", "进度展示", config.GlobalConfig.PrintProgress)

	results, err := check.Check()
	if err != nil {
		return fmt.Errorf("检测代理失败: %w", err)
	}

	slog.Info("检测完成")
	save.SaveConfig(results)
	utils.SendNotify(len(results))
	utils.UpdateSubs()

	// 执行回调脚本
	utils.ExecuteCallback(len(results))

	return nil
}

// TempLog 返回临时日志路径
func TempLog() string {
	return filepath.Join(os.TempDir(), "subs-check.log")
}

// Shutdown 尝试优雅关闭所有子服务与资源
func (app *App) Shutdown() {
	slog.Debug("开始关闭应用...")

	// 取消上下文，通知各子服务退出（sub-store 等）
	if app.cancel != nil {
		app.cancel()
	}

	// 停止 ticker/cron/watcher（如果存在）
	if app.ticker != nil {
		app.ticker.Stop()
	}
	if app.cron != nil {
		app.cron.Stop()
	}
	if app.watcher != nil {
		_ = app.watcher.Close()
	}

	// 优雅关闭 HTTP 服务
	if app.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := app.httpServer.Shutdown(ctx); err != nil {
			slog.Error("关闭 HTTP 服务器失败", "err", err)
		} else {
			slog.Info("HTTP 服务器关闭", "port", config.GlobalConfig.ListenPort)
		}
	}

	// 关闭 done 通道以通知定时 goroutine 退出（如果仍在）
	select {
	case <-app.done:
		// already closed or receiving
	default:
		// 保护性关闭 done，避免 panic
		close(app.done)
	}

	// 等待短时间，给子 goroutine 清理时间（作为最小可行方案）
	time.Sleep(500 * time.Millisecond)

	// TODO：尝试调用 assets 提供的清理接口
	// 或 WaitGroup 等待所有 goroutine 结束。

	slog.Info("应用已关闭")
	// fmt.Println("")
	// os.Exit(0)
}

// 判断是否运行在 Docker 容器中
func isDocker() bool {
    file, err := os.Open("/proc/1/cgroup")
    if err != nil {
        return false
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") {
            return true
        }
    }
    return false
}