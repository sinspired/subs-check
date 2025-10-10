package utils

import (
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

var ctrlCOccurred atomic.Bool

// BeforeExitHook 在 os.Exit 前调用的清理函数
var BeforeExitHook func()
var ShutdownHook func()

func SetupSignalHandler(forceClose *atomic.Bool, checking *atomic.Bool) <-chan struct{} {
	slog.Debug("设置信号处理器")

	stop := make(chan struct{})

	ctrlCSigChan := make(chan os.Signal, 1)
	signal.Notify(ctrlCSigChan, syscall.SIGINT, syscall.SIGTERM)

	hubSigChan := make(chan os.Signal, 1)
	signal.Notify(hubSigChan, syscall.SIGHUP)

	go func() {
		for sig := range ctrlCSigChan {
			slog.Debug("收到中断信号", "sig", sig)

			if checking.Load() {
				if ctrlCOccurred.CompareAndSwap(false, true) {
					forceClose.Store(true)
					slog.Warn("已发送停止检测信号，正在等待结果收集。再次按 Ctrl+C 将立即退出程序")
					continue
				}
			}

			// 立即调用 ShutdownHook
			if ShutdownHook != nil {
				ShutdownHook()
			}
			select {
			case <-stop:
			default:
				close(stop)
			}

			// 保险：5s 后强制退出
			time.AfterFunc(5*time.Second, func() {
				if BeforeExitHook != nil {
					BeforeExitHook() // 调用 app 注册的清理逻辑
				}
				os.Exit(0)
			})
		}
	}()

	go func() {
		for sig := range hubSigChan {
			slog.Info("收到 HUB 信号", "sig", sig)
			forceClose.Store(true)
			slog.Info("HUB 模式: 已设置强制关闭标志，任务将自动结束，程序继续运行")
		}
	}()

	return stop
}
