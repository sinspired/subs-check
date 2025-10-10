package utils

import (
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// 内部状态跟踪
var ctrlCOccurred atomic.Bool

// SetupSignalHandler 设置信号处理
// 同时支持两种信号处理模式：
// - HUB 信号(SIGHUP): 只设置 check.ForceClose 为 true，不退出程序
// - Ctrl+C 信号(SIGINT/SIGTERM): 第一次设置 ForceClose，第二次退出程序
// SetupSignalHandler 设置信号处理，返回一个退出信号通道
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

			// 如果正在检测中
			if checking.Load() {
				if ctrlCOccurred.CompareAndSwap(false, true) {
					forceClose.Store(true)
					slog.Warn("已发送停止检测信号，正在等待结果收集。再次按 Ctrl+C 将立即退出程序")
					continue
				}
			}

			// 否则（空闲状态，或第二次 Ctrl+C）
			slog.Info("收到退出信号，立即退出程序")
			select {
			case <-stop: // 已经关闭过
			default:
				close(stop) // 通知 app.Run() 退出
			}

			// 保险：5s 后强制退出
			time.AfterFunc(5*time.Second, func() {
				slog.Error("程序未能正常退出，强制终止")
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
