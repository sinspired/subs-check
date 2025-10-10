package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/sinspired/go-selfupdate"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

var originExePath string

// InitUpdateInfo 检查是否为重启进程
func (app *App) InitUpdateInfo() {
	if os.Getenv("SUBS_CHECK_RESTARTED") == "1" {
		slog.Info("版本更新成功")
		// 清理环境变量
		os.Unsetenv("SUBS_CHECK_RESTARTED")
	}
}

// restartSelf 尝试跨平台自启
func restartSelf(silentUpdate bool) error {
	exe := originExePath

	if runtime.GOOS == "windows" {
		return restartSelfWindows(exe)
	}

	// 非 Windows 平台使用 syscall.Exec
	return syscall.Exec(exe, os.Args, os.Environ())
}

// restartSelfWindows Windows 平台重启方案
func restartSelfWindows(exe string) error {
	args := os.Args[1:]

	// 转义参数
	quotedArgs := make([]string, len(args))
	for i, arg := range args {
		// 如果参数包含空格或特殊字符，需要加引号
		if strings.Contains(arg, " ") || strings.Contains(arg, "&") || strings.Contains(arg, "=") {
			quotedArgs[i] = fmt.Sprintf(`"%s"`, arg)
		} else {
			quotedArgs[i] = arg
		}
	}

	command := fmt.Sprintf(`timeout /t 1 /nobreak >nul && %s %s
	`, exe, strings.Join(quotedArgs, " "))

	// 启动批处理,不使用 START 命令，让批处理在当前控制台同步执行
	cmd := exec.Command("cmd.exe", "/c", command)

	// 继承当前控制台
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 继承环境变量
	cmd.Env = os.Environ()
	// 添加重启标记
	cmd.Env = append(cmd.Env, "SUBS_CHECK_RESTARTED=1")

	slog.Info("新版本启动中...请勿关闭窗口！")

	// 启动批处理（它会等待1秒后重启程序）
	if err := cmd.Start(); err != nil {
		// os.Remove(batPath)
		return fmt.Errorf("启动重启脚本失败: %w", err)
	}

	// 立即退出当前进程
	os.Exit(0)
	return nil
}

// 清理系统代理环境变量
func clearProxyEnv() {
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
	} {
		os.Unsetenv(key)
	}
}

// 单次尝试更新（可选择在尝试前清理代理）
func tryUpdateOnce(ctx context.Context, updater *selfupdate.Updater, latest *selfupdate.Release, exe string, assetURL, validationURL string, clearProxy bool, label string) error {
	if clearProxy {
		slog.Info("清理系统代理", slog.String("strategy", label))
		clearProxyEnv()
	}
	latest.AssetURL = assetURL
	latest.ValidationAssetURL = validationURL
	slog.Info("正在更新", slog.String("策略", label))
	return updater.UpdateTo(ctx, latest, exe)
}

func (app *App) updateSuccess(current string, latest string, silentUpdate bool) {
	slog.Info("更新成功，准备重启...")
	app.Shutdown()
	// TODO: 使用通知渠道发送通知
	if err := restartSelf(silentUpdate); err != nil {
		slog.Error("重启失败", "err", err)
	}
}

// CheckUpdateAndRestart 检查更新并在需要时重启
func (app *App) CheckUpdateAndRestart(silentUpdate bool) {
	ctx := context.Background()

	archMap := map[string]string{
		"amd64": "x86_64",
		"386":   "i386",
		"arm64": "aarch64",
		"arm":   "armv7",
	}
	arch, ok := archMap[runtime.GOARCH]
	if !ok {
		arch = runtime.GOARCH
	}

	githubClient, err := selfupdate.NewGitHubSource(
		selfupdate.GitHubConfig{
			APIToken: config.GlobalConfig.GithubToken,
		},
	)
	if err != nil {
		slog.Error("创建 GitHub 客户端失败", slog.Any("err", err))
		return
	}

	repo := selfupdate.NewRepositorySlug("sinspired", "subs-check")

	// 先检测系统代理
	slog.Info("更新代理环境")
	isSysProxy := utils.GetSysProxy()

	// 并发检测 GitHub Proxy
	ghProxyCh := make(chan bool, 1)
	go func() {
		ghProxyCh <- utils.GetGhProxy()
	}()

	// 第一次探测
	updaterProbe, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:     githubClient,
		Arch:       arch,
		Prerelease: true, // 调试时允许预发布版本
	})
	if err != nil {
		slog.Error("创建探测用 updater 失败", slog.Any("err", err))
		return
	}

	latest, found, err := updaterProbe.DetectLatest(ctx, repo)
	if err != nil {
		slog.Error("检查更新失败", slog.Any("err", err))
		return
	}
	if !found {
		slog.Debug("未找到可用版本")
		return
	}

	// 拼接 checksum 文件名
	checksumFile := fmt.Sprintf("subs-check_%s_checksums.txt", latest.Version())

	// 创建带校验器的 updater
	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:     githubClient,
		Arch:       arch,
		Validator:  &selfupdate.ChecksumValidator{UniqueFilename: checksumFile},
		Prerelease: true, // 调试时允许预发布版本
	})
	if err != nil {
		slog.Error("创建 updater 失败", slog.Any("err", err))
		return
	}

	latest, found, err = updater.DetectLatest(ctx, repo)
	if err != nil {
		slog.Error("检查更新失败", slog.Any("err", err))
		return
	}
	if !found {
		slog.Debug("未找到可用版本")
		return
	}

	// 开发版逻辑：不更新，只提示
	if strings.HasPrefix(app.version, "dev") {
		slog.Warn("当前为开发/调试版本，不执行自动更新")
		slog.Info("最新版本", slog.String("version", latest.Version()))
		slog.Info("手动更新", slog.String("url", latest.AssetURL))
		return
	}

	currentVersion := app.originVersion

	// 正式版逻辑：严格 semver 比较
	curVer, err := semver.NewVersion(currentVersion)
	if err != nil {
		slog.Error("版本号解析失败", slog.String("version", currentVersion), slog.Any("err", err))
		return
	}
	if !latest.GreaterThan(curVer.String()) {
		slog.Info("已是最新版本", slog.String("version", currentVersion))
		return
	}

	slog.Info("准备更新", slog.String("当前版本", curVer.String()), slog.String("最新版本", latest.Version()))

	exe, err := os.Executable()
	if err != nil {
		slog.Error("获取当前可执行文件失败", slog.Any("err", err))
		return
	}

	// 避免linux系统重启路径错误
	originExePath = exe

	// 策略分支
	if isSysProxy {
		// 立即尝试系统代理
		if err := tryUpdateOnce(ctx, updater, latest, exe,
			latest.AssetURL, latest.ValidationAssetURL, false, "使用系统代理"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
		// 等待 GitHub Proxy 结果（最多 10 秒）
		var isGhProxy bool
		select {
		case isGhProxy = <-ghProxyCh:
		case <-time.After(10 * time.Second):
			isGhProxy = false
		}
		if isGhProxy {
			ghProxy := config.GlobalConfig.GithubProxy
			proxyAsset := ghProxy + latest.AssetURL
			proxyValidation := ghProxy + latest.ValidationAssetURL
			if err := tryUpdateOnce(ctx, updater, latest, exe, proxyAsset, proxyValidation, true, "使用 GitHub 代理"); err == nil {
				app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
				return
			}
		}
		// 最后兜底
		if err := tryUpdateOnce(ctx, updater, latest, exe, latest.AssetURL, latest.ValidationAssetURL, true, "原始链接兜底"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
	} else {
		// 系统代理不可用 → 等 GitHub Proxy
		isGhProxy := <-ghProxyCh
		if isGhProxy {
			ghProxy := config.GlobalConfig.GithubProxy
			proxyAsset := ghProxy + latest.AssetURL
			proxyValidation := ghProxy + latest.ValidationAssetURL
			if err := tryUpdateOnce(ctx, updater, latest, exe, proxyAsset, proxyValidation, true, "使用 GitHub 代理"); err == nil {
				app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
				return
			}
		}
		// 兜底
		if err := tryUpdateOnce(ctx, updater, latest, exe, latest.AssetURL, latest.ValidationAssetURL, true, "原始链接兜底"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
	}

	slog.Error("更新失败，请稍后重试或手动更新", slog.String("url", latest.AssetURL))
}
