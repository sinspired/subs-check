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

var (
	originExePath string                                                    // exe路径,避免linux syscall路径错误
	repo          = selfupdate.NewRepositorySlug("sinspired", "subs-check") // 更新仓库
	arch          = getArch()                                               // 架构映射
	isSysProxy    bool                                                      // 系统代理是否可用
)

// 获取当前架构映射,和GitHub release对应
func getArch() string {
	archMap := map[string]string{
		"amd64": "x86_64",
		"386":   "i386",
		"arm64": "aarch64",
		"arm":   "armv7",
	}
	if mapped, ok := archMap[runtime.GOARCH]; ok {
		return mapped
	}
	return runtime.GOARCH
}

// 创建 GitHub 客户端
func newGitHubClient() (*selfupdate.GitHubSource, error) {
	return selfupdate.NewGitHubSource(
		selfupdate.GitHubConfig{
			// 使用定义的token,避免速率限制
			APIToken: config.GlobalConfig.GithubToken,
		},
	)
}

// 创建 Updater
func newUpdater(client *selfupdate.GitHubSource, checksumFile string, withValidator bool) (*selfupdate.Updater, error) {
	cfg := selfupdate.Config{
		Source: client,
		Arch:   arch,
		// 是否检测与发布版本
		Prerelease: config.GlobalConfig.Prerelease,
	}
	if withValidator {
		// 验证 checksumFile file,适合goreleaser默认创建的验证文件
		cfg.Validator = &selfupdate.ChecksumValidator{UniqueFilename: checksumFile}
	}
	return selfupdate.NewUpdater(cfg)
}

// InitUpdateInfo 检查是否为重启进程
func (app *App) InitUpdateInfo() {
	if os.Getenv("SUBS_CHECK_RESTARTED") == "1" {
		slog.Info("版本更新成功")
		os.Unsetenv("SUBS_CHECK_RESTARTED")
	}
}

// detectSuccessNotify 发送新版本通知
func detectSuccessNotify(currentVersion string, latest *selfupdate.Release) {
	isGUI := os.Getenv("START_FROM_GUI") != ""
	isDockerEnv := isDocker()
	autoUpdate := config.GlobalConfig.EnableSelfUpdate

	// 是否需要提示（任一条件满足）
	needNotify := !autoUpdate || isDockerEnv || isGUI

	if needNotify {
		slog.Warn("发现新版本",
			"当前版本", currentVersion,
			slog.String("最新版本", latest.Version()),
		)
	}

	// 提示用户开启自动更新（仅 CLI 且未开启自动更新）
	if !isGUI && !isDockerEnv && !autoUpdate {
		slog.Info("建议开启更新，在配置文件添加 update: true")
	}

	if needNotify {
		fmt.Println("\033[32m🔎 详情查看: https://github.com/sinspired/subs-check")
		fmt.Println("🔗 手动更新:", latest.AssetURL, "\033[0m")

		var downloadURL string
		switch {
		case isDockerEnv:
			downloadURL = "docker: ghcr.io/sinspired/subs-check:" + latest.Version()
		case isGUI:
			downloadURL = "GUI内核: " + latest.AssetURL
		default:
			downloadURL = latest.AssetURL
		}

		// 发送更新成功通知
		utils.SendNotifyDetectLatestRelease(
			currentVersion,
			latest.Version(),
			isDockerEnv || isGUI,
			downloadURL,
		)
	}
}

// updateSuccess 更新成功处理
func (app *App) updateSuccess(current string, latest string, silentUpdate bool) {
	slog.Info("更新成功，清理进程后重启...")
	app.Shutdown()

	// 发送更新成功通知
	utils.SendNotifySelfUpdate(current, latest)
	if err := restartSelf(silentUpdate); err != nil {
		slog.Error("重启失败", "err", err)
	}
}

// restartSelf 跨平台自启
func restartSelf(silentUpdate bool) error {
	exe := originExePath
	if runtime.GOOS == "windows" {
		if silentUpdate {
			return restartSelfWindowsSilent(exe)
		}
		return restartSelfWindows(exe)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

// Windows 平台重启方案,需要按任意键,能够正常接收ctrl+c信号
func restartSelfWindows(exe string) error {
	args := strings.Join(os.Args[1:], " ")

	// 使用当前窗口并接收ctrl+c信号
	// command := fmt.Sprintf(`ping -n 1 127.0.0.1 >nul && %s %s`, exe, args)

	// 打开新控制台
	command := fmt.Sprintf(`start %s %s`, exe, args)
	cmd := exec.Command("cmd.exe", "/c", command)

	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "SUBS_CHECK_RESTARTED=1")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动重启脚本失败: %w", err)
	}

	slog.Warn("\033[32m🚀 已在新窗口重启...\033[0m")

	os.Exit(0)
	return nil
}

// Windows 平台重启方案,会在当前窗口,但无法接收ctrl+c信号
func restartSelfWindowsSilent(exe string) error {
	args := strings.Join(os.Args[1:], " ")

	cmd := exec.Command(exe, args)

	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "SUBS_CHECK_RESTARTED=1")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动重启脚本失败: %w", err)
	}

	slog.Info("\033[32m🚀 即将重启...\033[0m")

	os.Exit(0)
	return nil
}

// 清理系统代理环境变量
func clearProxyEnv() {
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy"} {
		os.Unsetenv(key)
	}
}

// 单次尝试更新（带超时）
func tryUpdateOnce(parentCtx context.Context, updater *selfupdate.Updater, latest *selfupdate.Release,
	exe string, assetURL, validationURL string, clearProxy bool, label string) error {

	if clearProxy {
		slog.Info("清理系统代理", slog.String("strategy", label))
		clearProxyEnv()
	}

	latest.AssetURL = assetURL
	latest.ValidationAssetURL = validationURL
	slog.Info("正在更新", slog.String("策略", label))

	// 设置下载新版本单个策略超时,如未在配置文件内设置,默认为2分钟
	updateTimeout := 2 * time.Minute
	if config.GlobalConfig.UpdateTimeout > 0 {
		slog.Debug("设置更新超时", slog.Int("分钟", config.GlobalConfig.UpdateTimeout))
		updateTimeout = time.Duration(config.GlobalConfig.UpdateTimeout) * time.Minute
	}

	ctx, cancel := context.WithTimeout(parentCtx, updateTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- updater.UpdateTo(ctx, latest, exe)
	}()

	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("更新超时，切换下一个策略", slog.String("strategy", label))
			return ctx.Err()
		}
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// detectLatestRelease 探测最新版本并判断是否需要更新
func (app *App) detectLatestRelease() (*selfupdate.Release, bool, error) {
	ctx := context.Background()
	client, err := newGitHubClient()
	if err != nil {
		return nil, false, fmt.Errorf("创建 GitHub 客户端失败: %w", err)
	}

	updaterProbe, err := newUpdater(client, "", false)
	if err != nil {
		return nil, false, fmt.Errorf("创建探测用 updater 失败: %w", err)
	}

	// 探测前确保系统代理环境
	isSysProxy = utils.GetSysProxy()
	latest, found, err := updaterProbe.DetectLatest(ctx, repo)
	if err != nil {
		return nil, false, fmt.Errorf("检查更新失败: %w", err)
	}
	if !found {
		return nil, false, nil
	}

	if strings.HasPrefix(app.version, "dev-") {
		slog.Warn("当前为开发/调试版本，不执行自动更新")
		slog.Info("最新版本", slog.String("version", latest.Version()))
		slog.Info("手动更新", slog.String("url", latest.AssetURL))
		return nil, false, nil
	}

	currentVersion := app.originVersion

	curVer, err := semver.NewVersion(currentVersion)
	if err != nil {
		return nil, false, fmt.Errorf("版本号解析失败: %w", err)
	}
	if !latest.GreaterThan(curVer.String()) {
		slog.Info("已是最新版本", slog.String("version", currentVersion))
		return nil, false, nil
	}

	// 发送新版本通知
	detectSuccessNotify(currentVersion, latest)

	return latest, true, nil
}

// CheckUpdateAndRestart 检查并自动更新
func (app *App) CheckUpdateAndRestart(silentUpdate bool) {
	ctx := context.Background()

	latest, needUpdate, err := app.detectLatestRelease()
	if err != nil {
		slog.Error("探测最新版本失败", slog.Any("err", err))
		return
	}
	if !needUpdate || latest == nil {
		return
	}

	checksumFile := fmt.Sprintf("subs-check_%s_checksums.txt", latest.Version())
	client, err := newGitHubClient()
	if err != nil {
		slog.Error("创建 GitHub 客户端失败", slog.Any("err", err))
		return
	}

	updater, err := newUpdater(client, checksumFile, true)
	if err != nil {
		slog.Error("创建 updater 失败", slog.Any("err", err))
		return
	}

	latest, found, err := updater.DetectLatest(ctx, repo)
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

	slog.Warn(fmt.Sprintf("检测到新版本，自动更新重启：%s -> %s", curVer.String(), latest.Version()))

	exe, err := os.Executable()
	if err != nil {
		slog.Error("获取当前可执行文件失败", slog.Any("err", err))
		return
	}
	originExePath = exe

	// 更新策略逻辑
	ghProxyCh := make(chan bool, 1)
	go func() { ghProxyCh <- utils.GetGhProxy() }()

	if isSysProxy {
		// 策略 1：系统代理
		if err := tryUpdateOnce(ctx, updater, latest, exe, latest.AssetURL, latest.ValidationAssetURL, false, "使用系统代理"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
		// 策略 2：GitHub 代理
		var isGhProxy bool
		select {
		case isGhProxy = <-ghProxyCh:
		case <-time.After(10 * time.Second):
			isGhProxy = false
		}
		if isGhProxy {
			ghProxy := config.GlobalConfig.GithubProxy
			if err := tryUpdateOnce(ctx, updater, latest, exe, ghProxy+latest.AssetURL, ghProxy+latest.ValidationAssetURL, true, "使用 GitHub 代理"); err == nil {
				app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
				return
			}
		}
		// 策略 3：原始链接
		if err := tryUpdateOnce(ctx, updater, latest, exe, latest.AssetURL, latest.ValidationAssetURL, true, "使用原始链接"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
	} else {
		// 无系统代理，直接使用 GitHub 代理和原始链接
		// 策略 1：GitHub 代理
		isGhProxy := <-ghProxyCh
		if isGhProxy {
			ghProxy := config.GlobalConfig.GithubProxy
			if err := tryUpdateOnce(ctx, updater, latest, exe, ghProxy+latest.AssetURL, ghProxy+latest.ValidationAssetURL, true, "使用 GitHub 代理"); err == nil {
				app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
				return
			}
		}
		// 策略 2：原始链接
		if err := tryUpdateOnce(ctx, updater, latest, exe, latest.AssetURL, latest.ValidationAssetURL, true, "使用原始链接"); err == nil {
			app.updateSuccess(currentVersion, latest.Version(), silentUpdate)
			return
		}
	}

	slog.Error("更新失败，请稍后重试或手动更新", slog.String("url", latest.AssetURL))
}
