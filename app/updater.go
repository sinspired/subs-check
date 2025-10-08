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

	"github.com/Masterminds/semver/v3"
	"github.com/sinspired/go-selfupdate"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/utils"
)

// restartSelf 跨平台重启
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Env = os.Environ()

		// 关键：用 Run() 而不是 Start()
		if err := cmd.Run(); err != nil {
			return err
		}
		os.Exit(0)
	}

	// Unix-like 系统用 Exec 原地替换（前提：调用者已做清理）
	return syscall.Exec(exe, os.Args, os.Environ())
}

// 清理系统代理环境变量
func clearProxyEnv() {
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
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
	slog.Info("更新中", slog.String("策略", label))
	return updater.UpdateTo(ctx, latest, exe)
}

// CheckUpdateAndRestart 检查更新并在需要时重启
func (app *App) CheckUpdateAndRestart() {
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
	isSysProxy := utils.GetSysProxy()

	// 并发检测 GitHub Proxy
	ghProxyCh := make(chan bool, 1)
	go func() {
		ghProxyCh <- utils.GetGhProxy()
	}()

	// 第一次探测
	updaterProbe, err := selfupdate.NewUpdater(selfupdate.Config{
		Source: githubClient,
		Arch:   arch,
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
		Source:    githubClient,
		Arch:      arch,
		Validator: &selfupdate.ChecksumValidator{UniqueFilename: checksumFile},
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

	// 比较版本
	// currentVersion := app.version
	// TODO: 调试时后使用正式变量
	testVersion := "1.7.0"
	currentVersion := testVersion

	// 开发版逻辑：不更新，只提示
	if strings.HasPrefix(currentVersion, "dev-") {
		slog.Warn("当前为开发/调试版本，不执行自动更新")
		slog.Info("最新版本", slog.String("version", latest.Version()))
		slog.Info("手动更新", slog.String("url", latest.AssetURL))
		return
	}

	// 正式版逻辑：严格 semver 比较
	curVer, err := semver.NewVersion(currentVersion)
	if err != nil {
		slog.Error("版本号解析失败", slog.String("version", currentVersion), slog.Any("err", err))
		return
	}
	if !latest.GreaterThan(curVer.String()) {
		slog.Info("当前已是最新版本", slog.String("version", currentVersion))
		return
	}

	slog.Info("准备更新", slog.String("当前版本", curVer.String()), slog.String("最新版本", latest.Version()))

	exe, err := os.Executable()
	if err != nil {
		slog.Error("获取当前可执行文件失败", slog.Any("err", err))
		return
	}

	isGhProxy := utils.GetGhProxy()
	ghProxy := config.GlobalConfig.GithubProxy

	// 构造策略队列（注意：清理代理只在失败后下一次尝试前执行）
	type strategy struct {
		assetURL      string
		validationURL string
		clearProxy    bool
		label         string
	}
	var strategies []strategy

	origAsset := latest.AssetURL
	origValidation := latest.ValidationAssetURL
	proxyAsset := ghProxy + latest.AssetURL
	proxyValidation := ghProxy + latest.ValidationAssetURL

	if isSysProxy {
		// 1) 系统代理存在：先用原始链接（保留代理）
		strategies = append(strategies, strategy{
			assetURL: origAsset, validationURL: origValidation,
			clearProxy: false, label: "使用系统代理更新",
		})
		// 2) 失败后：清理代理再尝试 GitHub 代理（如有）
		if isGhProxy {
			strategies = append(strategies, strategy{
				assetURL: proxyAsset, validationURL: proxyValidation,
				clearProxy: true, label: "使用 GitHub 代理更新",
			})
		}
		// 3) 再失败：清理后使用原始链接兜底
		strategies = append(strategies, strategy{
			assetURL: origAsset, validationURL: origValidation,
			clearProxy: true, label: "使用原始链接兜底",
		})
	} else {
		// 无系统代理：优先 GitHub 代理（如有），否则原始链接
		if isGhProxy {
			strategies = append(strategies, strategy{
				assetURL: proxyAsset, validationURL: proxyValidation,
				clearProxy: false, label: "使用 GitHub 代理更新",
			})
		}
		strategies = append(strategies, strategy{
			assetURL: origAsset, validationURL: origValidation,
			clearProxy: false, label: "使用原始链接兜底",
		})
	}

	// 执行策略队列
	for i, s := range strategies {
		err := tryUpdateOnce(ctx, updater, latest, exe, s.assetURL, s.validationURL, s.clearProxy, s.label)
		if err != nil {
			slog.Debug("策略更新失败", slog.Int("index", i), slog.String("strategy", s.label), slog.Any("err", err))
			continue
		}
		slog.Info("更新成功，正在重启...")
		app.Shutdown()
		if err := restartSelf(); err != nil {
			slog.Error("重启失败", slog.Any("err", err))
		}
		return
	}

	slog.Error("更新失败,请稍后重试或手动更新", slog.String("url", latest.AssetURL))
}
