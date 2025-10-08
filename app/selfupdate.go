package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/sinspired/go-selfupdate"
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
            APIToken: "", // GitHub Token 提高速率限制
        },
    )
    if err != nil {
        fmt.Println("创建 GitHub 客户端失败:", err)
        return
    }

	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:    githubClient,
		Arch:      arch,
		Validator: &selfupdate.ChecksumValidator{UniqueFilename: "subs-check_1.8.0_checksums.txt"},
	})
	if err != nil {
		fmt.Println("创建 updater 失败:", err)
		return
	}

	repo := selfupdate.NewRepositorySlug("sinspired", "subs-check")
	latest, found, err := updater.DetectLatest(ctx, repo)
	if err != nil {
		fmt.Println("检查更新失败:", err)
		return
	}
	if !found {
		fmt.Println("未找到可用版本")
		return
	}

	// version:=app.version
	test_version := "1.6.6"
    if !latest.GreaterThan(test_version) {
        fmt.Println("当前已是最新版本。")
        return
    }

	fmt.Printf("发现新版本 %s，准备更新...\n", latest.Version())

	exe, err := os.Executable()
	if err != nil {
		fmt.Println("获取当前可执行文件失败:", err)
		return
	}

	// 使用代理加速（如有需要）
	proxyPrefix := "https://hub.885666.xyz/"
	latest.AssetURL = proxyPrefix + latest.AssetURL
	latest.ValidationAssetURL = proxyPrefix + latest.ValidationAssetURL

	if err := updater.UpdateTo(ctx, latest, exe); err != nil {
		fmt.Println("更新失败:", err)
		return
	}

	fmt.Println("更新成功，正在重启...")

	// 重启前关闭应用，确保 watcher/子进程被停止，通知sub-store停止运行
	app.Shutdown()

	// 然后再执行重启（exec 或 spawn + exit）
	if err := restartSelf(); err != nil {
		fmt.Println("重启失败:", err)
	}
}
