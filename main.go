//go:generate go-winres make --in winres/winres.json --product-version=git-tag --file-version=git-tag --arch=amd64,386,arm64
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/sinspired/subs-check/app"
)

// 命令行参数
var (
	flagConfigPath = flag.String("f", "", "配置文件路径")
)

func main() {
	// 解析命令行参数
	flag.Parse()

	// 初始化应用
	application := app.New(Version, fmt.Sprintf("%s-%s", Version, CurrentCommit), *flagConfigPath)
	// 版本更新成功通知
	application.InitUpdateInfo()
	slog.Info(fmt.Sprintf("当前版本: %s-%s", Version, CurrentCommit))

	if err := application.Initialize(); err != nil {
		slog.Error(fmt.Sprintf("初始化失败: %v", err))
		os.Exit(1)
	}

	application.Run()
}
