package assets

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"gopkg.in/natefinch/lumberjack.v2"
)

var InitSubStorePath = ""

type subStorePaths struct {
	substoreDir  string
	nodePath     string
	jsPath       string
	frontDir     string
	overYamlPath string
	logPath      string
}

// getSubStorePaths 获取 sub-store 相关路径
func getSubStorePaths() (*subStorePaths, error) {
	saver, err := method.NewLocalSaver()
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(saver.OutputPath) {
		// 处理用户写相对路径的问题
		saver.OutputPath = filepath.Join(saver.BasePath, saver.OutputPath)
	}

	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName += ".exe"
	}

	substoreDir := filepath.Join(saver.OutputPath, "sub-store")

	return &subStorePaths{
		substoreDir:  substoreDir,
		nodePath:     filepath.Join(substoreDir, nodeName),
		jsPath:       filepath.Join(substoreDir, "sub-store.bundle.js"),
		frontDir:     filepath.Join(substoreDir, "frontend"),
		overYamlPath: filepath.Join(saver.OutputPath, "ACL4SSR_Online_Full.yaml"),
		logPath:      filepath.Join(substoreDir, "sub-store.log"),
	}, nil
}

// RunSubStoreService 运行sub-store服务，支持 ctx，可被外部取消
func RunSubStoreService(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			slog.Info("Sub-store 服务已停止", "port", config.GlobalConfig.SubStorePort)
			return
		default:
			if err := startSubStore(ctx); err != nil {
				slog.Error("Sub-store 服务崩溃, 正在重启...", "error", err)
			}
			// 在循环间隙检查 ctx，若被取消则退出
			select {
			case <-ctx.Done():
				slog.Info("Sub-store 服务已停止", "port", config.GlobalConfig.SubStorePort)
				return
			case <-time.After(time.Second * 30):
				// 继续重启循环
			}
		}
	}
}

// migrateOldFiles 迁移旧文件
func migrateOldFiles(srcDir, fileName, targetDir string) error {
	src := filepath.Join(srcDir, fileName)
	dst := filepath.Join(targetDir, fileName)

	// 目标已存在 -> 不做任何操作
	if _, err := os.Stat(dst); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查目标文件失败: %w", err)
	}

	// 源不存在 -> 不做任何操作
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("检查源文件失败: %w", err)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("读取源文件失败: %w", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("写入目标文件失败: %w", err)
	}
	return nil
}

func killNodeProcess(nodePath string) {
	pid, err := findProcesses(nodePath)
	if err == nil {
		err := killProcess(pid)
		if err != nil {
			slog.Debug("Sub-store service kill failed", "error", err)
		}
		slog.Debug("Sub-store service already killed", "pid", pid)
	}
}

func startSubStore(ctx context.Context) error {
	paths, err := getSubStorePaths()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(paths.substoreDir), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.MkdirAll(paths.substoreDir, 0755); err != nil {
		return fmt.Errorf("创建sub-store目录失败: %w", err)
	}

	// 迁移sub-store配置
	if err := migrateOldFiles(filepath.Dir(paths.substoreDir), "sub-store.json", paths.substoreDir); err != nil {
		slog.Error("迁移sub-store配置失败")
	}

	// 在函数结束前确保尝试杀掉 node
	defer killNodeProcess(paths.nodePath)

	// 如果subs-check内存问题退出，会导致node二进制损坏，启动的node变成僵尸，所以删一遍
	_ = os.Remove(paths.nodePath)
	_ = os.Remove(paths.jsPath)
	_ = os.Remove(paths.overYamlPath)
	_ = os.RemoveAll(paths.frontDir)
	if err := decodeZstd(paths.nodePath, paths.jsPath, paths.overYamlPath, paths.frontDir); err != nil {
		return err
	}

	// 配置日志轮转
	logWriter := &lumberjack.Logger{
		Filename:   paths.logPath,
		MaxSize:    10, // 每个日志文件最大 10MB
		MaxBackups: 3,  // 保留 3 个旧文件
		MaxAge:     14,  // 保留 7 天
	}
	defer logWriter.Close()

	nodePath := paths.nodePath
	jsPath := paths.jsPath
	// 支持自定义node二进制文件路径，可兼容更多的设备
	if nodeBinPath := os.Getenv("NODEBIN_PATH"); nodeBinPath != "" {
		nodePath = nodeBinPath
	}
	// 支持自定义sub-store脚本路径
	if subStoreBinPath := os.Getenv("SUB_STORE_PATH"); subStoreBinPath != "" {
		jsPath = subStoreBinPath
	}

	// 构建命令
	cmd := exec.Command(nodePath, jsPath)
	// js会在运行目录释放依赖文件
	cmd.Dir = paths.substoreDir
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter

	// 检查MihomoOverwriteUrl是否包含本地IP，如果是则移除代理环境变量
	cleanProxyEnv := false
	if config.GlobalConfig.MihomoOverwriteURL != "" {
		parsedURL, err := url.Parse(config.GlobalConfig.MihomoOverwriteURL)
		if err == nil {
			host := parsedURL.Hostname()
			if isLocalIP(host) {
				cleanProxyEnv = true
				slog.Debug("MihomoOverwriteUrl contains local IP, removing proxy environment variables")
			}
		}
	}

	// ipv4/ipv6 都支持
	hostPort := strings.Split(config.GlobalConfig.SubStorePort, ":")
	// host可以为空，port不能为空
	if len(hostPort) == 2 && hostPort[1] != "" {
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("SUB_STORE_BACKEND_API_HOST=%s", hostPort[0]),
			fmt.Sprintf("SUB_STORE_BACKEND_API_PORT=%s", hostPort[1]),
		)
	} else if len(hostPort) == 1 {
		cmd.Env = append(os.Environ(), fmt.Sprintf("SUB_STORE_BACKEND_API_PORT=%s", hostPort[0])) // 设置端口
	} else {
		return fmt.Errorf("sub-store-port invalid port format: %s", config.GlobalConfig.SubStorePort)
	}

	// 如果MihomoOverwriteUrl包含本地IP，则移除所有代理环境变量
	if cleanProxyEnv {
		filteredEnv := make([]string, 0, len(cmd.Env))
		proxyVars := []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}

		for _, env := range cmd.Env {
			isProxyVar := false
			for _, proxyVar := range proxyVars {
				if strings.HasPrefix(strings.ToLower(env), strings.ToLower(proxyVar)+"=") {
					isProxyVar = true
					break
				}
			}
			if !isProxyVar {
				filteredEnv = append(filteredEnv, env)
			}
		}
		cmd.Env = filteredEnv
	}

	// 增加body限制，默认1M
	cmd.Env = append(cmd.Env, "SUB_STORE_BODY_JSON_LIMIT=30mb")

	InitSubStorePath = config.GlobalConfig.SubStorePath
	// 增加自定义访问路径
	if config.GlobalConfig.SubStorePath != "" {
		// 如果不是以 "/" 开头，则补上
		if !strings.HasPrefix(config.GlobalConfig.SubStorePath, "/") {
			config.GlobalConfig.SubStorePath = "/" + config.GlobalConfig.SubStorePath
		}
	} else {
		// 生成一个随机的 SubStorePath
		config.GlobalConfig.SubStorePath = "/" + generateRandomString(20)
		slog.Info("已随机生成", "sub-store-path", config.GlobalConfig.SubStorePath)
	}

	// TODO: 集成http-meta服务
	// 设置后端path
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SUB_STORE_FRONTEND_BACKEND_PATH=%s", config.GlobalConfig.SubStorePath),
	)

	// 集成sub-store前端并启用合并功能
	cmd.Env = append(cmd.Env, "SUB_STORE_BACKEND_MERGE=true")
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SUB_STORE_FRONTEND_PATH=%s", paths.frontDir),
	)

	// sub-store 环境变量: 后端上传文件至 gist
	if config.GlobalConfig.SubStoreSyncCron != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SUB_STORE_BACKEND_SYNC_CRON=%s", config.GlobalConfig.SubStoreSyncCron))
	}

	// sub-store 环境变量: 自动拉取订阅内容
	if config.GlobalConfig.SubStoreProduceCron != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SUB_STORE_PRODUCE_CRON=%s", config.GlobalConfig.SubStoreProduceCron))
	}

	// sub-store 环境变量: 当遇到错误时发送通知
	if config.GlobalConfig.SubStorePushService != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SUB_STORE_PUSH_SERVICE=%s", config.GlobalConfig.SubStorePushService))
	}

	// 启动子进程并监听 ctx 取消以便优雅杀掉子进程
	done := make(chan struct{})
	defer close(done)

	// 让子进程独立进程组，避免收到 Ctrl+C，在app中负责接收信号关闭sub-store
	setSysProcAttr(cmd) // 跨平台设置

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 sub-store 失败: %w", err)
	}

	slog.Info("Sub-store 服务已启动", "pid", cmd.Process.Pid, "port", config.GlobalConfig.SubStorePort, "log", paths.logPath)

	// ctx 取消时尝试杀掉子进程
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				err := cmd.Process.Kill()
				if err != nil {
					slog.Error("杀掉 node 进程失败", "error", err)
				} else {
					slog.Info("node 进程已终结", "pid", cmd.Process.Pid)
				}
			}
		case <-done:
			// 正常结束，不需要操作
		}
	}()

	// 等待程序结束（或被上面的 goroutine 杀掉）
	err = cmd.Wait()
	if err != nil {
		// 如果 ctx 已取消，视为优雅退出
		select {
		case <-ctx.Done():
			return nil
		default:
			return err
		}
	}
	return nil
}

// isLocalIP 检查IP是否是本地IP（127.0.0.1或局域网IP）
func isLocalIP(host string) bool {
	// 检查是否是localhost或127.0.0.1
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.Contains(host, ".local") {
		return true
	}

	// 检查IP是否有效
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// 检查是否是私有IP范围
	privateIPBlocks := []string{
		"10.0.0.0/8",     // 10.0.0.0 - 10.255.255.255
		"172.16.0.0/12",  // 172.16.0.0 - 172.31.255.255
		"192.168.0.0/16", // 192.168.0.0 - 192.168.255.255
		"169.254.0.0/16", // 169.254.0.0 - 169.254.255.255
		"fd00::/8",       // fd00:: - fdff:ffff...
	}

	for _, block := range privateIPBlocks {
		_, ipNet, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func decodeZstd(nodePath, jsPath, overYamlPath, frontDir string) error {
	// 创建 zstd 解码器
	zstdDecoder, err := zstd.NewReader(nil)
	if err != nil {
		return fmt.Errorf("创建zstd解码器失败: %w", err)
	}
	defer zstdDecoder.Close()

	// 解压 node 二进制文件
	nodeFile, err := os.OpenFile(nodePath, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("创建 node 文件失败: %w", err)
	}
	defer nodeFile.Close()

	zstdDecoder.Reset(bytes.NewReader(EmbeddedNode))
	if _, err := io.Copy(nodeFile, zstdDecoder); err != nil {
		return fmt.Errorf("解压 node 二进制文件失败: %w", err)
	}

	// 解压 sub-store 后端脚本
	jsFile, err := os.OpenFile(jsPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("创建 sub-store 脚本文件失败: %w", err)
	}
	defer jsFile.Close()

	zstdDecoder.Reset(bytes.NewReader(EmbeddedSubStoreBackend))
	if _, err := io.Copy(jsFile, zstdDecoder); err != nil {
		return fmt.Errorf("解压 sub-store 脚本失败: %w", err)
	}

	// 解压 sub-store 前端文件夹
	zstdDecoder.Reset(bytes.NewReader(EmbeddedSubStoreFrotend))
	tarReader := tar.NewReader(zstdDecoder)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取tar头失败: %w", err)
		}

		// 移除 tar 文件中的顶层目录
		parts := strings.Split(header.Name, "/")
		if len(parts) <= 1 {
			continue // 跳过顶层目录本身或空条目
		}
		relativePath := strings.Join(parts[1:], "/")
		if relativePath == "" {
			continue
		}
		target := filepath.Join(frontDir, relativePath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("创建父目录失败: %w", err)
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("创建文件失败: %w", err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("写入文件失败: %w", err)
			}
			outFile.Close()
		}
	}

	// 解压 覆写文件
	overYamlFile, err := os.OpenFile(overYamlPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("创建 ACL4SSR_Online_Full.yaml 文件失败: %w", err)
	}
	defer overYamlFile.Close()

	zstdDecoder.Reset(bytes.NewReader(EmbeddedOverrideYaml))
	if _, err := io.Copy(overYamlFile, zstdDecoder); err != nil {
		return fmt.Errorf("解压 ACL4SSR_Online_Full.yaml 失败: %w", err)
	}
	return nil
}

func findProcesses(targetName string) (int32, error) {
	processes, err := process.Processes()
	if err != nil {
		return 0, fmt.Errorf("获取进程列表失败: %v", err)
	}

	for _, p := range processes {
		name, err := p.Exe()
		if err == nil && name == targetName {
			return p.Pid, nil
		}
	}
	return 0, fmt.Errorf("未找到进程")
}

func killProcess(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return fmt.Errorf("无法找到进程 %d: %v", pid, err)
	}

	if err := p.Kill(); err != nil {
		return fmt.Errorf("杀死进程 %d 失败: %v", pid, err)
	}
	return nil
}

// FindNode 查找 Node 进程是否存在
func FindNode() (bool, error) {
	paths, err := getSubStorePaths()
	if err != nil {
		return false, err
	}
	pid, err := findProcesses(paths.nodePath)
	if err == nil && pid > 0 {
		return true, nil
	}
	return false, nil
}

// KillNode 杀掉 Node 进程
func KillNode() error {
	paths, err := getSubStorePaths()
	if err != nil {
		return err
	}
	pid, err := findProcesses(paths.nodePath)
	if err != nil {
		// 没找到进程，不算错误
		return nil
	}
	if err := killProcess(pid); err != nil {
		slog.Debug("Sub-store service kill failed", "error", err)
		return err
	}
	slog.Debug("Sub-store service killed", "pid", pid)
	return nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
