package assets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"encoding/json"

	"github.com/beck-8/subs-check/config"
	"github.com/beck-8/subs-check/save/method"
	"github.com/beck-8/subs-check/utils"
	"github.com/klauspost/compress/zstd"
	"github.com/oschwald/maxminddb-golang/v2"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// OpenMaxMindDB 使用指定路径或默认路径打开 MaxMind 数据库
func OpenMaxMindDB(dbPath string) (*maxminddb.Reader, error) {
	if dbPath!=""{
		return openDBWithArch(dbPath)
	}
	mmdbPath, err := resolveDBPath()
	if err != nil {
		return nil, err
	}

	// 如果数据库不存在，先解压生成
	if _, err := os.Stat(mmdbPath); os.IsNotExist(err) {
		if err := decompressEmbeddedMMDB(mmdbPath); err != nil {
			return nil, err
		}
	}

	return openDBWithArch(mmdbPath)
}

// 根据 GOARCH 选择合适的打开方式
func openDBWithArch(path string) (*maxminddb.Reader, error) {
	if runtime.GOARCH == "386" {
		return openFromBytes(path)
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("maxmind数据库打开失败: %w", err)
	}
	return db, nil
}

// 解压内置的 MaxMind 数据库到指定路径
func decompressEmbeddedMMDB(targetPath string) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建数据库目录失败: %w", err)
	}

	zstdDecoder, err := zstd.NewReader(nil)
	if err != nil {
		return fmt.Errorf("zstd解码器创建失败: %w", err)
	}
	defer zstdDecoder.Close()

	file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("maxmind数据库文件创建失败: %w", err)
	}
	defer file.Close()

	zstdDecoder.Reset(bytes.NewReader(EmbeddedMaxMindDB))
	if _, err := io.Copy(file, zstdDecoder); err != nil {
		return fmt.Errorf("maxmind数据库文件解压失败: %w", err)
	}

	return nil
}

// 解析数据库存放路径
func resolveDBPath() (string, error) {
	saver, err := method.NewLocalSaver()
	if err != nil {
		return "", err
	}

	if !filepath.IsAbs(saver.OutputPath) {
		saver.OutputPath = filepath.Join(saver.BasePath, saver.OutputPath)
	}

	if err := os.MkdirAll(saver.OutputPath, 0755); err != nil {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("无法获取当前工作目录: %w", err)
		}
		saver.OutputPath = filepath.Join(cwd, "output")
		if err := os.MkdirAll(saver.OutputPath, 0755); err != nil {
			return "", fmt.Errorf("无法创建输出目录: %w", err)
		}
	}

	return filepath.Join(saver.OutputPath, "GeoLite2-Country.mmdb"), nil
}

// 32 位程序使用从内存读取的方式
func openFromBytes(path string) (*maxminddb.Reader, error) {
	runtime.GC() // 释放内存

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件到内存失败: %w", err)
	}

	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("从字节数组创建reader失败: %w", err)
	}
	return reader, nil
}

// UpdateGeoLite2DB 检查并更新 GeoLite2 数据库
func UpdateGeoLite2DB() error {
	dbPath, err := resolveDBPath()
	if err != nil {
		return fmt.Errorf("解析数据库路径失败: %w", err)
	}

	apiURL := "https://api.github.com/repos/mojolabs-id/GeoLite2-Database/releases/latest"

	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取 release 信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API 状态码: %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("解析 release JSON 失败: %w", err)
	}

	var downloadURL string
	for _, asset := range rel.Assets {
		if asset.Name == "GeoLite2-Country.mmdb" {
			downloadURL = config.GlobalConfig.GithubProxy + asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return errors.New("未找到 GeoLite2-Country.mmdb 下载地址")
	}

	// 备份原文件
	bakPath := dbPath + ".bak"
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, bakPath); err != nil {
			return fmt.Errorf("备份原文件失败: %w", err)
		}
	}

	// 下载（重试 3 次）
	success := false
	for i := range 3 {
		if err := downloadFile(downloadURL, dbPath); err != nil {
			fmt.Printf("下载失败 (%d/3): %v\n", i+1, err)
			time.Sleep(1 * time.Second)
			continue
		}
		success = true
		break
	}

	if !success {
		// 回退
		if _, err := os.Stat(bakPath); err == nil {
			_ = os.Rename(bakPath, dbPath)
		}
		return errors.New("下载失败，已回退原文件")
	}

	// 成功则删除备份
	_ = os.Remove(bakPath)
	slog.Info("GeoLite2-Country.mmdb 更新完成")
	version:=rel.TagName
	utils.SendNotify_geoDB_update(version)
	return nil
}

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
