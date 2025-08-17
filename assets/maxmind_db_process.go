package assets

import (
    "bytes"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "runtime"

    "github.com/beck-8/subs-check/save/method"
    "github.com/klauspost/compress/zstd"
    "github.com/oschwald/maxminddb-golang/v2"
)

// OpenMaxMindDB 使用指定路径或默认路径打开 MaxMind 数据库
func OpenMaxMindDB(dbPath string) (*maxminddb.Reader, error) {
    mmdbPath, err := resolveDBPath(dbPath)
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
func resolveDBPath(dbPath string) (string, error) {
    if dbPath != "" {
        return dbPath, nil
    }

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
