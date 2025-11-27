package platform

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"github.com/juju/ratelimit"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/sinspired/subs-check/config"
)

var testURLs []string

func init() {
	if len(fastSpeedTestURLs) > 0 {
		testURLs = fastSpeedTestURLs
	}
}

// networkLimitedReader 基于底层网络流量限制读取
// 当底层传输字节数达到 limit 阈值时，提前返回 EOF
type networkLimitedReader struct {
	reader      io.Reader
	getNetBytes func() uint64 // 获取底层原子计数
	startBytes  uint64        // 初始读数
	limit       uint64        // 限制阈值 (0为不限制)
}

func (r *networkLimitedReader) Read(p []byte) (int, error) {
	if r.limit > 0 && r.getNetBytes != nil {
		curr := r.getNetBytes()

		// 防御性处理：计数器回绕（极罕见）
		if curr < r.startBytes {
			r.startBytes = curr
		}

		// 检查是否超出流量限制
		if (curr - r.startBytes) >= r.limit {
			return 0, io.EOF
		}
	}
	return r.reader.Read(p)
}

// CheckSpeed 执行下载测速
// getNetBytes: 闭包函数，用于获取底层连接的原子计数（避免32位系统对齐问题）
func CheckSpeed(httpClient *http.Client, bucket *ratelimit.Bucket, getNetBytes func() uint64) (int, int64, error) {
	// 1. 确定测速 URL
	url := config.GlobalConfig.SpeedTestURL
	if strings.Contains(url, "random") && len(testURLs) > 0 {
		url = testURLs[rand.Intn(len(testURLs))]
	}
	slog.Debug("测速开始", "URL", url)

	// 2. 构建上下文与请求
	timeout := time.Duration(config.GlobalConfig.DownloadTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, err
	}

	// 伪装浏览器指纹
	req.Header.Set("User-Agent", convert.RandUserAgent())
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	// 3. 发起请求 (复用连接池)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("http status %d", resp.StatusCode)
	}

	// 4. 准备流控读取器
	var startNetBytes uint64
	if getNetBytes != nil {
		startNetBytes = getNetBytes()
	}

	var limit uint64
	if mb := config.GlobalConfig.DownloadMB; mb > 0 {
		limit = uint64(mb) * 1024 * 1024
	}

	reader := &networkLimitedReader{
		reader:      resp.Body,
		getNetBytes: getNetBytes,
		startBytes:  startNetBytes,
		limit:       limit,
	}

	// 5. 执行下载 (计时)
	startTime := time.Now()
	_, err = io.Copy(io.Discard, reader)

	// 过滤正常的中断信号 (EOF, 超时, 取消)
	if err != nil && err != io.EOF && err != context.DeadlineExceeded && err != context.Canceled {
		return 0, 0, err
	}

	// 6. 结算数据
	duration := time.Since(startTime).Seconds()
	if duration < 0.1 {
		duration = 0.1 // 防止除零
	}

	var totalBytes int64
	if getNetBytes != nil {
		curr := getNetBytes()
		if curr >= startNetBytes {
			totalBytes = int64(curr - startNetBytes)
		}
	}

	if totalBytes <= 0 {
		return 0, 0, fmt.Errorf("no bytes transfer")
	}

	// 计算速度 (KB/s)
	speed := int(float64(totalBytes) / 1024.0 / duration)
	return speed, totalBytes, nil
}
