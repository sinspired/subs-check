package platform

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"log/slog"

	"github.com/juju/ratelimit"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/sinspired/subs-check/config"
)

func CheckSpeed(httpClient *http.Client, bucket *ratelimit.Bucket) (int, int64, error) {
	// 创建一个新的测速专用客户端，基于原有客户端的传输层
	speedClient := &http.Client{
		// 设置更长的超时时间用于测速
		Timeout: time.Duration(config.GlobalConfig.DownloadTimeout) * time.Second,
		// 保持原有的传输层配置
		Transport: httpClient.Transport,
	}

	req, err := http.NewRequest("GET", config.GlobalConfig.SpeedTestURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", convert.RandUserAgent())

	resp, err := speedClient.Do(req)
	if err != nil {
		slog.Debug(fmt.Sprintf("测速请求失败: %v", err))
		return 0, 0, err
	}
	defer resp.Body.Close()

	var totalBytes int64
	var limitSize int64
	startTime := time.Now()

	// 下载速度限制
	bucketReader := ratelimit.Reader(resp.Body, bucket)
	// 根据配置决定是否限制下载大小
	if config.GlobalConfig.DownloadMB > 0 {
		limitSize = int64(config.GlobalConfig.DownloadMB) * 1024 * 1024
	} else {
		limitSize = math.MaxInt64
	}
	limitedReader := io.LimitReader(bucketReader, limitSize)
	totalBytes, err = io.Copy(io.Discard, limitedReader)
	if err != nil && totalBytes == 0 {
		slog.Debug(fmt.Sprintf("totalBytes: %d, 读取数据时发生错误: %v", totalBytes, err))
		return 0, 0, err
	}

	// 计算下载时间（毫秒）
	duration := time.Since(startTime).Milliseconds()
	if duration == 0 {
		duration = 1 // 避免除以零
	}

	// 计算速度（KB/s）
	speed := int(float64(totalBytes) / 1024 * 1000 / float64(duration))

	return speed, totalBytes, nil
}
