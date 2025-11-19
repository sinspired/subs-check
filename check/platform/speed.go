package platform

import (
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

// 使用仅包含平均速度≥1024KB/s的URL列表
func init() {
	if len(fastSpeedTestURLs) > 0 {
		// 使用聚合生成的列表
		testURLs = fastSpeedTestURLs
	}
}

// CheckSpeed 从可用测速链接中随机选取一个进行下载测速
// networkLimitedReader 基于网络层字节计数器的大小限制 reader
type networkLimitedReader struct {
	reader      io.Reader
	getNetBytes func() uint64
	startBytes  uint64
	limit       uint64
}

func (r *networkLimitedReader) Read(p []byte) (n int, err error) {
	if r.getNetBytes != nil && r.limit > 0 {
		current := r.getNetBytes()
		if current < r.startBytes {
			// 如果出现回绕（极少见），重置起始点
			r.startBytes = current
		}
		networkRead := current - r.startBytes
		if networkRead >= r.limit {
			return 0, io.EOF
		}
		remaining := r.limit - networkRead
		if uint64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	return r.reader.Read(p)
}

// CheckSpeed 执行下载测速。为保证统计的是“网络传输层”的真实字节数（含压缩），
// 需要调用方提供 getNetBytes 用于读取底层连接累计的网络读取字节数。
// 返回速度单位为 KB/s，第二个返回值为此次测速期间的网络下载字节数。
func CheckSpeed(httpClient *http.Client, bucket *ratelimit.Bucket, getNetBytes func() uint64) (int, int64, error) {
	testOnceURL := config.GlobalConfig.SpeedTestURL

	if strings.Contains(testOnceURL, "random") && len(testURLs) > 0 {
		testOnceURL = testURLs[rand.Intn(len(testURLs))]
		slog.Debug(fmt.Sprintf("随机选择的测速URL: %s", testOnceURL))
	} else {
		testOnceURL = config.GlobalConfig.SpeedTestURL
		slog.Debug(fmt.Sprintf("使用配置测速URL: %s", testOnceURL))
	}

	// 创建一个新的测速专用客户端，基于原有客户端的传输层
	speedClient := &http.Client{
		// 设置更长的超时时间用于测速
		Timeout: time.Duration(config.GlobalConfig.DownloadTimeout) * time.Second,
		// 保持原有的传输层配置
		Transport: httpClient.Transport,
	}

	req, err := http.NewRequest("GET", testOnceURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", convert.RandUserAgent())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("sec-ch-ua-mobile", "?1")

	resp, err := speedClient.Do(req)
	if err != nil {
		slog.Debug(fmt.Sprintf("测速请求失败: %v", err))
		return 0, 0, err
	}
	defer resp.Body.Close()

	var copiedBytes int64
	// 开始计时
	startTime := time.Now()

	// 在拿到响应（resp）后再采样起始的网络字节计数，避免把握手/连接建立的字节计入下载统计。
	var startNetBytes uint64
	if getNetBytes != nil {
		startNetBytes = getNetBytes()
	}

	// 计算网络层的大小限制（基于配置的 DownloadMB）
	var limitSize uint64
	if config.GlobalConfig.DownloadMB > 0 {
		limitSize = uint64(config.GlobalConfig.DownloadMB) * 1024 * 1024
	} else {
		limitSize = 0 // 0 表示不限制
	}

	// 基于网络字节计数器的 reader：在每次 Read 前会检查网络层已读字节并在超过 limit 时返回 EOF
	limitedReader := &networkLimitedReader{
		reader:      resp.Body,
		getNetBytes: getNetBytes,
		startBytes:  startNetBytes,
		limit:       limitSize,
	}

	copiedBytes, err = io.Copy(io.Discard, limitedReader)
	if err != nil && copiedBytes == 0 {
		slog.Debug(fmt.Sprintf("copiedBytes: %d, 读取数据时发生错误: %v", copiedBytes, err))
		return 0, 0, err
	}

	// 计算下载时间（毫秒）
	duration := time.Since(startTime).Milliseconds()
	if duration == 0 {
		duration = 1 // 避免除以零
	}

	// 使用网络连接层的字节增量作为统计值（含压缩/加密后的真实传输量）
	var totalBytes int64
	if getNetBytes != nil {
		endNetBytes := getNetBytes()
		if endNetBytes >= startNetBytes {
			totalBytes = int64(endNetBytes - startNetBytes)
		} else {
			totalBytes = 0
		}
	} else {
		// 兜底：若未提供网络层统计函数，则退回到应用层统计（可能受解压影响）
		totalBytes = copiedBytes
	}

	// 计算速度（KB/s）
	speed := int(float64(totalBytes) / 1024 * 1000 / float64(duration))

	return speed, totalBytes, nil
}
