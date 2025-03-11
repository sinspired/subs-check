package checker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/bestruirui/bestsub/config"
	"github.com/bestruirui/bestsub/utils/log"
	"github.com/dlclark/regexp2"
)

func (c *Checker) CheckSpeed() {

	if config.GlobalConfig.Check.SpeedSkipName != "" {
		re := regexp2.MustCompile(config.GlobalConfig.Check.SpeedSkipName, regexp2.None)
		match, err := re.MatchString(c.Proxy.Raw["name"].(string))
		if err != nil {
			log.Debug("check speed skip name failed: %v", err)
			return
		}
		if match {
			c.Proxy.Info.SpeedSkip = true
			log.Debug("check speed skip : %v", c.Proxy.Raw["name"])
			return
		}
	}

	speedClient := &http.Client{
		Timeout:   time.Duration(config.GlobalConfig.Check.DownloadTimeout) * time.Second,
		Transport: c.Proxy.Client.Transport,
	}

	var startTime time.Time
	var resp *http.Response

	for _, url := range config.GlobalConfig.Check.SpeedTestUrl {
		reqCtx, cancel := context.WithTimeout(c.Proxy.Ctx, time.Duration(config.GlobalConfig.Check.Timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			continue
		}

		trace := &httptrace.ClientTrace{
			GotFirstResponseByte: func() {
				startTime = time.Now()
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

		resp, err = speedClient.Do(req)
		if err != nil {
			continue
		}

		var totalBytes int64
		var bytesRead atomic.Int64
		limitedReader := &io.LimitedReader{
			R: resp.Body,
			N: int64(config.GlobalConfig.Check.DownloadSize) * 1024 * 1024,
		}

		copyCtx, copyCancel := context.WithTimeout(c.Proxy.Ctx, time.Duration(config.GlobalConfig.Check.DownloadTimeout)*time.Second)
		defer copyCancel()

		done := make(chan struct{})
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := limitedReader.Read(buf)
				if n > 0 {
					bytesRead.Add(int64(n))
				}
				if err != nil {
					break
				}
			}
			totalBytes = bytesRead.Load()
			close(done)
		}()

		timeoutOccurred := false
		select {
		case <-done:
		case <-copyCtx.Done():
			timeoutOccurred = true
			totalBytes = bytesRead.Load()
			err = copyCtx.Err()
		}

		resp.Body.Close()

		if totalBytes > 0 {
			duration := time.Since(startTime).Milliseconds()
			if duration == 0 {
				duration = 1
			}

			c.Proxy.Info.Speed = int(float64(totalBytes) / 1024 * 1000 / float64(duration))

			if timeoutOccurred {
				log.Debug("Speed test for %v timed out but partial speed calculated: %v KB/s",
					c.Proxy.Raw["name"], c.Proxy.Info.Speed)
			}

			break
		}

		if err != nil {
			continue
		}
	}
}
