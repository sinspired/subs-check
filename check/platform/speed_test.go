package platform

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juju/ratelimit"
	"github.com/sinspired/subs-check/config"
)

type speedResult struct {
	URL     string
	SpeedKB float64
	Err     error
	Note    string
}

// TestCheckSpeedConcurrently 测试下载链接并输出结果文件
func TestCheckSpeedConcurrently(t *testing.T) {
	// Limit each download to 20MB to keep test quick and cheap
	const limitBytes = int64(20 * 1024 * 1024)

	// Concurrency limiter to avoid spawning 100+ downloads at once
	const maxConcurrent = 32
	sem := make(chan struct{}, maxConcurrent)

	// Align client timeout with config; provide sane default when unset
	tmo := time.Duration(config.GlobalConfig.DownloadTimeout) * time.Second
	if tmo <= 0 {
		tmo = 10 * time.Second
	}
	client := &http.Client{Timeout: tmo}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		list []speedResult
	)

	for _, raw := range SpeedTestURLs {
		url := raw
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				mu.Lock()
				list = append(list, speedResult{URL: url, Err: fmt.Errorf("create request: %w", err)})
				mu.Unlock()
				return
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				list = append(list, speedResult{URL: url, Err: fmt.Errorf("download: %w", err)})
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			// 非 2xx 状态直接判失败，避免读取错误页
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				mu.Lock()
				list = append(list, speedResult{URL: url, Err: fmt.Errorf("http status: %d", resp.StatusCode)})
				mu.Unlock()
				return
			}

			// No rate limit for testing, so use a large bucket
			bucket := ratelimit.NewBucket(time.Second, 1024*1024*1024) // 1GB/s
			bytes, copyErr := io.Copy(io.Discard, io.LimitReader(ratelimit.Reader(resp.Body, bucket), limitBytes))

			d := time.Since(start)
			if d <= 0 {
				d = time.Millisecond
			}
			speedKB := float64(bytes) / d.Seconds() / 1024

			if copyErr != nil {
				// 若命中读取上限（LimitReader），EOF 视为正常
				hitLimit := bytes >= limitBytes
				isTimeout := errors.Is(copyErr, context.DeadlineExceeded)
				if ne, ok := copyErr.(net.Error); ok && ne.Timeout() {
					isTimeout = true
				}
				// 已读取部分数据，且达到配置超时或确认为超时错误 -> 视为预期内，不记错误
				if hitLimit || (bytes > 0 && ((tmo > 0 && d >= tmo) || isTimeout)) {
					err = nil
				} else {
					err = fmt.Errorf("read: %w", copyErr)
				}
			}

			note := ""
			low := strings.ToLower(url)
			if strings.Contains(low, "/latest/") || strings.Contains(low, "-latest") || strings.Contains(low, "current") || strings.Contains(low, "-current") || strings.Contains(low, "-stable") || strings.Contains(low, "/stable/") {
				note = "contains-latest"
			}

			mu.Lock()
			list = append(list, speedResult{URL: url, SpeedKB: speedKB, Err: err, Note: note})
			mu.Unlock()
		}(url)
	}

	wg.Wait()

	// Sort by speed (desc), putting errors at the bottom
	sort.SliceStable(list, func(i, j int) bool {
		if (list[i].Err != nil) != (list[j].Err != nil) {
			// No-error first
			return list[j].Err != nil
		}
		return list[i].SpeedKB > list[j].SpeedKB
	})

	// Print ranked results
	fmt.Println("=== Ranked download speeds (KB/s) ===")
	for idx, r := range list {
		if r.Err == nil {
			fmt.Printf("%3d. %.2f KB/s  %s\n", idx+1, r.SpeedKB, r.URL)
		}
	}

	// Print errors clearly
	fmt.Println("\n=== Errors ===")
	for _, r := range list {
		if r.Err != nil {
			fmt.Printf("ERR: %s\n  -> %v\n", r.URL, r.Err)
		}
	}

	// Print URLs that contain placeholder-like markers
	fmt.Println("\n=== Needs version pinning (contains 'latest/current/stable') ===")
	for _, r := range list {
		if r.Note == "contains-latest" {
			fmt.Printf("PIN?: %s\n", r.URL)
		}
	}

	// Write CSV sorted by speed desc (带时间后缀，写入仓库根目录的 test_output)
	outDir := filepath.Join("test_output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("failed to create test_output dir: %v", err)
	}
	suffix := time.Now().Format("20060102_150405")
	csvPath := filepath.Join(outDir, fmt.Sprintf("speed_results_%s.csv", suffix))
	f, err := os.Create(csvPath)
	if err != nil {
		t.Logf("failed to create CSV: %v", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"rank", "url", "speed_kb_s", "error", "placeholder_flag"})
	rank := 1
	for _, r := range list {
		errStr := ""
		if r.Err != nil {
			errStr = r.Err.Error()
		}
		_ = w.Write([]string{
			fmt.Sprintf("%d", rank),
			r.URL,
			fmt.Sprintf("%.2f", r.SpeedKB),
			errStr,
			r.Note,
		})
		rank++
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Logf("failed to write CSV: %v", err)
	} else {
		fmt.Printf("\nCSV 已生成: %s\n", csvPath)
	}
}

// TestAggregateSpeedResults 聚合 test_output 下的 speed_results*.csv
// 生成三类导出：
// - speed_filter_fast.csv  (Avg >= threshold)
// - speed_filter_slow.csv  (Avg <  threshold)
// - speed_filter_all.csv   (全量并带有 fast/slow 分类)
func TestAggregateSpeedResults(t *testing.T) {
	outDir := filepath.Join("test_output")
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Logf("read dir error: %v", err)
		return
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if filepath.Ext(name) != ".csv" {
			continue
		}
		if name == "speed_results.csv" || (len(name) >= 14 && name[:14] == "speed_results_") {
			files = append(files, filepath.Join(outDir, name))
		}
	}
	if len(files) == 0 {
		t.Log("no speed_results*.csv found, skip aggregation")
		return
	}

	type agg struct {
		URL    string
		Speeds []float64
		Errors int
		Note   string
	}
	ingest := func(m map[string]*agg, path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		r := csv.NewReader(f)
		recs, err := r.ReadAll()
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			return nil
		}
		for i := 1; i < len(recs); i++ {
			rec := recs[i]
			if len(rec) < 5 {
				continue
			}
			url := rec[1]
			sp, _ := strconv.ParseFloat(rec[2], 64)
			errStr := rec[3]
			note := rec[4]
			a := m[url]
			if a == nil {
				a = &agg{URL: url}
				m[url] = a
			}
			if sp > 0 {
				a.Speeds = append(a.Speeds, sp)
			}
			if errStr != "" {
				a.Errors++
			}
			if a.Note == "" && note != "" {
				a.Note = note
			}
		}
		return nil
	}

	m := map[string]*agg{}
	for _, f := range files {
		if err := ingest(m, f); err != nil {
			t.Logf("ingest error: %s %v", f, err)
		}
	}

	type row struct {
		URL    string
		Avg    float64
		Min    float64
		Max    float64
		Count  int
		Errors int
		Note   string
	}
	var rows []row
	for _, a := range m {
		if len(a.Speeds) == 0 {
			continue
		}
		min, max, sum := a.Speeds[0], a.Speeds[0], 0.0
		for _, v := range a.Speeds {
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
			sum += v
		}
		avg := sum / float64(len(a.Speeds))
		rows = append(rows, row{URL: a.URL, Avg: avg, Min: min, Max: max, Count: len(a.Speeds), Errors: a.Errors, Note: a.Note})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Avg > rows[j].Avg })

	writeCSV := func(path string, rows []row, threshold float64, isPrimary bool) {
		f, err := os.Create(path)
		if err != nil {
			t.Logf("create %s: %v", path, err)
			return
		}
		defer f.Close()
		w := csv.NewWriter(f)
		_ = w.Write([]string{"url", "avg_kb_s", "min_kb_s", "max_kb_s", "samples", "errors"})
		for _, r := range rows {
			cond := r.Avg >= threshold
			if cond != isPrimary {
				continue
			}
			_ = w.Write([]string{
				r.URL,
				fmt.Sprintf("%.2f", r.Avg),
				fmt.Sprintf("%.2f", r.Min),
				fmt.Sprintf("%.2f", r.Max),
				fmt.Sprintf("%d", r.Count),
				fmt.Sprintf("%d", r.Errors),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			t.Logf("write %s: %v", path, err)
		}
	}

	writeClassified := func(path string, rows []row, threshold float64) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		_ = w.Write([]string{"url", "avg_kb_s", "min_kb_s", "max_kb_s", "samples", "errors", "category"})
		for _, r := range rows {
			cat := "slow"
			if r.Avg >= threshold {
				cat = "fast"
			}
			_ = w.Write([]string{
				r.URL,
				fmt.Sprintf("%.2f", r.Avg),
				fmt.Sprintf("%.2f", r.Min),
				fmt.Sprintf("%.2f", r.Max),
				fmt.Sprintf("%d", r.Count),
				fmt.Sprintf("%d", r.Errors),
				cat,
			})
		}
		w.Flush()
		return w.Error()
	}

	const threshold = 1024.0 // KB/s
	fastPath := filepath.Join(outDir, "speed_filter_fast.csv")
	slowPath := filepath.Join(outDir, "speed_filter_slow.csv")
	writeCSV(fastPath, rows, threshold, true)
	writeCSV(slowPath, rows, threshold, false)
	if err := writeClassified(filepath.Join(outDir, "speed_filter_all.csv"), rows, threshold); err != nil {
		t.Logf("write classified error: %v", err)
	}

	// 生成被 speed.go 检测并覆盖使用的变量文件：check/platform/speed_var.go
	// 选择策略：
	// - 平均速度 >= threshold（默认 1024 KB/s）
	// - 错误率 < 50%（errors/(errors+samples) < 0.5）
	// - 排除含有 placeholder 标记（contains-latest）
	// - 按平均速度降序
	type sel struct {
		URL    string
		Avg    float64
		Count  int
		Errors int
		Note   string
	}
	var selected []sel
	for _, r := range rows {
		total := r.Count + r.Errors
		if total == 0 {
			continue
		}
		errRate := float64(r.Errors) / float64(total)
		if r.Avg < threshold {
			continue
		}
		if errRate >= 0.5 {
			continue
		}
		if strings.Contains(strings.ToLower(r.Note), "contains-latest") {
			continue
		}
		selected = append(selected, sel{URL: r.URL, Avg: r.Avg, Count: r.Count, Errors: r.Errors, Note: r.Note})
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Avg > selected[j].Avg })

	// 组装 Go 源码
	// 采用直接声明并初始化变量：var fastSpeedTestURLs = []string{...}
	genPath := filepath.Join("speed_var.go")
	if err := os.MkdirAll(filepath.Dir(genPath), 0o755); err != nil {
		t.Logf("mkdir for speed_var.go error: %v", err)
		return
	}
	f, err := os.Create(genPath)
	if err != nil {
		t.Logf("create speed_var.go error: %v", err)
		return
	}
	defer f.Close()
	// 写入文件头（直接声明变量，而不是在 init 中赋值）
	header := fmt.Sprintf(`package platform

// Code generated by TestAggregateSpeedResults at %s; 
// 该文件通过聚合 test_output/speed_results*.csv 生成，用于提供额外精选测速 URL。

var fastSpeedTestURLs = []string{
`, time.Now().Format("2006-01-02 15:04:05"))
	if _, err := f.WriteString(header); err != nil {
		t.Logf("write header error: %v", err)
		return
	}
	for _, s := range selected {
		line := fmt.Sprintf("        \"%s\", // avg: %.2f KB/s, samples: %d, errors: %d\n", s.URL, s.Avg, s.Count, s.Errors)
		if _, err := f.WriteString(line); err != nil {
			t.Logf("write line error: %v", err)
			return
		}
	}
	if _, err := f.WriteString("}\n"); err != nil {
		t.Logf("write tail error: %v", err)
		return
	}
	t.Logf("generated curated list: %s (items=%d)", genPath, len(selected))
}
