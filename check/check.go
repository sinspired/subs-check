package check

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beck-8/subs-check/assets"
	"github.com/beck-8/subs-check/check/platform"
	"github.com/beck-8/subs-check/config"
	proxyutils "github.com/beck-8/subs-check/proxy"
	"github.com/juju/ratelimit"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Result 存储节点检测结果
type Result struct {
	Proxy          map[string]any
	Openai         bool
	OpenaiWeb      bool
	X              bool
	Youtube        string
	Netflix        bool
	Google         bool
	Cloudflare     bool
	Disney         bool
	Gemini         bool
	TikTok         string
	IP             string
	IPRisk         string
	Country        string
	CountryCodeTag string
}

// ProxyChecker 处理代理检测的主要结构体
type ProxyChecker struct {
	results     []Result
	proxyCount  int
	threadCount int
	progress    int32
	available   int32
	resultChan  chan Result
	tasks       chan map[string]any
}

var Progress atomic.Uint32
var Available atomic.Uint32
var ProxyCount atomic.Uint32
var TotalBytes atomic.Uint64

var ForceClose atomic.Bool

var Bucket *ratelimit.Bucket

// 上下文与取消函数，更精确控制并发程序
var ctx context.Context
var cancel context.CancelFunc

// NewProxyChecker 创建新的检测器实例
func NewProxyChecker(proxyCount int) *ProxyChecker {
	threadCount := config.GlobalConfig.Concurrent
	if proxyCount < threadCount {
		threadCount = proxyCount
	}

	ProxyCount.Store(uint32(proxyCount))
	return &ProxyChecker{
		results:     make([]Result, 0),
		proxyCount:  proxyCount,
		threadCount: threadCount,
		resultChan:  make(chan Result),
		tasks:       make(chan map[string]any, 1),
	}
}

// Check 执行代理检测的主函数
func Check() ([]Result, error) {
	proxyutils.ResetRenameCounter()
	ForceClose.Store(false)

	ProxyCount.Store(0)
	Available.Store(0)
	Progress.Store(0)

	TotalBytes.Store(0)

	// 之前好的节点前置
	var proxies []map[string]any
	if config.GlobalConfig.KeepSuccessProxies {
		slog.Info(fmt.Sprintf("添加之前测试成功的节点，数量: %d", len(config.GlobalProxies)))
		proxies = append(proxies, config.GlobalProxies...)
	}
	tmp, err := proxyutils.GetProxies()
	if err != nil {
		return nil, fmt.Errorf("获取节点失败: %w", err)
	}
	proxies = append(proxies, tmp...)
	slog.Info(fmt.Sprintf("获取节点数量: %d", len(proxies)))

	// 重置全局节点
	config.GlobalProxies = make([]map[string]any, 0)

	proxies = proxyutils.DeduplicateProxies(proxies) // 收集订阅节点阶段: 已优化内存
	slog.Info(fmt.Sprintf("去重后节点数量: %d", len(proxies)))

	// 随机乱序并根据 server 字段打乱节点顺序, 减少测速直接测死的概率
	cfg := proxyutils.ShuffleConfig{
		Threshold:  float64(config.GlobalConfig.Threshold), // CIDR/24 相同, 避免在一组(0.5: CIDR/16)
		Passes:     3,                                      // 改善轮数（1~3）
		MinSpacing: config.GlobalConfig.Concurrent * 2,     // CIDR/24 相同, 设置最小间隔为 并发数*2
		ScanLimit:  config.GlobalConfig.Concurrent * 2,     // 冲突向前扫描的最大距离
	}

	// 前500个不乱序,避免之前成功的节点被打散
	if len(proxies) > 500 {
		head := proxies[:500]
		tail := proxies[500:]

		// 仅对 tail 做乱序/智能打散
		proxyutils.SmartShuffleByServer(tail, cfg)

		proxies = append(proxies[:0], append(head, tail...)...)
	}

	cidr := proxyutils.ThresholdToCIDR(cfg.Threshold)
	slog.Info(fmt.Sprintf(
		"节点乱序, 相同 CIDR%s 范围 IP 的最小间距: %d",
		cidr, cfg.MinSpacing,
	))

	checker := NewProxyChecker(len(proxies))
	return checker.run(proxies)
}

// Run 运行检测流程
func (pc *ProxyChecker) run(proxies []map[string]any) ([]Result, error) {
	if config.GlobalConfig.TotalSpeedLimit != 0 {
		Bucket = ratelimit.NewBucketWithRate(float64(config.GlobalConfig.TotalSpeedLimit*1024*1024), int64(config.GlobalConfig.TotalSpeedLimit*1024*1024/10))
	} else {
		Bucket = ratelimit.NewBucketWithRate(float64(math.MaxInt64), int64(math.MaxInt64))
	}
	// 初始化上下文
	ctx, cancel = context.WithCancel(context.Background())

	// 并发进程外加载 MaxMind 数据库,避免频繁打开
	var geoDB *maxminddb.Reader
	var err error

	// 如果 MaxMindDBPath 为空会自动使用 subs-check 内置数据库
	geoDB, err = assets.OpenMaxMindDB(config.GlobalConfig.MaxMindDBPath)

	if err != nil {
		slog.Debug(fmt.Sprintf("打开 MaxMind 数据库失败: %v", err))
		geoDB = nil
	}

	// 确保数据库在函数结束时关闭
	if geoDB != nil {
		defer func() {
			if err := geoDB.Close(); err != nil {
				slog.Debug(fmt.Sprintf("关闭 MaxMind 数据库失败: %v", err))
			}
		}()
	}

	slog.Info("开始检测节点")
	slog.Info("当前参数", "timeout", config.GlobalConfig.Timeout, "concurrent", config.GlobalConfig.Concurrent, "enable-speedtest", config.GlobalConfig.SpeedTestUrl != "", "min-speed", config.GlobalConfig.MinSpeed, "download-timeout", config.GlobalConfig.DownloadTimeout, "download-mb", config.GlobalConfig.DownloadMB, "total-speed-limit", config.GlobalConfig.TotalSpeedLimit, "drop-bad-cf-nodes", config.GlobalConfig.DropBadCfNodes)

	done := make(chan bool)
	if config.GlobalConfig.PrintProgress {
		go pc.showProgress(done)
	}
	var wg sync.WaitGroup
	// 启动工作线程
	for i := 0; i < pc.threadCount; i++ {
		wg.Add(1)
		go pc.worker(&wg, geoDB)
	}

	// 发送任务
	go pc.distributeProxies(proxies)
	slog.Debug(fmt.Sprintf("发送任务: %d", len(proxies)))

	// 收集结果 - 添加一个 WaitGroup 来等待结果收集完成
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		pc.collectResults()
		collectWg.Done()
	}()

	wg.Wait()
	close(pc.resultChan)

	// 等待结果收集完成
	collectWg.Wait()
	// 等待进度条显示完成
	time.Sleep(100 * time.Millisecond)

	if config.GlobalConfig.PrintProgress {
		done <- true
	}

	if config.GlobalConfig.SuccessLimit > 0 && pc.available >= config.GlobalConfig.SuccessLimit {
		slog.Warn(fmt.Sprintf("达到节点数量限制: %d", config.GlobalConfig.SuccessLimit))
	}
	slog.Info(fmt.Sprintf("可用节点数量: %d", len(pc.results)))
	slog.Info(fmt.Sprintf("测试总消耗流量: %.3fGB", float64(TotalBytes.Load())/1024/1024/1024))

	// 检查订阅成功率并发出警告
	pc.checkSubscriptionSuccessRate(proxies)

	return pc.results, nil
}

// worker 处理单个代理检测的工作线程
func (pc *ProxyChecker) worker(wg *sync.WaitGroup, db *maxminddb.Reader) {
	defer wg.Done()
	for proxy := range pc.tasks {
		// 检查是否达到成功限制，如果达到则跳过当前任务
		if config.GlobalConfig.SuccessLimit > 0 && atomic.LoadInt32(&pc.available) >= config.GlobalConfig.SuccessLimit {
			pc.incrementProgress()
			cancel()
			continue
		}

		if result := pc.checkProxy(proxy, db); result != nil {
			pc.resultChan <- *result
		}
		pc.incrementProgress()
	}
}

// ctx 检查函数，接受停止信号
func checkCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// checkProxy 检测单个代理
func (pc *ProxyChecker) checkProxy(proxy map[string]any, db *maxminddb.Reader) *Result {
	res := &Result{
		Proxy: proxy,
	}
	// 快速取消点
	if checkCtxDone(ctx) {
		return nil
	}

	if os.Getenv("SUB_CHECK_SKIP") != "" {
		// slog.Debug(fmt.Sprintf("跳过检测代理: %v", proxy["name"]))
		return res
	}

	httpClient := CreateClient(proxy)
	if httpClient == nil {
		slog.Debug(fmt.Sprintf("创建代理Client失败: %v", proxy["name"]))
		return nil
	}
	defer httpClient.Close()

	gstatic, err := platform.CheckGstatic(httpClient.Client)
	if err != nil || !gstatic {
		slog.Debug(fmt.Sprintf("无法访问Gstatic: %v", proxy["name"]))
		return nil
	}

	google, err := platform.CheckGoogle(httpClient.Client)
	if err != nil || !google {
		return nil
	}
	// 检查 cloudflare 是否可访问前取消
	if checkCtxDone(ctx) {
		return nil
	}

	var isCfAccessible bool
	var cfLoc, cfIP string

	if config.GlobalConfig.DropBadCfNodes {
		if isCfAccessible, cfLoc, cfIP = platform.CheckCloudflare(httpClient.Client); !isCfAccessible {
			// 节点可用，但无法访问cloudflare，说明是未正确设置proxyip的cf节点
			slog.Debug(fmt.Sprintf("%v 无法访问Cloudflare, 已丢弃", proxy["name"]))
			return nil
		}
	}
	// 速度测试 前取消检查
	if checkCtxDone(ctx) {
		return nil
	}

	var speed int
	if config.GlobalConfig.SpeedTestUrl != "" {
		speed, _, err = platform.CheckSpeed(httpClient.Client, Bucket)
		if err != nil || speed < config.GlobalConfig.MinSpeed {
			return nil
		}
	}
	// MediaCheck 前取消检查。已经开始 MediaCheck 的任务等待其完成
	if checkCtxDone(ctx) {
		return nil
	}

	if config.GlobalConfig.MediaCheck {
		if cfLoc == "" && cfIP == "" {
			isCfAccessible, cfLoc, cfIP = platform.CheckCloudflare(httpClient.Client)
		}
		// 遍历需要检测的平台
		for _, plat := range config.GlobalConfig.Platforms {
			if isCfAccessible {
				// 只在能访问 cloudflare 时检测 openAI 和 X,因为都使用了 Cloudflare 的 CDN
				switch plat {
				case "x":
					// 由于 x 并不限制国家,理论上只要能访问 cloudflare 就能访问 x
					// 也许有更准确的方案?
					res.X = true
				case "openai":
					cookiesOK, clientOK := platform.CheckOpenAI(httpClient.Client)
					if clientOK && cookiesOK {
						res.Openai = true
					} else if cookiesOK || clientOK {
						res.OpenaiWeb = true
					}
				}
			}

			switch plat {
			case "youtube":
				if region, _ := platform.CheckYoutube(httpClient.Client); region != "" {
					res.Youtube = region
				}
			case "netflix":
				if ok, _ := platform.CheckNetflix(httpClient.Client); ok {
					res.Netflix = true
				}
			case "disney":
				if ok, _ := platform.CheckDisney(httpClient.Client); ok {
					res.Disney = true
				}
			case "gemini":
				if ok, _ := platform.CheckGemini(httpClient.Client); ok {
					res.Gemini = true
				}
			case "tiktok":
				if region, _ := platform.CheckTikTok(httpClient.Client); region != "" {
					res.TikTok = region
				}
			case "iprisk":
				country, ip, countryCode_tag, _ := proxyutils.GetProxyCountry(httpClient.Client, db, ctx, cfLoc, cfIP)
				if ip == "" {
					break
				}

				res.IP = ip
				res.Country = country
				res.CountryCodeTag = countryCode_tag

				risk, err := platform.CheckIPRisk(httpClient.Client, ip)
				if err == nil {
					res.IPRisk = risk
				} else {
					// 失败的可能性高，所以放上日志
					slog.Debug(fmt.Sprintf("查询IP风险失败: %v", err))
				}
			}
		}
	}
	// 更新代理名称
	pc.updateProxyName(res, httpClient, speed, db, cfLoc, cfIP)
	pc.incrementAvailable()
	return res
}

// updateProxyName 更新代理名称
func (pc *ProxyChecker) updateProxyName(res *Result, httpClient *ProxyClient, speed int, db *maxminddb.Reader, cfLoc string, cfIP string) {
	// 以节点IP查询位置重命名节点
	if config.GlobalConfig.RenameNode {
		if res.Country != "" {
			res.Proxy["name"] = config.GlobalConfig.NodePrefix + proxyutils.Rename(res.Country, res.CountryCodeTag)
		} else {
			country, _, countryCode_tag, _ := proxyutils.GetProxyCountry(httpClient.Client, db, ctx, cfLoc, cfIP)
			res.Proxy["name"] = config.GlobalConfig.NodePrefix + proxyutils.Rename(country, countryCode_tag)
		}
	}

	name := res.Proxy["name"].(string)
	name = strings.TrimSpace(name)

	var tags []string
	// 获取速度
	if config.GlobalConfig.SpeedTestUrl != "" {
		name = regexp.MustCompile(`\s*\|(?:\s*[\d.]+[KM]B/s)`).ReplaceAllString(name, "")
		var speedStr string
		if speed < 1024 {
			speedStr = fmt.Sprintf("%dKB/s", speed)
		} else {
			speedStr = fmt.Sprintf("%.1fMB/s", float64(speed)/1024)
		}
		tags = append(tags, speedStr)
	}

	if config.GlobalConfig.MediaCheck {
		// 移除已有的标记（IPRisk和平台标记）
		name = regexp.MustCompile(`\s*\|(?:NF|D\+|X|GPT⁺|GPT|GM|YT-[^|]+|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
	}

	// 按用户输入顺序定义
	for _, plat := range config.GlobalConfig.Platforms {
		switch plat {
		case "openai":
			if res.Openai {
				tags = append(tags, "GPT⁺")
			} else if res.OpenaiWeb {
				tags = append(tags, "GPT")
			}
		case "x":
			if res.X {
				tags = append(tags, "X")
			}
		case "netflix":
			if res.Netflix {
				tags = append(tags, "NF")
			}
		case "disney":
			if res.Disney {
				tags = append(tags, "D+")
			}
		case "gemini":
			if res.Gemini {
				tags = append(tags, "GM")
			}
		case "iprisk":
			if res.IPRisk != "" {
				tags = append(tags, res.IPRisk)
			}
		case "youtube":
			if res.Youtube != "" {
				// TODO: 位置准确之后，除了CN之外，似乎没必要加后缀了
				tags = append(tags, fmt.Sprintf("YT-%s", res.Youtube))
			}
		case "tiktok":
			if res.TikTok != "" {
				tags = append(tags, fmt.Sprintf("TK-%s", res.TikTok))
			}
		}
	}

	if tag, ok := res.Proxy["sub_tag"].(string); ok && tag != "" {
		tags = append(tags, tag)
	}

	// 将所有标记添加到名称中
	if len(tags) > 0 {
		name += "|" + strings.Join(tags, "|")
	}

	res.Proxy["name"] = name

}

// showProgress 显示进度条
func (pc *ProxyChecker) showProgress(done chan bool) {
	for {
		select {
		case <-done:
			fmt.Println()
			return
		default:
			current := atomic.LoadInt32(&pc.progress)
			available := atomic.LoadInt32(&pc.available)

			if pc.proxyCount == 0 {
				time.Sleep(100 * time.Millisecond)
				break
			}

			// if 0/0 = NaN ,shoule panic
			percent := float64(current) / float64(pc.proxyCount) * 100
			fmt.Printf("\r进度: [%-45s] %.1f%% (%d/%d) 可用: %d",
				strings.Repeat("=", int(percent/2))+">",
				percent,
				current,
				pc.proxyCount,
				available)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// 辅助方法
func (pc *ProxyChecker) incrementProgress() {
	atomic.AddInt32(&pc.progress, 1)
	Progress.Add(1)
}

func (pc *ProxyChecker) incrementAvailable() {
	atomic.AddInt32(&pc.available, 1)
	Available.Add(1)
}

// distributeProxies 分发代理任务
func (pc *ProxyChecker) distributeProxies(proxies []map[string]any) {
	for _, proxy := range proxies {
		if config.GlobalConfig.SuccessLimit > 0 && atomic.LoadInt32(&pc.available) >= config.GlobalConfig.SuccessLimit {
			slog.Debug("达到成功节点数量限制，停止派发新任务")
			cancel()
			break
		}
		if ForceClose.Load() {
			slog.Warn("收到强制关闭信号，停止派发任务")
			cancel()
			break
		}
		pc.tasks <- proxy
	}
	// 发送任务结束，进行一次内存回收
	for i := range proxies {
		proxies[i] = nil // 移除 map 引用
	}
	proxies = nil // 移除切片引用

	close(pc.tasks)
}

// collectResults 收集检测结果
func (pc *ProxyChecker) collectResults() {
	for result := range pc.resultChan {
		pc.results = append(pc.results, result)
	}
}

// checkSubscriptionSuccessRate 检查订阅成功率并发出警告
func (pc *ProxyChecker) checkSubscriptionSuccessRate(allProxies []map[string]any) {
	// 统计每个订阅的节点总数和成功数
	subStats := make(map[string]struct {
		total   int
		success int
	})

	// 统计所有节点的订阅来源
	for _, proxy := range allProxies {
		if subUrl, ok := proxy["sub_url"].(string); ok {
			stats := subStats[subUrl]
			stats.total++
			subStats[subUrl] = stats
		}
	}

	// 统计成功节点的订阅来源
	for _, result := range pc.results {
		if result.Proxy != nil {
			if subUrl, ok := result.Proxy["sub_url"].(string); ok {
				stats := subStats[subUrl]
				stats.success++
				subStats[subUrl] = stats
			}
			delete(result.Proxy, "sub_url")
			delete(result.Proxy, "sub_tag")
		}
	}

	// 检查成功率并发出警告
	for subUrl, stats := range subStats {
		if stats.total > 0 {
			successRate := float32(stats.success) / float32(stats.total)

			// 如果成功率低于x，发出警告
			if successRate < config.GlobalConfig.SuccessRate {
				slog.Warn(fmt.Sprintf("订阅成功率过低: %s", subUrl),
					"总节点数", stats.total,
					"成功节点数", stats.success,
					"成功占比", fmt.Sprintf("%.2f%%", successRate*100))
			} else {
				slog.Debug(fmt.Sprintf("订阅节点统计: %s", subUrl),
					"总节点数", stats.total,
					"成功节点数", stats.success,
					"成功占比", fmt.Sprintf("%.2f%%", successRate*100))
			}
		}
	}
}

// CreateClient creates and returns an http.Client with a Close function
type ProxyClient struct {
	*http.Client
	proxy     constant.Proxy
	Transport *StatsTransport
}

func CreateClient(mapping map[string]any) *ProxyClient {
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		slog.Debug(fmt.Sprintf("底层mihomo创建代理Client失败: %v", err))
		return nil
	}

	baseTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var u16Port uint16
			if port, err := strconv.ParseUint(port, 10, 16); err == nil {
				u16Port = uint16(port)
			}
			return proxy.DialContext(ctx, &constant.Metadata{
				Host:    host,
				DstPort: u16Port,
			})
		},
		DisableKeepAlives: true,
	}

	statsTransport := &StatsTransport{
		Base: baseTransport,
	}
	return &ProxyClient{
		Client: &http.Client{
			Timeout:   time.Duration(config.GlobalConfig.Timeout) * time.Millisecond,
			Transport: statsTransport,
		},
		proxy:     proxy,
		Transport: statsTransport,
	}
}

// Close closes the proxy client and cleans up resources
// 防止底层库有一些泄露，所以这里手动关闭
func (pc *ProxyClient) Close() {
	if pc.Client != nil {
		pc.Client.CloseIdleConnections()
	}

	// 即使这里不关闭，底层GC的时候也会自动关闭
	if pc.proxy != nil {
		pc.proxy.Close()
	}
	pc.Client = nil

	if pc.Transport != nil {
		TotalBytes.Add(atomic.LoadUint64(&pc.Transport.BytesRead))
		// 清理Transport资源
		if pc.Transport.Base != nil {
			if transport, ok := pc.Transport.Base.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
	}
	pc.Transport = nil
}

type countingReadCloser struct {
	io.ReadCloser
	counter *uint64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	atomic.AddUint64(c.counter, uint64(n))
	return n, err
}

type StatsTransport struct {
	Base      http.RoundTripper
	BytesRead uint64
}

func (s *StatsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	resp.Body = &countingReadCloser{
		ReadCloser: resp.Body,
		counter:    &s.BytesRead,
	}
	return resp, nil
}
