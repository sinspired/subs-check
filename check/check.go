// Package check 订阅检测主逻辑
package check

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/juju/ratelimit"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/constant"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/sinspired/subs-check/assets"
	"github.com/sinspired/subs-check/check/platform"
	"github.com/sinspired/subs-check/config"
	proxyutils "github.com/sinspired/subs-check/proxy"
	"github.com/sinspired/subs-check/save/method"
)

// 对外暴露变量，兼容GUI调用
var (
	Progress   atomic.Uint32 // 已检测数量（语义见算法）
	Available  atomic.Uint32 // 已可用数量（测速阶段完成,可用即+1）
	ProxyCount atomic.Uint32 // 总数（动态=总节点；分阶段=当前阶段规模）

	TotalBytes     atomic.Uint64
	ForceClose     atomic.Bool
	Successlimited atomic.Bool
	ProcessResults atomic.Bool

	Bucket *ratelimit.Bucket
)

// 存储测速和流媒体检测开关状态
var (
	speedON        bool
	mediaON        bool
	progressWeight ProgressWeight
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
	resultChan  chan Result
	proxyCount  int
	threadCount int
	available   atomic.Int32

	aliveConcurrent int
	speedConcurrent int
	mediaConcurrent int

	aliveChan chan *ProxyJob
	speedChan chan *ProxyJob
	mediaChan chan *ProxyJob

	pt *ProgressTracker
}

// ProxyJob 在测活-测速-流媒体检测任务间传输信息
type ProxyJob struct {
	Client *ProxyClient
	Result Result

	CfLoc string
	CfIP  string

	doneOnce sync.Once

	aliveMarked atomic.Bool
	speedMarked atomic.Bool
	mediaMarked atomic.Bool

	Speed int

	NeedCF         bool
	IsCfAccessible bool
}

// Close 确保 ProxyJob 的底层资源(mihomo客户端)被正确释放一次。
func (j *ProxyJob) Close() {
	j.doneOnce.Do(func() {
		if j.Client != nil {
			j.Client.Close()
			j.Client = nil // 切断对底层资源的引用
		}
		// 切断map引用，释放内存
		j.Result.Proxy = nil
		j.Result = Result{}
	})
}

// calcSpeedConcurrency 根据总速度限制计算速度测试的最佳并发数。
func calcSpeedConcurrency(proxyCount int) int {
	if config.GlobalConfig.TotalSpeedLimit <= 0 {
		threadCount := min(proxyCount, config.GlobalConfig.Concurrent)
		fnSpeed := NewPowerDecay(32, 1.1, 32, 1)
		return min(config.GlobalConfig.Concurrent, RoundInt(fnSpeed(float64(threadCount))))
	}
	L := float64(config.GlobalConfig.TotalSpeedLimit) // 单位: MB/s
	r := float64(config.GlobalConfig.MinSpeed) / 1024 // 目标每线程吞吐: MB/s
	c := max(int(L/r), 1)
	c = min(c, config.GlobalConfig.Concurrent)
	return c
}

// NewProxyChecker 创建新的检测器实例
func NewProxyChecker(proxyCount int) *ProxyChecker {
	threadCount := config.GlobalConfig.Concurrent
	if proxyCount < threadCount {
		threadCount = proxyCount
	}

	cAlive := config.GlobalConfig.AliveConcurrent
	cSpeed := config.GlobalConfig.SpeedConcurrent
	cMedia := config.GlobalConfig.MediaConcurrent

	// 分别设置测活\测速\媒体检测阶段并发数
	// 使用衰减算法,简单防呆设计
	aliveConc := 0
	speedConc := 0
	mediaConc := 0

	// 如果明确设置了正数
	if cAlive > 0 && cSpeed > 0 && cMedia > 0 {
		aliveConc = min(cAlive, proxyCount)
		speedConc = min(cSpeed, proxyCount)
		mediaConc = min(cMedia, proxyCount)
	} else {
		// 自动模式
		// 使用相对平滑的衰减方案
		fnAlive := NewLogDecay(400, 0.005, 400)
		fnMedia := NewExpDecay(400, 0.001, 100)
		if !speedON {
			fnMedia = NewExpDecay(400, 0.001, 150)
		}

		aliveConc = min(proxyCount, RoundInt(fnAlive(float64(threadCount))))
		speedConc = min(calcSpeedConcurrency(proxyCount), proxyCount)
		mediaConc = min(proxyCount, RoundInt(fnMedia(float64(threadCount))))

		// 超大线程数
		if threadCount > 1000 {
			slog.Info("除非你的 CPU 和路由器同时允许, 超过 1000 并发可能影响其它上网程序,如确有需求,请在配置文件分别指定测活-测速-媒体检测每个阶段并发数")
			slog.Info(fmt.Sprintf("已限制测活并发数: %d", aliveConc))
		}
	}

	var speedChanLength int
	// 测速阶段的缓冲通道不用太大,以形成阻塞,避免测活浪费资源
	fnScLength := NewTanhDecay(100, 0.0004, float64(aliveConc))
	speedChanLength = RoundInt(fnScLength(float64(speedConc)))
	if !speedON {
		speedChanLength = 1 // 不启用测速时，设置为最小缓冲
	}

	return &ProxyChecker{
		proxyCount:  proxyCount,
		threadCount: threadCount,

		// 设置不同检测阶段的并发数
		aliveConcurrent: aliveConc,
		speedConcurrent: speedConc,
		mediaConcurrent: mediaConc,

		// 设置缓冲通道
		aliveChan: make(chan *ProxyJob, int(float64(aliveConc)*1.2)),
		speedChan: make(chan *ProxyJob, speedChanLength),
		mediaChan: make(chan *ProxyJob, mediaConc*2),

		// 设置进度跟踪
		pt: NewProgressTracker(proxyCount),
	}
}

// Check 执行代理检测的主函数
func Check() ([]Result, error) {
	proxyutils.ResetRenameCounter()
	ForceClose.Store(false)
	Successlimited.Store(false)
	ProcessResults.Store(false)

	ProxyCount.Store(0)
	Available.Store(0)
	Progress.Store(0)

	TotalBytes.Store(0)

	// 初始化测速和流媒体检测开关
	speedON = config.GlobalConfig.SpeedTestURL != ""
	mediaON = config.GlobalConfig.MediaCheck

	// 获取订阅节点和之前成功的节点数量(已前置)
	proxies, rawCount, subWasSuccedLength, historyLength, err := proxyutils.GetProxies()

	if err != nil {
		return nil, fmt.Errorf("获取节点失败: %w", err)
	}
	slog.Info(fmt.Sprintf("已获取节点数量: %d", rawCount))
	slog.Info(fmt.Sprintf("去重后节点数量: %d", len(proxies)))

	if subWasSuccedLength > 0 {
		slog.Info(fmt.Sprintf("已加载上次检测可用节点，数量: %d", subWasSuccedLength))
	}

	if historyLength > 0 {
		slog.Info(fmt.Sprintf("已加载历次检测可用节点，数量: %d", historyLength))
	}

	// 设置之前成功的节点顺序在前
	headSize := subWasSuccedLength + historyLength
	if len(proxies) > headSize {
		// 假设有 15 个相似的ip
		calcMinSpacing := max(config.GlobalConfig.Concurrent*5, len(proxies)/15)

		// 随机乱序并根据 server 字段打乱节点顺序, 减少测速直接测死的概率
		cfg := proxyutils.ShuffleConfig{
			Threshold:  float64(config.GlobalConfig.Threshold), // CIDR/24 相同, 避免在一组(0.5: CIDR/16)
			Passes:     3,                                      // 改善轮数（1~3）
			MinSpacing: calcMinSpacing,                         // CIDR/24 相同, 设置最小间隔
			ScanLimit:  config.GlobalConfig.Concurrent * 2,     // 冲突向前扫描的最大距离
		}

		tail := proxies[headSize:]
		proxyutils.SmartShuffleByServer(tail, cfg)

		cidr := proxyutils.ThresholdToCIDR(cfg.Threshold)
		slog.Info(fmt.Sprintf("节点乱序, 相同 CIDR%s 最小间距: %d", cidr, cfg.MinSpacing))
	}

	if len(proxies) == 0 {
		slog.Info("没有需要检测的节点")
		return nil, nil
	}

	checker := NewProxyChecker(len(proxies))
	return checker.run(proxies)
}

// Run 运行检测流程
func (pc *ProxyChecker) run(proxies []map[string]any) ([]Result, error) {
	// 限速设置
	if limit := config.GlobalConfig.TotalSpeedLimit; limit > 0 {
		rate := float64(limit * 1024 * 1024)
		capacity := int64(rate / 10)
		Bucket = ratelimit.NewBucketWithRate(rate, capacity)
	} else {
		Bucket = ratelimit.NewBucketWithRate(float64(math.MaxInt64), int64(math.MaxInt64))
	}

	// // 初始化全局上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 如果 MaxMindDBPath 为空会自动使用 subs-check 内置数据库
	geoDB, err := assets.OpenMaxMindDB(config.GlobalConfig.MaxMindDBPath)

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

	// 组装参数
	args := []any{
		"enable-speedtest", speedON,
		"media-check", mediaON,
		"drop-bad-cf-nodes", config.GlobalConfig.DropBadCfNodes,
	}

	// 流水线并发参数
	if config.GlobalConfig.AliveConcurrent <= 0 || config.GlobalConfig.SpeedConcurrent <= 0 || config.GlobalConfig.MediaConcurrent <= 0 {
		args = append(args,
			"auto-concurrent", true, "concurrent", config.GlobalConfig.Concurrent,
			":alive", pc.aliveConcurrent,
		)
		if speedON {
			args = append(args, ":speed", pc.speedConcurrent)
		}
		if mediaON {
			args = append(args, ":media", pc.mediaConcurrent)
		}
	} else {
		args = append(args,
			"concurrent", config.GlobalConfig.Concurrent,
			":alive", pc.aliveConcurrent)
		if speedON {
			args = append(args, ":speed", pc.speedConcurrent)
		}
		if mediaON {
			args = append(args, ":media", pc.mediaConcurrent)
		}
	}
	// 只有在 >0 时才输出
	if config.GlobalConfig.SuccessLimit > 0 {
		args = append(args, "success-limit", config.GlobalConfig.SuccessLimit)
	}
	if config.GlobalConfig.TotalSpeedLimit > 0 && speedON {
		args = append(args, "total-speed-limit", config.GlobalConfig.TotalSpeedLimit)
	}

	// 再追加剩余参数
	args = append(args,
		"timeout", config.GlobalConfig.Timeout,
	)

	if speedON {
		args = append(args,
			"min-speed", config.GlobalConfig.MinSpeed,
			"download-timeout", config.GlobalConfig.DownloadTimeout,
			"download-mb", config.GlobalConfig.DownloadMB,
		)
	}

	if config.GlobalConfig.KeepSuccessProxies {
		args = append(args, "keep-success-proxies", config.GlobalConfig.KeepSuccessProxies)
	}

	if config.GlobalConfig.SubURLsStats {
		args = append(args, "sub-urls-stats", config.GlobalConfig.SubURLsStats)
	}

	// 最终日志调用
	slog.Info("当前参数", args...)

	// 监测 ForceClose
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ForceClose.Load() {
					slog.Warn("用户手动结束检测,等待收集结果")
					cancel()
					return
				}
			}
		}
	}()

	// 进度显示 —— 使用关闭信号并等待 showProgress 完成
	doneCh := make(chan struct{})
	finishedCh := make(chan struct{})

	if config.GlobalConfig.PrintProgress {
		go func() {
			pc.showProgress(doneCh)
			close(finishedCh)
		}()
	}

	// 启动流水线阶段
	go pc.distributeJobs(proxies, ctx)
	go pc.runAliveStage(ctx)
	go pc.runSpeedStage(ctx, cancel)
	pc.runMediaStageAndCollect(geoDB, ctx, cancel)

	// 确保进度显示到 100% 再打印收尾日志
	if config.GlobalConfig.PrintProgress {
		// 收集工作已全部完成，调用 Finalize 强制将进度设置为 100%
		pc.pt.Finalize()

		// 关闭 done 通知 showProgress 打印最终状态并退出，然后等待其完全结束
		close(doneCh)
		<-finishedCh
	}

	if config.GlobalConfig.SuccessLimit > 0 && pc.available.Load() >= config.GlobalConfig.SuccessLimit {
		slog.Info(fmt.Sprintf("达到成功节点数量限制 %d, 收集结果完成。", config.GlobalConfig.SuccessLimit))
	}

	// 标记检测完成，开始处理结果，保存，上传等
	ProcessResults.Store(true)

	// 检查订阅成功率并发出警告
	pc.checkSubscriptionSuccessRate(proxies)

	slog.Info(fmt.Sprintf("可用节点数量: %d", len(pc.results)))
	slog.Info(fmt.Sprintf("测试总消耗流量: %.3fGB", float64(TotalBytes.Load())/1024/1024/1024))

	// 手动解除引用
	for i := range proxies {
		proxies[i] = nil
	}

	// 在保存上传之前直接归还内存
	debug.FreeOSMemory()

	return pc.results, nil
}

// distributeJobs 分发代理任务
func (pc *ProxyChecker) distributeJobs(proxies []map[string]any, ctx context.Context) {
	defer close(pc.aliveChan)

	concurrency := min(pc.proxyCount, pc.aliveConcurrent)
	var wg sync.WaitGroup

	// 使用原子索引来分发任务
	var proxyIndex atomic.Int64
	proxyIndex.Store(-1) // 初始化为 -1

	// 定义主动 GC 的阈值
	const gcThreshold = 50000

	// 启动工作协程池
	for range concurrency {
		wg.Go(func() {
			for {
				// 原子地获取下一个代理索引
				index := proxyIndex.Add(1)
				if index >= int64(len(proxies)) {
					return // 所有代理都已处理完毕
				}

				if checkCtxDone(ctx) {
					return
				}

				mapping := proxies[index]

				// 任务取出后，立即断开源切片的引用
				// 此时，如果 mapping 没被后续 CreateClient 引用，它就是垃圾；
				// 如果 mapping 被传给了 Client，等 Job.Close() 时它也会变成垃圾。
				proxies[index] = nil

				// 周期性强制归还内存
				// 只有当索引达到阈值倍数时触发
				if index > 0 && index%gcThreshold == 0 {
					// 异步执行，尽量不阻塞分发，但在 CPU 极高时可能会有些许延迟
					go func(currentIdx int64) {
						slog.Info(fmt.Sprintf("已处理 %d 个节点，正在执行主动内存回收...", currentIdx))
						debug.FreeOSMemory()
					}(index)
				}

				cli := CreateClient(mapping)
				if cli == nil {
					// 创建失败：视为 alive 完成（失败），不进入 speed/media
					pc.pt.CountAlive(false)
					continue
				}

				job := &ProxyJob{
					Client: cli,
					Result: Result{Proxy: mapping},
				}
				job.NeedCF = config.GlobalConfig.DropBadCfNodes ||
					(config.GlobalConfig.MediaCheck && needsCF(config.GlobalConfig.Platforms))

				// 当 aliveChan 满时会阻塞
				select {
				case pc.aliveChan <- job:
				case <-ctx.Done():
					job.Close()
					return
				}
			}
		})
	}

	// 等待所有工作协程完成
	wg.Wait()
	// 分发结束，再次强制清理（此时 proxies 切片虽然 length 很大，但全是 nil）
	debug.FreeOSMemory()
}

// 测活
func (pc *ProxyChecker) runAliveStage(ctx context.Context) {
	// 根据是否启用测速，延迟关闭下一个阶段的通道。
	if speedON {
		defer close(pc.speedChan)
	} else {
		close(pc.speedChan)
		defer close(pc.mediaChan)
	}

	var wg sync.WaitGroup
	concurrency := pc.aliveConcurrent
	pc.pt.currentStage.Store(0)

	for range concurrency {
		wg.Go(func() {
			for job := range pc.aliveChan {
				if checkCtxDone(ctx) {
					job.Close()
					continue
				}
				// 节点测活
				isAlive := checkAlive(job)

				if !isAlive {
					// 记录非存活
					if job.aliveMarked.CompareAndSwap(false, true) {
						pc.pt.CountAlive(false)
					}
					job.Close()
					continue // 不进入 speed/media
				}

				// CF 过滤
				if job.NeedCF {
					job.IsCfAccessible, job.CfLoc, job.CfIP = platform.CheckCloudflare(job.Client.Client)
					if config.GlobalConfig.DropBadCfNodes && !job.IsCfAccessible {
						job.Close()
						// 记录丢弃
						if job.aliveMarked.CompareAndSwap(false, true) {
							pc.pt.CountAlive(false)
						}
						continue
					}
				}

				// 记录存活
				if job.aliveMarked.CompareAndSwap(false, true) {
					pc.pt.CountAlive(true)
				}

				// 流转
				if speedON {
					select {
					case pc.speedChan <- job:

					case <-ctx.Done():
						job.Close()
					}
				} else {
					// 无测速时：通过 alive 即可视为“可用”，确保 Available 与最终可用数量一致
					if job.speedMarked.CompareAndSwap(false, true) {
						pc.incrementAvailable()
					}
					select {
					case pc.mediaChan <- job:
					case <-ctx.Done():
						job.Close()
					}
				}
			}
		})
	}
	wg.Wait()

	// alive 阶段闭合：分阶段算法据此确定下一阶段规模
	pc.pt.FinishAliveStage()
}

// 测速
func (pc *ProxyChecker) runSpeedStage(ctx context.Context, cancel context.CancelFunc) {
	if !speedON {
		return
	}
	defer close(pc.mediaChan)

	// 确保达到成功节点数量限制的日志只输出一次
	var stopOnce sync.Once

	var wg sync.WaitGroup
	concurrency := pc.speedConcurrent

	for range concurrency {
		wg.Go(func() {
			for job := range pc.speedChan {
				if checkCtxDone(ctx) {
					job.Close()
					continue
				}
				getBytes := func() uint64 { return job.Client.Transport.BytesRead.Load() }
				speed, _, err := platform.CheckSpeed(job.Client.Client, Bucket, getBytes)
				success := err == nil && speed >= config.GlobalConfig.MinSpeed
				if job.speedMarked.CompareAndSwap(false, true) {
					pc.pt.CountSpeed(success)
					// 仅在测速成功时计入可用数量
					if success {
						pc.incrementAvailable()
					}
				}
				if !success {
					job.Close()
					continue
				}
				job.Speed = speed

				if config.GlobalConfig.SuccessLimit > 0 && pc.available.Load() >= config.GlobalConfig.SuccessLimit {
					stopOnce.Do(func() {
						Successlimited.Store(true)
						pc.pt.FinishAliveStage()
						if mediaON {
							if speedON {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待测速和媒体检测任务完成...", config.GlobalConfig.SuccessLimit))
							} else {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待媒体检测任务完成...", config.GlobalConfig.SuccessLimit))
							}
						} else {
							if speedON {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待测速和节点重命名任务完成...", config.GlobalConfig.SuccessLimit))
							} else {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待节点重命名任务完成...", config.GlobalConfig.SuccessLimit))
							}
						}

						cancel()
					})
				}

				// 流转
				pc.mediaChan <- job
			}
		})
	}
	wg.Wait()

	// speed 阶段闭合：分阶段算法据此确定媒体阶段规模
	pc.pt.FinishSpeedStage()
}

// 流媒体检测 + 收集结果
func (pc *ProxyChecker) runMediaStageAndCollect(db *maxminddb.Reader, ctx context.Context, cancel context.CancelFunc) {
	var wg sync.WaitGroup
	resultLength := pc.mediaConcurrent
	if config.GlobalConfig.SuccessLimit != 0 {
		resultLength = int(config.GlobalConfig.SuccessLimit)
	}

	pc.resultChan = make(chan Result, resultLength)

	// 设置成功数量限制
	var stopOnce sync.Once

	// 收集结果
	var collectorWg sync.WaitGroup
	collectorWg.Go(func() {
		pc.collectResults()
	})

	// 启动 workers（确保 collector 已启动以避免阻塞在无缓冲时）
	concurrency := pc.mediaConcurrent
	for range concurrency {
		wg.Go(func() {
			for job := range pc.mediaChan {
				if !speedON {
					// 只在没开启测速时接受媒体检测停止信号
					// 丢弃结果
					if checkCtxDone(ctx) {
						job.Close()
						continue
					}

					// 设置成功数量限制
					if config.GlobalConfig.SuccessLimit > 0 && pc.available.Load() >= config.GlobalConfig.SuccessLimit {
						stopOnce.Do(func() {
							Successlimited.Store(true)
							pc.pt.FinishAliveStage()
							if mediaON {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待媒体检测任务完成...", config.GlobalConfig.SuccessLimit))
								slog.Warn("测活模式将丢弃多余结果")
							} else {
								Successlimited.Store(true)
								slog.Warn(fmt.Sprintf("达到成功节点数量限制 %d, 等待节点重命名任务完成...", config.GlobalConfig.SuccessLimit))
								slog.Warn("测活模式将丢弃多余结果")
							}

							cancel()
						})
					}
				}

				if mediaON {
					for _, plat := range config.GlobalConfig.Platforms {
						mediaCheck(job, plat, db, ctx)
					}
				}

				pc.updateProxyName(&job.Result, job.Client, job.Speed, db, job.CfLoc, job.CfIP, ctx)

				// 将结果发送到 collector
				pc.resultChan <- job.Result

				if job.mediaMarked.CompareAndSwap(false, true) {
					pc.pt.CountMedia()
				}

				job.Close()
			}
		})
	}

	// 等待所有 worker 完成，再关闭 pc.resultChan，让 collector 退出
	wg.Wait()
	close(pc.resultChan)
	collectorWg.Wait()

	// 最后一次刷新并返回收集结果
	pc.pt.refresh()
}

// collectResults 收集检测结果
func (pc *ProxyChecker) collectResults() {
	for result := range pc.resultChan {
		pc.results = append(pc.results, result)
	}
}

// checkAlive 使用谷歌服务执行基本的存活检测。
func checkAlive(job *ProxyJob) bool {
	gstatic, err := platform.CheckGstatic(job.Client.Client)
	if err == nil && gstatic {
		return true
	}
	return false
}

// needsCF 判断所选的媒体检测平台是否需要Cloudflare访问权限。
func needsCF(platforms []string) bool {
	for _, p := range platforms {
		if p == "openai" || p == "x" {
			return true
		}
	}
	return false
}

// mediaCheck 根据平台类型分发到相应的检测函数。
func mediaCheck(job *ProxyJob, plat string, db *maxminddb.Reader, ctx context.Context) {
	switch plat {
	case "x":
		if job.NeedCF && !job.IsCfAccessible {
			break
		}
		job.Result.X = true
	case "openai":
		if job.NeedCF && !job.IsCfAccessible {
			break
		}
		cookiesOK, clientOK := platform.CheckOpenAI(job.Client.Client)
		if clientOK && cookiesOK {
			job.Result.Openai = true
		} else if clientOK || cookiesOK {
			job.Result.OpenaiWeb = true
		}
	case "youtube":
		if region, _ := platform.CheckYoutube(job.Client.Client); region != "" {
			job.Result.Youtube = region
		}
	case "netflix":
		if ok, _ := platform.CheckNetflix(job.Client.Client); ok {
			job.Result.Netflix = true
		}
	case "disney":
		if ok, _ := platform.CheckDisney(job.Client.Client); ok {
			job.Result.Disney = true
		}
	case "gemini":
		if ok, _ := platform.CheckGemini(job.Client.Client); ok {
			job.Result.Gemini = true
		}
	case "tiktok":
		if region, _ := platform.CheckTikTok(job.Client.Client); region != "" {
			job.Result.TikTok = region
		}
	case "iprisk":
		country, ip, countryCodeTag, _ := proxyutils.GetProxyCountry(job.Client.Client, db, ctx, job.CfLoc, job.CfIP)
		if ip == "" {
			break
		}
		job.Result.IP = ip
		job.Result.Country = country
		job.Result.CountryCodeTag = countryCodeTag
		if risk, err := platform.CheckIPRisk(job.Client.Client, ip); err == nil {
			job.Result.IPRisk = risk
		} else {
			// 失败的可能性高，所以放上日志
			slog.Debug(fmt.Sprintf("查询IP风险失败: %v", err))
		}
	}
}

// updateProxyName 更新代理名称
func (pc *ProxyChecker) updateProxyName(res *Result, httpClient *ProxyClient, speed int, db *maxminddb.Reader, cfLoc string, cfIP string, jctx context.Context) {
	// 以节点IP查询位置重命名（如果开启）
	if config.GlobalConfig.RenameNode {
		if res.Country == "" {
			country, _, countryCodeTag, _ := proxyutils.GetProxyCountry(httpClient.Client, db, jctx, cfLoc, cfIP)
			res.Country = country
			res.CountryCodeTag = countryCodeTag
		}
		if res.Country != "" {
			res.Proxy["name"] = config.GlobalConfig.NodePrefix + proxyutils.Rename(res.Country, res.CountryCodeTag)
		} else {
			originName := res.Proxy["name"].(string)
			res.Proxy["name"] = config.GlobalConfig.NodePrefix + proxyutils.Rename(res.Country, res.CountryCodeTag) + originName
		}
	}

	name := ""
	if v, ok := res.Proxy["name"].(string); ok {
		name = strings.TrimSpace(v)
	}

	var tags []string
	// 速度标签
	if config.GlobalConfig.SpeedTestURL != "" && speed > 0 {
		var speedStr string
		if speed < 100 {
			speedStr = fmt.Sprintf("%dKB/s", speed)
		} else {
			speedStr = fmt.Sprintf("%.1fMB/s", float64(speed)/1024)
		}
		tags = append(tags, speedStr)
	}

	if config.GlobalConfig.MediaCheck {
		// 移除旧标签
		name = regexp.MustCompile(`\s*\|(?:NF|D\+|GPT⁺|GPT|GM|X|YT|YT-[^|]+|TK|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
	}

	// 平台标签（按用户配置顺序）
	for _, plat := range config.GlobalConfig.Platforms {
		switch plat {
		case "openai":
			if res.Openai {
				tags = append(tags, "GPT⁺")
			} else if res.OpenaiWeb {
				tags = append(tags, "GPT")
			}
		case "x":
			if res.X && !strings.Contains(name, "⁻¹") && !strings.Contains(name, "🏴‍☠️") {
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
				// 只有YouTube地区和节点位置不一致时才添加YouTube地区
				if res.Country != res.Youtube {
					tags = append(tags, fmt.Sprintf("YT-%s", res.Youtube))
				} else {
					tags = append(tags, "YT")
				}
			}
		case "tiktok":
			if res.TikTok != "" {
				// 只有TikTok地区和节点位置不一致时才添加TikTok地区
				if res.Country != res.TikTok {
					tags = append(tags, fmt.Sprintf("TK-%s", res.TikTok))
				} else {
					tags = append(tags, "TK")
				}
			}
		}
	}

	if tag, ok := res.Proxy["sub_tag"].(string); ok && tag != "" {
		tags = append(tags, tag)
	}

	// 运营商标签
	if config.GlobalConfig.ISPCheck {
		ISPTag := proxyutils.GetISPInfo(httpClient.Client)
		if ISPTag != "" {
			tags = append(tags, ISPTag)
		}
	}

	// 将所有标记添加到名称中
	if len(tags) > 0 {
		name += "|" + strings.Join(tags, "|")
	}

	res.Proxy["name"] = name
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
		if subURL, ok := proxy["sub_url"].(string); ok {
			stats := subStats[subURL]
			stats.total++
			subStats[subURL] = stats
		}
	}

	// 统计成功节点的订阅来源
	for _, result := range pc.results {
		if result.Proxy != nil {
			if subURL, ok := result.Proxy["sub_url"].(string); ok {
				stats := subStats[subURL]
				stats.success++
				subStats[subURL] = stats
			}
			delete(result.Proxy, "sub_url")
			delete(result.Proxy, "sub_tag")
		}
	}

	// 检查成功率并发出警告
	for subURL, stats := range subStats {
		if stats.total > 0 {
			successRate := float32(stats.success) / float32(stats.total)

			// 如果成功率低于x，发出警告
			if successRate < config.GlobalConfig.SuccessRate {
				slog.Warn(fmt.Sprintf("订阅成功率过低: %s", subURL),
					"总节点数", stats.total,
					"成功节点数", stats.success,
					"成功占比", fmt.Sprintf("%.2f%%", successRate*100))
			} else {
				slog.Debug(fmt.Sprintf("订阅节点统计: %s", subURL),
					"总节点数", stats.total,
					"成功节点数", stats.success,
					"成功占比", fmt.Sprintf("%.2f%%", successRate*100))
			}
		}
	}

	// 根据用户配置，过滤出成功率>0的订阅并保存两个文件：
	// 1) 仅包含URL列表：subs-filtered.yaml
	// 2) 包含URL与成功率的统计：subs-filtered-stats.yaml（按成功率降序）
	if config.GlobalConfig.SubURLsStats {
		type pair struct {
			URL     string
			Rate    float64
			Total   int
			Success int
		}
		filtered := make([]string, 0, len(subStats))
		pairs := make([]pair, 0, len(subStats))

		for u, st := range subStats {
			if st.total <= 0 || st.success <= 0 {
				continue
			}
			r := float64(st.success) / float64(st.total)
			filtered = append(filtered, u)
			pairs = append(pairs, pair{URL: u, Rate: r, Total: st.total, Success: st.success})
		}

		// 排序：按成功率降序，再按URL升序
		slices.SortFunc(pairs, func(a, b pair) int {
			// 先按成功率降序 (b - a)
			if n := cmpFloat(b.Rate, a.Rate); n != 0 {
				return n
			}
			// 再按URL升序 (a - b)
			return strings.Compare(a.URL, b.URL)
		})

		// URL 列表保存为标准 YAML 数组
		if data, err := yaml.Marshal(filtered); err != nil {
			slog.Warn("序列化过滤后的订阅链接失败", "err", err)
		} else if err := method.SaveToStats(data, "subs-filtered.yaml"); err != nil {
			slog.Warn("保存过滤后的订阅链接失败", "err", err)
		}

		// 统计文件：每行一个条目，列表中为单键映射：- "<url>": <rate>
		// rate 保留4位小数，便于人眼阅读与程序解析
		var sb strings.Builder
		for _, p := range pairs {
			fmt.Fprintf(&sb, "- %q: %d/%d (%.3f%%)\n", p.URL, p.Success, p.Total, p.Rate*100)
		}
		if err := method.SaveToStats([]byte(sb.String()), "subs-filtered-stats.yaml"); err != nil {
			slog.Warn("保存过滤后的订阅统计失败", "err", err)
		}
	}
}

func cmpFloat(a, b float64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

type ProxyClient struct {
	*http.Client
	Transport *StatsTransport
	ctx       context.Context
	cancel    context.CancelFunc
	mProxy    constant.Proxy
}

// CreateClient 创建独立的代理客户端
func CreateClient(mapping map[string]any) *ProxyClient {
	pc := &ProxyClient{}

	var err error
	resolver.DisableIPv6 = false

	// 解析代理
	pc.mProxy, err = adapter.ParseProxy(mapping)
	if err != nil {
		slog.Debug(fmt.Sprintf("底层mihomo创建代理Client失败: %v", err))
		return nil
	}

	// 初始化全局控制 Context
	pc.ctx, pc.cancel = context.WithCancel(context.Background())
	// 捕获 ctx 用于闭包，防止 pc 指针后续变化（防御性，避免某次测试出现的nil指针错误）
	clientCtx := pc.ctx

	statsTransport := &StatsTransport{}
	var baseTransport *http.Transport
	networkLimitDefault := true

	baseTransport = &http.Transport{
		DialContext: func(reqCtx context.Context, network, addr string) (net.Conn, error) {
			// 基于请求的 ctx 创建合并 ctx
			mergedCtx, mergedCancel := context.WithCancel(reqCtx)

			// 使用 context.AfterFunc 监听全局 clientCtx
			// 当 clientCtx (ProxyClient) 被关闭时，立即调用 mergedCancel
			stop := context.AfterFunc(clientCtx, func() {
				mergedCancel()
			})

			// 资源清理
			// 无论拨号成功还是失败，函数返回时：
			// 1. stop(): 注销监听器，避免 mergedCtx 长期持有 clientCtx 的引用
			// 2. mergedCancel(): 释放 mergedCtx 资源
			defer stop()
			defer mergedCancel()

			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var u16Port uint16
			if port, err := strconv.ParseUint(portStr, 10, 16); err == nil {
				u16Port = uint16(port)
			}

			// 使用合并后的 ctx 进行拨号
			rawConn, err := pc.mProxy.DialContext(mergedCtx, &constant.Metadata{
				Host:    host,
				DstPort: u16Port,
			})
			if err != nil {
				return nil, err
			}

			return &countingConn{
				Conn:         rawConn,
				readCounter:  &statsTransport.BytesRead,
				writeCounter: &statsTransport.BytesWritten,
				networkLimit: networkLimitDefault,
			}, nil
		},
		DisableKeepAlives:   false,
		Proxy:               nil,
		IdleConnTimeout:     5 * time.Second,
		MaxIdleConnsPerHost: 5,
	}

	// HTTP/2 判断
	if baseTransport.ForceAttemptHTTP2 || len(baseTransport.TLSNextProto) > 0 {
		networkLimitDefault = false
	}

	statsTransport.Base = baseTransport
	pc.Transport = statsTransport

	pc.Client = &http.Client{
		Timeout:   time.Duration(config.GlobalConfig.Timeout) * time.Millisecond,
		Transport: statsTransport,
	}

	return pc
}

// Close 关闭客户端，释放所有资源
func (pc *ProxyClient) Close() {
	// 防御性检查：防止对 nil 指针调用 Close
	if pc == nil {
		return
	}

	// 发送取消信号
	// 这会立即触发 CreateClient 中 context.AfterFunc 注册的回调，
	// 从而中断所有正在进行的 Dial 过程。
	if pc.cancel != nil {
		pc.cancel()
	}

	// 关闭mihomo代理实例
	if pc.mProxy != nil {
		pc.mProxy.Close()
	}

	// 关闭 HTTP 连接池
	// 这里无法关闭mihomo建立的连接
	if pc.Client != nil {
		pc.Client.CloseIdleConnections()
	}

	// 统计数据
	if pc.Transport != nil {
		bytesRead := pc.Transport.BytesRead.Load()

		if bytesRead > 0 {
			TotalBytes.Add(bytesRead)
		}

		if pc.Transport.Base != nil {
			// 关闭mihomo连接，mihomo的bug？有时间去看一下mihomo代码
			pc.Transport.Base.CloseIdleConnections()
		}
	}
}

// countingReadCloser 封装了 io.ReadCloser，用于统计读取的字节数。
type countingReadCloser struct {
	io.ReadCloser
	counter *atomic.Uint64
}

// Read 为 countingReadCloser 实现 io.Reader 接口。
func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.counter.Add(uint64(n))
	}
	return n, err
}

// StatsTransport 是一个 http.RoundTripper 的封装，用于统计从响应体中读取的字节数。
type StatsTransport struct {
	Base         *http.Transport
	BytesRead    atomic.Uint64
	BytesWritten atomic.Uint64
}

// RoundTrip 为 StatsTransport 实现 http.RoundTripper 接口。
func (s *StatsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.Base.RoundTrip(req)
}

// countingConn 包裹 net.Conn，在网络连接层统计读/写字节数。
type countingConn struct {
	net.Conn
	readCounter  *atomic.Uint64
	writeCounter *atomic.Uint64
	networkLimit bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readCounter.Add(uint64(n))
		// 在连接层消耗 token
		if Bucket != nil && c.networkLimit {
			Bucket.Wait(int64(n))
		}
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.writeCounter.Add(uint64(n))
	}
	return n, err
}

// 工具函数
func (pc *ProxyChecker) incrementAvailable() {
	pc.available.Add(1)
	Available.Add(1)
}

// checkCtxDone 提供一个非阻塞的检查，判断上下文是否已结束或是否收到强制关闭信号。
func checkCtxDone(c context.Context) bool {
	if ForceClose.Load() {
		return true
	}
	select {
	case <-c.Done():
		return true
	default:
		return false
	}
}
