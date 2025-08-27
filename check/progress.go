package check

import (
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/beck-8/subs-check/config"
)

// 默认使用动态权重显示进度条
var progressAlgorithm ProgressAlgorithm

func init() {
    if config.GlobalConfig.ProgressMode == "stage" {
        progressAlgorithm = StagePriorityProgress
    } else {
        progressAlgorithm = DynamicWeightProgress
    }
}

// 切换进度显示
type ProgressAlgorithm int

const (
	DynamicWeightProgress ProgressAlgorithm = iota // 总数恒等于节点总数，按权重映射百分比
	StagePriorityProgress                          // 阶段优先：显示当前阶段完成/阶段总
)

// 不同检测阶段的进度权重
type ProgressWeight struct {
	alive float64
	speed float64
	media float64
}

// 存储每个阶段的检测进度信息
type ProgressTracker struct {
	// 总任务数
	totalJobs atomic.Int32

	// 已检测数量
	aliveDone atomic.Int32
	speedDone atomic.Int32
	mediaDone atomic.Int32

	// 成功数量
	aliveSuccess atomic.Int32
	speedSuccess atomic.Int32

	// 当前处于 测活-测速-媒体检测 阶段
	currentStage atomic.Int32

	// 确保进度条输出完成
	finalized atomic.Bool
}

// NewProgressTracker 初始化进度追踪器并重置外部原子变量。
func NewProgressTracker(total int) *ProgressTracker {
	pt := &ProgressTracker{}
	if total > math.MaxInt32 {
		total = math.MaxInt32
	}
	pt.totalJobs.Store(int32(total))
	pt.currentStage.Store(0)

	ProxyCount.Store(uint32(total))
	Progress.Store(0)

	// 初始化进度权重
	progressWeight = getCheckWeight(speedON, mediaON)
	return pt
}

// getCheckWeight 根据启用的检查来确定进度权重的分配。
func getCheckWeight(speedON, mediaON bool) ProgressWeight {
	w := ProgressWeight{alive: 85, speed: 10, media: 5} // 默认权重 (全部开启时)

	switch {
	case !speedON && !mediaON:
		w = ProgressWeight{alive: 100, speed: 0, media: 0}
	case !speedON:
		w = ProgressWeight{alive: 80, speed: 0, media: 20}
	case !mediaON:
		w = ProgressWeight{alive: 70, speed: 30, media: 0}
	}

	return w
}

// CountAlive 标记一个存活检测已完成，并更新进度。
func (pt *ProgressTracker) CountAlive(success bool) {
	pt.aliveDone.Add(1)
	if success {
		pt.aliveSuccess.Add(1)
	}
	pt.refresh()
}

// CountSpeed 标记一个速度测试已完成，并更新进度。
func (pt *ProgressTracker) CountSpeed(success bool) {
	pt.speedDone.Add(1)
	if success {
		pt.speedSuccess.Add(1)
	}
	pt.refresh()
}

// CountMedia 标记一个媒体检测已完成，并更新进度。
func (pt *ProgressTracker) CountMedia() {
	pt.mediaDone.Add(1)
	pt.refresh()
}

// FinishAliveStage 在所有存活检测完成后，将追踪器转换到下一阶段。
// 如果没有任何代理存活，可能会提前结束整个过程。
func (pt *ProgressTracker) FinishAliveStage() {
	aliveSucc := int(pt.aliveSuccess.Load())

	// 如果没有节点在存活测试中成功，且后续有其他阶段，则提前结束
	if aliveSucc <= 0 && (speedON || mediaON) {
		pt.Finalize()
		return
	}
	// 切换为测速阶段
	pt.currentStage.Store(1)
	pt.refresh()
}

// FinishSpeedStage 在所有速度测试完成后，将追踪器转换到媒体检测阶段。
// 如果没有任何代理通过速度测试，可能会提前结束。
func (pt *ProgressTracker) FinishSpeedStage() {
	if !mediaON {
		pt.refresh()
		return
	}
	speedSucc := int(pt.speedSuccess.Load())
	if speedSucc <= 0 {
		pt.Finalize()
		return
	}
	// 切换为媒体检测阶段
	pt.currentStage.Store(2)
	pt.refresh()
}

// Finalize 确保进度被标记为 100% 完成。
func (pt *ProgressTracker) Finalize() {
	pt.finalized.Store(true)
	ProxyCount.Store(uint32(pt.totalJobs.Load()))
	Progress.Store(uint32(pt.totalJobs.Load()))
	pt.refresh()
}

// refresh 根据所选算法更新进度的统一入口。
func (pt *ProgressTracker) refresh() {
	switch progressAlgorithm {
	case DynamicWeightProgress:
		pt.refreshDynamic()
	case StagePriorityProgress:
		pt.refreshStage()
	}
}

// refreshDynamic 根据各阶段完成率的加权和来计算进度。
func (pt *ProgressTracker) refreshDynamic() {
	// 只读一次快照式获取所有需要的原子值
	total := int(pt.totalJobs.Load())
	if total <= 0 {
		ProxyCount.Store(0)
		Progress.Store(0)
		return
	}
	aliveDone := int(pt.aliveDone.Load())
	speedDone := int(pt.speedDone.Load())
	mediaDone := int(pt.mediaDone.Load())

	aliveSucc := int(pt.aliveSuccess.Load())
	speedSucc := int(pt.speedSuccess.Load())

	// aliveRatio 基于总量
	aliveRatio := float64(aliveDone) / float64(total)

	// 阶段偏置（局部变量，更快也更直观）
	var speedBias, mediaBias float64
	stage := int(pt.currentStage.Load())
	switch stage {
	case 0:
		speedBias, mediaBias = 1.1, 1.1
	case 1:
		speedBias, mediaBias = 1.0, 1.1
	default:
		speedBias, mediaBias = 1.0, 1.0
	}

	// speedRatio：以 aliveSucc 为基准（若 aliveSucc==0 则为 0）
	speedRatio := 0.0
	if aliveSucc > 0 {
		speedRatio = float64(speedDone) / (float64(aliveSucc) * speedBias)
	}

	// mediaRatio：基准为 speedSucc（若开启测速），否则为 aliveSucc
	base := speedSucc
	if !speedON {
		base = aliveSucc
	}
	mediaRatio := 0.0
	if base > 0 {
		mediaRatio = float64(mediaDone) / (float64(base) * mediaBias)
	}

	// 使用全局权重计算 p（0..100）
	p := aliveRatio*progressWeight.alive + speedRatio*progressWeight.speed + mediaRatio*progressWeight.media

	// finalized 优先：一旦 finalize，直接显示 100%
	if pt.finalized.Load() {
		p = 100.0
	} else {
		// clamp 到 [0,100]，用单处判断减少分支
		if p <= 0 {
			p = 0
		} else if p >= 100 {
			p = 100
		}
	}

	// 映射回节点计数（ceil 进位）
	mappedF := p * float64(total) / 100.0
	checkedCount := uint32(math.Ceil(mappedF))
	if checkedCount > uint32(total) {
		checkedCount = uint32(total)
	}

	ProxyCount.Store(uint32(total))
	Progress.Store(checkedCount)
}

// refreshStage 根据当前阶段的完成情况来计算进度。
func (pt *ProgressTracker) refreshStage() {
	stage := int(pt.currentStage.Load())
	switch stage {
	case 0: // 存活检测阶段
		total := uint32(pt.totalJobs.Load())
		done := uint32(pt.aliveDone.Load())
		if done > total {
			done = total
		}
		ProxyCount.Store(total)
		Progress.Store(done)
	case 1: // 测速阶段
		total := uint32(pt.aliveSuccess.Load())
		if total == 0 {
			ProxyCount.Store(0)
			Progress.Store(0)
			return
		}
		done := uint32(pt.speedDone.Load())
		if done > total {
			done = total
		}
		ProxyCount.Store(total)
		Progress.Store(done)
	case 2: // 媒体检测阶段
		var base int32
		if speedON {
			base = pt.speedSuccess.Load()
		} else {
			base = pt.aliveSuccess.Load()
		}
		total := uint32(base)
		if total == 0 {
			ProxyCount.Store(0)
			Progress.Store(0)
			return
		}
		done := uint32(pt.mediaDone.Load())
		if done > total {
			done = total
		}
		ProxyCount.Store(total)
		Progress.Store(done)
	}
}

// showProgress 负责在控制台中渲染进度条。
func (pc *ProxyChecker) showProgress(done <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Print(pc.renderProgressString())
			fmt.Println()
			return
		case <-ticker.C:
			fmt.Print(pc.renderProgressString())
		}
	}
}

// renderProgressString 计算并格式化进度条字符串。
func (pc *ProxyChecker) renderProgressString() string {
	currentChecked := int(Progress.Load())
	total := int(ProxyCount.Load())
	available := atomic.LoadInt32(&pc.available)

	var percent float64
	if total == 0 {
		percent = 100
	} else {
		percent = float64(currentChecked) / float64(total) * 100
	}

	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	barWidth := 45
	barFilled := int(percent / 100 * float64(barWidth))

	return fmt.Sprintf("\r进度: [%-*s] %.1f%% (%d/%d) 可用: %d",
		barWidth,
		strings.Repeat("=", barFilled)+">",
		percent,
		currentChecked,
		total,
		available)
}
