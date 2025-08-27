package check

import (
	"fmt"
	"testing"
)

// TestDecayComparison 打印对比表，代替原 main 函数
func TestDecayComparison(t *testing.T) {
	// 参数（可按需调整）
	amp := 500.0
	base := 100.0 //最低限值

	// 各算法参数选取：目标是让不同算法在 0..1000 范围内有可比形状
	expB := 0.001      // 指数衰减速率
	logK := 0.01       // 对数缩放
	powerP := 1.1      // 幂指数
	powerAlpha := 32.0 // 幂饱和参数
	invK := 50.0       // 反比例饱和常数
	tanhB := 0.0004    // tanh 速率

	funcs := []struct {
		name string
		fn   DecayFunc
	}{
		{"exp", NewExpDecay(amp, expB, base)},
		{"log", NewLogDecay(amp, logK, base)},
		{"power", NewPowerDecay(amp, powerP, powerAlpha, base)},
		{"inv", NewInverseDecay(amp, invK, base)},
		{"tanh", NewTanhDecay(amp, tanhB, base)},
	}

	fmt.Printf("%-5s", "x")
	for _, f := range funcs {
		fmt.Printf(" %-8s", f.name)
	}
	fmt.Println()

	for i := 0; i <= 1000; i += 10 { // 缩小范围方便测试
		x := float64(i)
		fmt.Printf("%-5d", i)
		for _, f := range funcs {
			fmt.Printf(" %-8d", RoundInt(f.fn(x)))
			if RoundInt(f.fn(x)) > 1000 {
				// t.Error("自适应并发数不在预期范围")
			}
		}
		fmt.Println()
	}
}

// 示例：单独调用某个衰减算法
func TestAliveConcurrent(t *testing.T) {
	fn := NewLogDecay(400, 0.005, 400)
	fmt.Printf("%-5s%-5s\n", "X", "Concurrent")
	for i := 0; i <= 1000; i += 20 {
		fmt.Printf("%-8d%-8d\n", i, RoundInt(fn(float64(i))))
		if RoundInt(fn(float64(i))) > 1000 {
			t.Error("自适应并发数不在预期范围")
		}
	}
}
