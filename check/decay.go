package check

import (
	"math"
)

// DecayFunc 定义衰减函数签名
type DecayFunc func(x float64) float64

// 各种衰减构造器：返回 DecayFunc，最后计算为 base + amp * kernel(x)
// kernel(x) 要满足：kernel(0)=0，kernel(∞)=1

// NewExpDecay 指数衰减: kernel = 1 - exp(-b*x)
func NewExpDecay(amp, b, base float64) DecayFunc {
	return func(x float64) float64 {
		k := 1 - math.Exp(-b*x)
		return base + amp*k
	}
}

// NewLogDecay 对数衰减: kernel = ln(1+kx) / (1 + ln(1+kx))  -> 从 0 单调增到 1
func NewLogDecay(amp, kval, base float64) DecayFunc {
	return func(x float64) float64 {
		v := math.Log(1 + kval*x)
		k := 0.0
		if v > 0 {
			k = v / (1 + v)
		}
		return base + amp*k
	}
}

// NewPowerDecay 幂衰减 (power law): kernel = x^p / (x^p + alpha)
func NewPowerDecay(amp, p, alpha, base float64) DecayFunc {
	return func(x float64) float64 {
		if x <= 0 {
			return base
		}
		xp := math.Pow(x, p)
		k := xp / (xp + alpha)
		return base + amp*k
	}
}

// NewInverseDecay 反比例衰减 (Michaelis-Menten / saturating): kernel = x / (x + k)
func NewInverseDecay(amp, k, base float64) DecayFunc {
	return func(x float64) float64 {
		kern := x / (x + k)
		if x == 0 {
			kern = 0
		}
		return base + amp*kern
	}
}

// NewTanhDecay 双曲正切衰减: kernel = tanh(b*x)
func NewTanhDecay(amp, b, base float64) DecayFunc {
	return func(x float64) float64 {
		k := math.Tanh(b * x)
		return base + amp*k
	}
}

// RoundInt 四舍五入到整数
func RoundInt(v float64) int {
	return int(math.Round(v))
}
