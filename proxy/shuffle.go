package proxies

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

type ShuffleConfig struct {
	Threshold  float64    // 相邻相似度阈值，IPv4 /24 ≈ 0.75
	Passes     int        // 改善轮数（1~3）
	MinSpacing int        // 同一 IPv4 /24 的最小间距；<=0 关闭
	ScanLimit  int        // 冲突向前扫描的最大距离
	Rand       *rand.Rand // 随机数，为空则使用 time.Now().UnixNano()
}

type serverMeta struct {
	raw      string
	isIPv4   bool
	octets   [4]byte
	prefix24 uint32
	prefixOK bool
}

// SmartShuffleByServer 对 items 就地打乱，避免相邻相似，并尽量满足最小间距
func SmartShuffleByServer(items []map[string]any, cfg ShuffleConfig) {
	n := len(items)
	if n < 2 {
		return
	}

	// 默认参数
	if cfg.Passes <= 0 {
		cfg.Passes = 2
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.75
	}
	if cfg.ScanLimit <= 0 {
		cfg.ScanLimit = 64
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	// 先进行一次完全随机乱序
	rnd.Shuffle(n, func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})

	// 预解析服务器元数据
	metas := make([]serverMeta, n)
	for i := range items {
		if s, _ := items[i]["server"].(string); s != "" {
			metas[i] = parseServerMeta(s)
		}
	}

	// 初次打乱
	rnd.Shuffle(n, func(i, j int) {
		swap(items, metas, i, j)
	})

	// 检查最小间距
	checkSpacing := func(lp map[uint32]int, idx int, m serverMeta) bool {
		if cfg.MinSpacing <= 0 || !m.prefixOK {
			return true
		}
		if last, ok := lp[m.prefix24]; !ok || idx-last > cfg.MinSpacing {
			return true
		}
		return false
	}

	for pass := 0; pass < cfg.Passes; pass++ {
		changed := false
		lastPos := make(map[uint32]int, 64)

		if metas[0].prefixOK {
			lastPos[metas[0].prefix24] = 0
		}

		for i := 0; i < n-1; i++ {
			m1, m2 := metas[i], metas[i+1]
			if m1.prefixOK {
				if _, ok := lastPos[m1.prefix24]; !ok {
					lastPos[m1.prefix24] = i
				}
			}

			if similarity(m1, m2) >= cfg.Threshold || (cfg.MinSpacing > 0 && same24(m1, m2)) {
				bestJ, bestScore := -1, 2.0
				for j := i + 2; j < n && j < i+2+cfg.ScanLimit; j++ {
					mj := metas[j]
					if !checkSpacing(lastPos, i+1, mj) {
						continue
					}
					score := similarity(m1, mj)
					if score < cfg.Threshold {
						swap(items, metas, i+1, j)
						m2, changed = mj, true
						break
					}
					if score < bestScore {
						bestScore, bestJ = score, j
					}
				}
				if m2 == metas[i+1] && bestJ != -1 && checkSpacing(lastPos, i+1, metas[bestJ]) {
					swap(items, metas, i+1, bestJ)
					changed = true
				}
			}

			if metas[i+1].prefixOK {
				lastPos[metas[i+1].prefix24] = i + 1
			}
		}
		if !changed {
			break
		}
	}
}

func parseServerMeta(s string) serverMeta {
	m := serverMeta{raw: s}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			m.isIPv4 = true
			copy(m.octets[:], ip4)
			m.prefix24 = uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8
			m.prefixOK = true
		}
	}
	return m
}

func same24(a, b serverMeta) bool {
	return a.prefixOK && b.prefixOK && a.prefix24 == b.prefix24
}

func similarity(a, b serverMeta) float64 {
	if a.isIPv4 && b.isIPv4 {
		eq := 0
		for i := 0; i < 4; i++ {
			if a.octets[i] == b.octets[i] {
				eq++
			} else {
				break
			}
		}
		return float64(eq) / 4.0
	}
	na, nb := len(a.raw), len(b.raw)
	n := na
	if nb < n {
		n = nb
	}
	i := 0
	for i < n && a.raw[i] == b.raw[i] {
		i++
	}
	maxLen := na
	if nb > maxLen {
		maxLen = nb
	}
	if maxLen == 0 {
		return 0
	}
	return float64(i) / float64(maxLen)
}

func swap(items []map[string]any, metas []serverMeta, i, j int) {
	items[i], items[j] = items[j], items[i]
	metas[i], metas[j] = metas[j], metas[i]
}

// ThresholdToCIDR 根据 Threshold 计算 CIDR 文本
func ThresholdToCIDR(th float64) string {
	switch th {
	case 1.0:
		return "/32"
	case 0.75:
		return "/24"
	case 0.5:
		return "/16"
	case 0.25:
		return "/8"
	default:
		// 兜底逻辑：相似字节数 = 阈值 × 4
		prefix := int(th*4) * 8
		if prefix <=0 {
			prefix = 24
		} else if prefix > 32 {
			prefix = 32
		}
		return fmt.Sprintf("/%d", prefix)
	}
}
