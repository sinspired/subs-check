package proxies

import (
	"fmt"
	"math/rand/v2"
	"net"
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

	// 预解析服务器元数据
	metas := make([]serverMeta, n)
	for i := range items {
		if s, _ := items[i]["server"].(string); s != "" {
			metas[i] = parseServerMeta(s)
		}
	}

	// 初次完全打乱 (同时打乱 items 和 metas)
	rand.Shuffle(n, func(i, j int) {
		swap(items, metas, i, j)
	})

	// 检查最小间距的闭包函数
	checkSpacing := func(lp map[uint32]int, idx int, m serverMeta) bool {
		if cfg.MinSpacing <= 0 || !m.prefixOK {
			return true
		}
		// idx 是放置候选节点的位置，last 是上一次出现该 IP 段的位置
		// 要求: 当前位置 - 上次位置 > 最小间距
		if last, ok := lp[m.prefix24]; !ok || idx-last > cfg.MinSpacing {
			return true
		}
		return false
	}

	for pass := 0; pass < cfg.Passes; pass++ {
		changed := false
		// 每次 pass 重置 lastPos map，容量建议设为 n 或 64
		lastPos := make(map[uint32]int, 64)

		// 记录第 0 个元素的位置
		if metas[0].prefixOK {
			lastPos[metas[0].prefix24] = 0
		}

		for i := 0; i < n-1; i++ {
			// 记录当前节点 i 的位置信息（为了给后续节点判断间距用）
			m1, m2 := metas[i], metas[i+1]

			// 检查 items[i] 和 items[i+1] 是否冲突
			conflict := similarity(m1, m2) >= cfg.Threshold ||
				(cfg.MinSpacing > 0 && same24(m1, m2))

			if conflict {
				bestJ, bestScore := -1, 2.0 // 2.0 大于任何可能的相似度(最大1.0)

				// 向后搜索合适的候选者 j 来替换 i+1
				searchEnd := i + 2 + cfg.ScanLimit
				if searchEnd > n {
					searchEnd = n
				}

				for j := i + 2; j < searchEnd; j++ {
					mj := metas[j]

					// 候选者 mj 放到 i+1 的位置，必须满足与 m1 的间距要求
					// 这里的 lastPos 记录的是 i 及其之前的状态
					if !checkSpacing(lastPos, i+1, mj) {
						continue
					}

					score := similarity(m1, mj)

					// 如果找到一个足够好的，直接交换并跳出
					if score < cfg.Threshold {
						swap(items, metas, i+1, j)
						// 更新 m2 为新的节点，用于下一轮 i+1 和 i+2 的比较
						m2 = mj
						changed = true
						break
					}

					// 否则记录当前找到的相对最好的
					if score < bestScore {
						bestScore, bestJ = score, j
					}
				}

				// 如果没找到完美的，但找到了相对较好的，且满足间距要求，则通过
				// 注意：这里 m2 == metas[i+1] 说明上面的 break 没触发
				if !changed && bestJ != -1 {
					// 再次确认间距（其实上面循环里确认过了，但为了保险）
					if checkSpacing(lastPos, i+1, metas[bestJ]) {
						swap(items, metas, i+1, bestJ)
						changed = true

						m2 = metas[i+1]
					}
				}
			}

			// 更新 lastPos：现在 i+1 位置的元素已经确定（可能是换过来的，也可能是原来的）
			if m2.prefixOK {
				lastPos[m2.prefix24] = i + 1
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
			// 计算前24位: octet 0,1,2
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
	if na == 0 || nb == 0 {
		return 0
	}
	n := min(na, nb)
	i := 0
	for i < n && a.raw[i] == b.raw[i] {
		i++
	}
	maxLen := max(na, nb)
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
		if prefix <= 0 {
			prefix = 24
		} else if prefix > 32 {
			prefix = 32
		}
		return fmt.Sprintf("/%d", prefix)
	}
}
