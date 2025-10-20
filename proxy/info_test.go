package proxies

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/sinspired/checkip/pkg/ipinfo"
	"github.com/sinspired/subs-check/assets"
)

func TestGetAnalyzed(t *testing.T) {
	// 使用 subs-check 自己的 assets 包
	db, err := assets.OpenMaxMindDB("")

	if err != nil {
		t.Errorf("打开 MaxMind 数据库失败: %v", err)
		// 数据库打开失败时，设置为 nil，后续代码会处理这种情况
		db = nil
	}

	// 确保数据库在函数结束时关闭
	if db != nil {
		defer func() {
			if err := db.Close(); err != nil {
				t.Errorf("关闭 MaxMind 数据库失败: %v", err)
			}
		}()
	}
	// os.Setenv("SUBS-CHECK-CALL", "true")
	// defer os.Unsetenv("SUBS-CHECK-CALL")
	cli, err := ipinfo.New(
		ipinfo.WithHttpClient(&http.Client{}),
		ipinfo.WithDBReader(db),
		ipinfo.WithIPAPIs(
		// "https://ip.122911.xyz/api/ipinfo",
		// "https://check.torproject.org/api/ip",
		// "https://qifu-api.baidubce.com/ip/local/geo/v1/district",
		// "https://r.inews.qq.com/api/ip2city",
		// "https://g3.letv.com/r?format=1",
		// "https://cdid.c-ctrip.com/model-poc2/h",
		// "https://whois.pconline.com.cn/ipJson.jsp",
		// "https://api.live.bilibili.com/xlive/web-room/v1/index/getIpInfo",
		// "https://6.ipw.cn/",                  // IPv4使用了 CFCDN, IPv6 位置准确
		// "https://api6.ipify.org?format=json", // IPv4使用了 CFCDN, IPv6 位置准确
		),
		ipinfo.WithGeoAPIs(
		// "https://ip.122911.xyz/api/ipinfo",
		// "https://ident.me/json",
		// "https://tnedi.me/json",
		// "https://api.seeip.org/geoip",
		),
	)
	if err != nil {
		t.Errorf("%s", fmt.Sprintf("创建 ipinfo 客户端失败: %s", err))
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	loc, _, countryCodeTag, _ := cli.GetAnalyzed(ctx, "", "")
	if loc != "" && countryCodeTag != "" {
		t.Logf("GetAnalyzed 获取节点位置成功: %s %s", loc, countryCodeTag)
	} else {
		t.Error("未获取到数据，说明api不可用，或者查询逻辑未涵盖")
	}
}

func TestLookupGeoIPDataWithMMDB(t *testing.T) {
	// 使用 subs-check 自己的 assets 包
	db, err := assets.OpenMaxMindDB("")

	if err != nil {
		t.Errorf("打开 MaxMind 数据库失败: %v", err)
		// 数据库打开失败时，设置为 nil，后续代码会处理这种情况
		db = nil
	}

	// 确保数据库在函数结束时关闭
	if db != nil {
		defer func() {
			if err := db.Close(); err != nil {
				t.Errorf("关闭 MaxMind 数据库失败: %v", err)
			}
		}()
	}

	cli, err := ipinfo.New(
		ipinfo.WithHttpClient(&http.Client{}),
		ipinfo.WithDBReader(db),
	)
	if err != nil {
		t.Errorf("%s", fmt.Sprintf("创建 ipinfo 客户端失败: %s", err))
	}
	defer cli.Close()

	ip := "2a09:bac5:3988:263c::3cf:59"

	ipData := ipinfo.CreateIPDataFromIP(ip)

	_, err = cli.LookupGeoIPDataWithMMDB(ipData)
	if err != nil {
		t.Errorf("获取 MaxMind 数据失败: %v", err)
	} else {
		t.Logf("IP: %s, Country Code: %s, City: %s", ip, ipData.CountryCode, ipData.CountryName)
		if ipData.CountryCode == "" {
			t.Error("未能获取有效国家代码")
		}
	}
}
