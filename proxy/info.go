package proxies

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/sinspired/checkip/pkg/ipinfo"
	"github.com/sinspired/subs-check/config"
)

var ipAPIs = []string{
	// 可尝试在api后加 /cdn-cgi/trace, 如能返回loc则不可使用.
	"https://check.torproject.org/api/ip",
	"https://qifu-api.baidubce.com/ip/local/geo/v1/district",
	"https://r.inews.qq.com/api/ip2city",
	"https://g3.letv.com/r?format=1",
	"https://cdid.c-ctrip.com/model-poc2/h",
	"https://whois.pconline.com.cn/ipJson.jsp",
	"https://api.live.bilibili.com/xlive/web-room/v1/index/getIpInfo",
	"https://6.ipw.cn/",                  // IPv4使用了 CFCDN, IPv6 位置准确
	"https://api6.ipify.org?format=json", // IPv4使用了 CFCDN, IPv6 位置准确
}

var geoAPIs = []string{
	"https://ip.122911.xyz/api/ipinfo",
	"https://ident.me/json",
	"https://tnedi.me/json",
	"https://api.seeip.org/geoip",
}

var ipAPIsMe = []string{}

var geoAPIsMe = []string{
	"https://ip.122911.xyz/api/ipinfo",
}

// NewIPInfoClient 创建 ipinfo 检测客户端
func NewIPInfoClient(httpClient *http.Client, db *maxminddb.Reader, ipList, geoList []string) (*ipinfo.Client, error) {
	return ipinfo.New(
		ipinfo.WithHttpClient(httpClient),
		ipinfo.WithDBReader(db),
		ipinfo.WithIPAPIs(ipList...),
		ipinfo.WithGeoAPIs(geoList...),
	)
}

// GetProxyCountry 获取代理节点的位置代码，使用 github.com/sinspired/checkip/pkg/ipinfo API 获取 Analyzed 结果：
//
// - BadCFNode: HK⁻¹
//
// - CFNodeWithSameCountry: HK¹⁺
//
// - CFNodeWithDifferentCountry: HK¹-US⁰
//
// - NodeWithoutCF: HK²
//
// - 前两位字母是实际浏览网站识别的位置, -US⁰为使用CF CDN服务的网站识别的位置, 比如GPT, X等
func GetProxyCountry(httpClient *http.Client, db *maxminddb.Reader, GetAnalyzedCtx context.Context, cfLoc string, cfIP string) (loc string, ip string, countryCodeTag string, err error) {
	// 设置一个临时环境变量，以排除部分api因数据库更新不及时返回的 CN
	os.Setenv("SUBS-CHECK-CALL", "true")
	defer os.Unsetenv("SUBS-CHECK-CALL")

	cliMe, err := NewIPInfoClient(httpClient, db, ipAPIsMe, geoAPIsMe)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建 MeAPI 客户端失败: %s", err))
	} else {
		defer cliMe.Close()
	}

	for range config.GlobalConfig.SubUrlsReTry {
		loc, ip, countryCodeTag, err = cliMe.GetAnalyzed(GetAnalyzedCtx, cfLoc, cfIP)
		if err != nil {
			slog.Debug(fmt.Sprintf("MeAPI 获取节点位置失败: %v", err))
		}
		if loc != "" && countryCodeTag != "" {
			slog.Debug(fmt.Sprintf("MeAPI 获取节点位置成功:%s %s", ip, loc))
			return loc, ip, countryCodeTag, nil
		} else {
			slog.Debug(fmt.Sprintf("MeAPI 获取节点位置失败:%s: %s-%s", ip, loc, countryCodeTag))
		}
	}

	// 如失败，使用混合检测，不需要多次重试
	cli, err := NewIPInfoClient(httpClient, db, ipAPIs, geoAPIs)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建 ipinfo 主客户端失败: %s", err))
	} else {
		defer cli.Close()
		loc, ip, countryCodeTag, err = cli.GetAnalyzed(GetAnalyzedCtx, cfLoc, cfIP)
		if err != nil {
			slog.Debug(fmt.Sprintf("Analyzed 获取节点位置失败: %v", err))
			return "", "", "", nil
		}
		if loc != "" && countryCodeTag != "" {
			slog.Debug(fmt.Sprintf("Analyzed 获取节点位置成功: %s %s", loc, countryCodeTag))
			return loc, ip, countryCodeTag, nil
		} else {
			slog.Debug(fmt.Sprintf("Analyzed 获取节点位置空白: %s-%s", loc, countryCodeTag))
		}
	}
	return "", "", "", nil
}

func GetEdgeOneProxy(httpClient *http.Client) (loc string, ip string) {
	type GeoResponse struct {
		Eo struct {
			Geo struct {
				CountryCodeAlpha2 string `json:"countryCodeAlpha2"`
			} `json:"geo"`
			ClientIP string `json:"clientIp"`
		} `json:"eo"`
	}

	url := "https://functions-geolocation.edgeone.app/geo"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建请求失败: %s", err))
		return
	}
	req.Header.Set("User-Agent", convert.RandUserAgent())
	resp, err := httpClient.Get(url)
	if err != nil {
		slog.Debug(fmt.Sprintf("edgeone获取节点位置失败: %s", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Debug(fmt.Sprintf("edgeone返回非200状态码: %v", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("edgeone读取节点位置失败: %s", err))
		return
	}

	var eo GeoResponse
	err = json.Unmarshal(body, &eo)
	if err != nil {
		slog.Debug(fmt.Sprintf("解析edgeone JSON 失败: %v", err))
		return
	}

	return eo.Eo.Geo.CountryCodeAlpha2, eo.Eo.ClientIP
}

func GetCFProxy(httpClient *http.Client) (loc string, ip string) {
	url := "https://www.cloudflare.com/cdn-cgi/trace"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建请求失败: %s", err))
		return
	}
	req.Header.Set("User-Agent", convert.RandUserAgent())
	resp, err := httpClient.Get(url)
	if err != nil {
		slog.Debug(fmt.Sprintf("cf获取节点位置失败: %s", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Debug(fmt.Sprintf("cf返回非200状态码: %v", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("cf读取节点位置失败: %s", err))
		return
	}

	// Parse the response text to find loc=XX
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimPrefix(line, "loc=")
		}
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		}
	}
	return
}

func GetIPLark(httpClient *http.Client) (loc string, ip string) {
	type GeoIPData struct {
		IP      string `json:"ip"`
		Country string `json:"country_code"`
	}

	url := string([]byte{104, 116, 116, 112, 115, 58, 47, 47, 102, 51, 98, 99, 97, 48, 101, 50, 56, 101, 54, 98, 46, 97, 97, 112, 113, 46, 110, 101, 116, 47, 105, 112, 97, 112, 105, 47, 105, 112, 99, 97, 116})
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建请求失败: %s", err))
		return
	}
	req.Header.Set("User-Agent", "curl/8.7.1")
	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Debug(fmt.Sprintf("iplark获取节点位置失败: %s", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Debug(fmt.Sprintf("iplark返回非200状态码: %v", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("iplark读取节点位置失败: %s", err))
		return
	}

	var geo GeoIPData
	err = json.Unmarshal(body, &geo)
	if err != nil {
		slog.Debug(fmt.Sprintf("解析iplark JSON 失败: %v", err))
		return
	}

	return geo.Country, geo.IP
}

func GetMe(httpClient *http.Client) (loc string, ip string) {
	type GeoIPData struct {
		IP      string `json:"ip"`
		Country string `json:"country_code"`
	}

	url := "https://ip.122911.xyz/api/ipinfo"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Debug(fmt.Sprintf("创建请求失败: %s", err))
		return
	}
	req.Header.Set("User-Agent", "subs-check")
	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Debug(fmt.Sprintf("me获取节点位置失败: %s", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Debug(fmt.Sprintf("me返回非200状态码: %v", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("me读取节点位置失败: %s", err))
		return
	}

	var geo GeoIPData
	err = json.Unmarshal(body, &geo)
	if err != nil {
		slog.Debug(fmt.Sprintf("解析me JSON 失败: %v", err))
		return
	}

	return geo.Country, geo.IP
}
