package proxies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type IPAPIResponse struct {
	Location struct {
		CountryCode string `json:"country_code"`
	} `json:"location"`

	Company struct {
		Type string `json:"type"` // hosting, isp, business, education, government, banking
	} `json:"company"`

	ASN struct {
		CountryCode string `json:"country"`
		Type        string `json:"type"` // hosting, isp, business, education, government, banking
	} `json:"asn"`

	IsMobile bool `json:"is_mobile"`
}

type ISPType string

const (
	ISPHosting     ISPType = "hosting"     // 机房
	ISPResidential ISPType = "residential" // 住宅
	ISPMobile      ISPType = "mobile"      // 移动网络
	ISPBusiness    ISPType = "business"    // 商宽
	ISPEducation   ISPType = "education"   // 教育网
	ISPGovernment  ISPType = "government"  // 政府网络
	ISPBanking     ISPType = "banking"     // 银行/金融网络
	ISPOther       ISPType = "other"       // 未知
)

type IPInfo struct {
	Type      ISPType `json:"type"`        // 分类结果
	Details   string  `json:"details"`     // 中文描述
	IsNative  bool    `json:"is_native"`   // 是否原生
	IsDualISP bool    `json:"is_dual_isp"` // 是否双 ISP
}

func GetISPInfo(client *http.Client) string {
	ctx := context.Background()
	info, err := CheckISPInfoWithIPAPI(ctx, client, "me", "")
	if err != nil || info == nil || info.Type == ISPOther && info.Details == "" {
		return ""
	}

	parts := []string{}
	if info.IsNative {
		parts = append(parts, "原生")
	} else {
		parts = append(parts, "广播")
	}

	if info.Details != "" {
		parts = append(parts, info.Details)
	}

	return "[" + strings.Join(parts, "|") + "]"
}

func CheckISPInfoWithIPAPI(ctx context.Context, client *http.Client, ip, apiKey string) (*IPInfo, error) {
	baseURL, _ := url.Parse("https://api.ipapi.is")

	q := baseURL.Query()
	if apiKey != "" {
		q.Set("key", apiKey)
	}
	if ip != "" && ip != "me" {
		q.Set("q", ip)
	}
	baseURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "subs-check_pro/isp")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipapi API status: %d", resp.StatusCode)
	}

	var data IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// 数据为空或字段缺失 → 返回 nil
	if data.Company.Type == "" && data.ASN.Type == "" && !data.IsMobile {
		return nil, fmt.Errorf("empty response")
	}

	return analyzeIP(&data), nil
}

func analyzeIP(data *IPAPIResponse) *IPInfo {
	info := &IPInfo{}

	companyType := strings.ToLower(data.Company.Type)
	asnType := strings.ToLower(data.ASN.Type)

	// 如果关键字段为空，直接返回空结果
	if companyType == "" && asnType == "" && !data.IsMobile {
		return &IPInfo{}
	}

	// 是否原生IP：IP 注册地与 ASN 注册地一致
	if data.Location.CountryCode != "" && data.ASN.CountryCode != "" {
		info.IsNative = strings.EqualFold(data.Location.CountryCode, data.ASN.CountryCode)
	}

	// 双 ISP 判定：Company 和 ASN 类型均为 ISP
	info.IsDualISP = companyType == "isp" && asnType == "isp"

	// 类型分类 companyType x asnType 矩阵
	// 1. hosting + (非 isp) → 机房
	// 2. hosting + isp → 住宅拨号 VPS
	// 3. isp + isp → 住宅
	// 4. mobile → 移动
	// 5. business → 商宽
	// 6. education → 教育
	// 7. government → 政府
	// 8. banking → 银行
	// 9. other → 机房
	switch {
	// 1. 机房 (Hosting)
	case companyType == "hosting" && asnType != "isp":
		info.Type = ISPHosting
		info.Details = "机房"

	// 2. 住宅拨号 VPS (伪 IDC)
	case companyType == "hosting" && asnType == "isp":
		info.Type = ISPResidential
		info.Details = "住宅拨号"

	// 3. 住宅 (Residential) - 双 ISP
	case info.IsDualISP: // 等价于 companyType == "isp" && asnType == "isp"
		info.Type = ISPResidential
		info.Details = "住宅"

	// 4. 移动网络 (Mobile)
	case data.IsMobile || companyType == "mobile" || asnType == "mobile":
		info.Type = ISPMobile
		info.Details = "移动"

	// 5. 商宽 (Business)
	case companyType == "business" || asnType == "business":
		info.Type = ISPBusiness
		info.Details = "商宽"

	// 6. 教育网
	case companyType == "education" || asnType == "education":
		info.Type = ISPEducation
		info.Details = "教育"

	// 7. 政府网络
	case companyType == "government" || asnType == "government":
		info.Type = ISPGovernment
		info.Details = "政府"

	// 8. 银行网络
	case companyType == "banking" || asnType == "banking":
		info.Type = ISPBanking
		info.Details = "银行"

	// 9. 其他
	default:
		info.Type = ISPOther
		info.Details = "机房"
	}

	return info
}
