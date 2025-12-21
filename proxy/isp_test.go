package proxies

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// 获取 API Key（建议放在环境变量中）
func getAPIKey() string {
	apiKey := os.Getenv("IPAPI_KEY")
	return apiKey
}

// TestCurrentIP 测试当前网络出口 IP
func TestCurrentIP(t *testing.T) {
	apiKey := getAPIKey()
	client := &http.Client{Timeout: 10 * time.Second}

	// ipapi.is 支持传入空字符串或 "me" 来获取当前出口 IP
	info, err := CheckISPInfoWithIPAPI(context.Background(), client, "me", apiKey)
	if err != nil {
		t.Fatalf("查询当前 IP 失败: %v", err)
	}

	t.Logf("当前网络出口 IP 信息: %+v", info)
}

// TestSpecificIP 测试指定 IP
func TestSpecificIP(t *testing.T) {
	apiKey := getAPIKey()
	client := &http.Client{Timeout: 10 * time.Second}

	// 这里用一个常见的公共 IP，例如 Google DNS
	ip := "8.8.8.8"

	info, err := CheckISPInfoWithIPAPI(context.Background(), client, ip, apiKey)
	if err != nil {
		t.Fatalf("查询指定 IP %s 失败: %v", ip, err)
	}

	t.Logf("指定 IP (%s) 信息: %+v", ip, info)
}

func TestGetISPInfo(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
	ispInfo := GetISPInfo(client)
	t.Logf("ISP 信息: %s", ispInfo)
}