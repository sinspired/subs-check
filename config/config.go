// Package config 解析配置文件
package config

import (
	_ "embed"
)

type SingBoxConfig struct {
	Version string   `yaml:"version"`
	JSON    []string `yaml:"json"`
	JS      []string `yaml:"js"`
}

type Config struct {
	PrintProgress        bool     `yaml:"print-progress"`
	ProgressMode         string   `yaml:"progress-mode"`
	Concurrent           int      `yaml:"concurrent"`
	AliveConcurrent      int      `yaml:"alive-concurrent"`
	SpeedConcurrent      int      `yaml:"speed-concurrent"`
	MediaConcurrent      int      `yaml:"media-concurrent"`
	CheckInterval        int      `yaml:"check-interval"`
	CronExpression       string   `yaml:"cron-expression"`
	SpeedTestURL         string   `yaml:"speed-test-url"`
	DownloadTimeout      int      `yaml:"download-timeout"`
	DownloadMB           int      `yaml:"download-mb"`
	TotalSpeedLimit      int      `yaml:"total-speed-limit"`
	Threshold            float32  `yaml:"threshold"`
	MinSpeed             int      `yaml:"min-speed"`
	Timeout              int      `yaml:"timeout"`
	FilterRegex          string   `yaml:"filter-regex"`
	SaveMethod           string   `yaml:"save-method"`
	WebDAVURL            string   `yaml:"webdav-url"`
	WebDAVUsername       string   `yaml:"webdav-username"`
	WebDAVPassword       string   `yaml:"webdav-password"`
	GithubToken          string   `yaml:"github-token"`
	GithubGistID         string   `yaml:"github-gist-id"`
	GithubAPIMirror      string   `yaml:"github-api-mirror"`
	WorkerURL            string   `yaml:"worker-url"`
	WorkerToken          string   `yaml:"worker-token"`
	S3Endpoint           string   `yaml:"s3-endpoint"`
	S3AccessID           string   `yaml:"s3-access-id"`
	S3SecretKey          string   `yaml:"s3-secret-key"`
	S3Bucket             string   `yaml:"s3-bucket"`
	S3UseSSL             bool     `yaml:"s3-use-ssl"`
	S3BucketLookup       string   `yaml:"s3-bucket-lookup"`
	SubUrlsReTry         int      `yaml:"sub-urls-retry"`
	SubUrlsRetryInterval int      `yaml:"sub-urls-retry-interval"`
	SubUrlsTimeout       int      `yaml:"sub-urls-timeout"`
	SubUrlsRemote        []string `yaml:"sub-urls-remote"`
	SubUrls              []string `yaml:"sub-urls"`
	SubURLsStats         bool     `yaml:"sub-urls-stats"`
	SuccessRate          float32  `yaml:"success-rate"`
	MihomoAPIURL         string   `yaml:"mihomo-api-url"`
	MihomoAPISecret      string   `yaml:"mihomo-api-secret"`
	ListenPort           string   `yaml:"listen-port"`
	RenameNode           bool     `yaml:"rename-node"`
	KeepSuccessProxies   bool     `yaml:"keep-success-proxies"`
	OutputDir            string   `yaml:"output-dir"`
	AppriseAPIServer     string   `yaml:"apprise-api-server"`
	RecipientURL         []string `yaml:"recipient-url"`
	NotifyTitle          string   `yaml:"notify-title"`
	SubStorePort         string   `yaml:"sub-store-port"`
	SubStorePath         string   `yaml:"sub-store-path"`
	SubStoreSyncCron     string   `yaml:"sub-store-sync-cron"`
	SubStorePushService  string   `yaml:"sub-store-push-service"`
	SubStoreProduceCron  string   `yaml:"sub-store-produce-cron"`
	MihomoOverwriteURL   string   `yaml:"mihomo-overwrite-url"`
	MediaCheck           bool     `yaml:"media-check"`
	Platforms            []string `yaml:"platforms"`
	MaxMindDBPath        string   `yaml:"maxmind-db-path"`
	DropBadCfNodes       bool     `yaml:"drop-bad-cf-nodes"`
	EnhancedTag          bool     `yaml:"enhanced-tag"`
	SuccessLimit         int32    `yaml:"success-limit"`
	NodePrefix           string   `yaml:"node-prefix"`
	NodeType             []string `yaml:"node-type"`
	EnableWebUI          bool     `yaml:"enable-web-ui"`
	APIKey               string   `yaml:"api-key"`
	SharePassword        string   `yaml:"share-password"`
	CallbackScript       string   `yaml:"callback-script"`
	SystemProxy          string   `yaml:"system-proxy"`
	GithubProxy          string   `yaml:"github-proxy"`
	GithubProxyGroup     []string `yaml:"ghproxy-group"`
	EnableSelfUpdate     bool     `yaml:"update"`
	UpdateOnStartup      bool     `yaml:"update-on-startup"`
	CronCheckUpdate      string   `yaml:"cron-check-update"`
	Prerelease           bool     `yaml:"prerelease"`
	UpdateTimeout        int      `yaml:"update-timeout"`

	// 新增 singbox的ios版本停留在1.11，这里进行兼容
	SingboxLatest SingBoxConfig `yaml:"singbox-latest"`
	SingboxOld    SingBoxConfig `yaml:"singbox-old"`
}

var GlobalConfig = &Config{
	// 新增配置，给未更改配置文件的用户一个默认值
	ListenPort:         ":8199",
	NotifyTitle:        "🔔 节点状态更新",
	MihomoOverwriteURL: "http://127.0.0.1:8199/ACL4SSR_Online_Full.yaml",
	Platforms:          []string{"openai", "youtube", "netflix", "disney", "gemini", "iprisk"},
	DownloadMB:         20,
}

//go:embed config.example.yaml
var DefaultConfigTemplate []byte
