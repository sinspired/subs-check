package app

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/sinspired/subs-check/check"
	"github.com/sinspired/subs-check/config"
	"github.com/sinspired/subs-check/save/method"
	"github.com/sinspired/subs-check/utils"
)

const (
	DefaultPort     = ":8199"
	LogTimeFormat   = "2006-01-02 15:04:05"
	MaxLogLines     = 2000
	ShareDirName    = "more"
	TemplatePattern = "templates/*.html"
	StaticPrefix    = "/static"
	AdminPath       = "/admin"
	APIAuthHeader   = "X-API-Key"
	HeaderFromCheck = "X-From-Subs-Check"
	QueryFromCheck  = "from_subs_check"
)

var (
	initAPIKey string
	geneAPIKey string
)

// initHTTPServer 初始化并启动HTTP服务器
func (app *App) initHTTPServer() error {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(app.silentLoggerMiddleware())

	saver, err := method.NewLocalSaver()
	if err != nil {
		return fmt.Errorf("获取http监听目录失败: %w", err)
	}

	app.ensureAPIKey()
	app.registerStaticRoutes(router, saver.OutputPath)

	if err := app.registerShareRoutes(router, saver.OutputPath); err != nil {
		slog.Error("注册分享路由失败", "error", err)
	}

	if !config.GlobalConfig.EnableWebUI {
		slog.Info("Web控制面板已禁用, 仍可通过apiKey访问订阅文件", "api-key", config.GlobalConfig.APIKey)
		router.GET(AdminPath, func(c *gin.Context) {
			c.String(http.StatusForbidden, "Web 控制面板已禁用，请在配置中启用 EnableWebUI")
		})
	} else {
		app.registerWebUIRoutes(router)
		app.registerAPIRoutes(router)
	}

	listenAddr := normalizeListenAddr(config.GlobalConfig.ListenPort)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: router,
	}
	app.httpServer = srv

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP服务器启动失败", "error", err)
		}
	}()

	slog.Info("HTTP 服务器启动", "port", strings.TrimPrefix(listenAddr, ":"))
	return nil
}

// ensureAPIKey 如未设置，生成一个随机值
func (app *App) ensureAPIKey() {
	initAPIKey = config.GlobalConfig.APIKey
	if config.GlobalConfig.APIKey == "" {
		if apiKey := os.Getenv("API_KEY"); apiKey != "" {
			config.GlobalConfig.APIKey = apiKey
		} else {
			config.GlobalConfig.APIKey = utils.GenerateRandomString(10)
			geneAPIKey = config.GlobalConfig.APIKey
			slog.Warn("未设置api-key，已随机生成", "api-key", config.GlobalConfig.APIKey)
		}
	}
}

// silentLoggerMiddleware 通过软件自身发出的部分请求，不显示日志
func (app *App) silentLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Query().Get(QueryFromCheck) == "true" ||
			strings.EqualFold(c.GetHeader(HeaderFromCheck), "true") {
			c.Next()
		} else {
			gin.Logger()(c)
		}
	}
}

// registerStaticRoutes 注册静态路由
//
// - 公共文件：无需鉴权，直接暴露
//
// - 受保护文件：需要鉴权中间件
func (app *App) registerStaticRoutes(router *gin.Engine, outputPath string) {
	// 公共静态文件映射（无需鉴权）
	publicFiles := map[string]string{
		"/ACL4SSR_Online_Full.yaml":     "ACL4SSR_Online_Full.yaml",
		"/bdg.yaml":                     "bdg.yaml",
		"/sub/ACL4SSR_Online_Full.yaml": "ACL4SSR_Online_Full.yaml",
		"/sub/bdg.yaml":                 "bdg.yaml",
	}
	for routePath, fileName := range publicFiles {
		router.StaticFile(routePath, filepath.Join(outputPath, fileName))
	}

	// 受保护静态文件映射（需鉴权）
	authGroup := router.Group("/")
	authGroup.Use(app.authMiddleware())
	protectedFiles := map[string]string{
		"/all.yaml":     "all.yaml",     // 最新节点
		"/history.yaml": "history.yaml", // 历史节点
		"/base64.yaml":  "base64.yaml",  // Base64 格式
		"/mihomo.yaml":  "mihomo.yaml",  // Mihomo 格式
	}
	for routePath, fileName := range protectedFiles {
		authGroup.StaticFile(routePath, filepath.Join(outputPath, fileName))
	}
}

// registerShareRoutes 注册分享路由
func (app *App) registerShareRoutes(router *gin.Engine, outputPath string) error {
	// 加密分享
	if config.GlobalConfig.SharePassword != "" {
		slog.Info("订阅分享 已启用", "code", config.GlobalConfig.SharePassword)
		sharePath := "/sub/" + config.GlobalConfig.SharePassword + "/*filepath"
		router.GET(sharePath, app.handleFileShare(outputPath, true))
	}

	// 公开分享
	moreDirPath := filepath.Join(outputPath, ShareDirName)
	if _, err := os.Stat(moreDirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(moreDirPath, 0755); err != nil {
			return err
		}
	}

	router.GET("/more/*filepath", app.handleFileShare(moreDirPath, false))
	return nil
}

// registerWebUIRoutes 注册WebUI路由
func (app *App) registerWebUIRoutes(router *gin.Engine) {
	slog.Info("启用Web控制面板", "path", "http://ip:port/admin", "api-key", config.GlobalConfig.APIKey)

	router.SetHTMLTemplate(template.Must(template.New("").ParseFS(configFS, TemplatePattern)))

	staticSub, _ := fs.Sub(staticFS, "static")
	router.StaticFS(StaticPrefix, http.FS(staticSub))

	router.GET(AdminPath, func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", gin.H{
			"configPath": app.configPath,
		})
	})

	router.GET("/admin/version", app.getOriginVersion)
}

// registerAPIRoutes 注册api状态路由
func (app *App) registerAPIRoutes(router *gin.Engine) {
	api := router.Group("/api")
	api.Use(app.authMiddleware())
	{
		api.GET("/config", app.getConfig)
		api.POST("/config", app.updateConfig)
		api.GET("/status", app.getStatus)
		api.POST("/trigger-check", app.triggerCheckHandler)
		api.POST("/force-close", app.forceCloseHandler)
		api.GET("/version", app.getVersion)
		api.GET("/singbox-versions", app.getSingboxVersions)
		api.GET("/logs", app.getLogs)
	}
}

// authMiddleware 认证中间件
func (app *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader(APIAuthHeader)
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(config.GlobalConfig.APIKey)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "无效的API密钥"})
			return
		}
		c.Next()
	}
}

// normalizeListenAddr 处理监听端口
func normalizeListenAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultPort
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 65535 {
		return ":" + s
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n <= 65535 {
			return net.JoinHostPort(host, port)
		}
		return DefaultPort
	}
	return DefaultPort
}

// API 处理方法

// getConfig 获取配置
func (app *App) getConfig(c *gin.Context) {
	configData, err := os.ReadFile(app.configPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取配置文件失败: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"content":        string(configData),
		"sub_store_path": config.GlobalConfig.SubStorePath,
	})
}

// updateConfig 更新配置
func (app *App) updateConfig(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}
	var yamlData map[string]any
	if err := yaml.Unmarshal([]byte(req.Content), &yamlData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("YAML格式错误: %v", err)})
		return
	}
	if err := os.WriteFile(app.configPath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存配置文件失败: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "配置已更新"})
}

// getStatus 获取检测状态
func (app *App) getStatus(c *gin.Context) {
	lastCheckTime := ""
	if t, ok := app.lastCheck.time.Load().(time.Time); ok && !t.IsZero() {
		lastCheckTime = t.Format(LogTimeFormat)
	}

	lastCheck := gin.H{}
	if lastCheckTime != "" || app.lastCheck.duration.Load() != 0 || app.lastCheck.Total.Load() != 0 {
		lastCheck = gin.H{
			"time":      lastCheckTime,
			"duration":  app.lastCheck.duration.Load(),
			"total":     app.lastCheck.Total.Load(),
			"available": app.lastCheck.available.Load(),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"checking":   app.checking.Load(),
		"proxyCount": check.ProxyCount.Load(),
		"available":  check.Available.Load(),
		"progress":   check.Progress.Load(),
		"forceClose": check.ForceClose.Load(),
		"successlimited": check.Successlimited.Load(),
		"lastCheck":  lastCheck,
	})
}

func (app *App) triggerCheckHandler(c *gin.Context) {
	app.TriggerCheck()
	c.JSON(http.StatusOK, gin.H{"message": "已触发检测"})
}

func (app *App) forceCloseHandler(c *gin.Context) {
	check.ForceClose.Store(true)
	c.JSON(http.StatusOK, gin.H{"message": "已强制关闭"})
}

// getLogs 获取日志
func (app *App) getLogs(c *gin.Context) {
	logPath := TempLog()
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{"logs": []string{}})
		return
	}
	lines, err := ReadLastNLines(logPath, MaxLogLines)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取日志失败: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": lines})
}

// getVersion 获取版本
func (app *App) getVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": app.version, "latest_version": app.latestVersion})
}

func (app *App) getOriginVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": app.originVersion, "latest_version": app.latestVersion})
}

func (app *App) getSingboxVersions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"latest": utils.LatestSingboxVersion, "old": utils.OldSingboxVersion})
}

// ReadLastNLines 读取最新日志
func ReadLastNLines(filePath string, n int) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ring := make([]string, n)
	count := 0

	for scanner.Scan() {
		ring[count%n] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if count <= n {
		return ring[:count], nil
	}

	result := make([]string, n)
	start := count % n
	copy(result, ring[start:])
	copy(result[n-start:], ring[:start])
	return result, nil
}
