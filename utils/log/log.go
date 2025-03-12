package log

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

type LogLevel int

var LogLevelSet LogLevel

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
	LogLevelPanic
	InfoColor  = "\033[34m"
	WarnColor  = "\033[33m"
	ErrorColor = "\033[31m"
	DebugColor = "\033[32m"
	ResetColor = "\033[0m"
	TimeFormat = "2006-01-02T15:04:05"
)

var (
	absPath           string
	absPathNormalized string
	location          string
)

func init() {
	wd, err := os.Getwd()
	if err != nil {
		absPath = "."
	} else {
		absPath = wd
	}
	absPathNormalized = strings.ReplaceAll(absPath, "\\", "/")
}

func SetLogLevel(level string) {
	switch level {
	case "debug":
		LogLevelSet = LogLevelDebug
	case "info":
		LogLevelSet = LogLevelInfo
	case "warn":
		LogLevelSet = LogLevelWarn
	case "error":
		LogLevelSet = LogLevelError
	case "fatal":
		LogLevelSet = LogLevelFatal
	case "panic":
		LogLevelSet = LogLevelPanic
	}
}
func log(level LogLevel, format string, v ...any) {
	if level < LogLevelSet {
		return
	}
	var levelStr string
	var color string
	switch level {
	case LogLevelInfo:
		levelStr = "INFO"
		color = InfoColor
	case LogLevelWarn:
		levelStr = "WARN"
		color = WarnColor
	case LogLevelError:
		levelStr = "ERROR"
		color = ErrorColor
	case LogLevelFatal:
		levelStr = "FATAL"
		color = ErrorColor
	case LogLevelDebug:
		levelStr = "DEBUG"
		color = DebugColor
	case LogLevelPanic:
		levelStr = "PANIC"
		color = ErrorColor
	}

	if level == LogLevelDebug || level == LogLevelError {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			file = strings.ReplaceAll(file, "\\", "/")
			if strings.HasPrefix(file, absPathNormalized) {
				relPath := strings.TrimPrefix(file, absPathNormalized)
				relPath = strings.TrimPrefix(relPath, "/")
				location = fmt.Sprintf("%s:%d ", relPath, line)
			} else {
				location = fmt.Sprintf("%s:%d ", file, line)
			}
		}
	} else {
		location = ""
	}

	fmt.Printf("%s%-5s%s [%s] %s%s\n", color, levelStr, ResetColor, time.Now().Format(TimeFormat), location, fmt.Sprintf(format, v...))
}

func Info(format string, v ...any) {
	log(LogLevelInfo, format, v...)
}

func Warn(format string, v ...any) {
	log(LogLevelWarn, format, v...)
}

func Error(format string, v ...any) {
	log(LogLevelError, format, v...)
}

func Fatal(format string, v ...any) {
	log(LogLevelFatal, format, v...)
}
func Debug(format string, v ...any) {
	log(LogLevelDebug, format, v...)
}
func Panic(format string, v ...any) {
	log(LogLevelPanic, format, v...)
}

func MaskURL(url string) string {
	doubleSlashIndex := strings.Index(url, "//")
	if doubleSlashIndex == -1 {
		return url
	}

	domainAndPath := url[doubleSlashIndex+2:]
	pathStart := strings.Index(domainAndPath, "/")
	var domain, path string
	if pathStart == -1 {
		domain = domainAndPath
		path = ""
	} else {
		domain = domainAndPath[:pathStart]
		path = domainAndPath[pathStart:]
	}

	maskedDomain := maskDomain(domain)

	maskedPath := maskPath(path)

	return url[:doubleSlashIndex+2] + maskedDomain + "/" + maskedPath
}

func maskDomain(domain string) string {
	lastDotIndex := strings.LastIndex(domain, ".")
	if lastDotIndex == -1 {
		return domain
	}

	subDomain := domain[:lastDotIndex]
	topLevelDomain := domain[lastDotIndex:]

	if len(subDomain) > 2 {
		maskedSub := string(subDomain[0]) + strings.Repeat("*", len(subDomain)-1)
		maskedSub = maskedSub[:len(maskedSub)-1] + string(subDomain[len(subDomain)-1])
		if len(maskedSub) > 4 {
			maskedSub = maskedSub[:2] + "**" + maskedSub[len(maskedSub)-1:]
		}
		subDomain = maskedSub
	}

	return subDomain + topLevelDomain
}

func maskPath(path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	if len(parts) <= 1 {
		return path
	}

	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}

	for i, part := range parts {
		if len(part) > 8 {
			parts[i] = part[:2] + "..." + part[len(part)-2:]
		}
	}

	return strings.Join(parts, "/")
}
