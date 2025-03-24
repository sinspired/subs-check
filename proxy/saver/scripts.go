package saver

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bestruirui/bestsub/config"
	"github.com/bestruirui/bestsub/proxy/info"
	"github.com/bestruirui/bestsub/utils/log"
)

var (
	tempDir         string
	tempProxiesFile string
)

func init() {
	tempDir = os.TempDir()
	tempProxiesFile = filepath.Join(tempDir, "bestsub_temp_proxies.json")

}

func ExecuteScripts(scripts []string) error {
	if len(scripts) == 0 {
		return nil
	}

	for _, scriptPath := range scripts {
		if err := executeScript(scriptPath); err != nil {
			log.Error("Failed to execute script %s: %v", scriptPath, err)
			return err
		}
	}
	return nil
}

func executeScript(scriptPath string) error {
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("script file not found: %s", scriptPath)
	}

	ext := strings.ToLower(filepath.Ext(scriptPath))
	var cmd *exec.Cmd

	switch ext {
	case ".js":
		cmd = exec.Command("node", scriptPath)
	case ".py":
		cmd = exec.Command("python", scriptPath)
	case ".sh":
		cmd = exec.Command("sh", scriptPath)
	case ".bat":
		cmd = exec.Command("cmd", "/c", scriptPath)
	case ".ps1":
		cmd = exec.Command("powershell", "-File", scriptPath)
	default:
		cmd = exec.Command(scriptPath)
	}

	logFilePath := scriptPath + ".log"
	logFile, err := os.Create(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer logFile.Close()

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	log.Info("Executing script: %s", scriptPath)
	log.Info("Logging output to: %s", logFilePath)
	return cmd.Run()
}

func BeforeSaveDo(results *[]info.Proxy) error {
	log.Info("Executing before-save scripts")
	var rawProxies []map[string]any
	for i := range *results {
		rawProxies = append(rawProxies, (*results)[i].Raw)
		rawProxies[i]["country"] = (*results)[i].Info.Country
		rawProxies[i]["speed"] = (*results)[i].Info.Speed
		rawProxies[i]["disney"] = (*results)[i].Info.Unlock.Disney
		rawProxies[i]["youtube"] = (*results)[i].Info.Unlock.Youtube
		rawProxies[i]["netflix"] = (*results)[i].Info.Unlock.Netflix
		rawProxies[i]["chatgpt"] = (*results)[i].Info.Unlock.Chatgpt
	}

	jsonData, err := json.MarshalIndent(map[string]any{
		"proxies": rawProxies,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize proxies failed: %w", err)
	}

	err = os.WriteFile(tempProxiesFile, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("save proxies to temp file failed: %w", err)
	}

	log.Debug("Proxies saved to temp file: %s", tempProxiesFile)

	ExecuteScripts(config.GlobalConfig.Save.BeforeSaveDo)

	return nil
}

func AfterSaveDo(results *[]info.Proxy) error {
	log.Info("Executing after-save scripts")
	ExecuteScripts(config.GlobalConfig.Save.AfterSaveDo)
	if config.GlobalConfig.LogLevel == "debug" {
		log.Debug("Debug mode, not removing temp file: %s", tempProxiesFile)
	} else {
		err := os.Remove(tempProxiesFile)
		if err != nil {
			return fmt.Errorf("remove temp file failed: %w", err)
		}
		log.Debug("Removed temp file: %s", tempProxiesFile)
	}
	return nil
}
