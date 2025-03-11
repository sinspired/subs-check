package saver

import (
	"fmt"

	"github.com/bestruirui/bestsub/config"
	"github.com/bestruirui/bestsub/proxy/info"
	"github.com/bestruirui/bestsub/utils"
	"github.com/bestruirui/bestsub/utils/log"
	"gopkg.in/yaml.v3"
)

type ProxyCategory struct {
	Name    string
	Proxies []map[string]any
	Filter  func(result info.Proxy) bool
}

type ConfigSaver struct {
	results     *[]info.Proxy
	categories  []ProxyCategory
	saveMethods []func([]byte, string) error
}

func NewConfigSaver(results *[]info.Proxy) *ConfigSaver {
	return &ConfigSaver{
		results:     results,
		saveMethods: chooseSaveMethods(),
		categories: []ProxyCategory{
			{
				Name:    "all.yaml",
				Proxies: make([]map[string]any, 0),
				Filter: func(result info.Proxy) bool {
					if utils.Contains(config.GlobalConfig.Check.Items, "speed") {
						if result.Info.Speed > config.GlobalConfig.Check.MinSpeed || result.Info.SpeedSkip {
							return true
						} else {
							log.Debug("proxy %s speed %d does not meet the condition, skipping", result.Raw["name"], result.Info.Speed)
							return false
						}
					}
					return result.Info.Alive
				},
			},
			{
				Name:    "openai.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result info.Proxy) bool { return result.Info.Unlock.Chatgpt },
			},
			{
				Name:    "youtube.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result info.Proxy) bool { return result.Info.Unlock.Youtube },
			},
			{
				Name:    "netflix.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result info.Proxy) bool { return result.Info.Unlock.Netflix },
			},
			{
				Name:    "disney.yaml",
				Proxies: make([]map[string]any, 0),
				Filter:  func(result info.Proxy) bool { return result.Info.Unlock.Disney },
			},
		},
	}
}

func SaveConfig(results *[]info.Proxy) {
	if len(config.GlobalConfig.Save.BeforeSaveDo) > 0 {
		if err := BeforeSaveDo(results); err != nil {
			log.Error("Failed to execute before-save scripts: %v", err)
		}
	}

	saver := NewConfigSaver(results)
	if err := saver.Save(); err != nil {
		log.Error("save config failed: %v", err)
	}

	if len(config.GlobalConfig.Save.AfterSaveDo) > 0 {
		if err := AfterSaveDo(results); err != nil {
			log.Error("Failed to execute after-save scripts: %v", err)
		}
	}
}

func (cs *ConfigSaver) Save() error {
	cs.categorizeProxies()

	for _, category := range cs.categories {
		if err := cs.saveCategory(category); err != nil {
			log.Error("save %s category failed: %v", category.Name, err)
			continue
		}
	}

	return nil
}

func (cs *ConfigSaver) categorizeProxies() {
	for _, result := range *cs.results {
		for i := range cs.categories {
			if cs.categories[i].Filter(result) {
				cs.categories[i].Proxies = append(cs.categories[i].Proxies, result.Raw)
			}
		}
	}
}

func (cs *ConfigSaver) saveCategory(category ProxyCategory) error {
	if len(category.Proxies) == 0 {
		log.Warn("%s proxies are empty, skip", category.Name)
		return nil
	}
	log.Debug("save %s category %v proxies", category.Name, len(category.Proxies))
	yamlData, err := yaml.Marshal(map[string]any{
		"proxies": category.Proxies,
	})
	if err != nil {
		return fmt.Errorf("serialize %s failed: %w", category.Name, err)
	}

	for _, saveMethod := range cs.saveMethods {
		if err := saveMethod(yamlData, category.Name); err != nil {
			log.Error("save %s failed with one method: %v", category.Name, err)
		}
	}

	return nil
}

func chooseSaveMethods() []func([]byte, string) error {
	methods := make([]func([]byte, string) error, 0)

	// 遍历配置的保存方法
	for _, methodName := range config.GlobalConfig.Save.Method {
		switch methodName {
		case "r2":
			if err := ValiR2Config(); err == nil {
				methods = append(methods, UploadToR2Storage)
			} else {
				log.Error("R2 config is incomplete: %v", err)
			}
		case "gist":
			if err := ValiGistConfig(); err == nil {
				methods = append(methods, UploadToGist)
			} else {
				log.Error("Gist config is incomplete: %v", err)
			}
		case "webdav":
			if err := ValiWebDAVConfig(); err == nil {
				methods = append(methods, UploadToWebDAV)
			} else {
				log.Error("WebDAV config is incomplete: %v", err)
			}
		case "http":
			if err := ValiHTTPConfig(); err == nil {
				methods = append(methods, SaveToHTTP)
			} else {
				log.Error("HTTP config is incomplete: %v", err)
			}
		case "local":
			methods = append(methods, SaveToLocal)
		default:
			log.Error("unknown save method: %s", methodName)
		}
	}

	if len(methods) == 0 {
		log.Warn("no valid save methods configured, using local save only")
		methods = append(methods, SaveToLocal)
	}

	return methods
}
