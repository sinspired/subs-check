package utils

import (
	"net/http"
	"net/url"
	"time"

	"github.com/bestruirui/bestsub/config"
	"golang.org/x/net/proxy"
)

func NewHTTPClient() *http.Client {
	var client *http.Client

	if config.GlobalConfig.Proxy.Type == "http" {
		proxyURLStr := config.GlobalConfig.Proxy.Address
		if config.GlobalConfig.Proxy.Username != "" && config.GlobalConfig.Proxy.Password != "" {
			parsedURL, err := url.Parse(proxyURLStr)
			if err == nil {
				proxyURLStr = (&url.URL{
					Scheme: parsedURL.Scheme,
					User:   url.UserPassword(config.GlobalConfig.Proxy.Username, config.GlobalConfig.Proxy.Password),
					Host:   parsedURL.Host,
					Path:   parsedURL.Path,
				}).String()
			}
		}

		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			client = &http.Client{Timeout: 30 * time.Second}
		} else {
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
		}
	} else if config.GlobalConfig.Proxy.Type == "socks" {
		var auth *proxy.Auth
		if config.GlobalConfig.Proxy.Username != "" && config.GlobalConfig.Proxy.Password != "" {
			auth = &proxy.Auth{
				User:     config.GlobalConfig.Proxy.Username,
				Password: config.GlobalConfig.Proxy.Password,
			}
		}

		socksDialer, err := proxy.SOCKS5("tcp", config.GlobalConfig.Proxy.Address, auth, proxy.Direct)
		if err != nil {
			client = &http.Client{Timeout: 30 * time.Second}
		} else {
			transport := &http.Transport{Dial: socksDialer.Dial}
			client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
		}
	} else {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	return client
}
