package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Matchers []struct {
		Subnets []string `yaml:"subnets"` // CIDR
		Secret  string   `yaml:"secret"`
		Mapper  string   `yaml:"mapper"`
	} `yaml:"matchers"`

	Radius struct {
		TokenExpiry string `yaml:"token_expiry"` // Duration string, e.g., "1h", "30m"
	} `yaml:"radius"`

	OAuth struct {
		UserInfoURL string `yaml:"user_info_url"`
		TokenURL    string `yaml:"token_url"`
		AuthURL     string `yaml:"auth_url"`
		RedirectURL string `yaml:"redirect_url"`

		Scopes       []string `yaml:"scopes"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`

		ServerAddr string `yaml:"server_addr"` // e.g., ":8080"
		TLS        struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
	}
}

var globalConfig *Config

func init() {
	fh, err := os.Open("config.yml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	defer fh.Close()

	decoder := yaml.NewDecoder(fh)

	globalConfig = &Config{}
	err = decoder.Decode(globalConfig)
	if err != nil {
		log.Fatalf("Failed to decode config: %v", err)
	}
}

func GetConfig() *Config {
	return globalConfig
}
