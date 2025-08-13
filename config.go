package main

import (
	"log"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Matchers []struct {
		Subnets []string      `yaml:"subnets"` // CIDR
		Secret  StringWithEnv `yaml:"secret"`
		Mapper  string        `yaml:"mapper"`
	} `yaml:"matchers"`

	Radius struct {
		TokenExpiry StringWithEnv `yaml:"token_expiry"` // Duration string, e.g., "1h", "30m"
	} `yaml:"radius"`

	StaticUsers []*OAuthUserInfo `yaml:"static_users"`

	OAuth struct {
		UserInfoURL StringWithEnv `yaml:"userinfo_url"`
		TokenURL    StringWithEnv `yaml:"token_url"`
		AuthURL     StringWithEnv `yaml:"auth_url"`
		RedirectURL StringWithEnv `yaml:"redirect_url"`

		Scopes       []string      `yaml:"scopes"`
		ClientID     StringWithEnv `yaml:"client_id"`
		ClientSecret StringWithEnv `yaml:"client_secret"`

		ServerAddr StringWithEnv `yaml:"server_addr"` // e.g., ":8080"
		TLS        struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
	}
}

var (
	globalConfig *Config
	staticUsers  map[string]*OAuthUserInfo
)

func init() {
	fh, err := os.Open("config.yml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	defer func() {
		_ = fh.Close()
	}()

	decoder := yaml.NewDecoder(fh)
	decoder.KnownFields(true)

	globalConfig = &Config{}
	err = decoder.Decode(globalConfig)
	if err != nil {
		log.Fatalf("Failed to decode config: %v", err)
	}

	staticUsers = make(map[string]*OAuthUserInfo)
	for _, user := range globalConfig.StaticUsers {
		staticUsers[user.Username] = user
	}
}

type StringWithEnv string

func (e *StringWithEnv) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return err
	}
	*e = StringWithEnv(os.ExpandEnv(str))
	return nil
}

func GetConfig() *Config {
	return globalConfig
}

func extractIP(addr net.Addr) net.IP {
	switch convAddr := addr.(type) {
	case *net.TCPAddr:
		return convAddr.IP
	case *net.UDPAddr:
		return convAddr.IP
	case *net.IPAddr:
		return convAddr.IP
	default:
		return net.IPv4(0, 0, 0, 0)
	}
}

func GetStaticUserInfo(username string, remoteAddr net.Addr) *OAuthUserInfo {
	userInfo := staticUsers[username]
	for userInfo == nil {
		return nil
	}

	remoteIP := extractIP(remoteAddr)

	for _, ip := range userInfo.AllowedIPs {
		if ip.Equal(remoteIP) {
			return userInfo
		}
	}
	return nil
}
