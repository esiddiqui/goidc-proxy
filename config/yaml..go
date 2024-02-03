package config

import (
	"net/url"
)

type Route struct {
	Prefix       string   `yaml:"prefix"`
	StripPrefix  bool     `yaml:"stripPrefix"`
	UpstreamUrl  string   `yaml:"upstreamUrl"`
	AuthRequired bool     `yaml:"authRequired"`
	ProxyUrl     *url.URL `yaml:"-"`
}

type CookieConfig struct {
	Name    string `yaml:"name"`
	Session bool   `yaml:"session"`
	Ttl     string `yaml:"ttl"`
	Secure  bool   `yaml:"secure"`
}

type SessionType string

const (
	SessionTypeNone   SessionType = "none"
	SessionTypeMemory SessionType = "memory"
	SessionTypeRedis  SessionType = "redis"
)

type SessionConfig struct {
	Type SessionType `yaml:"type"`
	Host string      `yaml:"host"`
	Port int32       `yaml:"port"`
}

type ServerConfig struct {
	Port    int32         `yaml:"port"`
	Cookie  CookieConfig  `yaml:"cookie"`
	Session SessionConfig `yaml:"session"`
}

type OidConfig struct {
	ClientId          string         `yaml:"clientId"`
	ClientSecret      string         `yaml:"clientSecret"`
	MetadataUrl       string         `yaml:"metadataUrl"`       // public url for fetching metadata
	Metadata          *GoidcMetadata `yaml:"metadata"`          // if supplied `metadataUrl` is ignored
	OpenIdMetadataUrl string         `yaml:"openIdMetadataUrl"` // public url for fetching openId metadata
	OpenIdMetadata    *GoidcConfig   `yaml:"openIdMetadata"`    // if supplied `openIdMetadataUrl` is ignored
	EndpiontMountBase *string        `yaml:"endpointMountBase"` // the base path to mount all oidc paths
	CallbackPath      *string        `yaml:"callbackPath"`      // sub-path to handle auth-code callback
	UserInfoPath      *string        `yaml:"userInfoPath"`      // sub-path to handle userInfo path (available when oidc userInfo endpoint exists)
	InfoPath          *string        `yaml:"infoPath"`          // sub-path for info path
	SessionPath       *string        `yaml:"sessionPath"`       // sub-path for session path
	Scopes            []string       `yaml:"scopes"`
}

type GoidcConfig struct {
	Server ServerConfig `yaml:"server"`
	Oidc   OidConfig    `yaml:"oidc"`
	Routes []Route      `yaml:"routes"`
}
