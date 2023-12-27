package config

import (
	"net/url"
	"strings"
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
	ClientId          string   `yaml:"clientId"`
	ClientSecret      string   `yaml:"clientSecret"`
	IssuerUrl         string   `yaml:"issuerUrl"` // deprecated: use metadataUrl
	MetadataUrl       string   `yaml:"metadataUrl"`
	EndpiontMountBase string   `yaml:"endpointMountBase"`
	CallbackPath      string   `yaml:"callbackPath"`
	UserInfoPath      string   `yaml:"userInfoPath"`
	Scopes            []string `yaml:"scopes"`
}

type GoidcConfig struct {
	Server ServerConfig `yaml:"server"`
	Oidc   OidConfig    `yaml:"oidc"`
	Routes []Route      `yaml:"routes"`
}

// find mapping that best matches the supplied path
// loops through all the defined routes & matches the
// prefix with the incoming path; the longest-matching path
// is returned
func (p GoidcConfig) FindRouteForPath(path string) *Route {

	var selected Route
	var found bool
	for _, m := range p.Routes {
		if strings.HasPrefix(path, m.Prefix) {
			if len(m.Prefix) > len(selected.Prefix) {
				selected = m
				found = true
			}
		}
	}

	if !found {
		return nil
	}

	return &selected
}
