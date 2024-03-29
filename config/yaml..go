package config

import (
	"net/url"

	"github.com/esiddiqui/goidc-proxy/types"
	log "github.com/sirupsen/logrus"
)

type Route struct {
	Prefix       string   `yaml:"prefix"`
	StripPrefix  bool     `yaml:"stripPrefix"`
	UpstreamUrl  string   `yaml:"upstreamUrl"`
	AuthRequired bool     `yaml:"authRequired"`
	ProxyUrl     *url.URL `yaml:"-"`
}

type CookieAgePolicy string

const (
	AgePolicySupplied CookieAgePolicy = "supplied"
	AgePolicyAligned  CookieAgePolicy = "aligned"
)

type CookieConfig struct {
	Name       string `yaml:"name"`
	AgeSeconds int    `yaml:"ageSeconds"`
	Secure     bool   `yaml:"secure"`
	Session    bool   `yaml:"session"` // TODO check & remove
	Ttl        string `yaml:"ttl"`     // TODO check & remove
}

type SessionType string

const (
	SessionTypeMemory SessionType = "memory"
	SessionTypeRedis  SessionType = "redis"
)

type StoreConfig struct {
	Type SessionType `yaml:"type"`
	Host string      `yaml:"host"`
	Port int32       `yaml:"port"`
}

type SessionConfig struct {
	Store  StoreConfig  `yaml:"store"`
	Cookie CookieConfig `yaml:"cookie"`
}

type ServerConfig struct {
	Port    int32         `yaml:"port"`
	Cookie  CookieConfig  `yaml:"cookie"`
	Session SessionConfig `yaml:"session"`
}

type OidConfig struct {
	ClientId          string                    `yaml:"clientId"`
	ClientSecret      string                    `yaml:"clientSecret"`
	MetadataUrl       string                    `yaml:"metadataUrl"`       // public url for fetching metadata
	Metadata          *types.AuthServerMetadata `yaml:"metadata"`          // if supplied `metadataUrl` is ignored
	OpenIdMetadataUrl string                    `yaml:"openIdMetadataUrl"` // public url for fetching openId metadata
	OpenIdMetadata    *GoidcConfig              `yaml:"openIdMetadata"`    // if supplied `openIdMetadataUrl` is ignored
	EndpiontMountBase *string                   `yaml:"endpointMountBase"` // the base path to mount all oidc paths
	CallbackPath      *string                   `yaml:"callbackPath"`      // sub-path to handle auth-code callback
	UserInfoPath      *string                   `yaml:"userInfoPath"`      // sub-path to handle userInfo path (available when oidc userInfo endpoint exists)
	InfoPath          *string                   `yaml:"infoPath"`          // sub-path for info path
	SessionPath       *string                   `yaml:"sessionPath"`       // sub-path for session path
	Scopes            []string                  `yaml:"scopes"`
}

type GoidcConfig struct {
	Server  ServerConfig  `yaml:"server"`
	Session SessionConfig `yaml:"session"`
	Oidc    OidConfig     `yaml:"oidc"`
	Routes  []Route       `yaml:"routes"`
}

// override some values from environment if they are set.
// environment always takes precedence
func (c *GoidcConfig) overrideFromEnv(env EnvConfig) {

	if env.ClientId != "" {
		log.WithField("source", "environment").Debug("reading client_id")
		c.Oidc.ClientId = env.ClientId
	}

	if env.ClientSecret != "" {
		log.WithField("source", "environment").Debug("reading client_secret")
		c.Oidc.ClientSecret = env.ClientSecret
	}

}
