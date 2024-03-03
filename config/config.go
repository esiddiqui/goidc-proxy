package config

import (
	"net/url"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	defaultOidcMountBase    string = "/oidc"
	defaultAuthCallbackPath string = "/authorization-code/callback"
	defaultSessionPath      string = "/session"
	defaultUserInfoPath     string = "/userinfo"
	defaultInfoPath         string = "/info"

	defaultSessionCookieName string = "goidcsessionid"
)

// LoadConfig reads the oidc config from the supplied file
func LoadConfig(path string) *GoidcConfig {

	log.WithField("source", path).Info("loading config")
	cfg, err := loadFromFile(path)
	if err != nil {
		panic(err)
	}

	// set any defaults
	setDefaults(cfg)

	log.WithField("srouce", "environment").Debug("loading config")
	env := loadFromEnv()
	cfg.overrideFromEnv(env)
	return cfg
}

// set defaults
func setDefaults(cfg *GoidcConfig) {

	if cfg.Server.Cookie.Name == "" {
		cfg.Server.Cookie.Name = defaultSessionCookieName
	}

	oidc := &cfg.Oidc

	if oidc.EndpiontMountBase == nil {
		log.WithField("oidc.endpointMountBase", defaultOidcMountBase).Debug("setting value")
		oidc.EndpiontMountBase = &defaultOidcMountBase
	}

	if oidc.CallbackPath == nil {
		log.WithField("oidc.callbackPath", defaultAuthCallbackPath).Debug("setting value")
		oidc.CallbackPath = &defaultAuthCallbackPath
	}

	if oidc.UserInfoPath == nil {
		log.WithField("oidc.userInfoPath", defaultUserInfoPath).Debug("setting value")
		oidc.UserInfoPath = &defaultUserInfoPath
	}

	if oidc.InfoPath == nil {
		log.WithField("oidc.infoPath", defaultInfoPath).Debug("setting value")
		oidc.InfoPath = &defaultInfoPath
	}

	if oidc.SessionPath == nil {
		log.WithField("oidc.sessionPath", defaultSessionPath).Debug("setting value")
		oidc.SessionPath = &defaultSessionPath
	}

}

// loadProxyConfig reads & parses the proxy config from the supplied path
func loadFromFile(path string) (*GoidcConfig, error) {

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := GoidcConfig{}
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	var routes []Route
	for _, m := range cfg.Routes {

		// convert upstream to url
		u, err := url.Parse(m.UpstreamUrl)
		if err != nil {
			return nil, err
		}
		m2 := m
		m2.ProxyUrl = u
		routes = append(routes, m2)
	}
	cfg.Routes = routes

	return &cfg, nil
}
