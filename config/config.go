package config

import (
	"net/url"
	"os"

	"gopkg.in/yaml.v2"
)

func LoadConfig() *GoidcConfig {
	env := loadFromEnv()

	path := env.ProxyConfigPath
	yaml, err := loadFromFile(path)
	if err != nil {
		panic(err)
	}

	overrideFromEnv(env, yaml)
	return yaml
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

// overrideFromEnv override GoidcConfig from env
func overrideFromEnv(env EnvConfig, yaml *GoidcConfig) {

	if env.ClientId != "" {
		yaml.Oidc.ClientId = env.ClientId
	}

	if env.ClientSecret != "" {
		yaml.Oidc.ClientSecret = env.ClientSecret
	}

	if env.MetadataUrl != "" {
		yaml.Oidc.MetadataUrl = env.MetadataUrl
	}

	if env.OpenIdUrl != "" {
		yaml.Oidc.OpenIdMetadataUrl = env.OpenIdUrl
	}

	if env.OidcEndpointMount != "" {
		yaml.Oidc.EndpiontMountBase = env.OidcEndpointMount
	}

	if env.AuthCallackPath != "" {
		yaml.Oidc.CallbackPath = env.AuthCallackPath
	}
}
