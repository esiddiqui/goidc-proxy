package config

import (
	"os"
	"strconv"
	"strings"
)

type EnvConfig struct {
	ProxyPort                     int32    // "8080"
	UpstreamBaseUri               string   // "localhost:8080"
	ProxyConfigPath               string   // path for proxy configuration, default ./resources/proxy.yml
	UpstreamPostLoginRedirectPath string   // "/"
	UpstreamProtectedPaths        []string // all paths that are protected with oidc
	SessionProvider               string   //  memory | redis
	SessionRedisHost              string   // redis host
	SessionRedisPort              int32    // 6579
	ClientId                      string
	ClientSecret                  string
	MetadataUrl                   string
	OpenIdUrl                     string
	OidcEndpointMount             string
	AuthCallackPath               string
	UserInfoPath                  string
}

func loadFromEnv() EnvConfig {
	return EnvConfig{
		ProxyPort:                     readInt32ValueFromEnv("GOIDC_PROXY_PORT", 3939),
		ProxyConfigPath:               readStringValueFromEnv("GOIDC_PROXY_CONFIG_PATH", "./resources/proxy.yml"), // required
		UpstreamProtectedPaths:        readStringArrayValueFromEnv("GOIDC_UPSTREAM_PROTECTED_PATHS", []string{"/"}),
		UpstreamPostLoginRedirectPath: readStringValueFromEnv("GOIDC_UPSTREAM_POST_LOGIN_REDIRECT", "/"),
		SessionProvider:               readStringValueFromEnv("GOIDC_SESSION_PROVIDER", "memory"),
		SessionRedisHost:              readStringValueFromEnv("GOIDC_REDIS_HOST", ""),
		SessionRedisPort:              readInt32ValueFromEnv("GOIDC_REDIS_PORT", 6379),
		ClientId:                      readStringValueFromEnv("GOIDC_OIDC_CLIENT_ID", ""),
		ClientSecret:                  readStringValueFromEnv("GOIDC_OIDC_CLIENT_SECRET", ""),
		MetadataUrl:                   readStringValueFromEnv("GOIDC_METADATA_URL", ""),
		OpenIdUrl:                     readStringValueFromEnv("GOIDC_OPENID_URL", ""),
		OidcEndpointMount:             readStringValueFromEnv("GOIDC_OIDC_ENDPOINTS_MOUNT_PATH", "/oidc"),
		AuthCallackPath:               readStringValueFromEnv("GOIDC_OIDC_ENDPOINTS_AUTH_CALLBACK_PATH", "/authorization-code/callback"),
		UserInfoPath:                  readStringValueFromEnv("GOIDC_OIDC_USERINFO_ENDPOINT_PATH", "/v1/userinfo"),
	}
}

// readStringValueFromEnv reads a string value from the supplied environment variable,
// if the value is not set, i.e empty, the the supplied default is returned
func readStringValueFromEnv(varName, defaultValue string) string {
	value := os.Getenv(varName)
	if value == "" {
		return defaultValue
	}
	return value
}

// readStringArrayValueFromEnv reads a string array value from the supplied environment variable,
// the read value is converted to a string by splitting it with `,` as the seprateor
// if the value is not set, i.e empty, the the supplied default is returned
func readStringArrayValueFromEnv(varName string, defaultValue []string) []string {
	value := os.Getenv(varName)
	if value == "" {
		return defaultValue
	}

	return strings.Split(value, ",")
}

// readInt32ValueFromEnv reads an int32 value from the supplied environment variable,
// if there an error converting the read value to a valid integer, the default is returned
// if the value is not set, i.e empty, the the supplied default is returned
func readInt32ValueFromEnv(varName string, defaultValue int32) int32 {
	value := os.Getenv(varName)
	if value == "" {
		return defaultValue
	}
	int32Value, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return int32(int32Value)
}

// readBoolValueFromEnv reads a boolean value from the supplied environment variable,
// the literals, true, yes or on are considered TRUE, all other values are considered FALSE
// if the value is not set, i.e empty, the the supplied default is returned
// func readBoolValueFromEnv(varName string, defaultValue bool) bool {
// 	value := os.Getenv(varName)
// 	if value == "" {
// 		return defaultValue
// 	}

// 	if strings.ToLower(value) == "true" || strings.ToLower(value) == "yes" || strings.ToLower(value) == "on" {
// 		return true
// 	}

// 	return false
// }
