package config

import (
	"os"
)

type EnvConfig struct {
	ClientId     string
	ClientSecret string
}

func loadFromEnv() EnvConfig {
	return EnvConfig{
		ClientId:     readStringValueFromEnv("GOIDC_CLIENT_ID", ""),
		ClientSecret: readStringValueFromEnv("GOIDC_CLIENT_SECRET", ""),
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
// func readStringArrayValueFromEnv(varName string, defaultValue []string) []string {
// 	value := os.Getenv(varName)
// 	if value == "" {
// 		return defaultValue
// 	}

// 	return strings.Split(value, ",")
// }

// readInt32ValueFromEnv reads an int32 value from the supplied environment variable,
// if there an error converting the read value to a valid integer, the default is returned
// if the value is not set, i.e empty, the the supplied default is returned
// func readInt32ValueFromEnv(varName string, defaultValue int32) int32 {
// 	value := os.Getenv(varName)
// 	if value == "" {
// 		return defaultValue
// 	}
// 	int32Value, err := strconv.Atoi(value)
// 	if err != nil {
// 		return defaultValue
// 	}

// 	return int32(int32Value)
// }

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
