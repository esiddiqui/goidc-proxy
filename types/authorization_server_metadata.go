package types

// AuthServerMetadata represents the OAuth 2.0 Authorization Server Metadata
// as defined by RFC 8414 https://datatracker.ietf.org/doc/html/rfc8414

type AuthServerMetadata struct {
	Issuer                                    string   `json:"issuer" yaml:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint" yaml:"token_endpoint"`
	UserinfoEndpoint                          *string  `json:"userinfo_endpoint" yaml:"userinfo_endpoint"`
	RegistrationEndpoint                      string   `json:"regisration_endpoint" yaml:"regisration_endpoint"`
	JwksUri                                   string   `json:"jwks_uri" yaml:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported" yaml:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported" yaml:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported" yaml:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported" yaml:"subject_types_supported"`
	ScopesSupported                           []string `json:"scopes_supported" yaml:"scopes_supported"`
	TokenEndpointAuthMessagesSupported        []string `json:"token_endpoint_auth_methods_supported" yaml:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                           []string `json:"claims_supported" yaml:"claims_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported" yaml:"code_challenge_methods_supported"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint" yaml:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported" yaml:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpoint                        string   `json:"revocation_endpoint" yaml:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported" yaml:"revocation_endpoint_auth_methods_supported"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint" yaml:"end_session_endpoint"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported" yaml:"request_parameter_supported"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported" yaml:"request_object_signing_alg_values_supported"`
	DeviceAuthorizationEndpoint               string   `json:"device_authorization_endpoint" yaml:"device_authorization_endpoint"`
	DropSigningAlgValuesSupported             []string `json:"drop_signing_alg_values_supported" yaml:"drop_signing_alg_values_supported"`
}
