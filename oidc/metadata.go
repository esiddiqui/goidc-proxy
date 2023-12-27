package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type GoidcMetadata struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	RegistrationEndpoint                      string   `json:"regisration_endpoint"`
	JwksUri                                   string   `json:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	ScopesSupported                           []string `json:"scopes_supported"`
	TokenEndpointAuthMessagesSupported        []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported"`
	DeviceAuthorizationEndpoint               string   `json:"device_authorization_endpoint"`
	DropSigningAlgValuesSupported             []string `json:"dpop_signing_alg_values_supported"`
}

// NewFromIssuerUrl is a band-aid way to infer some key authorization server metadata information from
// the issuerUrl.
func NewFromIssuerUrl(issuerUrl string) (*GoidcMetadata, error) {
	metadata := &GoidcMetadata{
		Issuer: issuerUrl,
	}
	metadata.AuthorizationEndpoint = fmt.Sprintf("%v/v1/authorize", issuerUrl)
	metadata.TokenEndpoint = fmt.Sprintf("%v/v1/token", issuerUrl)
	return nil, nil
}

// ParseFromUrl fetches the authorization server metadata from the supplied metadata/well-know url
func NewFromMetadataUrl(url string) (*GoidcMetadata, error) {
	req, _ := http.NewRequest("GET", url, bytes.NewReader([]byte("")))
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	metadata := &GoidcMetadata{}
	err = json.Unmarshal(body, metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}
