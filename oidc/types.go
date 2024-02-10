package oidc

import (
	"net/http"
)

// TokenResponse respresents the payload for oidc token exchange message
// https://openid.net/specs/openid-connect-basic-1_0.html Section 2.1.6.2
type TokenResponse struct {
	Error            string  `json:"error,omitempty"`
	ErrorDescription string  `json:"error_description,omitempty"`
	ErrorUri         string  `json:"error_uri,omitempty"`
	AccessToken      string  `json:"access_token,omitempty"`
	TokenType        string  `json:"token_type,omitempty"`
	IdToken          string  `json:"id_token,omitempty"`
	ExpiresIn        *int    `json:"expires_in,omitempty"`
	Scope            *string `json:"scope,omitempty"`
	RefreshToken     *string `json:"refresh_token,omitempty"`
}

// StateRequestCache holds the state of the http request
// before the oidc flow is executed. Each request is cached
// against a sessionid
// TODO @esiddiquithis needs more work
type StateRequestCache map[string]*http.Request
