package oidc

import (
	"net/http"
)

type Base map[string]any

// Exchange respresents the payload for oidc token exchange message
type Exchange struct {
	Base
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

// StateRequestCache holds the state of the http request
// before the oidc flow is executed. Each request is cached
// against a sessionid
// TODO @esiddiquithis needs more work
type StateRequestCache map[string]*http.Request
