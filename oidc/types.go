package oidc

import (
	"net/http"
)

// StateRequestCache holds the state of the http request
// before the oidc flow is executed. Each request is cached
// against a sessionid
// TODO @esiddiquithis needs more work
type StateRequestCache map[string]*http.Request
