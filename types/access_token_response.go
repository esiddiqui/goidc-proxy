package types

// AccessTokenResponse represents the OAuth Access Token Response structure
// as defined by the RFC 6749 Section 4.2.2
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
// https://openid.net/specs/openid-connect-basic-1_0.html Section 2.1.6.2

type AccessTokenResponse struct {
	// error response field
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
	// successful response field
	AccessToken  string  `json:"access_token,omitempty"`
	TokenType    string  `json:"token_type,omitempty"`
	IdToken      string  `json:"id_token,omitempty"`
	ExpiresIn    *int    `json:"expires_in,omitempty"`
	Scope        *string `json:"scope,omitempty"`
	State        *string `json:"state,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
}
