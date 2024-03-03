package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/esiddiqui/goidc-proxy/session"
	"github.com/esiddiqui/goidc-proxy/types"
	log "github.com/sirupsen/logrus"
)

// redirectToAuthServer builds & responds with an http redirect for the caller
// with the correct query string parameters (resonse_type, client_id, scope
// and a redirect_uri etc & url to the auth servers' /authorize endpoint.
func (p *HttpServer) redirectToAuthServer(w http.ResponseWriter, r *http.Request) {

	state := NewSessionToken()
	log.WithField("value", state).Debug("session token/state parameter generated")

	redirectUri := p.getRedirectUri(r)
	log.WithField("value", redirectUri).Debug("redirection uri")

	// set reponse header values
	w.Header().Add("Cache-Control", "no-cache")

	// set query string parameters
	scopesString := "oidc" // default if not supplied
	if len(p.cfg.Oidc.Scopes) > 0 {
		scopesString = strings.Join(p.cfg.Oidc.Scopes, " ")
	}
	q := r.URL.Query()
	q.Add("client_id", p.cfg.Oidc.ClientId)
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", scopesString)
	q.Add("redirect_uri", redirectUri)
	q.Add("state", state)
	q.Add("prompt", "login") // TODO @esiddiqui: this is okta specific; used to forece login screen even when authserver side has a valid session

	authRedirectEndppoint := fmt.Sprintf("%v?%v", p.metadata.AuthorizationEndpoint, q.Encode())
	log.WithField("value", authRedirectEndppoint).Debugf("creating refirect required for: %v", authRedirectEndppoint)

	// TODO: @esiddiqui need to convert this to cache impl
	// start a new session
	sessionObj := session.Object{
		OrignalRequest: *r,
	}

	// using state value as session token, we cache the orignal request.
	err := p.sessionMgr.Set(w, state, sessionObj)
	if err != nil {
		log.Errorf("error setting session for request %v", state)
	}
	//p.requestCache[state] = r // save reference to orignal request
	http.Redirect(w, r, authRedirectEndppoint, http.StatusTemporaryRedirect)
}

// exchangeCode uses the auth "code" & exchanges it for a access_token & id_token
// from the auth servers token_endpoint.
// func (p *HttpServer) exchangeCode(code string, r *http.Request) (*session.Object, error) {

// 	// create auth header by base64(client_id:client_secret)
// 	clientId := p.cfg.Oidc.ClientId
// 	clientSecret := p.cfg.Oidc.ClientSecret
// 	basicAuthCredentials := base64.StdEncoding.EncodeToString(
// 		[]byte(clientId + ":" + clientSecret))

// 	redirectUri := p.getRedirectUri(r)
// 	log.Debugf("redirect uri: %v", redirectUri)

// 	// set form data
// 	data := url.Values{}
// 	data.Set("grant_type", "authorization_code") // TODO grant type (this needs to be configurable?)
// 	data.Set("code", code)                       // auth code
// 	data.Set("client_id", clientId)              // clientID // linkedin requires this...
// 	data.Set("client_secret", clientSecret)      // clientSecret // linkedin required this...
// 	data.Set("redirect_uri", redirectUri)        // redirect uri set to oidc application

// 	url := p.metadata.TokenEndpoint
// 	log.Debugf("auth code exchange url %v", url)
// 	req, _ := http.NewRequest("POST", url, strings.NewReader(data.Encode()))

// 	// set headers
// 	h := req.Header
// 	h.Add("Authorization", fmt.Sprintf("Basic %v", basicAuthCredentials))
// 	h.Add("Accept", "application/json")
// 	h.Add("User-Agent", "goidc-proxy")
// 	h.Add("Content-Type", "application/x-www-form-urlencoded")
// 	// h.Add("Connection", "close")
// 	// h.Add("Content-Length", "0")

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	defer resp.Body.Close()

// 	var cachedObj session.Object
// 	var token types.AccessTokenResponse
// 	_ = json.Unmarshal(body, &token)

// 	// set cache objects expiry to match the expired_in from token; else 100 years for now...
// 	cachedObj.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // 100 years;
// 	if token.ExpiresIn != nil {
// 		secs := *token.ExpiresIn
// 		expiresAt := time.Now().Add(time.Second * time.Duration(secs))
// 		cachedObj.ExpiresAt = expiresAt
// 	}
// 	cachedObj.Value = token

// 	// TODO: @esiddiqui need to clear this out after some testings...
// 	// we'll use this to keep an eye on various id endpoint responses
// 	// to see if we do need to add any more fields to the exchange.
// 	// cachedObj. = make(map[string]any)
// 	cachedObj.TokenRaw = string(body)
// 	return &cachedObj, nil
// }

// exchangeCode exchanges the auth code for an access_token/id_token from the auth server
// using the back channel token endpoint.
func (p *HttpServer) exchangeCode(code string, r *http.Request) (*types.AccessTokenResponse, error) {

	// create auth header by base64(client_id:client_secret)
	clientId := p.cfg.Oidc.ClientId
	clientSecret := p.cfg.Oidc.ClientSecret
	basicAuthCredentials := base64.StdEncoding.EncodeToString(
		[]byte(clientId + ":" + clientSecret))

	// redirect uri as configered with the auth server is also required by the token endpoint
	// although there is no redirection involved in this flow...
	redirectUri := p.getRedirectUri(r)
	log.Debugf("redirect uri: %v", redirectUri)

	// set form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code") // TODO grant type (this needs to be configurable?)
	data.Set("code", code)                       // TODO auth code (this needs to configurable)
	data.Set("client_id", clientId)              // clientID // linkedin requires this
	data.Set("client_secret", clientSecret)      // clientSecret // linkedin required this
	data.Set("redirect_uri", redirectUri)        // redirect uri set to oidc application

	url := p.metadata.TokenEndpoint
	log.Debugf("auth code exchange url %v", url)
	req, _ := http.NewRequest("POST", url, strings.NewReader(data.Encode()))

	// set headers
	h := req.Header
	h.Add("Authorization", fmt.Sprintf("Basic %v", basicAuthCredentials))
	h.Add("Accept", "application/json")
	h.Add("User-Agent", "goidc-proxy")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	// h.Add("Connection", "close")
	// h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var token types.AccessTokenResponse
	_ = json.Unmarshal(body, &token)
	return &token, nil
}

// getRedirectUri builds & returns the OIDC redirctUri to use
func (p *HttpServer) getRedirectUri(r *http.Request) string {

	config := p.cfg
	goidcScheme := "http"
	if r.TLS != nil {
		goidcScheme = "https"
	}
	goidcHost := r.Host
	goidcMount := *config.Oidc.EndpiontMountBase
	goidcCallbackPath := *config.Oidc.CallbackPath
	baseUri := fmt.Sprintf("%v://%v", goidcScheme, goidcHost)                    // http://<host-header>:3000
	redirectUri := fmt.Sprintf("%v%v%v", baseUri, goidcMount, goidcCallbackPath) // baseUri ^^ + /<oidcMount> + /<callbackPath>
	log.Infof(redirectUri)
	return redirectUri
}
