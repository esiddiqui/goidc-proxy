package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/esiddiqui/goidc-proxy/config"
	_ "github.com/esiddiqui/goidc-proxy/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	QueryStringParamCode  string = "code"
	QueryStringParamState string = "state"
	QueryStringParamError string = "error"
)

type GoidcServer struct {
	cfg           *config.GoidcConfig
	rproxy        *GoidcReverseProxy
	metadata      *config.GoidcMetadata
	cookieManager CookieManager
	sessionStore  SessionStore
	requestCache  StateRequestCache
}

// NewGoidcProxyServer sets up all required pieces for the goidc-proxy, any critical
// failures will result in a non-nil error being returned & a panic
func NewGoidcProxyServer(cfg *config.GoidcConfig) (*GoidcServer, error) {

	var err error
	if cfg == nil {
		return nil, errors.Errorf("invalid or nil config supplied to initialize GoidcProxyServer")
	}

	log.Info("Initializing session provider")
	var sess SessionStore
	if cfg.Server.Session.Type == config.SessionTypeMemory {
		sess = NewInMemorySessionStore()
	} else {
		return nil, errors.New("redis is currently not supported as a session store")
	}

	// initializing state request cache
	reqCache := make(StateRequestCache)

	// initializing cookie manager
	cookieMgr := NewCookieManager(cfg.Server.Cookie.Name)

	// configure oidc
	// var metadata *config.GoidcMetadata
	metadata := cfg.Oidc.Metadata
	if cfg.Oidc.Metadata == nil {
		log.Infof("loading metadata from metadataUrl %v", cfg.Oidc.MetadataUrl)
		metadata, err = config.NewFromMetadataUrl(cfg.Oidc.MetadataUrl)
		if err != nil {
			return nil, err
		}
	}

	server := &GoidcServer{
		cfg:           cfg,
		metadata:      metadata,
		sessionStore:  sess,
		cookieManager: cookieMgr,
		requestCache:  reqCache,
		rproxy:        NewGoidcReverseProxy(*cfg),
	}

	err = server.startHttpServer()
	return server, err
}

// ProtectedPathHandler is an http handler supplied by the GoidcProxyServer to handle
// a protected path that must be behind an oidc auth flow.
func (p *GoidcServer) ProtectedPathHandler(w http.ResponseWriter, r *http.Request) {

	// read cookie value
	token, err := p.cookieManager.GetSessionToken(r)
	if err != nil {
		p.redirectToAuthServer(w, r)
		return
	}

	// retrieve session from session store
	sess, err := p.sessionStore.GetSession(*token)
	if err != nil {
		p.redirectToAuthServer(w, r)
		return
	}

	// for authorized requrests we fetch the Exchange object from session
	// and set a couple of headers for now
	exch := sess.(Exchange)
	r.Header.Set("x-goidcify-id-token", exch.IdToken)
	r.Header.Set("x-goidcify-scope", exch.Scope)
	p.rproxy.handle(w, r)
}

func (p *GoidcServer) UnProtectedPathHandler(w http.ResponseWriter, r *http.Request) {
	p.rproxy.handle(w, r)
}

// AuthCodeCallbackHandler is an http hanlder supplied by the GoidcProxyServer to handle
// oidc authorization-code/callback endopint; this is endpoint that is called by the OIDC
// authorization server with the results of the OIDC auth.
func (p *GoidcServer) AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {

	q := r.URL.Query()

	// if the auth server returns an error; return it as-is
	// TODO: @esiddiqui this may be very Okta specific, check !
	authServerReturnedAnError := q.Get(QueryStringParamError) != ""
	if authServerReturnedAnError {
		log.Error("error response from authorization server")
		w.Header().Set("content-type", "application/json")
		json, _ := json.Marshal(q)
		_, _ = w.Write([]byte(json))
		return
	}

	// get the state & auth code from the response
	state := q.Get(QueryStringParamState)
	authCode := q.Get(QueryStringParamCode)

	// Make sure the code was provided
	if authCode == "" {
		log.Error("The auto code was not returned, or is not accessible")
		http.Error(w, "authorization code was not returned by auth server", http.StatusInternalServerError)
		return
	}

	log.WithFields(log.Fields{
		"State":    state,
		"AuthCode": authCode,
	}).Info("Good message returned from auth server")

	// exchange auth_code for tokens (auth token, id token)
	exchange, err := p.exchangeCode(authCode, r)
	if err != nil || exchange.Error != "" {
		log.Error("error while exchange auth code for tokens")
		log.Errorf("error type: %v", exchange.Error)
		log.Errorf("error description: %v", exchange.ErrorDescription)
		http.Error(w, exchange.ErrorDescription, http.StatusInternalServerError)
		return
	}

	// create new session for this request
	sessionToken := NewSessionToken() // <--- why, when we can use state?
	log.Debugf("new session being created with: %v", sessionToken)
	err = p.sessionStore.CreateNewSession(sessionToken, *exchange)
	if err != nil {
		http.Error(w, "error creating a new session", http.StatusInternalServerError)
		return
	}

	// set session token in cookie
	// align cookie max-age with the tokens' expiry
	p.cookieManager.SetCookie(w, sessionToken, exchange.ExpiresIn)
	log.Debugf("session cookied set %v, expiry is %v\n", sessionToken, exchange.ExpiresIn)
	log.Debugf("access_token: %v\n", exchange.AccessToken)
	log.Debugf("id_token: %v\n", exchange.IdToken)

	// TODO: @esiddiqui later we need to use a redirect to the orignal request parameters/headers etc
	// restore original request components/parameters for the redirect
	log.Debugf("redirecting to default /\n")

	relativePath := "/" // default redirect after auth is successful
	// check state cache
	if og_request, ok := p.requestCache[state]; ok {
		relativePath = og_request.URL.Path // just the path off of the original cached requests
		//TODO: @esiddiqui we should also implement restoring orignal body/query parameters etc
		log.Infof("restoring original request path %v after auth is successful", relativePath)
		// remove this key
		delete(p.requestCache, state)
	}
	http.Redirect(w, r, relativePath, http.StatusFound)
}

// GetOidcUserInfoHanlder is the http handler for the GET /<oidcEndpointMount>/userinfo
// Ex from Okta: https://developer.okta.com/docs/reference/api/oidc/#userinfo
func (p *GoidcServer) GetOidcUserInfoHanlder(w http.ResponseWriter, r *http.Request) {

	// read cookie value
	token, err := p.cookieManager.GetSessionToken(r)
	if err != nil {
		p.redirectToAuthServer(w, r)
		return
	}

	// retrieve session from session store
	sess, err := p.sessionStore.GetSession(*token)
	if err != nil {
		p.redirectToAuthServer(w, r)
		return
	}

	exch := sess.(Exchange)
	// TODO: @esiddiqui fetch this userinfo endpoint from the /.well-known/openid-configuration
	userProfileUrl := fmt.Sprintf("%v%v", p.metadata.Issuer, p.cfg.Oidc.UserInfoPath) //TODO: @esiddiqui check if this is portable across auth servers
	req, _ := http.NewRequest("GET", userProfileUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", fmt.Sprintf("Bearer %v", exch.AccessToken))
	h.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(body)
}

// GetOidcSessionHanlder is the http handler for the GET /<oidcEndpointMount>/userinfo
// Ex from Okta: https://developer.okta.com/docs/reference/api/oidc/#userinfo
func (p *GoidcServer) GetOidcSessionHanlder(w http.ResponseWriter, r *http.Request) {

	// read cookie value
	token, err := p.cookieManager.GetSessionToken(r)
	if err != nil {
		p.redirectToAuthServer(w, r)
		return
	}

	sessionInfo := make(map[string]any)
	sessionInfo["session_id"] = token
	sess, err := p.sessionStore.GetSession(*token)
	if err != nil {
		sess = err.Error()
	}
	sessionInfo["access_token"] = sess
	bytes, _ := json.Marshal(sessionInfo)
	_, _ = w.Write(bytes)

}

// GetInfoHandler is an http hanlder supplied by the GoidcProxyServer for the GET /<oidcEndpointMount>/info
func (p *GoidcServer) GetInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	infoMap := make(map[string]any)
	infoMap["version"] = "dev"
	infoMap["config"] = p.cfg
	infoMap["sessions"] = p.sessionStore.All()
	infoMap["metadata"] = p.metadata
	bytes, _ := json.Marshal(infoMap)
	_, _ = w.Write(bytes)
}

// oidc helpers

// redirectToAuthServer sets up an http redirect response for the caller
// with the correct query string parameters (resonse_type, client_id, scope
// and a redirect_uri etc & url to the auth services /authorize endpoint.
func (p *GoidcServer) redirectToAuthServer(w http.ResponseWriter, r *http.Request) {

	state := NewSessionToken()
	log.Debugf("state value (session token): %v", state)

	redirectUri := p.getRedirectUri(r)
	log.Debugf("redirection uri: %v", redirectUri)

	w.Header().Add("Cache-Control", "no-cache")
	q := r.URL.Query()
	q.Add("client_id", p.cfg.Oidc.ClientId)
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	scopesString := "openid-connect"
	if len(p.cfg.Oidc.Scopes) > 0 {
		scopesString = strings.Join(p.cfg.Oidc.Scopes, " ")
	}
	q.Add("scope", scopesString)
	q.Add("redirect_uri", redirectUri)
	q.Add("state", state)
	q.Add("prompt", "login") // this is to force login screen even when authserver session is still valid (okta specific)

	authRedirectEndppoint := fmt.Sprintf("%v?%v", p.metadata.AuthorizationEndpoint, q.Encode()) //fmt.Sprintf("%v/v1/authorize?", p.cfg.Oidc.IssuerUrl) + q.Encode()
	fmt.Printf("forwarding request to: %v\n", authRedirectEndppoint)

	// TODO: @esiddiqui need to convert this to cache impl
	p.requestCache[state] = r // save reference to orignal request
	http.Redirect(w, r, authRedirectEndppoint, http.StatusTemporaryRedirect)
}

// getRedirectUri builds & returns the OIDC redirctUri to use
func (p *GoidcServer) getRedirectUri(r *http.Request) string {

	config := p.cfg
	goidcScheme := "http"
	if r.TLS != nil {
		goidcScheme = "https"
	}
	goidcHost := r.Host
	goidcMount := config.Oidc.EndpiontMountBase
	goidcCallbackPath := config.Oidc.CallbackPath
	baseUri := fmt.Sprintf("%v://%v", goidcScheme, goidcHost)                    // http://<host-header>:3000
	redirectUri := fmt.Sprintf("%v%v%v", baseUri, goidcMount, goidcCallbackPath) // baseUri ^^ + /<oidcMount> + /<callbackPath>
	log.Infof(redirectUri)
	return redirectUri
}

// ExchangeCode uses the auth "code" & exchange it for a access_token & id_token
// from the auth server token ()`v1/token` endpoint
func (p *GoidcServer) exchangeCode(code string, r *http.Request) (*Exchange, error) {

	// create header for
	clientId := p.cfg.Oidc.ClientId
	clientSecret := p.cfg.Oidc.ClientSecret
	basicAuthCredentials := base64.StdEncoding.EncodeToString(
		[]byte(clientId + ":" + clientSecret))

	// q := r.URL.Query()
	// q.Set("grant_type", "authorization_code")
	// q.Set("code", code)
	redirectUri := p.getRedirectUri(r)
	log.Debugf("redirection uri: %v", redirectUri)
	// q.Set("redirect_uri", redirectUri)

	// set form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectUri)

	// TODO: @esiddiqui - confirm /v1/token is correctly specified for the Auth Server
	// url := fmt.Sprintf("%v?%v", p.metadata.TokenEndpoint, q.Encode()) //p.cfg.Oidc.IssuerUrl + "/v1/token?" + q.Encode()

	url := fmt.Sprintf("%v", p.metadata.TokenEndpoint) //p.cfg.Oidc.IssuerUrl + "/v1/token?" + q.Encode()
	log.Infof("auth code exchange url %v", url)
	req, _ := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	// req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))

	// set headers
	h := req.Header
	h.Add("Authorization", fmt.Sprintf("Basic %v", basicAuthCredentials))
	h.Add("Accept", "application/json")
	h.Add("User-Agent", "goidc-proxy")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	// h.Add("Connection", "close")
	// h.Add("Content-Length", "0")

	// q := req.URL.Query()
	// q.Set("grant_type", "authorization_code")
	// q.Set("code", code)
	// redirectUri := p.getRedirectUri(r)
	// log.Debugf("redirection uri: %v", redirectUri)
	// q.Set("redirect_uri", redirectUri)

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
	var exchange Exchange
	_ = json.Unmarshal(body, &exchange)
	return &exchange, nil
}
