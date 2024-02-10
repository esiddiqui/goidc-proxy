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
	"time"

	"github.com/esiddiqui/goidc-proxy/config"
	_ "github.com/esiddiqui/goidc-proxy/config"
	"github.com/esiddiqui/goidc-proxy/session"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	QueryStringParamCode  string = "code"
	QueryStringParamState string = "state"
	QueryStringParamError string = "error"
)

type GoidcServer struct {
	cfg        *config.GoidcConfig
	rproxy     *GoidcReverseProxy
	metadata   *config.GoidcMetadata
	sessionMgr session.Manager
	//requestCache StateRequestCache
}

// NewGoidcProxyServer sets up all required pieces for the goidc-proxy, any critical
// failures will result in a non-nil error being returned & a panic
func StartGoidcProxyServer(cfg *config.GoidcConfig) error {

	var err error
	if cfg == nil {
		return errors.Errorf("invalid or nil config supplied to initialize GoidcProxyServer")
	}

	// initialize session manager
	session, err := session.NewSessionManager(&cfg.Session)
	if err != nil {
		return err
	}

	// configure oidc
	// TODO: @esiddiqui, need to start with empty metadata,
	// try from the url first, if exists, then merge that
	// with what's defined explicitly
	metadata := cfg.Oidc.Metadata
	if cfg.Oidc.Metadata == nil {
		log.WithField("Url", cfg.Oidc.MetadataUrl).Info("loading oauth2.0/oidc metadata")
		metadata, err = config.NewFromMetadataUrl(cfg.Oidc.MetadataUrl)
		if err != nil {
			return err
		}
	}

	server := &GoidcServer{
		cfg:        cfg,
		metadata:   metadata,
		sessionMgr: *session,
		rproxy:     NewGoidcReverseProxy(cfg),
	}

	err = server.startHttpServer()
	return err
}

// startHttpServer starts an http server
func (p *GoidcServer) startHttpServer() error {

	cfg := p.cfg

	// set up routes deinfed in the proxy config to be handled by protected path handler
	for _, route := range cfg.Routes {
		if route.AuthRequired {
			hf := p.sessionMgr.GetSessionWrapperHandler(p.rproxy.handlerFunc(), p.redirectToAuthServer)
			http.HandleFunc(route.Prefix, hf)
		} else {
			http.Handle(route.Prefix, p.rproxy) // let the proxy handle this
		}
	}

	// set up all <oidc>/ path handlers
	c := cfg.Oidc
	shf := p.sessionMgr.GetSessionWrapperHandler(p.getOidcSessionHanlder, p.redirectToAuthServer)
	http.HandleFunc(fmt.Sprintf("%v%v", *c.EndpiontMountBase, *c.SessionPath), shf)

	uhf := p.sessionMgr.GetSessionWrapperHandler(p.getOidcUserInfoHanlder, p.redirectToAuthServer)
	http.HandleFunc(fmt.Sprintf("%v%v", *c.EndpiontMountBase, *c.UserInfoPath), uhf)

	ih := p.sessionMgr.GetSessionWrapperHandler(p.getInfoHandler, p.redirectToAuthServer)
	http.HandleFunc(fmt.Sprintf("%v%v", *c.EndpiontMountBase, *c.InfoPath), ih) // has to go, for test only.

	// authcode callback handler
	var authCallbackPathFull = fmt.Sprintf("%v%v", *c.EndpiontMountBase, *c.CallbackPath)
	log.WithField("path", authCallbackPathFull).Debug("setting auth callback path")
	http.HandleFunc(authCallbackPathFull, p.authCodeCallbackHandler)

	// start server
	log.WithField("port", cfg.Server.Port).Info("starting goidc-proxy server")
	return http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), nil)
}

// http handlers

// authCodeCallbackHandler is an http hanlder supplied by the GoidcProxyServer to handle
// oidc authorization-code/callback endopint; this is endpoint that is called by the OIDC
// authorization server with the results of the OIDC auth.
func (p *GoidcServer) authCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {

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

	// check state integrity by confirming a nil-session exists for this request
	token, sess, err := p.sessionMgr.Get(r)
	if err != nil || token == nil {
		log.Error("error finding a session & orignal request for this auth callback")
		http.Error(w, "error finding a session & orignal request for this auth callback", http.StatusInternalServerError)
		return
	}

	if state != *token {
		log.WithFields(log.Fields{
			"state": state,
			"token": *token,
		}).Error("state & session token values do not match")
		http.Error(w, fmt.Sprintf("state %v & session token %v for this session do not match", state, *token), http.StatusInternalServerError)
		return

	}

	// Make sure the code was provided
	if authCode == "" {
		log.Error("The auth code was not returned, or is not accessible")
		http.Error(w, "authorization code was not returned by auth server", http.StatusInternalServerError)
		return
	}

	log.WithFields(log.Fields{
		"state":    state,
		"authCode": authCode,
	}).Debug("good message returned from auth server")

	// exchange auth_code for tokens (auth token, id token)
	cachedObj, err := p.exchangeCode(authCode, r)
	exchange := cachedObj.Value.(TokenResponse)
	if err != nil || exchange.Error != "" {
		log.WithField("status", "error").Error("exhanged auth_code for access_token")
		log.WithField("type", exchange.Error).Errorf("error occurred")
		log.WithField("description", exchange.ErrorDescription).Errorf("error occurred")
		log.WithField("uri", exchange.ErrorUri).Errorf("error occurred")
		http.Error(w, exchange.ErrorDescription, http.StatusInternalServerError)
		return
	}

	log.WithField("status", "success").Debug("exhanged auth_code for access_token")

	// create new session for this request
	// TODO: @esiddiqui, why create a new session_token when we can use state?
	// sessionToken := NewSessionToken()
	log.WithField("session_token", state).Debugf("setting session token in session")

	sess.TokenRaw = cachedObj.TokenRaw
	sess.Value = cachedObj.Value
	err = p.sessionMgr.Set(w, state, *cachedObj)
	if err != nil {
		http.Error(w, "error creating a new session", http.StatusInternalServerError)
		return
	}
	/*
		err = p.sessionStore.CreateNewSession(sessionToken, cachedObj)
		if err != nil {
			http.Error(w, "error creating a new session", http.StatusInternalServerError)
			return
		}

		// set session token in cookie
		// align cookie max-age with the tokens' expiry
		expiry := int(-1)
		if exchange.ExpiresIn != nil {
			expiry = *exchange.ExpiresIn
		}

		p.cookieManager.SetCookie(w, sessionToken, expiry)

		---------
	*/
	log.WithField("expiry", exchange.ExpiresIn).Debugf("session cookied set")
	log.WithField("access_token", exchange.AccessToken).Debugf("access_token received")
	log.WithField("id_token", exchange.IdToken).Debugf("id_token received")

	// TODO: @esiddiqui later we need to use a redirect to the orignal request parameters/headers etc
	// restore original request components/parameters for the redirect
	// log.Debugf("redirecting to default /\n")

	relativePath := "/" // default redirect after auth is successful
	if sess.OrignalRequest.URL.Path != "" {
		relativePath = sess.OrignalRequest.URL.Path
		log.WithField("url", relativePath).Debug("restoring original request path")
	}
	// if og_request, ok := p.requestCache[state]; ok {
	// 	relativePath = og_request.URL.Path // just the path off of the original cached requests
	// 	//TODO: @esiddiqui we should also implement restoring orignal body/query parameters etc
	// 	log.Infof("restoring original request path %v after auth is successful", relativePath)
	// 	// remove this key
	// 	delete(p.requestCache, state)
	// }

	http.Redirect(w, r, relativePath, http.StatusFound)
}

// GetOidcUserInfoHanlder is the http handler for the GET /<oidcEndpointMount>/userinfo
// Ex from Okta: https://developer.okta.com/docs/reference/api/oidc/#userinfo
func (p *GoidcServer) getOidcUserInfoHanlder(w http.ResponseWriter, r *http.Request) {

	// TODO: @esiddiqui make this nicer

	if p.metadata.UserinfoEndpoint == nil {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte("{ 'error': 'no userinfo_endpoint defined from oidc metadata'}"))
		return
	}

	sw, ok := w.(session.ResponseWriterWithSessionInfo)
	if !ok {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte("{ 'error': 'cannot retrieve goidc session'}"))
	}

	val := sw.SessionObject.Value
	exch := val.(TokenResponse)
	userProfileUrl := *p.metadata.UserinfoEndpoint

	req, _ := http.NewRequest("GET", userProfileUrl, bytes.NewReader([]byte("")))
	// set request header
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
	_, _ = sw.Write(body)
}

// GetOidcSessionHanlder is the http handler for the GET /<oidcEndpointMount>/userinfo
// Ex from Okta: https://developer.okta.com/docs/reference/api/oidc/#userinfo
func (p *GoidcServer) getOidcSessionHanlder(w http.ResponseWriter, r *http.Request) {
	token, sess, err := p.sessionMgr.Get(r)
	if err != nil {
		p.redirectToAuthServer(w, r)
	}

	sessionInfo := make(map[string]any)
	sessionInfo["session_id"] = token
	sessionInfo["access_token"] = sess
	bytes, _ := json.Marshal(sessionInfo)
	_, _ = w.Write(bytes)
}

// GetInfoHandler is an http hanlder supplied by the GoidcProxyServer for the GET /<oidcEndpointMount>/info
func (p *GoidcServer) getInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	infoMap := make(map[string]any)
	infoMap["version"] = "dev"
	infoMap["config"] = p.cfg
	infoMap["sessions"] = p.sessionMgr.All()
	infoMap["metadata"] = p.metadata
	bytes, _ := json.Marshal(infoMap)
	_, _ = w.Write(bytes)
}

// oidc helpers

// redirectToAuthServer builds & responds with an http redirect for the caller
// with the correct query string parameters (resonse_type, client_id, scope
// and a redirect_uri etc & url to the auth servers' /authorize endpoint.
func (p *GoidcServer) redirectToAuthServer(w http.ResponseWriter, r *http.Request) {

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
func (p *GoidcServer) exchangeCode(code string, r *http.Request) (*session.Object, error) {

	// create auth header by base64(client_id:client_secret)
	clientId := p.cfg.Oidc.ClientId
	clientSecret := p.cfg.Oidc.ClientSecret
	basicAuthCredentials := base64.StdEncoding.EncodeToString(
		[]byte(clientId + ":" + clientSecret))

	redirectUri := p.getRedirectUri(r)
	log.Debugf("redirect uri: %v", redirectUri)
	// q.Set("redirect_uri", redirectUri)

	// set form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code") // grant type
	data.Set("code", code)                       // auth code
	data.Set("client_id", clientId)              // clientID // linkedin requires this...
	data.Set("client_secret", clientSecret)      // clientSecret // linkedin required this...
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

	// log.Debug(string(body))

	defer resp.Body.Close()

	var cachedObj session.Object
	var token TokenResponse
	_ = json.Unmarshal(body, &token)

	cachedObj.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // 100 years;
	if token.ExpiresIn != nil {
		secs := *token.ExpiresIn
		expiresAt := time.Now().Add(time.Second * time.Duration(secs))
		cachedObj.ExpiresAt = expiresAt
	}
	cachedObj.Value = token

	// TODO: @esiddiqui need to clear this out after some testings...
	// we'll use this to keep an eye on various id endpoint responses
	// to see if we do need to add any more fields to the exchange.
	// cachedObj. = make(map[string]any)
	cachedObj.TokenRaw = string(body)
	return &cachedObj, nil
}

// getRedirectUri builds & returns the OIDC redirctUri to use
func (p *GoidcServer) getRedirectUri(r *http.Request) string {

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
