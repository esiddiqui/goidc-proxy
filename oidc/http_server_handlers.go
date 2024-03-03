package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/esiddiqui/goidc-proxy/session"
	"github.com/esiddiqui/goidc-proxy/types"
	log "github.com/sirupsen/logrus"
)

// http handlers

// authCodeCallbackHandler is an http hanlder supplied by this HttpServer to handle
// Oauth2.0 authorization-code/callback redirection; see RFC 6749 Section 4.1.2
// for details https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
//
// This authorization server redirects the user to along with the results of the OIDC
// authorization to this url.
//
// success:
// --------
// if a success response is received, which means the resource owner successfully
// authenticated with the authorization server (and provided the consent etc.); the
// following steps are taken:
//
// 1- validate the request; check if a session exists for this request. if not, return
//
//	an error. an empty session must exist for all request that ever flew through goidc-proxy.
//	this is where some of the original request parameters are stored, like state, original
//	request path etc.
//
// 2- the session token & the `state` parameter must be the same.
//
// 3- Then goidc-proxy will do a back-channel exchange() operation with the auth server
// to exachange the auth code for an auth token. an error response from the exchange() is
// again relayed to the user via http response. if the operation is successful, the received
// token is saved in the goidc session for this request, the session expiry is updated to
// align with the received token response `expires_in` parameter & the response redirection
// is sent to the user's original request before the auth flow started. This is saved in
// the session as orignal-request
//
// error:
// ------
// if an error response is receieved, it is relayed as-is to the http response
func (p *HttpServer) authCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {

	q := r.URL.Query()

	// if the auth server returns an error; return it as-is
	authServerReturnedAnError := q.Get(QueryStringParamError) != ""
	if authServerReturnedAnError {
		log.Error("error response from authorization server")
		w.Header().Set("content-type", "application/json")
		json, _ := json.Marshal(q)
		_, _ = w.Write([]byte(json))
		return
	}

	// get the state & auth code from the response query params
	state := q.Get(QueryStringParamState)
	authCode := q.Get(QueryStringParamCode)

	// check state integrity by confirming a nil-session exists for this request
	token, session, err := p.sessionMgr.Get(r)
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

	// exchange auth code to token(s)
	tokenResponse, err := p.exchangeCode(authCode, r)

	// if error response
	if err != nil || tokenResponse.Error != "" {
		// show error response to user
		log.WithField("status", "error").Error("exhanged auth_code for access_token")
		log.WithField("type", tokenResponse.Error).Errorf("error occurred")
		log.WithField("description", tokenResponse.ErrorDescription).Errorf("error occurred")
		log.WithField("uri", tokenResponse.ErrorUri).Errorf("error occurred")
		http.Error(w, tokenResponse.ErrorDescription, http.StatusInternalServerError)
		return
	}

	// set cache objects expiry to match the expired_in from token; else 100 years for now...
	// var cachedObj session.Object
	session.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // TODO: @esiddiqui fix this, for now its 100 years;
	if tokenResponse.ExpiresIn != nil {
		expiresAt := time.Now().Add(time.Second * time.Duration(*tokenResponse.ExpiresIn))
		session.ExpiresAt = expiresAt
	}
	session.Value = tokenResponse

	// TODO: @esiddiqui need to clear this out after some testings...
	// we'll use this to keep an eye on various id endpoint responses
	// to see if we do need to add any more fields to the exchange.
	// cachedObj. = make(map[string]any)
	raw, _ := json.Marshal(tokenResponse)
	session.TokenRaw = string(raw)

	log.WithField("status", "success").Debug("exhanged auth_code for access_token")
	log.WithField("session_token", state).Debugf("setting session token in session")

	// update session
	err = p.sessionMgr.Set(w, state, *session)
	if err != nil {
		http.Error(w, "error creating a new session", http.StatusInternalServerError)
		return
	}

	log.WithField("expiry", tokenResponse.ExpiresIn).Debugf("session cookied set")
	log.WithField("access_token", tokenResponse.AccessToken).Debugf("access_token received")
	log.WithField("id_token", tokenResponse.IdToken).Debugf("id_token received")

	relativePath := "/" // default redirect after auth is successful
	if session.OrignalRequest.URL.Path != "" {
		relativePath = session.OrignalRequest.URL.Path
		log.WithField("url", relativePath).Debug("restoring original request path")
	}

	// TODO: this must be change to proxy instread of redirect
	// also need to cater for original query parameters, body content etc
	http.Redirect(w, r, relativePath, http.StatusFound)
}

// GetOidcUserInfoHanlder is the http handler for the GET /<oidcEndpointMount>/userinfo
// Ex from Okta: https://developer.okta.com/docs/reference/api/oidc/#userinfo
func (p *HttpServer) getOidcUserInfoHanlder(w http.ResponseWriter, r *http.Request) {

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
	exch := val.(types.AccessTokenResponse)
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
func (p *HttpServer) getOidcSessionHanlder(w http.ResponseWriter, r *http.Request) {
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
func (p *HttpServer) getInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	infoMap := make(map[string]any)
	infoMap["version"] = "dev"
	infoMap["config"] = p.cfg
	infoMap["sessions"] = p.sessionMgr.All()
	infoMap["metadata"] = p.metadata
	bytes, _ := json.Marshal(infoMap)
	_, _ = w.Write(bytes)
}
