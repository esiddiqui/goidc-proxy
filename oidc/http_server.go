package oidc

import (
	"fmt"
	"net/http"

	"github.com/esiddiqui/goidc-proxy/config"
	_ "github.com/esiddiqui/goidc-proxy/config"
	"github.com/esiddiqui/goidc-proxy/session"
	"github.com/esiddiqui/goidc-proxy/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	QueryStringParamCode  string = "code"
	QueryStringParamState string = "state"
	QueryStringParamError string = "error"
)

type HttpServer struct {
	cfg        *config.GoidcConfig
	rproxy     *GoidcReverseProxy
	metadata   *types.AuthServerMetadata
	sessionMgr session.Manager
}

// StartGoidcProxyServer sets up all required pieces for the goidc-proxy, any critical
// failures will result in a non-nil error being returned & a panic
func StartHttpServer(cfg *config.GoidcConfig) error {

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
		log.WithField("Url", cfg.Oidc.MetadataUrl).Info("loading oauth2.0/oidc auth server metadata")
		metadata, err = config.NewFromMetadataUrl(cfg.Oidc.MetadataUrl)
		if err != nil {
			return err
		}
	}

	server := &HttpServer{
		cfg:        cfg,
		metadata:   metadata,
		sessionMgr: *session,
		rproxy:     NewGoidcReverseProxy(cfg.Routes),
	}

	err = server.startHttpServer()
	return err
}

// startHttpServer starts an http server
func (p *HttpServer) startHttpServer() error {

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

	// set up authcode callback handler R

	var authCallbackPathFull = fmt.Sprintf("%v%v", *c.EndpiontMountBase, *c.CallbackPath)
	log.WithField("path", authCallbackPathFull).Debug("setting auth callback path")
	http.HandleFunc(authCallbackPathFull, p.authCodeCallbackHandler)

	// start server

	log.WithField("port", cfg.Server.Port).Info("starting goidc-proxy server")
	return http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), nil)
}
