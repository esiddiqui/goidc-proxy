package oidc

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// startHttpServer starts an http server
func (p *GoidcServer) startHttpServer() error {

	cfg := p.cfg

	// set up routes deinfed in the proxy config to be handled by protected path handler
	for _, route := range cfg.Routes {
		if route.AuthRequired {
			http.HandleFunc(route.Prefix, p.ProtectedPathHandler)
		} else {
			http.HandleFunc(route.Prefix, p.UnProtectedPathHandler)
		}
	}

	// set up all <oidc>/ path handlers
	http.HandleFunc(fmt.Sprintf("%v/userinfo", cfg.Oidc.EndpiontMountBase), p.GetOidcUserInfoHanlder)
	http.HandleFunc(fmt.Sprintf("%v/info", cfg.Oidc.EndpiontMountBase), p.GetInfoHandler)
	http.HandleFunc(fmt.Sprintf("%v%v", cfg.Oidc.EndpiontMountBase, cfg.Oidc.CallbackPath), p.AuthCodeCallbackHandler)

	log.Infof("starting goidc-proxy server on port %v", cfg.Server.Port)
	return http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), nil)
}
