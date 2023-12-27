package main

import (
	"github.com/esiddiqui/goidc-proxy/config"
	"github.com/esiddiqui/goidc-proxy/oidc"
	log "github.com/sirupsen/logrus"
)

func main() {

	cfg := config.LoadConfig()
	_, err := oidc.NewGoidcProxyServer(cfg)
	if err != nil {
		panic(err)
	}
	/*
		// set up routes deinfed in the proxy config to be handled by protected path handler
		for _, route := range cfg.Routes {
			if route.AuthRequired {
				http.HandleFunc(route.Prefix, proxy.ProtectedPathHandler)
			} else {
				http.HandleFunc(route.Prefix, proxy.UnProtectedPathHandler)
			}
		}

		// set up all <oidc>/ path handlers
		http.HandleFunc(fmt.Sprintf("%v/userinfo", cfg.Oidc.EndpiontMountBase), proxy.GetOidcUserInfoHanlder)
		http.HandleFunc(fmt.Sprintf("%v/info", cfg.Oidc.EndpiontMountBase), proxy.GetInfoHandler)
		http.HandleFunc(fmt.Sprintf("%v%v", cfg.Oidc.EndpiontMountBase, cfg.Oidc.CallbackPath), proxy.AuthCodeCallbackHandler)

		log.Infof("starting goidc-proxy server on port %v", cfg.Server.Port)
		_ = http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), nil)
	*/
	log.Info("goidc-proxy is up")
	ch := make(chan bool)
	<-ch
}
