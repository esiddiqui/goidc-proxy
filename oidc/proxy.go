package oidc

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/esiddiqui/goidc-proxy/config"
	log "github.com/sirupsen/logrus"
)

// GoidcReverseProxy wraps an httputil::ReverseProxy & goidc
// config to proxy requests to upstreams (targets) based on
// the config routes defined
type GoidcReverseProxy struct {
	proxy  *httputil.ReverseProxy
	config config.GoidcConfig
}

// NewGoidcReverseProxy create & returns a GoidcReverseProxy
func NewGoidcReverseProxy(cfg config.GoidcConfig) *GoidcReverseProxy {
	p := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			req := r.In
			route := cfg.FindRouteForPath(req.URL.Path)
			log.Infof("route %v (%v) matches requeset with path %v", route.Prefix, route.AuthRequired, req.URL.Path)
			r.SetURL(route.ProxyUrl)
			r.Out.Host = route.ProxyUrl.Host
			if route.StripPrefix {

				origRequestedPath := r.In.URL.Path // incoming path as requested by client
				origTargetPath := r.Out.URL.Path   // outgoing path as prepared by proxy

				// since target path is already built by proxy using the "upstreamUrl.Path + requestedPath"
				// now when stripPrefix == yes, we will first remove the requestedPath it.
				strippedTargetPathPrefix := strings.TrimSuffix(origTargetPath, origRequestedPath)
				// remove trailing slash
				if strings.HasSuffix(strippedTargetPathPrefix, "/") {
					strippedTargetPathPrefix = strings.TrimSuffix(strippedTargetPathPrefix, "/")
				}

				// now we remove the matched prefix from the beginning of requestedPath
				strippedOutPath := strings.TrimPrefix(origRequestedPath, route.Prefix)
				// ensure leading slash
				if !strings.HasPrefix(strippedOutPath, "/") {
					strippedOutPath = fmt.Sprintf("/%v", strippedOutPath)
				}
				r.Out.URL.Path = fmt.Sprintf("%v%v", strippedTargetPathPrefix, strippedOutPath) // set the outgoing path
				log.Infof("requested path: %v, upstream built: %v, upstream final: %v%v", origRequestedPath, origTargetPath, r.Out.Host, strippedOutPath)
			}
			r.SetXForwarded() //set x-forwarded* headers..
		},
		ErrorHandler:   errorHandler,
		ModifyResponse: modifyResponse,
	}

	return &GoidcReverseProxy{
		config: cfg,
		proxy:  p,
	}
}

// handle supplies an http handler function to proxy a request using the reverse proxy configuration
func (p GoidcReverseProxy) handle(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// modifyResponse modifies the response for all proxied requests, before
// the resonse is sent back to the clients.
func modifyResponse(r *http.Response) error {
	r.Header.Set("sever", "goidc-proxy v0.1")
	return nil
}

// errorHandler logs errored-out proxied requests
func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Errorf("error while proxing request %v", err.Error())
}
