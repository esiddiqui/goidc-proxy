package oidc

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/esiddiqui/goidc-proxy/config"
	"github.com/esiddiqui/goidc-proxy/session"
	"github.com/esiddiqui/goidc-proxy/types"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
)

// GoidcReverseProxy uses an httputil.ReverseProxy to proxy requests to
// upstreams (targets) based on the config routes defined in the goidc config
type GoidcReverseProxy struct {
	proxy             *httputil.ReverseProxy
	routes            []config.Route
	propagationPolicy config.PropagationPolicy
}

// NewGoidcReverseProxy create & returns a GoidcReverseProxy using the
// rules defined in the goidc config
func NewGoidcReverseProxy(routes []config.Route, propagationPolicy config.PropagationPolicy) *GoidcReverseProxy {
	p := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			req := r.In
			route := findRouteForPath(routes, req.URL.Path)
			log.WithFields(log.Fields{
				"incoming":     req.URL.Path,
				"routePrefix":  route.Prefix,
				"authRequired": route.AuthRequired,
			}).Debugf("proxying request")

			r.SetURL(route.ProxyUrl)
			r.Out.Host = route.ProxyUrl.Host

			if route.StripPrefix {
				origRequestedPath := r.In.URL.Path // incoming path as requested by client
				origTargetPath := r.Out.URL.Path   // outgoing path as prepared by proxy

				// since target path is already built by proxy using the "upstreamUrl.Path + requestedPath"
				// now when stripPrefix == yes, we will first remove the requestedPath it.
				strippedTargetPathPrefix := strings.TrimSuffix(origTargetPath, origRequestedPath)
				// remove trailing slash
				strippedTargetPathPrefix = strings.TrimSuffix(strippedTargetPathPrefix, "/")
				// now we remove the matched prefix from the beginning of requestedPath
				strippedOutPath := strings.TrimPrefix(origRequestedPath, route.Prefix)
				// ensure leading slash
				if !strings.HasPrefix(strippedOutPath, "/") {
					strippedOutPath = fmt.Sprintf("/%v", strippedOutPath)
				}
				r.Out.URL.Path = fmt.Sprintf("%v%v", strippedTargetPathPrefix, strippedOutPath) // set the outgoing path

				log.WithFields(log.Fields{
					"origRequestedPath": origRequestedPath,
					"origTargetPath":    origTargetPath,
					"r.out.host":        r.Out.Host,
					"strippedOutPath":   strippedOutPath,
				}).Debugf("proxying request after stripping Prefix")
			}
			r.SetXForwarded() //set x-forwarded* headers..

			// propagate oidc tokens to upstream
			if sessObj, ok := r.In.Context().Value(session.SessionContextKey).(*session.Object); ok && sessObj != nil {
				if tokenRes, ok := sessObj.Value.(*types.AccessTokenResponse); ok {
					if propagationPolicy == config.PropagationPolicyAWS {
						// AWS ALB compatible headers
						r.Out.Header.Set("x-amzn-oidc-accesstoken", tokenRes.AccessToken)

						// x-amzn-oidc-identity: The subject field (sub) from the user info endpoint
						// Extracting 'sub' from the IdToken if present
						if tokenRes.IdToken != "" {
							if t, err := jwt.Parse([]byte(tokenRes.IdToken), jwt.WithVerify(false)); err == nil {
								if sub, ok := t.Get("sub"); ok {
									r.Out.Header.Set("x-amzn-oidc-identity", fmt.Sprintf("%v", sub))
								}
							}
							r.Out.Header.Set("x-amzn-oidc-data", tokenRes.IdToken)
						}
					} else {
						// Default headers
						r.Out.Header.Set("X-Auth-Access-Token", tokenRes.AccessToken)
						if tokenRes.IdToken != "" {
							r.Out.Header.Set("X-Auth-Id-Token", tokenRes.IdToken)
						}
					}
				}
			}
		},
		ErrorHandler:   errorHandler,
		ModifyResponse: modifyResponse,
	}

	return &GoidcReverseProxy{
		routes:            routes,
		proxy:             p,
		propagationPolicy: propagationPolicy,
	}
}

// handlerFunc returns the reverseProxy's serveHTTP method so you can use the
// GoidcReverseProxy as an http.HandlerFunc
func (p *GoidcReverseProxy) handlerFunc() func(http.ResponseWriter, *http.Request) {
	return p.proxy.ServeHTTP
}

// ServeHTTP exposes the underlying httpUtil.ReverseProxy's ServeHTTP method
// so the GoidcReverseProxy can be used directly as an http.Handler
func (p *GoidcReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// modifyResponse modifies the response for all proxied requests, before
// the resonse is sent back to the clients.
func modifyResponse(r *http.Response) error {
	r.Header.Set("server", "goidc-proxy v0.1")
	return nil
}

// errorHandler logs errored-out proxied requests
func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.WithFields(log.Fields{
		"err":     err.Error(),
		"host":    r.Host,
		"request": r.URL.Path,
	}).Error("error while proxing request")
	http.Error(w, err.Error(), http.StatusBadGateway)
}

// from the supplied routes ([]Route), find the best matching
// the supplied request URL.
//
// This function loops through all the supplied routes & matches the
// route prefix with the incoming path; the longest-matching path
// is returned
func findRouteForPath(routes []config.Route, path string) *config.Route {

	var selected config.Route
	var found bool

	for _, m := range routes {
		if strings.HasPrefix(path, m.Prefix) {
			if len(m.Prefix) > len(selected.Prefix) {
				selected = m
				found = true
			}
		}
	}

	if !found {
		return nil
	}

	return &selected
}
