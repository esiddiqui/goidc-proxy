

goidc-proxy is an http proxy that instantly OIDC-ifies your web-applications or services by negotiating the OIDC auth flows & managinging
sessions. Currently it supports the Authorization-code flow only. Once the auth has been negotiated a session is established & synced
with the ODIC auth_token expiry. A session cookie is sent to the browser & while that cookie is active & present, all susbsequent requests
are proxied to the upstream paths. 

Sessions are stored in an in-memory cache so a single instance of the goidc-proxy can be used. 

The goidc-proxy is configured using the proxy.yml file that is read from the default `./resources/proxy.yml` or a file pointed by the env
var `GOIDCFY_PROXY_CONFIG_PATH`.

The following sample configuration defines some basic:

```yaml
# this section defines the proxy server parameters & session management configuration like cookie & session storage
server: 
  port: 3939 # proxy server listen port
  cookie:
    name: goidcjessionid # session cookie name to use
  session:
    type: memory # type of session storage, memory | redis
    host: redis.cluster.local # redis host to use for session management
    port: 6379 # redis port to use for session management
# this section configure the OIDC related properties. 
# client credentials must be ideally supplied via environment variables
oidc: 
  clientID: <secret> # client ID for oidc authoriztion-code flow; preferably supply via env. GOIDC_OIDC_CLIENT_ID
  clientSecret: <secret> # client Secret for the  authorization-code flow; preferably supply via env. GOIDC_OIDC_CLIENT_SECRET
  issuerUrl: https://domain.auth.com/oauth2/authserver # oidc issuerUrl, use metadataUrl preferrably
  metadataUrl: https://domain.auth.com/oauth2/authserver/.well-known/oauth-authorization-server # metadata/well know url
  endpointMountBase: /oidc # all oidc specific endpoints will be mounted at this base path, oidc/info, oidc/userinfo etc.
  authCallbackPath: /authorization-code/callback # oidc auth callback path when authorization-code flow is used; 
  
# routes that will be configured by proxy. 
# route matching at runtime is done using the best/longest prefix match only; e.g. for configuration
# below an incoming request for /api/v1/info will match route 2, while /api/v2 will match route 1
# no wild-cards are allowed in route prefix
routes: 
  - prefix: /                            # route prefix for match incoming request path
    stripPrefix: false                   # strip the matched part before proxying the request upstream 
    upstreamUrl: http://localhost:3000   # the upstream (target) to proxy the request
    authRequired: yes                    # yes | no, if yes, auth is performed, if no, requests are proxied without auth
  - prefix: /api/v1/ 
    stripPrefix: false 
    upstreamUrl: http://localhost:8080
    authRequired: yes

```

Environment variables can override most of the configuration supplied via yaml proxy configuration.

| Env var | Default | Description |
|---|---|---|
|GOIDC_PROXY_PORT|`3939`| proxy server listen port|
|GOIDCFY_PROXY_CONFIG_PATH|`./resources/proxy.yml`| proxy server configuration file; this is read first to read configuration from the yaml. All other missing values, not supplied in the yaml are overriden from the environment afterwards|
|GOIDC_SESSION_PROVIDER| `memory`| session storage to use, default is `memory` but `redis` is also available |
|GOIDC_REDIS_HOST| |  when `redis` session store is used, supply redis host|
|GOIDC_REDIS_PORT| `6739` | when `redis` session store is used, supply redis port|
|GOIDC_OIDC_CLIENT_ID|  | OIDC application client ID for authorization-code flow |
|GOIDC_OIDC_CLIENT_SECRET|  | OIDC application client secret for authorization-code flow |
|GOIDC_ISSUER_URL|  | **DEPRECATED:** issuer url for the OIDC authorization server|
|GOIDC_METADATA_URL|  | **NEW:** the OIDC authorization server metadata or well-known url|
|GOIDC_OIDC_ENDPOINTS_MOUNT_PATH| `/oidc` | the path to mount all oidc specific endpoints supplied by `goidc-proxy`  e.g `oidc/info`  & `oidc/userinfo` etc|
|GOIDC_OIDC_ENDPOINTS_AUTH_CALLBACK_PATH| `/authorization-code/callback` | The path, part of the OIDC authorization-flow callback URL. An endpoint route will be setup on the goidc-proxy for this path to process the authorization code returned by the authorization server after authorization is complete. When authorization fails on the auth server, the error details are sent to this endpoint as well. This is path section for the URL. |


