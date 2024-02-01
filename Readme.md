

`goidc-proxy` is an http proxy server that enables OIDC auth for http web-applications & microservices. The proxy sits between the http client (e.g a browser) & the upstreams (webapp frontends, micro-services etc) and enforces that the requests are authenticated; that is, they have an active `goidc-proxy` session, that holds valid OIDC credentials (an OIDC access_token, id_token etc.). Only then, the requests are proxied to the configured upstream. Only one authorization server can be configured per instance. However, multiple backends can be proxied to; thus essentially enabling a Single-SignOn (SSO) solution. Currently `goidc-proxy` enforces session manangement. As a benefit of that, the upstream web application do not need to worry about it. 

A `/<oidc_mount_pt>/userinfo` endpoint is also exposed by the proxy for the client or the upstream services to fetch authorization information. This requires the authorization server being used also exposes an OpenID `/userinfo` endpoint, and corresponding `scopes` were requested during OIDC auth flow for it to return the required information. Using that access_token for each session, the `goidc_proxy` can call the `/userinfo` endpoint & return the response so it can be consumed by the client or the upstream.

## Supported OAuth flows:
Currently only the authorization-code flow is supported. Once the flow is successful, OIDC credentials are stored in a session which is tracked using a cookie. The validity of the cookie is synced with the expiry set on the OIDC access_token; After expiry the session is cleared & any new requests are sent to complete the auth flow with the authorization server.

In addition some basic request rewriting can be done using the `stripPrefix` setting for each route.  For more details on these settings check the Proxy configuration section below.

The `goidc-proxy` can also proxy requests to multiple upstream targets based on rules defined in the configuraiton. 

The configuration for the oidc authorization server, session & proxy server itself are pretty straightfoward & self-explanatory. See Proxy Configuration section for more details.


The diagram below shows the flow of http traffic (request/response) via the `goidc-proxy` to upstream servers & back. At present, the `goidc-proxy` does not terminate TLS, so as a best-practice it must never to be exposed to the clients on internet directly. There must a load-balancer configured that sits between the client & proxy to terminate TLS & simply forward all incoming requests.


```
                         [ OIDC auth server]
                                  ^
                                 /|\
                                  |
                                  |                 _______ /web   ---> [ webapp ]
                                  |                / 
 [ client ] <---->[ LB ]<--->[ goidc-proxy ] _____/_______ /api/v3 ---> [ service-v3]
                                  ^               \
                                 /|\               \_____ /api/v1  ---> [ service-v1 ]
                                  |                
                                  |
                             [ proxy.yml ]

```

## Session

Sessions are stored in an in-memory cache so only a single instance of the proxy can be deployed. 

**Upcomfing:** In future the sessions would be stored to an out-of-process cache like Redis to allow load-balancing the `goidc-proxy` itself to allow scaling.


## Proxy Configuration:

The `goidc-proxy` is primarily configured via a yaml file. However, some configuration can be overridden from the environment variables. e.g secrets should not be stored in the yaml, rather supplied at runtime.

### Yaml Configuration:

The `goidc-proxy` is configured using a yaml configuration file that is read from a default location at `./resources/proxy.yml` or from the file pointed by the env var `GOIDC_PROXY_CONFIG_PATH`. See below for an explanation of various config fields:

```yaml
# SECTION 1
# this section defines the proxy server parameters & session management configuration like cookie & session storage
server: 
  port: 3939 # proxy server listen port
  cookie:
    name: goidcjessionid # session cookie name to use
  session:
    type: memory # type of session storage, memory | redis
    host: redis.cluster.local # redis host to use for session management
    port: 6379 # redis port to use for session management

# SECTION 2
# this section configure the OIDC related properties. 
# client credentials must be ideally supplied via environment variables
oidc: 
  # client ID for oidc authoriztion-code flow; preferably supply via env. GOIDC_OIDC_CLIENT_ID
  clientID: <secret>     
  # client Secret for the  authorization-code flow; preferably supply via env. GOIDC_OIDC_CLIENT_SECRET
  clientSecret: <secret> 
  # metadata can be supplied directly under this item
  metadata: 
    issuer: 
    authorization_endpoint: 
    token_endpoint: 
    registration_endpoint: 
    jwks_uri: 
      :
      :
      :
  # metadata/well-know url; used this instead of metadata if the auth server has a metadata endpoint
  metadataUrl: https://domain.auth.com/oauth2/authserver/.well-known/oauth-authorization-server 
  # all oidc specific endpoints will be mounted at this base path, oidc/info, oidc/userinfo etc.
  endpointMountBase: /oidc 
  # oidc auth callback path when authorization-code flow is used; 
  authCallbackPath: /authorization-code/callback
  userInfoPath: /v1/userinfo # oidc userinfo endpoint path for the auth server;
  scopes:  # requested scopes when making the auth request
   - openid
   - scopeC
   - scopeB


# SECTION 3
# routes that will be configured at the proxy. 
# route matching at runtime is done using the best/longest prefix match only; e.g. for configuration
# below an incoming request for /api/v1/info will match route 2, while /api/v2 will match route 1
# no wild-cards are allowed in route prefix
routes: 
    # route prefix for match incoming request path
  - prefix: /                           
    # strip the matched part before proxying the request upstream 
    stripPrefix: false                   
    # the upstream (target) to proxy the request
    upstreamUrl: http://localhost:3000
    # yes | no, if yes, OIDC auth is performed & a session is checked before each proxy; if no, requests are proxied as-is
    authRequired: yes
  - prefix: /api/v1/ 
    stripPrefix: false 
    upstreamUrl: http://localhost:8080
    authRequired: yes

```

### Environment Variables for Configuration

Environment variables can override most of the configuration supplied via yaml proxy configuration.

| Env var | Default | Description |
|---|---|---|
|GOIDC_CLIENT_ID|  | OIDC application client ID for authorization-code flow |
|GOIDC_CLIENT_SECRET|  | OIDC application client secret for authorization-code flow |

