

`goidc-proxy` is an http proxy server that instantly enables authorization and an identity layer for HTTP web applications or microservices via. OAuth 2.0 framework & OpenID Connect.

It sits between the http client or a user agent (e.g a browser) & the up-stream (e.g webapp frontends, microservices etc) and ensures all requests to protected resources are authorized; that is, they have an active `goidc-proxy` session which in turn holds valid OAuth/OIDC credentials (an OAuth access_token, an OIDC id_token etc.). After that the requests are proxied to the configured upstreams. 

Presently only one authorization server can be configured per `goidc-proxy` runtime. However, multiple backends can be proxied to; thus essentially enabling a Single-SignOn (SSO) solution. 

## Session Management

`goidc-proxy` also implements basic http session handling & relies on it for proxying requests appropriately. The `authentication` status of a request is determined using the session as well. The upstream application does not need to worry about performing session handling of it's own if it can work off the basic session information managed & exposed by the `goidc-proxy`. 


 ## User Info endpoint

A `/<oidc_mount_pt>/userinfo` endpoint is also set up by the `goidc-proxy`, which can be consumed by the user-agent or the upstream service to fetch identity information. This endpoint only works when the authorization server configured also exposes an OpenID `/userinfo` endpoint; as well as the corresponding `scopes` being requested during authorization for it to return the required information.


## Supported OAuth Grants

### 1. Authorization Code Grant

Presently only the **Authorization Code Grant** is supported. Once the authorization code flow is successful, the OAuth2.0 & OpenID Connect credentials are stored in the session which is tracked using a cookie. The validity of the cookie is synced with the expiry set on the OIDC access_token; After expiry the session is cleared & any new requests are passed through the authorization flow with the authorization server.

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

### 2. Client Credentials Grant 
TODO

### 3. Un-supported Grants

The **Implicit Grant** being not *very* secure & more suited for client-side only applications is not on the roadmap at the moment.

**Resource Owner Password Credentials** may be supported in the future. However, since this requres the resource owner's password to be passed via the OAuth client, it is not a very commonly-used flow; especially with non-trusted OAuth clients.

## Proxy Features


### Request rewrites

Some basic request rewriting can be done using the `stripPrefix` setting for each route.  For more details on these settings check the Proxy configuration section below. The `goidc-proxy` can also proxy requests to multiple upstream targets based on rules defined in the configuraiton. 




## Session

Sessions are stored in an in-memory cache so only a single instance of the proxy can be deployed. 

**Upcomfing:** In future the sessions would be stored to an out-of-process cache like Redis to allow load-balancing the `goidc-proxy` itself to allow scaling.


## Proxy Configuration:

The configuration settings for the authorization server, session & proxy server itself are pretty straightfoward & self-explanatory. 

ßThe `goidc-proxy` is primarily configured via a yaml file. However, some configuration can be overridden from the environment variables. e.g secrets should not be stored in the yaml, rather supplied at runtime.

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



## Specifications, references & materials

[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)

[OAuth 2.0 Authorization Server Metdata](https://datatracker.ietf.org/doc/html/rfc8414)

[OpenID Connect Basic Client Implementer's Guide 1.0](https://openid.net/specs/openid-connect-core-1_0.html)