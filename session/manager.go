package session

import (
	"net/http"
	"time"

	"github.com/esiddiqui/goidc-proxy/config"
	"github.com/pkg/errors"
)

type HandlerFuncWithSession func(w http.ResponseWriter, r *http.Request, s any)

type OptsFunc func(*Manager)

type Manager struct {
	store         Store
	cookieManager *CookieManager
}

// builder

// WithStore add session store to the sessionManager
func WithStore(store Store) OptsFunc {
	return func(manager *Manager) {
		manager.store = store
	}
}

// WithCookieManager add cookieManager to the sessionManager
func WithCookieManager(cookieManager *CookieManager) OptsFunc {
	return func(manager *Manager) {
		manager.cookieManager = cookieManager
	}
}

// NewSessionManager create & return a new SessionManager with the supplied options
func NewSessionManager(cfg *config.SessionConfig, opts ...OptsFunc) (*Manager, error) {

	cookieCfg := cfg.Cookie
	sess := &Manager{
		cookieManager: &CookieManager{
			Name:   cookieCfg.Name,
			MaxAge: cookieCfg.AgeSeconds,
			Secure: cookieCfg.Secure,
		},
	}

	storeConfig := cfg.Store
	if storeConfig.Type == config.SessionTypeMemory {
		sess.store = NewInMemorySessionStore()
	} else {
		return nil, errors.Errorf("session store type %v not supported", storeConfig.Type)
	}

	// apply opts to override any settings
	for _, opt := range opts {
		opt(sess)
	}

	return sess, nil
}

// methods

// Exists checks if a valid goidc session exist for this request.
// first looks for a session token in the goidc cookie. If a cookie
// is found, it uses the value to fetch a session from the store.
func (m Manager) Exists(r *http.Request) bool {
	token, err := m.cookieManager.getCookieValue(r)
	if err != nil {
		return false
	}
	return m.store.SessionExists(*token)
}

// Emtpy checks if a valid goid session exists & is not empty
// a session is considered empty if it doesnt exist, or if it
// exists with a nil value.
// func (m Manager) Empty2(r *http.Request) bool {
// 	if !m.Exists(r) {
// 		return true
// 	}

// 	// error fetching the value, consider it empty
// 	_, val, err := m.Get(r)
// 	if err != nil {
// 		return true
// 	}

// 	// nil value is empty
// 	if val == nil {
// 		return true
// 	}

// 	return false
// }

// GetSessionToken returns a session token if one exists for this request
func (m Manager) GetSessionToken(r *http.Request) (*string, error) {
	token, err := m.cookieManager.getCookieValue(r)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Get returns a token & value stored in the session for this request
func (m Manager) Get(r *http.Request) (*string, *Object, error) {
	token, err := m.cookieManager.getCookieValue(r)
	if err != nil {
		return nil, nil, err
	}
	obj, err := m.store.GetSession(*token)
	if obj != nil {
		sessObj := obj.(Object)
		return token, &sessObj, err
	}

	return token, nil, err
}

// All returns a map of session token to value for all values stored
// in the store,
// @Deprecated
func (m Manager) All() map[string]any {
	return m.store.All()
}

// Set would make a new session with the supplied token & value.
// If the session alreay exists, it will update the value
// Next it will add the Set-Cookie header to the response
func (m Manager) Set(w http.ResponseWriter, token string, value Object) error {

	// store token=value in session store
	err := m.store.SetSession(token, value)
	if err != nil {
		return err
	}

	// store token in cookie
	expiry := int(time.Until(value.ExpiresAt).Seconds())
	if expiry < 0 {
		expiry = m.cookieManager.MaxAge // if expiry was set in past, set it to 1;
	}
	m.cookieManager.setCookieValue(w, token, expiry)
	return nil
}

// http handlers

// getSessionWrapperHandler returns an http.HanlderFunc, which checks for a valid
// session & if it exists, calls the yesHandler, & if not the noHanlder.
func (m Manager) GetSessionWrapperHandler(yesHandler, noHandler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// if session doesn't exist, or the session has a nil-value
		if _, sess, err := m.Get(r); err != nil || sess.Value == nil {
			noHandler(w, r)
			return
		} else {
			wr_w := NewResponseWriterWithSessionInfo(w, sess)
			yesHandler(wr_w, r)
			return
		}
	})
}
