package oidc

import (
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type CookieManager struct {
	cookieName string
}

func NewCookieManager(cookieName string) CookieManager {
	return CookieManager{cookieName}
}

// SetCookie sets the session cookie value & a max-age with the supplied value
func (c CookieManager) SetCookie(w http.ResponseWriter, value string, age int) {
	log.Infof("session cookied %v=%v (max-age: %v)", c.cookieName, value, age)
	http.SetCookie(w, &http.Cookie{
		Name:   c.cookieName,
		Path:   "/",
		Value:  value,
		MaxAge: age,
	})
}

// GetSessionToken reads the value of the goidcsession cookie, which is the
// session token or key used to locate a valid session
func (c CookieManager) GetSessionToken(r *http.Request) (*string, error) {
	log.Infof("getting session cookied %v", c.cookieName)
	cookie, err := r.Cookie(c.cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		log.Debugf("no session cookie with name %v found for this request", c.cookieName)
	} else {
		log.Debugf("error occurred while fetching cookie %v value", c.cookieName)
	}

	if cookie == nil {
		log.Debug("session cookie has expired")
		return nil, err
	}
	return &cookie.Value, nil
}
