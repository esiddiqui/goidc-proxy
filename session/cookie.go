package session

import (
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type CookieManager struct {
	Name   string
	MaxAge int
	Secure bool
}

func NewCookieManager(cookieName string) CookieManager {
	return CookieManager{
		Name:   cookieName,
		MaxAge: 100, // TODO: @esiddiqui set this to the correct default
		Secure: false,
	}
}

// SetCookieValue sets a cookie name, value & a max-age with the supplied values
func (c CookieManager) setCookieValue(w http.ResponseWriter, value string, age int) {

	log.WithFields(log.Fields{
		"name":  c.Name,
		"value": value,
		"age":   age,
	}).Debug("setting cookie value")

	http.SetCookie(w, &http.Cookie{
		Name:   c.Name,
		Path:   "/",
		Value:  value,
		MaxAge: age,
	})
}

// GetCookieValue returns the value for a cookie name, else error
func (c CookieManager) getCookieValue(r *http.Request) (*string, error) {

	cookie, err := r.Cookie(c.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.WithField("name", c.Name).Debug("no cookie found")
		} else {
			log.WithField("name", c.Name).Debugf("error fetching cookie")
		}
		return nil, err
	}

	if cookie == nil {
		log.WithField("name", c.Name).Debugf("cookie has expired")
		return nil, err
	}

	value := cookie.Value
	log.WithFields(log.Fields{
		"name":  c.Name,
		"value": value,
	}).Debugf("fetching cookie value")
	return &value, nil
}
