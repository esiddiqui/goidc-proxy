package session

import (
	"net/http"
	"time"
)

// Store defines a session store interface to be
// implemented by a concrete objects
type Store interface {
	All() map[string]any
	SetSession(key string, data any) error
	GetSession(key string) (any, error)
	InvalidateSession(key string) error
	SessionExists(key string) bool
}

// Object wraps the data stored for each session key
type Object struct {
	TokenRaw       string       `json:"raw"`
	Value          any          `json:"val"`
	OrignalRequest http.Request `json:"-"` //reference to the orignal un-auth requeest if oidc flow is triggered
	ExpiresAt      time.Time    `json:"expiresOn"`
}

type ResponseWriterWithSessionInfo struct {
	http.ResponseWriter
	SessionObject *Object // this is the object from session; generic typed for some sanity
}

// Write just wraps the http.ResponseWriter::Write()
func (w ResponseWriterWithSessionInfo) Write(bytes []byte) (int, error) {
	return w.ResponseWriter.Write(bytes)
}

// NewResponseWriterWithSessionInfo creates a new
func NewResponseWriterWithSessionInfo(w http.ResponseWriter, sessionObject *Object) ResponseWriterWithSessionInfo {
	return ResponseWriterWithSessionInfo{w, sessionObject}
}
