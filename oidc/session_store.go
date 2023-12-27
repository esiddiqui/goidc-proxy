package oidc

// SessionStore defines a SessionStore interface to be
// implemented by a concrete object
type SessionStore interface {
	All() map[string]any
	CreateNewSession(key string, data any) error
	GetSession(key string) (any, error)
	InvalidateSession(key string) error
	SessionExists(key string) bool
}
