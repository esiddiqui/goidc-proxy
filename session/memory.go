package session

import (
	"fmt"
	"sync"
)

type InMemorySessionStore struct {
	mutex    sync.Mutex
	sessions map[string]any
}

func NewInMemorySessionStore() Store {
	return &InMemorySessionStore{
		sessions: make(map[string]any),
	}
}

// All dumps the sessionStore as a key/value map, do not use in prod
func (m *InMemorySessionStore) All() map[string]any {
	return m.sessions
}

// CreateNewSession creates a new session for the supplied key & value
func (m *InMemorySessionStore) SetSession(key string, value any) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sessions[key] = value
	return nil
}

// GetSession returns the session object for the supplied key, or error if it doesn't exist
func (m *InMemorySessionStore) GetSession(key string) (any, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if v, ok := m.sessions[key]; !ok {
		return nil, fmt.Errorf("session %v doesn't exists", key)
	} else {
		return v, nil
	}
}

// InvalidateSession deletes an existing session
func (m *InMemorySessionStore) InvalidateSession(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.sessions, key)
	return nil
}

// SessionExists returns true if a session for the supplied key exists, else false
func (m *InMemorySessionStore) SessionExists(key string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, ok := m.sessions[key]
	return ok
}
