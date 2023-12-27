package oidc

import "github.com/google/uuid"

func NewSessionToken() string {
	return uuid.NewString()
}
