package main

import (
	"time"
)

type RefreshToken struct {
	ID          string
	UserGUID    string
	TokenHash   string
	AccessToken string
	UserAgent   string
	IP          string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	Revoked     bool
}
