package models

import "time"

type AccessToken struct {
	ID             string
	UserGUID       string
	ExpiresAt      time.Time
	RefreshTokenID string

	WebToken string
}
