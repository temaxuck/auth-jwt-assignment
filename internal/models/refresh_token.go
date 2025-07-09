package models

import "time"

type RefreshToken struct {
	ID        string
	UserGUID  string
	TokenHash string
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool

	WebToken string
}

func NewRefreshToken(tokenID string, userID string, tokenHash string, userAgent string, ip string, createdAt time.Time, expiresAt time.Time, revoked bool, token string) *RefreshToken {
	return &RefreshToken{
		tokenID,
		userID,
		tokenHash,
		userAgent,
		ip,
		createdAt,
		expiresAt,
		revoked,

		token,
	}
}
