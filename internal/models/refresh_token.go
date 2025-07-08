package models

import "time"

type RefreshToken struct {
	ID          string    `morm:"id, UUID, PRIMARY KEY"`
	UserGUID    string    `morm:"user_id, UUID, NOT NULL"`
	TokenHash   string    `morm:"token_hash, TEXT, NOT NULL"`
	AccessToken string    `morm:"access_token, TEXT, NOT NULL"`
	UserAgent   string    `morm:"user_agent, TEXT, NOT NULL"`
	IP          string    `morm:"ip, TEXT, NOT NULL"`
	ExpiresAt   time.Time `morm:"expires_at, TIMESTAMP, NOT NULL"`
	CreatedAt   time.Time `morm:"created_at, TIMESTAMP, NOT NULL, DEFAULT NOW()"`
	Revoked     bool      `morm:"revoked, BOOLEAN, NOT NULL, DEFAULT FALSE"`
}

func (rt RefreshToken) TableName() string {
	return "refresh_tokens"
}
