package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenPayload struct {
	jwt.RegisteredClaims
	UserGUID  string           `json:"sub"`
	ExpiresAt *jwt.NumericDate `json:"exp"`
}

func (t AccessTokenPayload) Validate() error {
	if t.ExpiresAt.Time.Before(time.Now()) {
		return fmt.Errorf("token expired")
	}

	return nil
}
