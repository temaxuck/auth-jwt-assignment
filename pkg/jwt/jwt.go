package jwt

import (
	"errors"
	"fmt"
	"time"

	_jwt "github.com/golang-jwt/jwt/v5"

	"github.com/google/uuid"
)

type Claims struct {
	RefreshTokenID string `json:"rtid"`
	_jwt.RegisteredClaims
}

type JWT struct {
	secret []byte
	ttl    time.Duration
}

func New(secret []byte, ttl time.Duration) *JWT {
	return &JWT{secret, ttl}
}

func (j *JWT) GenerateToken(userID string, rtID string) (token string, claims *Claims, err error) {
	claims = &Claims{
		RefreshTokenID: rtID,
		RegisteredClaims: _jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID,
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(j.ttl)),
		},
	}
	token, err = _jwt.NewWithClaims(_jwt.SigningMethodHS512, claims).SignedString(j.secret)

	return token, claims, err
}

func (j *JWT) ValidateToken(token string) (*Claims, error) {
	t, err := _jwt.ParseWithClaims(
		token,
		&Claims{},
		func(t *_jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*_jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
			}
			return []byte(j.secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	p, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}

	return p, nil
}
