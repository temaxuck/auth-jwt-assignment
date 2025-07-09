package jwt

import (
	"errors"
	"fmt"
	"time"

	_jwt "github.com/golang-jwt/jwt/v5"

	"github.com/google/uuid"
)

type AccessTokenPayload struct {
	RefreshTokenID string `json:"rtid"`
	_jwt.RegisteredClaims
}

func (p *AccessTokenPayload) GetExpiresAt() time.Time {
	return p.ExpiresAt.Time
}

type JWT struct {
	secret []byte
	ttl    time.Duration
}

func New(secret []byte, ttl time.Duration) *JWT {
	return &JWT{secret, ttl}
}

func (j *JWT) GenerateToken(userID string, rtID string) (token string, payload *AccessTokenPayload, err error) {
	payload = &AccessTokenPayload{
		RefreshTokenID: rtID,
		RegisteredClaims: _jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(j.ttl)),
			ID:        uuid.New().String(),
		},
	}
	token, err = _jwt.NewWithClaims(_jwt.SigningMethodHS512, payload).SignedString(j.secret)

	return token, payload, err
}

func (j *JWT) ValidateToken(token string) (*AccessTokenPayload, error) {
	t, err := _jwt.ParseWithClaims(
		token,
		&AccessTokenPayload{},
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

	p, ok := t.Claims.(*AccessTokenPayload)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}

	return p, nil
}
