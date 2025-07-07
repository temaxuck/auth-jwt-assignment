package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const TOKEN_HASH_SIZE = 54

func IssueAccessToken(cfg *Config, guid string) (token string, expires time.Time, err error) {
	expires = time.Now().Add(cfg.Auth.AccessTokenLifetime)
	token, err = jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": guid,
			"exp": expires.Unix(),
		},
	).SignedString(cfg.Auth.Secret)
	return token, expires, err
}

func IssueRefreshToken(cfg *Config, db *pgxpool.Pool, guid string, accessToken string, userAgent string, ip string) (token string, expires time.Time, err error) {
	rawToken, err := generateRawToken(cfg)
	if err != nil {
		return "", time.Time{}, err
	}

	now := time.Now()
	expires = now.Add(cfg.Auth.RefreshTokenLifetime)
	t, err := newRefreshToken(guid, rawToken, accessToken, userAgent, ip, now, expires, false)
	if err != nil {
		return "", time.Time{}, err
	}

	err = storeRefreshToken(db, t)
	if err != nil {
		return "", time.Time{}, err
	}

	return rawToken, expires, nil
}

func SetTokenCookie(w http.ResponseWriter, cookieName string, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func ValidateAccessToken(cfg *Config, token string) (*AccessTokenPayload, error) {
	t, err := jwt.ParseWithClaims(
		token,
		&AccessTokenPayload{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %w", t.Header["alg"])
			}
			return cfg.Auth.Secret, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Validation failed: %v", err)
	}

	p, ok := t.Claims.(*AccessTokenPayload)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	return p, nil
}

func newRefreshToken(guid string, rawToken string, accessToken string, userAgent string, ip string, expiresAt time.Time, createdAt time.Time, revoked bool) (*RefreshToken, error) {
	t := &RefreshToken{}
	hashedToken, err := hashToken(rawToken)
	if err != nil {
		return t, err
	}

	t.UserGUID = guid
	t.TokenHash = hashedToken
	t.AccessToken = accessToken
	t.UserAgent = userAgent
	t.IP = ip
	t.ExpiresAt = expiresAt
	t.CreatedAt = createdAt
	t.Revoked = revoked

	return t, nil
}

func storeRefreshToken(db *pgxpool.Pool, t *RefreshToken) error {
	query := `INSERT INTO refresh_tokens (
                   user_id,
                   token_hash,
                   access_token,
                   user_agent,
                   ip,
                   expires_at,
                   created_at,
                   revoked
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := db.Exec(
		context.Background(), query,
		t.UserGUID, t.TokenHash, t.AccessToken, t.UserAgent, t.IP, t.ExpiresAt, t.CreatedAt, t.Revoked,
	)

	return err
}

func generateRawToken(cfg *Config) (string, error) {
	bytes := make([]byte, TOKEN_HASH_SIZE)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hash), err
}
