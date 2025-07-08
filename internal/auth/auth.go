package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	c "auth-jwt-assignment/config"
	m "auth-jwt-assignment/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const TOKEN_HASH_SIZE = 36 // = $(Bcrypt Max Password Length) / $(Chars Per byte) = 72 / 2

func IssueAccessToken(guid string, lifetime time.Duration, secret []byte) (token string, expires time.Time, err error) {
	expires = time.Now().Add(lifetime)
	token, err = jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": guid,
			"exp": expires.Unix(),
		},
	).SignedString(secret)

	return token, expires, err
}

func IssueRefreshToken(db *pgxpool.Pool, guid string, accessToken string, userAgent string, ip string, lifetime time.Duration) (token string, expires time.Time, err error) {
	tokenID := uuid.New().String()
	rawToken, err := generateRawToken()
	if err != nil {
		return "", time.Time{}, err
	}

	now := time.Now()
	expires = now.Add(lifetime)
	t, err := newRefreshToken(tokenID, guid, rawToken, accessToken, userAgent, ip, now, expires, false)
	if err != nil {
		return "", time.Time{}, err
	}

	err = t.Insert(db)
	if err != nil {
		return "", time.Time{}, err
	}

	token = fmt.Sprintf("%s:%s", tokenID, rawToken)
	return base64.StdEncoding.EncodeToString([]byte(token)), expires, nil
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

func ResetTokenCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func ValidateAccessToken(cfg *c.Config, token string) (*AccessTokenPayload, error) {
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

func RevokeRefreshToken(db *pgxpool.Pool, t *m.RefreshToken) error {
	_, err := db.Exec(
		context.Background(),
		`UPDATE refresh_tokens SET revoked = true WHERE id=$1`,
		t.ID,
	)
	return err
}

func RevokeRefreshTokensForClient(db *pgxpool.Pool, userId string, clientIP string, clientUA string) error {
	rts, err := m.RefreshTokenAll(db, map[string]any{
		"UserGUID":  userId,
		"IP":        clientIP,
		"UserAgent": clientUA,
	})
	if err != nil {
		return err
	}
	return revokeRefreshTokens(db, rts)
}

func RevokeRefreshTokensForIP(db *pgxpool.Pool, userId string, clientIP string) error {
	rts, err := m.RefreshTokenAll(db, map[string]any{
		"UserGUID": userId,
		"IP":       clientIP,
	})
	if err != nil {
		return err
	}
	return revokeRefreshTokens(db, rts)
}

func FetchRefreshTokenByRawToken(db *pgxpool.Pool, guid string, tokenStringB64 string) (*m.RefreshToken, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(tokenStringB64)
	if err != nil {
		return nil, err
	}
	tokenParts := strings.SplitN(string(decodedToken), ":", 2)
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}
	tokenID := tokenParts[0]
	rawToken := tokenParts[1]

	rt, err := m.RefreshTokenFirst(db, map[string]any{"ID": tokenID})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch refresh token: %w", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(rt.TokenHash), []byte(rawToken)); err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	return rt, nil
}

func NotifyRefreshFromNewIP(url, userID, newIP, oldIP, userAgent string) error {
	payload := map[string]string{
		"user_guid":  userID,
		"new_ip":     newIP,
		"old_ip":     oldIP,
		"user_agent": userAgent,
	}
	data, _ := json.Marshal(payload)
	_, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}

	return nil
}

func revokeRefreshTokens(db *pgxpool.Pool, rts []m.RefreshToken) error {
	for _, rt := range rts {
		err := RevokeRefreshToken(db, &rt)
		if err != nil {
			return err
		}
	}
	return nil
}

func newRefreshToken(tokenID string, userID string, rawToken string, accessToken string, userAgent string, ip string, expiresAt time.Time, createdAt time.Time, revoked bool) (*m.RefreshToken, error) {
	t := &m.RefreshToken{}
	hashedToken, err := hashToken(rawToken)
	if err != nil {
		return t, err
	}

	t.ID = tokenID
	t.UserGUID = userID
	t.TokenHash = hashedToken
	t.AccessToken = accessToken
	t.UserAgent = userAgent
	t.IP = ip
	t.ExpiresAt = expiresAt
	t.CreatedAt = createdAt
	t.Revoked = revoked

	return t, nil
}

func generateRawToken() (string, error) {
	bytes := make([]byte, TOKEN_HASH_SIZE)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), err
}

func hashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hash), err
}
