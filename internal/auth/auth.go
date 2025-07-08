package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	c "auth-jwt-assignment/config"
	m "auth-jwt-assignment/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	err = storeRefreshToken(db, t)
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
	rts, err := getRefreshTokensByClient(db, userId, clientIP, clientUA)
	if err != nil {
		return fmt.Errorf("Couldn't fetch tokens for client: %v", err)
	}
	return revokeRefreshTokens(db, rts)
}

func RevokeRefreshTokensForIP(db *pgxpool.Pool, userId string, clientIP string) error {
	rts, err := getRefreshTokensByIP(db, userId, clientIP)
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
		return nil, fmt.Errorf("Invalid token format")
	}
	tokenID := tokenParts[0]
	rawToken := tokenParts[1]

	rt, err := getRefreshTokenByTokenID(db, tokenID)
	if err = bcrypt.CompareHashAndPassword([]byte(rt.TokenHash), []byte(rawToken)); err != nil {
		return nil, fmt.Errorf("Invalid refresh token")
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

func storeRefreshToken(db *pgxpool.Pool, t *m.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (
                  id,
                  user_id,
                  token_hash,
                  access_token,
                  user_agent,
                  ip,
                  expires_at,
                  created_at,
                  revoked
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := db.Exec(
		context.Background(), query,
		t.ID, t.UserGUID, t.TokenHash, t.AccessToken, t.UserAgent, t.IP, t.ExpiresAt, t.CreatedAt, t.Revoked,
	)

	return err
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

func getRefreshTokensByClient(db *pgxpool.Pool, userId string, clientIP string, clientUA string) ([]m.RefreshToken, error) {
	rows, err := db.Query(
		context.Background(),
		`SELECT
             id, user_id, token_hash, access_token, user_agent, ip, expires_at, created_at, revoked
         FROM refresh_tokens
         WHERE user_id=$1 AND ip=$2 AND user_agent=$3`,
		userId, clientIP, clientUA,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rts []m.RefreshToken
	for rows.Next() {
		var rt m.RefreshToken
		if err := rows.Scan(
			&rt.ID,
			&rt.UserGUID,
			&rt.TokenHash,
			&rt.AccessToken,
			&rt.UserAgent,
			&rt.IP,
			&rt.ExpiresAt,
			&rt.CreatedAt,
			&rt.Revoked,
		); err != nil {
			return nil, err
		}
		rts = append(rts, rt)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rts, nil
}

func getRefreshTokensByIP(db *pgxpool.Pool, userId string, clientIP string) ([]m.RefreshToken, error) {
	rows, err := db.Query(
		context.Background(),
		`SELECT
             id, user_id, token_hash, access_token, user_agent, ip, expires_at, created_at, revoked
         FROM refresh_tokens
         WHERE user_id=$1 AND ip=$2`,
		userId, clientIP,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rts []m.RefreshToken
	for rows.Next() {
		var rt m.RefreshToken
		if err := rows.Scan(
			&rt.ID,
			&rt.UserGUID,
			&rt.TokenHash,
			&rt.AccessToken,
			&rt.UserAgent,
			&rt.IP,
			&rt.ExpiresAt,
			&rt.CreatedAt,
			&rt.Revoked,
		); err != nil {
			return nil, err
		}
		rts = append(rts, rt)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rts, nil
}

func getRefreshTokenByTokenID(db *pgxpool.Pool, tokenID string) (*m.RefreshToken, error) {
	row := db.QueryRow(
		context.Background(),
		`SELECT
             id, user_id, token_hash, access_token, user_agent, ip, expires_at, created_at, revoked
         FROM refresh_tokens
         WHERE id=$1`,
		tokenID,
	)

	var rt m.RefreshToken
	err := row.Scan(
		&rt.ID,
		&rt.UserGUID,
		&rt.TokenHash,
		&rt.AccessToken,
		&rt.UserAgent,
		&rt.IP,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&rt.Revoked,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("Refresh token not found")
		}
		return nil, err
	}
	return &rt, nil
}
