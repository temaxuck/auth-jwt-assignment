package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
	"auth-jwt-assignment/pkg/twc"

	"github.com/google/uuid"
)

func IssueTokenPair(r *repo.TokenRepo, j *jwt.JWT, userID string, userAgent string, ip string) (at *jwt.AccessTokenPayload, atString string, rt *m.RefreshToken, rtString string, err error) {
	rtString, rt, err = IssueRefreshToken(r, userID, userAgent, ip)
	if err != nil {
		return nil, "", nil, "", err
	}
	atString, at, err = j.GenerateToken(userID, rt.ID)
	if err != nil {
		return nil, "", nil, "", err
	}

	return at, atString, rt, rtString, nil
}

func IssueRefreshToken(r *repo.TokenRepo, userID string, userAgent string, ip string) (token string, rt *m.RefreshToken, err error) {
	tokenID := uuid.New().String()
	tp, err := twc.New(tokenID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token web container: %w", err)
	}
	tokenB64, tokenHash, err := tp.Encode()
	if err != nil {
		return "", nil, err
	}

	rt, err = r.CreateRefreshToken(tokenID, userID, tokenHash, userAgent, ip)
	if err != nil {
		return "", nil, err
	}

	return tokenB64, rt, nil
}

// TODO: put `SetTokenCookie` into handler utilities
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

// TODO: put `ResetTokenCookie` into handler utilities
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

func ValidateRefreshToken(rt *m.RefreshToken, at *jwt.AccessTokenPayload) bool {
	if rt.Revoked ||
		rt.ID != at.RefreshTokenID ||
		rt.UserGUID != at.Subject ||
		rt.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

func Deauthorize(r *repo.TokenRepo, at *jwt.AccessTokenPayload, rt *m.RefreshToken) error {
	var errs []error

	if at != nil {
		if err := r.BlacklistAccessToken(at); err != nil {
			errs = append(errs, fmt.Errorf("failed to blacklist access token: %w", err))
		}
	}
	if rt != nil {
		if err := r.RevokeRefreshToken(rt); err != nil {
			errs = append(errs, fmt.Errorf("failed to revoke refresh token: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func ExtractRefreshToken(r *repo.TokenRepo, tokenB64 string) (*m.RefreshToken, error) {
	tp, err := twc.Decode(tokenB64)
	if err != nil {
		return nil, err
	}

	rt, err := r.GetRefreshTokenByID(tp.TokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch refresh token: %w", err)
	}

	if err = tp.Validate(rt.TokenHash); err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
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
