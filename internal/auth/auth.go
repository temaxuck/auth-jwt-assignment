package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	c "auth-jwt-assignment/config"
	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
	"auth-jwt-assignment/pkg/twc"

	"github.com/google/uuid"
)

type AuthService struct {
	j   *jwt.JWT
	tr  *repo.TokenRepo
	cfg *c.Config
}

func NewAuthService(j *jwt.JWT, tr *repo.TokenRepo, cfg *c.Config) *AuthService {
	return &AuthService{j, tr, cfg}
}

func (as *AuthService) IssueTokenPair(userID string, userAgent string, ip string) (at *m.AccessToken, rt *m.RefreshToken, err error) {
	rt, err = as.IssueRefreshToken(userID, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}
	at, err = as.IssueAccessToken(userID, rt.ID)
	if err != nil {
		return nil, nil, err
	}

	return at, rt, nil
}

func (as *AuthService) IssueAccessToken(userID string, refreshTokenID string) (*m.AccessToken, error) {
	token, claims, err := as.j.GenerateToken(userID, refreshTokenID)
	if err != nil {
		return nil, err
	}

	return jwtToAccessToken(token, claims), nil
}

func (as *AuthService) IssueRefreshToken(userID string, userAgent string, ip string) (rt *m.RefreshToken, err error) {
	tokenID := uuid.New().String()
	tp, err := twc.New(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token web container: %w", err)
	}
	tokenB64, tokenHash, err := tp.Encode()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rt = m.NewRefreshToken(tokenID, userID, tokenHash, userAgent, ip, now, now.Add(as.cfg.Auth.RefreshTokenTTL), false, tokenB64)
	err = as.tr.CreateRefreshToken(rt)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

func (as *AuthService) ValidateAccessToken(atString string) (at *m.AccessToken, err error) {
	claims, err := as.j.ValidateToken(atString)
	if err != nil {
		return nil, err
	}
	at = jwtToAccessToken(atString, claims)

	blacklisted, err := as.tr.CheckIfAccessTokenBlacklisted(at)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, errors.New("token is blacklisted")
	}

	return at, nil
}

func (as *AuthService) ValidateRefreshToken(rt *m.RefreshToken, at *m.AccessToken) bool {
	if rt.Revoked ||
		rt.ID != at.RefreshTokenID ||
		rt.UserGUID != at.UserGUID ||
		rt.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

func (as *AuthService) Deauthorize(at *m.AccessToken, rt *m.RefreshToken) error {
	var errs []error

	if at != nil {
		if err := as.tr.BlacklistAccessToken(at); err != nil {
			errs = append(errs, fmt.Errorf("failed to blacklist access token: %w", err))
		}
	}
	if rt != nil {
		if err := as.RevokeRefreshToken(rt); err != nil {
			errs = append(errs, fmt.Errorf("failed to revoke refresh token: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (as *AuthService) RevokeRefreshToken(rt *m.RefreshToken) error {
	return as.tr.RevokeRefreshToken(rt)
}

func (as *AuthService) RevokeRefreshTokensForUserIP(userID string, ip string) error {
	return as.tr.RevokeRefreshTokensForUserIP(userID, ip)
}

func (as *AuthService) ExtractRefreshToken(tokenB64 string) (*m.RefreshToken, error) {
	tp, err := twc.Decode(tokenB64)
	if err != nil {
		return nil, err
	}

	rt, err := as.tr.GetRefreshTokenByID(tp.TokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch refresh token: %w", err)
	}
	rt.WebToken = tokenB64

	if err = tp.Validate(rt.TokenHash); err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	return rt, nil
}

func (as *AuthService) NotifyRefreshFromNewIP(url, userID, newIP, oldIP, userAgent string) error {
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

func jwtToAccessToken(token string, claims *jwt.Claims) *m.AccessToken {
	return &m.AccessToken{
		ID:             claims.ID,
		UserGUID:       claims.Subject,
		ExpiresAt:      claims.ExpiresAt.Time,
		RefreshTokenID: claims.RefreshTokenID,

		WebToken: token,
	}
}
