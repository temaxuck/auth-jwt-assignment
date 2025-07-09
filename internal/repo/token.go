package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/pkg/jwt"
)

type TokenRepo struct {
	db              *pgxpool.Pool
	RefreshTokenTTL time.Duration
}

func NewTokenRepo(db *pgxpool.Pool, refreshTokenTTL time.Duration) *TokenRepo {
	return &TokenRepo{
		db:              db,
		RefreshTokenTTL: refreshTokenTTL,
	}
}

func (r *TokenRepo) InitDBState() error {
	query := `
    CREATE TABLE IF NOT EXISTS at_blacklist (
        jti UUID PRIMARY KEY,
        expires_at TIMESTAMP NOT NULL
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id UUID PRIMARY KEY,
        user_id  UUID  NOT NULL,
        token_hash  TEXT  NOT NULL,
        user_agent  TEXT  NOT NULL,
        ip  TEXT  NOT NULL,
        created_at  TIMESTAMP  NOT NULL  DEFAULT NOW(),
        expires_at  TIMESTAMP  NOT NULL,
        revoked  BOOLEAN  NOT NULL  DEFAULT FALSE
    );`

	if _, err := r.db.Exec(context.Background(), query); err != nil {
		return fmt.Errorf("failed to initialize db state: %w", err)
	}

	return nil
}

func (r *TokenRepo) CreateRefreshToken(tokenID string, userID string, tokenHash string, userAgent string, ip string) (*m.RefreshToken, error) {
	now := time.Now()
	expires := now.Add(r.RefreshTokenTTL)
	rt := m.NewRefreshToken(tokenID, userID, tokenHash, userAgent, ip, now, expires, false)

	query := `
    INSERT INTO refresh_tokens (
        id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`

	_, err := r.db.Exec(
		context.Background(), query,
		rt.ID, rt.UserGUID, rt.TokenHash, rt.UserAgent,
		rt.IP, rt.CreatedAt, rt.ExpiresAt, rt.Revoked,
	)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

func (r *TokenRepo) GetRefreshTokenByID(tokenID string) (*m.RefreshToken, error) {
	query := `
    SELECT 
        id, user_id, token_hash, user_agent, ip, expires_at, created_at, revoked
    FROM refresh_tokens
    WHERE "id"=$1;`

	var rt m.RefreshToken

	err := r.db.QueryRow(context.Background(), query, tokenID).Scan(
		&rt.ID, &rt.UserGUID, &rt.TokenHash, &rt.UserAgent,
		&rt.IP, &rt.ExpiresAt, &rt.CreatedAt, &rt.Revoked,
	)
	if err != nil {
		return nil, err
	}

	return &rt, nil
}

func (r *TokenRepo) RevokeRefreshToken(rt *m.RefreshToken) error {
	query := `UPDATE refresh_tokens SET "revoked"=true WHERE "id"=$1;`
	_, err := r.db.Exec(context.Background(), query, rt.ID)
	if err != nil {
		return err
	}

	rt.Revoked = true
	return nil
}

func (r *TokenRepo) RevokeRefreshTokensForUserIP(userID string, ip string) error {
	query := `UPDATE refresh_tokens SET "revoked"=true WHERE "id"=$1 AND "ip"=$2;`
	_, err := r.db.Exec(context.Background(), query, userID, ip)
	if err != nil {
		return err
	}

	return nil
}

func (r *TokenRepo) BlacklistAccessToken(at *jwt.AccessTokenPayload) error {
	query := `INSERT INTO at_blacklist (jti, expires_at) VALUES ($1, $2);`
	_, err := r.db.Exec(context.Background(), query, at.ID, at.GetExpiresAt())

	return err
}

func (r *TokenRepo) CheckIfAccessTokenBlacklisted(at *jwt.AccessTokenPayload) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM at_blacklist WHERE "jti"=$1);`

	var blacklisted bool
	err := r.db.QueryRow(context.Background(), query, at.ID).Scan(&blacklisted)
	if err != nil {
		return false, err
	}

	return blacklisted, err
}
