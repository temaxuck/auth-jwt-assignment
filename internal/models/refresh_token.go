package models

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshToken struct {
	ID          string    `mqe:"id, UUID, PRIMARY KEY"`
	UserGUID    string    `mqe:"user_id, UUID, NOT NULL"`
	TokenHash   string    `mqe:"token_hash, TEXT, NOT NULL"`
	AccessToken string    `mqe:"access_token, TEXT, NOT NULL"`
	UserAgent   string    `mqe:"user_agent, TEXT, NOT NULL"`
	IP          string    `mqe:"ip, TEXT, NOT NULL"`
	ExpiresAt   time.Time `mqe:"expires_at, TIMESTAMP, NOT NULL"`
	CreatedAt   time.Time `mqe:"created_at, TIMESTAMP, NOT NULL, DEFAULT NOW()"`
	Revoked     bool      `mqe:"revoked, BOOLEAN, NOT NULL, DEFAULT FALSE"`
}

func (rt RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (rt RefreshToken) CreateTable(db *pgxpool.Pool) error {
	columns, err := GetColumns(rt, true)
	if err != nil {
		return err
	}

	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s ( %s )", rt.TableName(), strings.Join(columns, ",\n  "))
	if _, err := db.Exec(context.Background(), query); err != nil {
		return fmt.Errorf("failed to initalize table: %w", err)
	}

	return nil
}

func (rt *RefreshToken) Insert(db *pgxpool.Pool) error {
	tableName := rt.TableName()
	columns, err := GetColumns(rt, false)
	if err != nil {
		return err
	}

	placeholder, _ := argsPlaceholderString(uint(len(columns)))
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tableName, strings.Join(columns, ", "), placeholder)
	_, err = db.Exec(
		context.Background(), query,
		rt.ID, rt.UserGUID, rt.TokenHash, rt.AccessToken, rt.UserAgent, rt.IP, rt.ExpiresAt, rt.CreatedAt, rt.Revoked,
	)

	return err
}

// Fetches first refresh token that satisfies filters.
//
// `filters` is map, where key is a struct field with "mqe" tag, (not sql table column name!), and
// value is the value to filter by
func RefreshTokenFirst(db *pgxpool.Pool, filters map[string]any) (*RefreshToken, error) {
	rt := RefreshToken{}
	tableName := rt.TableName()
	columns, err := GetColumns(rt, false)
	if err != nil {
		return nil, err
	}
	whereClauses, args, _, err := parseClauseExpr(&rt, filters, -1)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), tableName)
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	row := db.QueryRow(context.Background(), query, args...)
	err = row.Scan(
		&rt.ID, &rt.UserGUID, &rt.TokenHash, &rt.AccessToken,
		&rt.UserAgent, &rt.IP, &rt.ExpiresAt, &rt.CreatedAt, &rt.Revoked,
	)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return &rt, nil
}

// Fetches all refresh tokens that satisfy filters.
//
// See `RefreshTokenFirst` for arguments documentation
func RefreshTokenAll(db *pgxpool.Pool, filters map[string]any) ([]RefreshToken, error) {
	rt := RefreshToken{}
	tableName := rt.TableName()
	columns, err := GetColumns(rt, false)
	if err != nil {
		return nil, err
	}
	whereClauses, args, _, err := parseClauseExpr(&rt, filters, -1)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), tableName)
	if len(whereClauses) > 0 {
		query = fmt.Sprintf("%s WHERE %s", query, strings.Join(whereClauses, " AND "))
	}

	rows, err := db.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rts []RefreshToken
	for rows.Next() {
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

func (rt *RefreshToken) Update(db *pgxpool.Pool, newValues map[string]any) error {
	tableName := rt.TableName()
	setClauses, setArgs, setArgc, err := parseClauseExpr(rt, newValues, -1)
	if err != nil {
		return err
	}
	if len(setClauses) == 0 {
		return fmt.Errorf("set clause cannot be empty")
	}

	query := fmt.Sprintf("UPDATE %s SET %s WHERE id=$%d", tableName, strings.Join(setClauses, ", "), setArgc)
	args := append(setArgs, rt.ID)
	if _, err := db.Exec(context.Background(), query, args...); err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

	return nil
}
