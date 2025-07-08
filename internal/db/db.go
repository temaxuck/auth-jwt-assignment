package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	c "auth-jwt-assignment/config"
	m "auth-jwt-assignment/internal/models"
)

func ConnectDB(cfg *c.Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.PG.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pool config: %w", err)
	}
	poolConfig.MaxConns = cfg.PG.PoolSize

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	err = pool.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}

func InitDB(pool *pgxpool.Pool) error {
	err := m.RefreshToken{}.CreateTable(pool)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}
