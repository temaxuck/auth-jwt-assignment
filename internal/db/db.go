package db

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	c "auth-jwt-assignment/config"
	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/pkg/morm"
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

// NOTE: For this specific small assignment we probably don't need to keep models aligned with
// database tables. That's why we create the tables (here it's just one) manually. Usually, I'd use
// GORM for that.
func InitDB(pool *pgxpool.Pool) error {
	query, err := morm.CreateTable(m.RefreshToken{})
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	if _, err := pool.Exec(context.Background(), string(query)); err != nil {
		return fmt.Errorf("failed to initalize table: %w", err)
	}

	return nil
}
