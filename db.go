package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectDB(cfg *Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.PG.URL)
	if err != nil {
		return nil, fmt.Errorf("Couldn't parse pool config: %w", err)
	}
	poolConfig.MaxConns = cfg.PG.PoolSize

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("Couldn't connect to database: %w", err)
	}

	err = pool.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Couldn't ping database: %w", err)
	}

	return pool, nil
}

// NOTE: For this specific small assignment we probably don't need to keep models aligned with
// database tables. That's why we create the tables (here it's just one) manually. Usually, I'd use
// GORM for that.
func InitDB(pool *pgxpool.Pool) error {
	query := `CREATE TABLE IF NOT EXISTS refresh_tokens (
                  id SERIAL PRIMARY KEY,
                  user_id UUID NOT NULL,
                  token_hash TEXT NOT NULL,
                  access_token TEXT NOT NULL,
                  user_agent TEXT NOT NULL,
                  ip TEXT NOT NULL,
                  expires_at TIMESTAMP NOT NULL,
                  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                  revoked BOOLEAN NOT NULL DEFAULT FALSE
              );`
	if _, err := pool.Exec(context.Background(), query); err != nil {
		return fmt.Errorf("Couldn't initialized database: %w", err)
	}

	return nil
}
