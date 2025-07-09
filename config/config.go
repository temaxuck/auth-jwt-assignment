package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Auth struct {
		AccessTokenTTL  time.Duration
		RefreshTokenTTL time.Duration
		Secret          []byte
		WebhookURL      string
	}

	PG struct {
		URL      string
		PoolSize int32
	}
}

func NewConfig() *Config {
	cfg := &Config{}

	cfg.Auth.Secret = []byte(requireEnvVar("SECRET_KEY"))
	cfg.Auth.AccessTokenTTL = time.Duration(defaultIntVar("ACCESS_TOKEN_TTL_SECONDS", 60*15)) * time.Second
	cfg.Auth.RefreshTokenTTL = time.Duration(defaultIntVar("REFRESH_TOKEN_TTL_SECONDS", 60*60*24)) * time.Second
	cfg.Auth.WebhookURL = optionalEnvVar("WEBHOOK_URL")

	cfg.PG.URL = requireEnvVar("POSTGRES_URL")
	cfg.PG.PoolSize = int32(defaultIntVar("POSTGRES_POOL_SIZE", 1))

	return cfg
}

func requireEnvVar(varname string) string {
	env := os.Getenv(varname)
	if env == "" {
		log.Fatalf("ERROR: Variable %q must be present in environment", varname)
	}

	return env
}

func optionalEnvVar(varname string) string {
	return os.Getenv(varname)
}

func defaultEnvVar(varname string, defaultVal any) any {
	if env := os.Getenv(varname); env != "" {
		return env
	}
	return defaultVal
}

func defaultIntVar(varname string, defaultVal int) int {
	if env := os.Getenv(varname); env != "" {
		v, err := strconv.Atoi(env)
		if err != nil {
			log.Fatalf("ERROR: Couldn't parse integer value: %s", env)
		}
		return v
	}

	return defaultVal
}
