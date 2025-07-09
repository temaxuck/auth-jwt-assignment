package main

import (
	"log"
	"os"

	c "auth-jwt-assignment/config"
	pg "auth-jwt-assignment/internal/postgres"
	"auth-jwt-assignment/internal/repo"
)

func main() {
	cfg := c.NewConfig()
	db, err := pg.Connect(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}

	tr := repo.NewTokenRepo(db)
	err = tr.InitDBState()
	if err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}

	log.Printf("INFO: Successfully initialized database")
}
