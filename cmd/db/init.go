package main

import (
	"log"

	c "auth-jwt-assignment/config"
	pg "auth-jwt-assignment/internal/postgres"
	"auth-jwt-assignment/internal/repo"
)

func main() {
	cfg := c.NewConfig()
	db, err := pg.Connect(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	tr := repo.NewTokenRepo(db)
	err = tr.InitDBState()
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	log.Printf("INFO: Successfully initialized database")
}
