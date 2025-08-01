package main

import (
	"flag"
	"fmt"
	"log"

	c "auth-jwt-assignment/config"
	"auth-jwt-assignment/internal/http"
	pg "auth-jwt-assignment/internal/postgres"
)

// @title Authentication JWT API
// @version 1.0
// @description JWT Authentication Assignment API

// @contact.name Artem Darizhapov
// @contact.email gorropand@gmail.com

// @BasePath /
func main() {
	addr := parseAddrFromCli()
	cfg := c.NewConfig()
	db, err := pg.Connect(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	s := http.NewServer(addr, cfg, db)
	log.Fatal(s.RunServer())
}

func parseAddrFromCli() string {
	var serverPort uint
	var serverHost string

	flag.UintVar(&serverPort, "p", 8080, "Port the http server to run on")
	flag.StringVar(&serverHost, "h", "localhost", "Host the http server to run on")

	flag.Parse()

	return fmt.Sprintf("%s:%d", serverHost, serverPort)
}
