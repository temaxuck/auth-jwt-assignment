package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	c "auth-jwt-assignment/config"
	"auth-jwt-assignment/internal/http"
	pg "auth-jwt-assignment/internal/postgres"
)

func main() {
	addr := parseAddrFromCli()
	cfg := c.NewConfig()
	db, err := pg.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}
	if err := pg.InitDB(db); err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}

	log.Fatal(http.RunServer(addr, cfg, db))
}

func parseAddrFromCli() string {
	var serverPort uint
	var serverHost string

	flag.UintVar(&serverPort, "p", 8080, "Port the http server to run on")
	flag.StringVar(&serverHost, "h", "localhost", "Host the http server to run on")

	flag.Parse()

	return fmt.Sprintf("%s:%d", serverHost, serverPort)
}
