package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	c "auth-jwt-assignment/config"
	db "auth-jwt-assignment/internal/db"
	"auth-jwt-assignment/internal/http"
)

func main() {
	addr := parseAddrFromCli()
	cfg := c.NewConfig()
	pg, err := db.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}
	if err := db.InitDB(pg); err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}

	log.Fatal(http.RunServer(addr, cfg, pg))
}

func parseAddrFromCli() string {
	var serverPort uint
	var serverHost string

	flag.UintVar(&serverPort, "p", 8080, "Port the http server to run on")
	flag.StringVar(&serverHost, "h", "localhost", "Host the http server to run on")

	flag.Parse()

	return fmt.Sprintf("%s:%d", serverHost, serverPort)
}
