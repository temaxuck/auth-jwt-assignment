package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	addr := parseAddrFromCli()
	cfg := NewConfig()
	db, err := ConnectDB(cfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}
	if err := InitDB(db); err != nil {
		log.Fatalf("ERROR: %v", err)
		os.Exit(1)
	}

	log.Fatal(runServer(addr, cfg, db))
}

func parseAddrFromCli() string {
	var serverPort uint
	var serverHost string

	flag.UintVar(&serverPort, "p", 8080, "Port the http server to run on")
	flag.StringVar(&serverHost, "h", "localhost", "Host the http server to run on")

	flag.Parse()

	return fmt.Sprintf("%s:%d", serverHost, serverPort)
}
