ENV_FILE        ?= .env
BUILD_DIR       ?= ./build
SWAG_EXECUTABLE ?= ~/go/bin/swag

SERVER_HOST ?= localhost
SERVER_PORT ?= 8080

include $(ENV_FILE)
export

.PHONY: build run init_db build_docs dev

build:
	mkdir -p $(BUILD_DIR)

	go build -o $(BUILD_DIR)/server ./cmd/server/
	go build -o $(BUILD_DIR)/db ./cmd/db/

run: build
	$(BUILD_DIR)/server -h $(SERVER_HOST) -p $(SERVER_PORT)

init_db: build
	$(BUILD_DIR)/db

build_docs:
	$(SWAG_EXECUTABLE) init -g cmd/server/main.go

dev:
	go run cmd/server/main.go
