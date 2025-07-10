ENV_FILE        ?= .env
BUILD_DIR       ?= ./build
SWAG_EXECUTABLE ?= ~/go/bin/swag

SERVER_HOST ?= localhost
SERVER_PORT ?= 8080

include $(ENV_FILE)
export

build:
	go $(BUILD_DIR)/server -o cmd/server/
	go $(BUILD_DIR)/db -o cmd/db/

run: build
	$(BUILD_DIR)/server -h $(SERVER_HOST) -p $(SERVER_PORT)

init_db: build
	$(BUILD_DIR)/db

build_docs:
	$(SWAG_EXECUTABLE) init -g cmd/server/main.go

dev:
	go run cmd/server/main.go
