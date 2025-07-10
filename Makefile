ENV_FILE ?= .env

include $(ENV_FILE)
export

run:
	go run cmd/server/main.go

init_db:
	go run cmd/db/init.go
