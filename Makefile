ENV_FILE        ?= .env
SWAG_EXECUTABLE ?= ~/go/bin/swag

include $(ENV_FILE)
export

run:
	go run cmd/server/main.go

init_db:
	go run cmd/db/init.go

build_docs:
	$(SWAG_EXECUTABLE) init -g cmd/server/main.go
