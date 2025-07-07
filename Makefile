ENV_FILE ?= .env

include $(ENV_FILE)
export

run:
	go run .

