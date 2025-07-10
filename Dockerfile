FROM golang:1.23.4-alpine AS builder

WORKDIR /app
COPY . .

RUN apk add --no-cache make
RUN go mod download
RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN make build
RUN make build_docs

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/build/db ./db
COPY --from=builder /app/build/server ./server
COPY --from=builder /app/docs ./docs

CMD ./db && ./server -h ${SERVER_HOST} -p ${SERVER_PORT}