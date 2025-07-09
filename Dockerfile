FROM golang:1.23.4-alpine AS builder

WORKDIR /app
COPY . .

RUN go mod download
RUN go build -o /app/bin/init ./cmd/db/init.go
RUN go build -o /app/bin/server ./cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/bin/init ./init
COPY --from=builder /app/bin/server ./server

CMD ./init && ./server -h 0.0.0.0 -p 8080