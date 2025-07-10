FROM golang:1.23.4-alpine AS builder

WORKDIR /app
COPY . .

RUN apk add --no-cache make
RUN go mod download
RUN make build

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/build/db ./db
COPY --from=builder /app/build/server ./server

RUN chmod +x ./db ./server

RUN ls -alh

CMD ./db && ./server -h ${SERVER_HOST} -p ${SERVER_PORT}