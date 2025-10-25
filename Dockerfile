# syntax=docker/dockerfile:1
FROM golang:1.23-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Устанавливаем утилиты для дебага сети (Alpine)
RUN apk add --no-cache \
    busybox-extras \
    curl

RUN go build -o main ./auth/cmd

EXPOSE 8080

CMD ["/app/main"]