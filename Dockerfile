# syntax=docker/dockerfile:1
FROM golang:1.23

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main ./auth/cmd

EXPOSE 8080

CMD ["/app/main"]