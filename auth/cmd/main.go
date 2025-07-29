package main

import (
	"github.com/14kear/TestingQuestionJWT/auth/internal/storage"
	"log"
)

func main() {
	database, err := storage.InitDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	authRepository :=
}
