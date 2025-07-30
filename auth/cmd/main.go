package main

import (
	app2 "github.com/14kear/TestingQuestionJWT/auth/internal/app"
	"github.com/14kear/TestingQuestionJWT/auth/internal/config"
	"log"
	"os"
)

func main() {
	cfg := config.Load(os.Getenv("CONFIG_PATH"))

	app, err := app2.NewApp(cfg)
	if err != nil {
		log.Fatalf("failed to init app: %v", err)
	}

	if err := app.Run(cfg.HTTP.Port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
