package app

import (
	"github.com/14kear/TestingQuestionJWT/auth/internal/config"
	"github.com/14kear/TestingQuestionJWT/auth/internal/handlers"
	"github.com/14kear/TestingQuestionJWT/auth/internal/repo"
	"github.com/14kear/TestingQuestionJWT/auth/internal/routes"
	"github.com/14kear/TestingQuestionJWT/auth/internal/services"
	"github.com/14kear/TestingQuestionJWT/auth/internal/storage"
	"github.com/gin-gonic/gin"
	"log"
	"log/slog"
)

func NewApp(cfg *config.Config) (*gin.Engine, error) {
	logger := slog.Default()

	database, err := storage.InitDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	repository := repo.NewRepository(database)

	service := services.NewAuth(logger, repository, repository, cfg.Secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	handler := handlers.NewAuthHandler(service, cfg.WebhookURL)

	r := gin.Default()
	auth := r.Group("/auth")
	routes.RegisterRoutes(auth, handler, cfg.Secret)

	return r, nil
}
