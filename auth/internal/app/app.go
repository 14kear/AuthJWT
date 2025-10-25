package app

import (
	"fmt"

	"github.com/14kear/TestingQuestionJWT/auth/internal/cache"
	"github.com/14kear/TestingQuestionJWT/auth/internal/config"
	"github.com/14kear/TestingQuestionJWT/auth/internal/email"
	"github.com/14kear/TestingQuestionJWT/auth/internal/handlers"
	"github.com/14kear/TestingQuestionJWT/auth/internal/repo"
	"github.com/14kear/TestingQuestionJWT/auth/internal/routes"
	"github.com/14kear/TestingQuestionJWT/auth/internal/services"
	"github.com/14kear/TestingQuestionJWT/auth/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"log"
	"log/slog"
)

func NewApp(cfg *config.Config) (*gin.Engine, error) {
	logger := slog.Default()

	database, err := storage.InitDB(cfg)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	repository := repo.NewRepository(database)
	// TODO: убрать

	emailClient := email.NewSMTPClient(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Password, cfg.SMTP.From)
	fmt.Printf("Creating SMTP client: host=%s, port=%d\n", cfg.SMTP.Host, cfg.SMTP.Port)

	redisClient := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddress,
	})
	redisStorage := cache.NewRedisVerificationStorage(redisClient)

	service := services.NewAuth(logger, repository, repository, redisStorage, emailClient, cfg.Secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	handler := handlers.NewAuthHandler(service)

	r := gin.Default()
	auth := r.Group("/auth")
	routes.RegisterRoutes(auth, handler, cfg.Secret)

	return r, nil
}
