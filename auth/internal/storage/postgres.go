package storage

import (
	"github.com/14kear/TestingQuestionJWT/auth/internal/entity"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

var db *gorm.DB

func InitDB() (*gorm.DB, error) {
	dsn := "host=localhost user=postgres password=123456 dbname=postgres port=5433 sslmode=disable"
	var err error

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}

	if err := db.AutoMigrate(&entity.User{}, &entity.RefreshToken{}); err != nil {
		log.Fatalf("Could not migrate table: %v", err)
	}

	return db, nil
}
