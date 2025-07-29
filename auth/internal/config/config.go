package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env             string        `yaml:"env" env-default:"local"`
	AccessTokenTTL  time.Duration `yaml:"access_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_ttl"`
	WebhookURL      string        `yaml:"webhook_url"`
	HTTP            HTTPConfig    `yaml:"http"`
	Secret          string        `yaml:"secret"`
}

type HTTPConfig struct {
	Port string `yaml:"port"`
}

func Load(path string) *Config {
	var config Config
	err := cleanenv.ReadConfig(path, &config)
	if err != nil {
		log.Fatalf("cannot read config: %s", err)
	}
	return &config
}
