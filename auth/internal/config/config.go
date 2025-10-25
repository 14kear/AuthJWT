package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env             string        `yaml:"env" env-default:"local"`
	AccessTokenTTL  time.Duration `yaml:"access_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_ttl"`
	HTTP            HTTPConfig    `yaml:"http"`
	Secret          string        `yaml:"secret"`
	DB              DBConfig      `yaml:"postgres"`
	SMTP            SMTPConfig    `yaml:"smtp"`
	RedisAddress    string        `yaml:"redis_addr"`
}

type HTTPConfig struct {
	Port string `yaml:"port"`
}

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Dbname   string `yaml:"dbname"`
	Sslmode  string `yaml:"sslmode"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

func Load(path string) *Config {
	var config Config
	err := cleanenv.ReadConfig(path, &config)
	if err != nil {
		log.Fatalf("cannot read config: %s", err)
	}
	return &config
}
