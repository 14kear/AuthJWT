package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
)

type Config struct {
	Env    string     `yaml:"env" env-default:"local"`
	HTTP   HTTPConfig `yaml:"http"`
	Secret string     `yaml:"secret"`
}

type HTTPConfig struct {
	Port int `yaml:"port"`
}

func Load(path string) *Config {
	var config Config
	err := cleanenv.ReadConfig(path, &config)
	if err != nil {
		log.Fatalf("cannot read config: %s", err)
	}
	return &config
}
