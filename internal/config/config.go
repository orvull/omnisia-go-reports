package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	GRPCAddr          string
	JWTSigningKey     string
	JWTTTLSeconds     int64
	RefreshTTLSeconds int64
	GoogleClientID    string
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getInt64(key string, def int64) int64 {
	v := getenv(key, "")
	if v == "" {
		return def
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Printf("invalid int for %s, using default: %v", key, err)
		return def
	}
	return i
}

func Load() Config {
	return Config{
		GRPCAddr:          getenv("GRPC_ADDR", ":50051"),
		JWTSigningKey:     getenv("JWT_SIGNING_KEY", "dev_insecure_change_me"),
		JWTTTLSeconds:     getInt64("JWT_TTL_SECONDS", 900),
		RefreshTTLSeconds: getInt64("REFRESH_TTL_SECONDS", 14*24*3600),
		GoogleClientID:    getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
	}
}
