package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"warden/account"
	"warden/auth"
	"warden/db"
	"warden/middleware"
	"warden/session"
)

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env: %s", key)
	}
	return v
}

func main() {
	if err := db.Connect(context.Background(), mustEnv("DATABASE_URL")); err != nil {
		log.Fatalf("db connect failed: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mustEnv("REDIS_URL")})
	sm := session.NewManager(rdb)

	r := gin.Default()
	if proxies := os.Getenv("TRUSTED_PROXIES"); proxies != "" {
		if err := r.SetTrustedProxies(strings.Split(proxies, ",")); err != nil {
			log.Fatalf("invalid TRUSTED_PROXIES: %v", err)
		}
	} else {
		_ = r.SetTrustedProxies(nil)
	}

	v1 := r.Group("/api/v1")
	auth.NewHandler(sm, rdb).RegisterRoutes(v1)

	protected := v1.Group("")
	protected.Use(middleware.Auth(sm))
	account.NewHandler(sm).RegisterRoutes(protected)

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
