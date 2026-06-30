package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	limiterredis "github.com/ulule/limiter/v3/drivers/store/redis"
)

func RateLimit(rdb *redis.Client, prefix string, period time.Duration, limit int64) gin.HandlerFunc {
	store, err := limiterredis.NewStoreWithOptions(rdb, limiter.StoreOptions{
		Prefix: "rl:" + prefix,
	})
	if err != nil {
		panic("rate limiter store init failed: " + err.Error())
	}
	instance := limiter.New(store, limiter.Rate{
		Period: period,
		Limit:  limit,
	})
	return func(c *gin.Context) {
		key := c.ClientIP()
		lctx, err := instance.Get(c.Request.Context(), key)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		if lctx.Reached {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}
