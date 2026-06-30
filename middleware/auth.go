package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"warden/session"
)

const sessionCookie = "session_id"

func Auth(sm *session.Manager) gin.HandlerFunc {
	return authorize(sm, false)
}

func Pending2FA(sm *session.Manager) gin.HandlerFunc {
	return authorize(sm, true)
}

func authorize(sm *session.Manager, pendingOnly bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := extractSessionID(c)
		if id == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		s, err := sm.Get(c.Request.Context(), id)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		if s.Pending2FA != pendingOnly {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "2fa required"})
			return
		}

		_ = sm.Refresh(c.Request.Context(), id)

		c.Set("userID", s.UserID)
		c.Next()
	}
}

func extractSessionID(c *gin.Context) string {
	if cookie, err := c.Cookie(sessionCookie); err == nil && cookie != "" {
		return cookie
	}

	header := c.GetHeader("Authorization")
	if token, ok := strings.CutPrefix(header, "Bearer "); ok {
		return token
	}

	return ""
}
