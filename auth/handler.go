package auth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"warden/db"
	"warden/middleware"
	"warden/models"
	"warden/session"
)

const sessionCookie = "session_id"

type Handler struct {
	sm  *session.Manager
	rdb *redis.Client
}

func NewHandler(sm *session.Manager, rdb *redis.Client) *Handler {
	return &Handler{sm: sm, rdb: rdb}
}

func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/auth")
	login := middleware.RateLimit(h.rdb, "login", time.Minute, 5)
	g.POST("/register", middleware.RateLimit(h.rdb, "register", time.Hour, 10), h.Register)
	g.POST("/login", login, h.Login)
	g.POST("/logout", h.Logout)

	twofa := g.Group("", middleware.Pending2FA(h.sm))
	twofa.POST("/2fa", middleware.RateLimit(h.rdb, "2fa", time.Minute, 5), h.Verify2FA)
	twofa.POST("/2fa/recovery", middleware.RateLimit(h.rdb, "recovery", time.Minute, 5), h.Recovery)
}

func (h *Handler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	exists, err := db.AccountExists(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "email already taken"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	id, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if _, err := db.CreateAccount(
		c.Request.Context(),
		id.String(), req.Email, string(hash),
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	sessionID, err := h.sm.Create(c.Request.Context(), id.String(), c.GetHeader("User-Agent"), c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	setSessionCookie(c, sessionID)
	c.JSON(http.StatusCreated, gin.H{})
}

func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	account, err := db.GetAccountByEmail(c.Request.Context(), req.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if account.OTPSecret != nil && len(account.RecoveryCodes) > 0 {
		sessionID, err := h.sm.CreatePending2FA(c.Request.Context(), account.ID, c.GetHeader("User-Agent"), c.ClientIP())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		setSessionCookie(c, sessionID)
		c.JSON(http.StatusOK, gin.H{"requires_2fa": true})
		return
	}

	sessionID, err := h.sm.Create(c.Request.Context(), account.ID, c.GetHeader("User-Agent"), c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	setSessionCookie(c, sessionID)
	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) Verify2FA(c *gin.Context) {
	var req models.TwoFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	account, err := db.GetAccountByID(c.Request.Context(), c.GetString("userID"))
	if err != nil || account.OTPSecret == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if !ValidateTOTP(*account.OTPSecret, req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	oldSessionID, _ := c.Cookie(sessionCookie)
	_ = h.sm.Delete(c.Request.Context(), oldSessionID)

	sessionID, err := h.sm.Create(c.Request.Context(), account.ID, c.GetHeader("User-Agent"), c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	setSessionCookie(c, sessionID)
	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) Recovery(c *gin.Context) {
	var req models.RecoveryLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetString("userID")
	ok, err := db.ConsumeRecoveryCode(c.Request.Context(), userID, req.Code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid recovery code"})
		return
	}

	account, err := db.GetAccountByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	oldSessionID, _ := c.Cookie(sessionCookie)
	_ = h.sm.Delete(c.Request.Context(), oldSessionID)

	sessionID, err := h.sm.Create(c.Request.Context(), account.ID, c.GetHeader("User-Agent"), c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	setSessionCookie(c, sessionID)
	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) Logout(c *gin.Context) {
	sessionID, err := c.Cookie(sessionCookie)
	if err == nil {
		_ = h.sm.Delete(c.Request.Context(), sessionID)
	}
	clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{})
}

func setSessionCookie(c *gin.Context, sessionID string) {
	c.SetCookie(sessionCookie, sessionID, 72*60*60, "/", "", true, true)
}

func clearSessionCookie(c *gin.Context) {
	c.SetCookie(sessionCookie, "", -1, "/", "", true, true)
}
