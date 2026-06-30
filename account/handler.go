package account

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"warden/auth"
	"warden/db"
	"warden/models"
	"warden/session"
)

const sessionCookie = "session_id"

type Handler struct {
	sm *session.Manager
}

func NewHandler(sm *session.Manager) *Handler {
	return &Handler{sm: sm}
}

func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/account")
	g.GET("/me", h.GetMe)
	g.PATCH("/me/password", h.ChangePassword)
	g.PATCH("/me/email", h.ChangeEmail)
	g.DELETE("/me", h.DeleteAccount)
	g.POST("/me/2fa/setup", h.TwoFASetup)
	g.POST("/me/2fa/confirm", h.TwoFAConfirm)
	g.DELETE("/me/2fa", h.TwoFADisable)
	g.GET("/me/sessions", h.GetSessions)
	g.DELETE("/me/sessions", h.TerminateAllSessions)
	g.DELETE("/me/sessions/:id", h.TerminateSession)
}

func (h *Handler) GetMe(c *gin.Context) {
	account, err := db.GetAccountByID(c.Request.Context(), c.GetString("userID"))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.clearSession(c)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         account.ID,
		"email":      account.Email,
		"has_2fa":    account.OTPSecret != nil && len(account.RecoveryCodes) > 0,
		"created_at": account.CreatedAt,
	})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetString("userID")
	account, err := db.GetAccountByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.OldPassword)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.NewPassword)) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must differ from old"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := db.UpdateAccountPassword(c.Request.Context(), userID, string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	sessionID, _ := c.Cookie(sessionCookie)
	_ = h.sm.DeleteAllExcept(c.Request.Context(), userID, sessionID)

	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) ChangeEmail(c *gin.Context) {
	var req models.ChangeEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetString("userID")
	account, err := db.GetAccountByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	if account.Email == req.NewEmail {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new email must differ from current"})
		return
	}

	exists, err := db.AccountExists(c.Request.Context(), req.NewEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "email already taken"})
		return
	}

	if err := db.UpdateAccountEmail(c.Request.Context(), userID, req.NewEmail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) DeleteAccount(c *gin.Context) {
	var req models.DeleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetString("userID")
	account, err := db.GetAccountByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	if account.OTPSecret != nil {
		switch {
		case req.Code != "":
			if !auth.ValidateTOTP(*account.OTPSecret, req.Code) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
				return
			}
		case req.RecoveryCode != "":
			ok, err := db.ConsumeRecoveryCode(c.Request.Context(), userID, auth.HashRecoveryCode(req.RecoveryCode))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return
			}
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid recovery code"})
				return
			}
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "2fa code required"})
			return
		}
	}

	if err := db.DeleteAccount(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	_ = h.sm.DeleteAll(c.Request.Context(), userID)
	h.clearSession(c)
	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) GetSessions(c *gin.Context) {
	userID := c.GetString("userID")

	sessions, err := h.sm.List(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	currentID, _ := c.Cookie(sessionCookie)

	type sessionResponse struct {
		ID        string    `json:"id"`
		Current   bool      `json:"current"`
		UserAgent string    `json:"user_agent"`
		IP        string    `json:"ip"`
		CreatedAt time.Time `json:"created_at"`
	}

	result := make([]sessionResponse, 0, len(sessions))
	for _, s := range sessions {
		result = append(result, sessionResponse{
			ID:        s.ID,
			Current:   s.ID == currentID,
			UserAgent: s.UserAgent,
			IP:        s.IP,
			CreatedAt: s.CreatedAt,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Current && !result[j].Current
	})

	c.JSON(http.StatusOK, result)
}

func (h *Handler) TerminateSession(c *gin.Context) {
	sessionID := c.Param("id")
	currentID, _ := c.Cookie(sessionCookie)

	if sessionID == currentID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot terminate current session"})
		return
	}

	if err := h.sm.Delete(c.Request.Context(), sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) TerminateAllSessions(c *gin.Context) {
	userID := c.GetString("userID")
	currentID, _ := c.Cookie(sessionCookie)

	if err := h.sm.DeleteAllExcept(c.Request.Context(), userID, currentID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *Handler) clearSession(c *gin.Context) {
	if id, err := c.Cookie(sessionCookie); err == nil {
		_ = h.sm.Delete(c.Request.Context(), id)
	}
	c.SetCookie(sessionCookie, "", -1, "/", "", true, true)
}
