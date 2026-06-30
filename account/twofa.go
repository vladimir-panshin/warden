package account

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"warden/auth"
	"warden/db"
	"warden/models"
)

func (h *Handler) TwoFASetup(c *gin.Context) {
	userID := c.GetString("userID")

	account, err := db.GetAccountByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if account.OTPSecret != nil && len(account.RecoveryCodes) > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "2fa already enabled"})
		return
	}

	secret, qrBase64, err := auth.GenerateTOTP(account.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := db.UpdateAccountOTP(c.Request.Context(), userID, &secret, nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"qr":     "data:image/png;base64," + qrBase64,
	})
}

func (h *Handler) TwoFAConfirm(c *gin.Context) {
	var req models.TwoFAConfirmRequest
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

	if account.OTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2fa setup not initiated"})
		return
	}

	if account.RecoveryCodes != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "2fa already enabled"})
		return
	}

	if !auth.ValidateTOTP(*account.OTPSecret, req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	codes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := db.UpdateRecoveryCodes(c.Request.Context(), userID, codes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}

func (h *Handler) TwoFADisable(c *gin.Context) {
	var req models.TwoFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Code == "" && req.RecoveryCode == "" {
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

	if account.OTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2fa is not enabled"})
		return
	}

	if req.Code != "" {
		if !auth.ValidateTOTP(*account.OTPSecret, req.Code) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
			return
		}
	} else {
		ok, err := db.ConsumeRecoveryCode(c.Request.Context(), userID, req.RecoveryCode)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid recovery code"})
			return
		}
	}

	if err := db.UpdateAccountOTP(c.Request.Context(), userID, nil, nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
