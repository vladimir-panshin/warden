package models

type RegisterRequest struct {
	Email    string `json:"email"    binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type TwoFARequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type RecoveryLoginRequest struct {
	Code string `json:"code" binding:"required,len=12"`
}

type ChangeEmailRequest struct {
	NewEmail string `json:"new_email" binding:"required,email,max=255"`
	Password string `json:"password"  binding:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

type DeleteAccountRequest struct {
	Password     string `json:"password"      binding:"required"`
	Code         string `json:"code"          binding:"omitempty,len=6"`
	RecoveryCode string `json:"recovery_code" binding:"omitempty,len=12"`
}

type TwoFAConfirmRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type TwoFADisableRequest struct {
	Password     string `json:"password"      binding:"required"`
	Code         string `json:"code"          binding:"omitempty,len=6"`
	RecoveryCode string `json:"recovery_code" binding:"omitempty,len=12"`
}
