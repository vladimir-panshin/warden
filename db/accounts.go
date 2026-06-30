package db

import (
	"context"
	"fmt"
	"time"
)

type Account struct {
	ID            string
	Email         string
	PasswordHash  string
	OTPSecret     *string
	RecoveryCodes []string
	CreatedAt     time.Time
}

func CreateAccount(ctx context.Context, id, email, passwordHash string) (*Account, error) {
	query := `
		INSERT INTO accounts (id, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, email, password_hash, otp_secret, recovery_codes, created_at`

	a := &Account{}
	err := DB.QueryRow(ctx, query, id, email, passwordHash).Scan(
		&a.ID, &a.Email, &a.PasswordHash,
		&a.OTPSecret, &a.RecoveryCodes, &a.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateAccount: %w", err)
	}
	return a, nil
}

func GetAccountByID(ctx context.Context, id string) (*Account, error) {
	query := `
		SELECT id, email, password_hash, otp_secret, recovery_codes, created_at
		FROM accounts WHERE id = $1`

	a := &Account{}
	err := DB.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.Email, &a.PasswordHash,
		&a.OTPSecret, &a.RecoveryCodes, &a.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetAccountByID: %w", err)
	}
	return a, nil
}

func GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	query := `
		SELECT id, email, password_hash, otp_secret, recovery_codes, created_at
		FROM accounts WHERE email = $1`

	a := &Account{}
	err := DB.QueryRow(ctx, query, email).Scan(
		&a.ID, &a.Email, &a.PasswordHash,
		&a.OTPSecret, &a.RecoveryCodes, &a.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetAccountByEmail: %w", err)
	}
	return a, nil
}

func AccountExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := DB.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM accounts WHERE email = $1)`, email,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("AccountExists: %w", err)
	}
	return exists, nil
}

func UpdateAccountEmail(ctx context.Context, id, email string) error {
	_, err := DB.Exec(ctx,
		`UPDATE accounts SET email = $1 WHERE id = $2`,
		email, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateAccountEmail: %w", err)
	}
	return nil
}

func UpdateAccountPassword(ctx context.Context, id, passwordHash string) error {
	_, err := DB.Exec(ctx,
		`UPDATE accounts SET password_hash = $1 WHERE id = $2`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateAccountPassword: %w", err)
	}
	return nil
}

func UpdateAccountOTP(ctx context.Context, id string, secret *string, recoveryCodes []string) error {
	_, err := DB.Exec(ctx,
		`UPDATE accounts SET otp_secret = $1, recovery_codes = $2 WHERE id = $3`,
		secret, recoveryCodes, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateAccountOTP: %w", err)
	}
	return nil
}

func UpdateRecoveryCodes(ctx context.Context, id string, codes []string) error {
	_, err := DB.Exec(ctx,
		`UPDATE accounts SET recovery_codes = $1 WHERE id = $2`,
		codes, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateRecoveryCodes: %w", err)
	}
	return nil
}

func ConsumeRecoveryCode(ctx context.Context, id, code string) (bool, error) {
	tag, err := DB.Exec(ctx,
		`UPDATE accounts
		 SET recovery_codes = array_remove(recovery_codes, $2)
		 WHERE id = $1 AND $2 = ANY(recovery_codes)`,
		id, code,
	)
	if err != nil {
		return false, fmt.Errorf("ConsumeRecoveryCode: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func DeleteAccount(ctx context.Context, id string) error {
	_, err := DB.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeleteAccount: %w", err)
	}
	return nil
}
