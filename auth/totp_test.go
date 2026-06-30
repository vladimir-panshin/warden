package auth

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(codes) != 8 {
		t.Fatalf("expected 8 codes, got %d", len(codes))
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if len(code) != 12 {
			t.Errorf("expected code length 12, got %d (%q)", len(code), code)
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(code); err != nil {
			t.Errorf("code %q is not valid base32: %v", code, err)
		}
		if seen[code] {
			t.Errorf("duplicate recovery code: %q", code)
		}
		seen[code] = true
	}
}

func TestGenerateAndValidateTOTP(t *testing.T) {
	secret, qr, err := GenerateTOTP("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if qr == "" {
		t.Fatal("expected non-empty QR data")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to derive code: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Error("expected a freshly generated code to validate")
	}

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if ValidateTOTP(secret, wrong) {
		t.Errorf("expected wrong code %q to fail validation", wrong)
	}
}
