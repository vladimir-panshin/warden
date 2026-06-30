package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/pquerna/otp/totp"
)

func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

func GenerateTOTP(email string) (secret, qrBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "warden",
		AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("generateTOTP: %w", err)
	}

	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", fmt.Errorf("generateTOTP image: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", fmt.Errorf("generateTOTP encode: %w", err)
	}

	return key.Secret(), base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, 8)
	for i := range codes {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generateRecoveryCodes: %w", err)
		}
		codes[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:12]
	}
	return codes, nil
}
