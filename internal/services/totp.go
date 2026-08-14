package services

// totp.go implements RFC 6238 TOTP (SHA-1, 6 digits, 30-second steps) for MFA
// without external dependencies.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpWindow tolerates one step of clock skew in each direction
	totpWindow = 1
)

// GenerateTOTPSecret returns a new 160-bit secret, base32-encoded (the format
// authenticator apps expect)
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// BuildOTPAuthURI renders the otpauth:// enrollment URI encoded into QR codes
func BuildOTPAuthURI(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer),
		totpDigits, int(totpPeriod.Seconds()))
}

// totpCode computes the RFC 6238 code for a specific counter step
func totpCode(secret string, step uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)

	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1000000), nil
}

// GenerateTOTPCode computes the code valid at the given time (used by tests
// and could back a future recovery tool)
func GenerateTOTPCode(secret string, at time.Time) (string, error) {
	return totpCode(secret, uint64(at.Unix())/uint64(totpPeriod.Seconds()))
}

// ValidateTOTPCode checks a user-supplied code against the secret, tolerating
// ±1 time step of clock skew
func ValidateTOTPCode(secret, code string, at time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	step := uint64(at.Unix()) / uint64(totpPeriod.Seconds())
	for delta := -totpWindow; delta <= totpWindow; delta++ {
		expected, err := totpCode(secret, uint64(int64(step)+int64(delta)))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
