package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	DefaultTOTPPeriod = 30
	DefaultTOTPDigits = 6
	totpWindow        = 1 // ±1 step for clock drift tolerance
)

// GenerateTOTPSecret returns a random base32-encoded 160-bit TOTP secret.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="), nil
}

// ValidateTOTP checks a 6-digit TOTP code against the base32 secret.
// Accepts codes from (now-window*period) to (now+window*period) to handle clock drift.
func ValidateTOTP(secret, code string, period, digits int) bool {
	if period <= 0 {
		period = DefaultTOTPPeriod
	}
	if digits <= 0 {
		digits = DefaultTOTPDigits
	}
	counter := time.Now().Unix() / int64(period)
	for offset := -totpWindow; offset <= totpWindow; offset++ {
		expected, err := computeHOTP(secret, counter+int64(offset), digits)
		if err == nil && expected == code {
			return true
		}
	}
	return false
}

// GenerateTOTP returns the current TOTP code for testing / seeding.
func GenerateTOTP(secret string, period, digits int) (string, error) {
	if period <= 0 {
		period = DefaultTOTPPeriod
	}
	if digits <= 0 {
		digits = DefaultTOTPDigits
	}
	return computeHOTP(secret, time.Now().Unix()/int64(period), digits)
}

// computeHOTP implements RFC 4226 HOTP.
func computeHOTP(secret string, counter int64, digits int) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	for len(s)%8 != 0 {
		s += "="
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, binCode%mod), nil
}

// TOTPProvisioningURI builds an otpauth:// URI for QR code generation.
func TOTPProvisioningURI(issuer, accountName, secret string, period, digits int) string {
	if period <= 0 {
		period = DefaultTOTPPeriod
	}
	if digits <= 0 {
		digits = DefaultTOTPDigits
	}
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, accountName, secret, issuer, digits, period,
	)
}

// GenerateBackupCodes creates n cryptographically random 10-char hex backup codes.
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = fmt.Sprintf("%X", b)
	}
	return codes, nil
}
