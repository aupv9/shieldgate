package mfa

import (
	"crypto/rand"
	"strings"
)

const (
	// RecoveryCodeCount is how many recovery codes are issued at a time
	RecoveryCodeCount = 10
	// recoveryCodeChars is the number of characters per code (two groups of
	// five, 50 bits)
	recoveryCodeChars = 10
	// recoveryAlphabet avoids look-alike characters (0/O, 1/I/L)
	recoveryAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
)

// NewRecoveryCodes returns RecoveryCodeCount random codes formatted XXXXX-XXXXX
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		raw := make([]byte, recoveryCodeChars)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, b := range raw {
			if j == recoveryCodeChars/2 {
				sb.WriteByte('-')
			}
			// 256 is not a multiple of 31; the bias (< 1 bit over the code)
			// does not matter at 50 bits
			sb.WriteByte(recoveryAlphabet[int(b)%len(recoveryAlphabet)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

// NormalizeRecoveryCode makes entry forgiving: case, spaces and dashes are
// ignored
func NormalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, strings.TrimSpace(code))
}

// LooksLikeTOTP reports whether input is a TOTP code rather than a
// recovery code
func LooksLikeTOTP(input string) bool {
	input = strings.TrimSpace(input)
	if len(input) != Digits {
		return false
	}
	for _, r := range input {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
