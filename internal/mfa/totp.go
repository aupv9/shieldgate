// Package mfa implements time-based one-time passwords (RFC 6238) and the
// encryption that protects TOTP secrets at rest.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; what authenticator apps implement
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a TOTP code
	Digits = 6
	// Period is the TOTP time step
	Period = 30 * time.Second
	// Skew is how many steps before or after the current one are accepted,
	// to tolerate clock drift between server and phone
	Skew = 1
	// secretBytes is the shared secret length (160 bits, RFC 4226 §4)
	secretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random TOTP secret
func NewSecret() ([]byte, error) {
	secret := make([]byte, secretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// EncodeSecret returns the base32 form users type into authenticator apps
func EncodeSecret(secret []byte) string {
	return b32.EncodeToString(secret)
}

// Step returns the TOTP time step containing t
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// Code returns the TOTP code for a time step (RFC 4226 §5.3 truncation)
func Code(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, value%1_000_000)
}

// Verify checks code against the steps around now and returns the matching
// step, so the caller can reject reuse of that step. Comparison is
// constant-time.
func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	current := Step(now)
	matched, ok := int64(0), false
	for step := current - Skew; step <= current+Skew; step++ {
		if subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code)) == 1 && !ok {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// KeyURI returns the otpauth:// URI that authenticator apps read from a QR
// code (Google Authenticator key URI format)
func KeyURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
