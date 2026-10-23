package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the length of the MFA encryption key (AES-256)
const KeySize = 32

// ErrDecrypt is returned when a sealed secret cannot be opened, e.g. after
// the encryption key changed
var ErrDecrypt = errors.New("mfa: cannot decrypt secret")

// Keys protects MFA data at rest: AES-256-GCM for TOTP secrets (which must be
// recoverable to compute codes) and HMAC-SHA256 for recovery codes (which
// only need comparing). Both subkeys derive from one master key.
type Keys struct {
	aead    cipher.AEAD
	hmacKey []byte
}

// ParseKey decodes a base64 (standard or URL, padded or not) master key of
// KeySize bytes
func ParseKey(encoded string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(encoded); err == nil {
			if len(key) != KeySize {
				return nil, fmt.Errorf("mfa: key must be %d bytes, got %d", KeySize, len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("mfa: key is not valid base64")
}

// DeriveKey derives a master key from another secret, for deployments
// without a dedicated MFA key. Changing that secret makes enrolled
// authenticators unreadable.
func DeriveKey(secret string) []byte {
	key := make([]byte, KeySize)
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("shieldgate mfa master key"))
	if _, err := io.ReadFull(r, key); err != nil {
		panic(err) // HKDF-SHA256 cannot fail for 32 bytes
	}
	return key
}

// NewKeys builds Keys from a master key
func NewKeys(master []byte) (*Keys, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("mfa: key must be %d bytes", KeySize)
	}
	subkey := func(info string) []byte {
		out := make([]byte, KeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte(info)), out); err != nil {
			panic(err)
		}
		return out
	}
	block, err := aes.NewCipher(subkey("totp secret encryption"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, hmacKey: subkey("recovery code hmac")}, nil
}

// Seal encrypts a TOTP secret. aad binds the ciphertext to its owner so a
// sealed secret copied to another user's row does not open.
func (k *Keys) Seal(secret []byte, aad string) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := k.aead.Seal(nonce, nonce, secret, []byte(aad))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a secret sealed with the same aad
func (k *Keys) Open(sealed, aad string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce, ciphertext := raw[:k.aead.NonceSize()], raw[k.aead.NonceSize():]
	secret, err := k.aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return secret, nil
}

// HashRecoveryCode returns the keyed hash stored for a recovery code. The
// key means a database leak alone does not allow brute-forcing the codes.
func (k *Keys) HashRecoveryCode(code string) string {
	mac := hmac.New(sha256.New, k.hmacKey)
	mac.Write([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}
