// Package crypto provides cryptographic utilities for ShieldGate,
// including RSA key management for JWT RS256 signing and JWKS publication.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// RSAKeyManager manages an RSA-2048 key pair used for JWT RS256 signing
// and public-key exposure via the JWKS endpoint.
//
// The key is loaded once at startup and protected by a read-write mutex so
// that future key-rotation support can be added without changing callers.
type RSAKeyManager struct {
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	keyID      string
	createdAt  time.Time
}

// NewRSAKeyManager creates or loads an RSAKeyManager.
//
//   - pemPath   path to a PEM-encoded PKCS#1 or PKCS#8 private key file (highest priority)
//   - inlinePEM PEM string embedded in config/env (used when pemPath is empty)
//
// If both are empty a fresh 2048-bit key pair is generated in memory.
// The in-memory key is recreated on every restart; persist pemPath/inlinePEM
// in production to keep the JWKS stable across deployments.
func NewRSAKeyManager(pemPath, inlinePEM string) (*RSAKeyManager, error) {
	km := &RSAKeyManager{createdAt: time.Now()}

	switch {
	case pemPath != "":
		data, err := os.ReadFile(pemPath)
		if err != nil {
			return nil, fmt.Errorf("rsa: read %q: %w", pemPath, err)
		}
		return km, km.loadPEM(data)
	case inlinePEM != "":
		return km, km.loadPEM([]byte(inlinePEM))
	default:
		return km, km.generate()
	}
}

func (km *RSAKeyManager) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa: generate: %w", err)
	}
	km.privateKey = key
	km.keyID = "auto-generated"
	return nil
}

func (km *RSAKeyManager) loadPEM(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("rsa: no valid PEM block found")
	}

	// Try PKCS#1 first, then PKCS#8.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		km.privateKey = key
		km.keyID = "default"
		return nil
	}

	iface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("rsa: unable to parse key (tried PKCS1 and PKCS8): %w", err)
	}
	rsaKey, ok := iface.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("rsa: PEM does not contain an RSA private key")
	}
	km.privateKey = rsaKey
	km.keyID = "default"
	return nil
}

// PrivateKey returns the RSA private key used for JWT signing.
func (km *RSAKeyManager) PrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey
}

// PublicKey returns the RSA public key used for JWT verification.
func (km *RSAKeyManager) PublicKey() *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if km.privateKey == nil {
		return nil
	}
	return &km.privateKey.PublicKey
}

// KeyID returns the identifier placed in the JWT "kid" header and JWKS "kid" field.
func (km *RSAKeyManager) KeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// JWKSet returns an RFC 7517-compliant JSON Web Key Set containing the RSA
// public key. The returned map is ready to be JSON-serialised and served
// from GET /.well-known/jwks.json.
func (km *RSAKeyManager) JWKSet() map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.privateKey == nil {
		return map[string]interface{}{"keys": []interface{}{}}
	}

	pub := &km.privateKey.PublicKey
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": km.keyID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
