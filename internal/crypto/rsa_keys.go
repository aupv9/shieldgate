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
	"path/filepath"

	"github.com/google/uuid"
)

const (
	rsaKeySize     = 2048
	privateKeyFile = "private.pem"
	publicKeyFile  = "public.pem"
)

// KeyManager manages an RSA key pair used for JWT signing (RS256).
// Keys are generated at startup; when RSAKeyPath is configured they are
// persisted to disk and reloaded on subsequent starts.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	kid        string // key ID — stable identifier embedded in JWT header
}

// NewKeyManager creates a KeyManager. When keyPath is non-empty the manager
// tries to load existing PEM files from that directory; if they don't exist it
// generates a fresh pair and writes them there.
func NewKeyManager(keyPath string) (*KeyManager, error) {
	km := &KeyManager{}

	if keyPath != "" {
		if err := os.MkdirAll(keyPath, 0700); err != nil {
			return nil, fmt.Errorf("create RSA key directory: %w", err)
		}

		privPath := filepath.Join(keyPath, privateKeyFile)
		if _, err := os.Stat(privPath); err == nil {
			// Load existing key pair
			if err := km.load(keyPath); err != nil {
				return nil, fmt.Errorf("load RSA keys: %w", err)
			}
			return km, nil
		}
	}

	// Generate a new key pair
	if err := km.generate(); err != nil {
		return nil, fmt.Errorf("generate RSA key pair: %w", err)
	}

	if keyPath != "" {
		if err := km.persist(keyPath); err != nil {
			// Non-fatal — in-memory keys still work
			fmt.Printf("Warning: could not persist RSA keys to %s: %v\n", keyPath, err)
		}
	}

	return km, nil
}

// PrivateKey returns the RSA private key (used for signing).
func (km *KeyManager) PrivateKey() *rsa.PrivateKey {
	return km.privateKey
}

// PublicKey returns the RSA public key (used for verification).
func (km *KeyManager) PublicKey() *rsa.PublicKey {
	return &km.privateKey.PublicKey
}

// KID returns the stable key ID embedded in JWT headers.
func (km *KeyManager) KID() string {
	return km.kid
}

// JWK returns a JSON Web Key representation of the public key suitable for
// serving on the /.well-known/jwks.json endpoint.
func (km *KeyManager) JWK() map[string]interface{} {
	pub := &km.privateKey.PublicKey

	// Encode the modulus (n) and exponent (e) as Base64URL per RFC 7518 §6.3
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBig := big.NewInt(int64(pub.E))
	e := base64.RawURLEncoding.EncodeToString(eBig.Bytes())

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": km.kid,
		"n":   n,
		"e":   e,
	}
}

// generate creates a new RSA-2048 key pair and assigns a random KID.
func (km *KeyManager) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return err
	}
	km.privateKey = key
	km.kid = uuid.New().String()
	return nil
}

// persist writes the key pair and KID to keyPath as PEM files.
func (km *KeyManager) persist(keyPath string) error {
	privBytes := x509.MarshalPKCS1PrivateKey(km.privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(filepath.Join(keyPath, privateKeyFile), privPEM, 0600); err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&km.privateKey.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err := os.WriteFile(filepath.Join(keyPath, publicKeyFile), pubPEM, 0644); err != nil {
		return err
	}

	// Persist the KID alongside the keys so it is stable across restarts.
	kidPath := filepath.Join(keyPath, "kid.txt")
	if err := os.WriteFile(kidPath, []byte(km.kid), 0644); err != nil {
		return err
	}

	return nil
}

// load reads a key pair and KID from keyPath.
func (km *KeyManager) load(keyPath string) error {
	privData, err := os.ReadFile(filepath.Join(keyPath, privateKeyFile))
	if err != nil {
		return err
	}

	block, _ := pem.Decode(privData)
	if block == nil {
		return fmt.Errorf("invalid PEM block in %s", privateKeyFile)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	km.privateKey = key

	// Load KID; generate a new one if missing (first migration from older version).
	kidPath := filepath.Join(keyPath, "kid.txt")
	kidData, err := os.ReadFile(kidPath)
	if err != nil {
		km.kid = uuid.New().String()
	} else {
		km.kid = string(kidData)
	}

	return nil
}
