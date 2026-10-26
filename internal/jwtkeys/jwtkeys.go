// Package jwtkeys manages the keys used to sign and verify JWTs and publishes
// the public halves as a JSON Web Key Set (RFC 7517).
//
// A KeySet has exactly one active signing key plus any number of
// verification-only keys. Rotating keys without downtime:
//
//  1. Add the new key as a verification key, so it appears in the JWKS
//     before anything is signed with it, and wait for JWKS caches to expire.
//  2. Make the new key the signing key and move the old one to verification.
//  3. Once every token signed by the old key has expired, remove it.
package jwtkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Supported signing algorithms
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
	AlgHS256 = "HS256"
)

// TypeAccessToken is the typ header of JWT access tokens (RFC 9068 §2.1).
// It keeps an access token from being accepted where an ID token is
// expected, and the other way around, although both carry the same issuer
// and signing key.
const TypeAccessToken = "at+jwt"

// minRSABits is the smallest RSA modulus accepted (NIST SP 800-131A)
const minRSABits = 2048

// Key is a single signing or verification key
type Key struct {
	ID  string
	Alg string

	// signKey is the private key (or HMAC secret); nil for public-only keys
	signKey interface{}
	// verifyKey is the public key (or HMAC secret)
	verifyKey interface{}
}

// CanSign reports whether the key holds private material
func (k *Key) CanSign() bool {
	return k.signKey != nil
}

// KeySet holds the active signing key and every key accepted for verification
type KeySet struct {
	active *Key
	keys   []*Key // active first, then verification keys in config order
	byID   map[string]*Key
	algs   []string
}

// NewKeySet builds a KeySet. The active key must hold private material;
// verification keys may be public-only. Key IDs must be unique.
func NewKeySet(active *Key, verification ...*Key) (*KeySet, error) {
	if active == nil || !active.CanSign() {
		return nil, errors.New("active key must be able to sign")
	}

	ks := &KeySet{active: active, byID: make(map[string]*Key)}
	seenAlg := make(map[string]bool)
	for _, k := range append([]*Key{active}, verification...) {
		if k.Alg == AlgHS256 && k != active {
			return nil, errors.New("HS256 secrets cannot be verification keys")
		}
		if _, dup := ks.byID[k.ID]; dup {
			return nil, fmt.Errorf("duplicate key id %q", k.ID)
		}
		ks.byID[k.ID] = k
		ks.keys = append(ks.keys, k)
		if !seenAlg[k.Alg] {
			seenAlg[k.Alg] = true
			ks.algs = append(ks.algs, k.Alg)
		}
	}
	return ks, nil
}

// NewHMAC builds a single-key HS256 KeySet from a shared secret. HS256 tokens
// carry no kid and the secret is never published in the JWKS.
func NewHMAC(secret string) *KeySet {
	key := &Key{Alg: AlgHS256, signKey: []byte(secret), verifyKey: []byte(secret)}
	ks, _ := NewKeySet(key)
	return ks
}

// Algorithm returns the algorithm of the active signing key
func (ks *KeySet) Algorithm() string {
	return ks.active.Alg
}

// ActiveKeyID returns the kid of the active signing key ("" for HS256)
func (ks *KeySet) ActiveKeyID() string {
	return ks.active.ID
}

// Sign signs claims with the active key, setting the kid header
func (ks *KeySet) Sign(claims jwt.Claims) (string, error) {
	return ks.SignTyped(claims, "JWT")
}

// SignTyped is Sign with the given typ header, such as TypeAccessToken
func (ks *KeySet) SignTyped(claims jwt.Claims, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(ks.active.Alg), claims)
	token.Header["typ"] = typ
	if ks.active.ID != "" {
		token.Header["kid"] = ks.active.ID
	}
	return token.SignedString(ks.active.signKey)
}

// Parse verifies a token against the key set and decodes it into claims.
// The key is chosen by kid and must match the token's alg, which rules out
// algorithm-confusion attacks (e.g. an RSA public key used as an HMAC secret).
// Extra options (issuer, audience, ...) are applied on top.
func (ks *KeySet) Parse(tokenString string, claims jwt.Claims, opts ...jwt.ParserOption) (*jwt.Token, error) {
	opts = append([]jwt.ParserOption{jwt.WithValidMethods(ks.algs)}, opts...)
	return jwt.ParseWithClaims(tokenString, claims, ks.keyfunc, opts...)
}

// HasType reports whether a parsed token's typ header is typ. JOSE media
// types are case-insensitive and may carry an "application/" prefix
// (RFC 7515 §4.1.9).
func HasType(token *jwt.Token, typ string) bool {
	got, _ := token.Header["typ"].(string)
	got = strings.ToLower(got)
	return strings.TrimPrefix(got, "application/") == strings.ToLower(typ)
}

// TokenHash computes an OIDC token hash such as at_hash (OIDC Core §3.1.3.6):
// the left half of the hash of the token, using the hash of the active
// signing alg, base64url-encoded. Every supported alg uses SHA-256.
func (ks *KeySet) TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64(sum[:len(sum)/2])
}

func (ks *KeySet) keyfunc(token *jwt.Token) (interface{}, error) {
	kid, _ := token.Header["kid"].(string)

	var key *Key
	if kid == "" {
		// Only HS256 tokens are issued without a kid
		if ks.active.Alg != AlgHS256 {
			return nil, errors.New("token has no kid")
		}
		key = ks.active
	} else {
		key = ks.byID[kid]
		if key == nil {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
	}

	if token.Method.Alg() != key.Alg {
		return nil, fmt.Errorf("token alg %q does not match key alg %q", token.Method.Alg(), key.Alg)
	}
	return key.verifyKey, nil
}

// JWK is a public JSON Web Key (RFC 7517 §4)
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a JSON Web Key Set (RFC 7517 §5)
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public keys, active key first. HMAC secrets are omitted.
func (ks *KeySet) JWKS() JWKSet {
	set := JWKSet{Keys: []JWK{}}
	for _, k := range ks.keys {
		if jwk, ok := publicJWK(k); ok {
			set.Keys = append(set.Keys, jwk)
		}
	}
	return set
}

func publicJWK(k *Key) (JWK, bool) {
	jwk := JWK{Use: "sig", Alg: k.Alg, Kid: k.ID}
	switch pub := k.verifyKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = b64(pub.N.Bytes())
		jwk.E = b64(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		jwk.Kty = "EC"
		jwk.Crv = pub.Curve.Params().Name
		jwk.X = b64(pub.X.FillBytes(make([]byte, size)))
		jwk.Y = b64(pub.Y.FillBytes(make([]byte, size)))
	default:
		return JWK{}, false
	}
	return jwk, true
}

// thumbprint computes the RFC 7638 JWK thumbprint, used as the kid so every
// replica derives the same ID from the same key without coordination
func thumbprint(jwk JWK) string {
	var members interface{}
	switch jwk.Kty {
	case "RSA":
		members = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{jwk.E, jwk.Kty, jwk.N}
	case "EC":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{jwk.Crv, jwk.Kty, jwk.X, jwk.Y}
	}
	// encoding/json emits struct fields in declaration order with no
	// whitespace, which is the canonical form RFC 7638 requires
	data, _ := json.Marshal(members)
	sum := sha256.Sum256(data)
	return b64(sum[:])
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// newKey wraps a private or public RSA/ECDSA key, validating its strength
// and deriving its alg and kid
func newKey(k interface{}) (*Key, error) {
	key := &Key{}
	switch v := k.(type) {
	case *rsa.PrivateKey:
		key.signKey, key.verifyKey = v, &v.PublicKey
	case *rsa.PublicKey:
		key.verifyKey = v
	case *ecdsa.PrivateKey:
		key.signKey, key.verifyKey = v, &v.PublicKey
	case *ecdsa.PublicKey:
		key.verifyKey = v
	default:
		return nil, fmt.Errorf("unsupported key type %T", k)
	}

	switch pub := key.verifyKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key is %d bits, minimum is %d", pub.N.BitLen(), minRSABits)
		}
		key.Alg = AlgRS256
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("EC key must use curve P-256 for ES256, got %s", pub.Curve.Params().Name)
		}
		key.Alg = AlgES256
	}

	jwk, _ := publicJWK(key)
	key.ID = thumbprint(jwk)
	return key, nil
}

// ParsePEM parses the first PEM block holding an RSA or P-256 EC key, private
// (PKCS#1, PKCS#8, SEC 1) or public (PKIX, PKCS#1)
func ParsePEM(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	var (
		parsed interface{}
		err    error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", block.Type, err)
	}
	return newKey(parsed)
}

// LoadFile reads and parses a PEM key file
func LoadFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := ParsePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// Generate creates a fresh in-memory signing key for alg (RS256 or ES256)
func Generate(alg string) (*Key, error) {
	switch alg {
	case AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, minRSABits)
		if err != nil {
			return nil, err
		}
		return newKey(k)
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return newKey(k)
	default:
		return nil, fmt.Errorf("cannot generate key for alg %q", alg)
	}
}

// Options configures Load
type Options struct {
	// Alg is the signing algorithm: RS256, ES256 or HS256
	Alg string
	// SigningKeyFile is a PEM private key; required for RS256/ES256 unless
	// AllowEphemeral is set
	SigningKeyFile string
	// VerificationKeyFiles are comma-separated PEM files (private or public)
	// accepted for verification and published in the JWKS
	VerificationKeyFiles string
	// HMACSecret is the shared secret used when Alg is HS256
	HMACSecret string
	// AllowEphemeral generates a throwaway key when SigningKeyFile is empty.
	// Tokens then stop verifying on restart and across replicas.
	AllowEphemeral bool
}

// Load builds a KeySet from Options. The second return value is true when an
// ephemeral key was generated.
func Load(opts Options) (*KeySet, bool, error) {
	alg := strings.ToUpper(strings.TrimSpace(opts.Alg))

	if alg == AlgHS256 {
		if opts.SigningKeyFile != "" || opts.VerificationKeyFiles != "" {
			return nil, false, errors.New("key files are not used with HS256")
		}
		if opts.HMACSecret == "" {
			return nil, false, errors.New("HS256 requires a JWT secret")
		}
		return NewHMAC(opts.HMACSecret), false, nil
	}
	if alg != AlgRS256 && alg != AlgES256 {
		return nil, false, fmt.Errorf("unsupported signing alg %q (want RS256, ES256 or HS256)", opts.Alg)
	}

	var (
		active    *Key
		ephemeral bool
		err       error
	)
	switch {
	case opts.SigningKeyFile != "":
		active, err = LoadFile(opts.SigningKeyFile)
		if err != nil {
			return nil, false, err
		}
		if !active.CanSign() {
			return nil, false, fmt.Errorf("%s: signing key must be a private key", opts.SigningKeyFile)
		}
		if active.Alg != alg {
			return nil, false, fmt.Errorf("%s: key is for %s but signing alg is %s", opts.SigningKeyFile, active.Alg, alg)
		}
	case opts.AllowEphemeral:
		active, err = Generate(alg)
		if err != nil {
			return nil, false, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
		ephemeral = true
	default:
		return nil, false, fmt.Errorf("a signing key file is required for %s", alg)
	}

	var verification []*Key
	for _, path := range strings.Split(opts.VerificationKeyFiles, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		key, err := LoadFile(path)
		if err != nil {
			return nil, false, err
		}
		verification = append(verification, key)
	}

	ks, err := NewKeySet(active, verification...)
	if err != nil {
		return nil, false, err
	}
	return ks, ephemeral, nil
}
