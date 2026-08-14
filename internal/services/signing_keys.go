package services

// signing_keys.go manages asymmetric token-signing keys: lazy bootstrap of an
// RSA key on first use, kid-based verification, JWKS publication, and
// zero-downtime rotation (rotated keys keep verifying until retired).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"shieldgate/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const signingKeyBits = 2048

type cachedSigningKey struct {
	kid     string
	private *rsa.PrivateKey
}

// signingKeysAvailable reports whether asymmetric signing is wired up.
// Unit tests that build the service with nil repos fall back to HS256.
func (s *authServiceImpl) signingKeysAvailable() bool {
	return s.repos != nil && s.repos.SigningKey != nil
}

// activeSigningKey returns the current signing key, bootstrapping one on first use
func (s *authServiceImpl) activeSigningKey(ctx context.Context) (*cachedSigningKey, error) {
	s.keyMu.RLock()
	if s.activeKey != nil {
		key := s.activeKey
		s.keyMu.RUnlock()
		return key, nil
	}
	s.keyMu.RUnlock()

	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.activeKey != nil {
		return s.activeKey, nil
	}

	record, err := s.repos.SigningKey.GetActive(ctx)
	if err == models.ErrSigningKeyNotFound {
		record, err = s.generateSigningKey(ctx)
	}
	if err != nil {
		return nil, err
	}

	private, err := parsePrivateKeyPEM(record.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	s.activeKey = &cachedSigningKey{kid: record.KID, private: private}
	return s.activeKey, nil
}

func (s *authServiceImpl) generateSigningKey(ctx context.Context) (*models.SigningKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	record := &models.SigningKey{
		ID:            uuid.New(),
		KID:           uuid.New().String(),
		Algorithm:     "RS256",
		PrivateKeyPEM: encodePrivateKeyPEM(private),
		IsActive:      true,
	}
	if err := s.repos.SigningKey.Create(ctx, record); err != nil {
		return nil, err
	}

	s.logger.WithField("kid", record.KID).Info("generated new RS256 signing key")
	return record, nil
}

// RotateSigningKey promotes a fresh key. The previous key stays in JWKS and
// keeps verifying already-issued tokens until it is retired out of band.
func (s *authServiceImpl) RotateSigningKey(ctx context.Context) error {
	if !s.signingKeysAvailable() {
		return models.ErrSigningKeyNotFound
	}

	s.keyMu.Lock()
	defer s.keyMu.Unlock()

	if err := s.repos.SigningKey.DeactivateAll(ctx); err != nil {
		return err
	}
	record, err := s.generateSigningKey(ctx)
	if err != nil {
		return err
	}
	private, err := parsePrivateKeyPEM(record.PrivateKeyPEM)
	if err != nil {
		return err
	}
	s.activeKey = &cachedSigningKey{kid: record.KID, private: private}
	s.verifyKeys = nil // invalidate verification cache
	return nil
}

// GetJWKS returns the public keys of every serving signing key (RFC 7517)
func (s *authServiceImpl) GetJWKS(ctx context.Context) (*models.JWKS, error) {
	jwks := &models.JWKS{Keys: []models.JWK{}}
	if !s.signingKeysAvailable() {
		return jwks, nil
	}

	// Ensure at least one key exists before publishing the set
	if _, err := s.activeSigningKey(ctx); err != nil {
		return nil, err
	}

	records, err := s.repos.SigningKey.ListServing(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		private, err := parsePrivateKeyPEM(record.PrivateKeyPEM)
		if err != nil {
			s.logger.WithError(err).WithField("kid", record.KID).Error("skipping unparsable signing key")
			continue
		}
		jwks.Keys = append(jwks.Keys, publicJWK(record.KID, &private.PublicKey))
	}
	return jwks, nil
}

// signToken signs claims with the active RS256 key (kid in the header), or
// HS256 when no key store is available (unit-test fallback)
func (s *authServiceImpl) signToken(ctx context.Context, claims *models.JWTClaims) (string, error) {
	if !s.signingKeysAvailable() {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return token.SignedString([]byte(s.config.JWTSecret))
	}

	key, err := s.activeSigningKey(ctx)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.kid
	return token.SignedString(key.private)
}

// verificationKeyfunc resolves the verification key for a parsed token:
// RS256 via the kid header, HS256 via the shared secret (legacy fallback)
func (s *authServiceImpl) verificationKeyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			kid, _ := token.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("missing kid header")
			}
			return s.publicKeyForKID(ctx, kid)
		case *jwt.SigningMethodHMAC:
			return []byte(s.config.JWTSecret), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	}
}

func (s *authServiceImpl) publicKeyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if !s.signingKeysAvailable() {
		return nil, models.ErrSigningKeyNotFound
	}

	s.keyMu.RLock()
	if key, ok := s.verifyKeys[kid]; ok {
		s.keyMu.RUnlock()
		return key, nil
	}
	s.keyMu.RUnlock()

	record, err := s.repos.SigningKey.GetByKID(ctx, kid)
	if err != nil {
		return nil, err
	}
	private, err := parsePrivateKeyPEM(record.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	s.keyMu.Lock()
	if s.verifyKeys == nil {
		s.verifyKeys = make(map[string]*rsa.PublicKey)
	}
	s.verifyKeys[kid] = &private.PublicKey
	s.keyMu.Unlock()

	return &private.PublicKey, nil
}

// Helpers

func encodePrivateKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func parsePrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func publicJWK(kid string, pub *rsa.PublicKey) models.JWK {
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(pub.E))
	// strip leading zeros from the exponent
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	return models.JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes[i:]),
	}
}
