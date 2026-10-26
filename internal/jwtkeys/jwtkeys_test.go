package jwtkeys_test

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
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/jwtkeys"
)

func claims() jwt.MapClaims {
	return jwt.MapClaims{"sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}
}

func mustKeySet(t *testing.T, active *jwtkeys.Key, verification ...*jwtkeys.Key) *jwtkeys.KeySet {
	t.Helper()
	ks, err := jwtkeys.NewKeySet(active, verification...)
	require.NoError(t, err)
	return ks
}

func mustGenerate(t *testing.T, alg string) *jwtkeys.Key {
	t.Helper()
	k, err := jwtkeys.Generate(alg)
	require.NoError(t, err)
	return k
}

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
	return path
}

func TestSignParse_AsymmetricAlgs_RoundTripWithKid(t *testing.T) {
	for _, alg := range []string{jwtkeys.AlgRS256, jwtkeys.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			// Arrange
			ks := mustKeySet(t, mustGenerate(t, alg))

			// Act
			signed, err := ks.Sign(claims())
			require.NoError(t, err)
			token, err := ks.Parse(signed, jwt.MapClaims{})

			// Assert
			require.NoError(t, err)
			assert.True(t, token.Valid)
			assert.Equal(t, alg, token.Header["alg"])
			assert.Equal(t, ks.ActiveKeyID(), token.Header["kid"])
		})
	}
}

func TestParse_TokenFromRetiredKey_VerifiesOnlyWhileKeyIsListed(t *testing.T) {
	// Arrange
	oldKey, newKey := mustGenerate(t, jwtkeys.AlgRS256), mustGenerate(t, jwtkeys.AlgRS256)
	signed, err := mustKeySet(t, oldKey).Sign(claims())
	require.NoError(t, err)

	// Act
	_, errDuringRotation := mustKeySet(t, newKey, oldKey).Parse(signed, jwt.MapClaims{})
	_, errAfterRetire := mustKeySet(t, newKey).Parse(signed, jwt.MapClaims{})

	// Assert
	assert.NoError(t, errDuringRotation)
	assert.ErrorContains(t, errAfterRetire, "unknown kid")
}

func TestParse_HMACSignedWithRSAPublicKey_Rejected(t *testing.T) {
	// Arrange: classic alg-confusion attack — sign HS256 using the published
	// RSA public key bytes as the HMAC secret, under the RSA key's kid
	key := mustGenerate(t, jwtkeys.AlgRS256)
	ks := mustKeySet(t, key)
	jwk := ks.JWKS().Keys[0]
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims())
	forged.Header["kid"] = jwk.Kid
	signed, err := forged.SignedString([]byte(jwk.N))
	require.NoError(t, err)

	// Act
	_, err = ks.Parse(signed, jwt.MapClaims{})

	// Assert
	assert.Error(t, err)
}

func TestParse_AlgNone_Rejected(t *testing.T) {
	// Arrange
	ks := mustKeySet(t, mustGenerate(t, jwtkeys.AlgRS256))
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, claims())
	unsigned.Header["kid"] = ks.ActiveKeyID()
	signed, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// Act
	_, err = ks.Parse(signed, jwt.MapClaims{})

	// Assert
	assert.Error(t, err)
}

func TestParse_AsymmetricTokenWithoutKid_Rejected(t *testing.T) {
	// Arrange: a correctly signed token whose header simply omits kid
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwtkeys.LoadFile(writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	require.NoError(t, err)
	ks := mustKeySet(t, key)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims()).SignedString(rsaKey)
	require.NoError(t, err)

	// Act
	_, err = ks.Parse(signed, jwt.MapClaims{})

	// Assert
	assert.ErrorContains(t, err, "no kid")
}

func TestHMAC_SignAndParse_NoKidAndNotPublished(t *testing.T) {
	// Arrange
	ks := jwtkeys.NewHMAC("a-very-long-shared-secret-for-tests-only")

	// Act
	signed, err := ks.Sign(claims())
	require.NoError(t, err)
	token, parseErr := ks.Parse(signed, jwt.MapClaims{})

	// Assert
	require.NoError(t, parseErr)
	assert.NotContains(t, token.Header, "kid")
	assert.Equal(t, jwtkeys.AlgHS256, ks.Algorithm())
	assert.Empty(t, ks.JWKS().Keys)
}

func TestJWKS_ThirdPartyCanVerifyUsingOnlyPublishedKey(t *testing.T) {
	// Arrange
	ks := mustKeySet(t, mustGenerate(t, jwtkeys.AlgRS256))
	signed, err := ks.Sign(claims())
	require.NoError(t, err)
	published, err := json.Marshal(ks.JWKS())
	require.NoError(t, err)

	// Act: a relying party decodes the JWKS JSON and rebuilds the RSA key
	var set struct {
		Keys []struct{ Kid, N, E string }
	}
	require.NoError(t, json.Unmarshal(published, &set))
	n, _ := base64.RawURLEncoding.DecodeString(set.Keys[0].N)
	e, _ := base64.RawURLEncoding.DecodeString(set.Keys[0].E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	token, err := jwt.Parse(signed, func(*jwt.Token) (interface{}, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))

	// Assert
	require.NoError(t, err)
	assert.True(t, token.Valid)
	assert.Equal(t, set.Keys[0].Kid, token.Header["kid"])
}

func TestJWKS_RotationSet_PublishesAllPublicKeysActiveFirst(t *testing.T) {
	// Arrange
	active, next := mustGenerate(t, jwtkeys.AlgRS256), mustGenerate(t, jwtkeys.AlgES256)
	ks := mustKeySet(t, active, next)

	// Act
	keys := ks.JWKS().Keys

	// Assert
	require.Len(t, keys, 2)
	assert.Equal(t, active.ID, keys[0].Kid)
	assert.Equal(t, next.ID, keys[1].Kid)
	assert.Equal(t, "EC", keys[1].Kty)
	assert.Equal(t, "P-256", keys[1].Crv)
	x, _ := base64.RawURLEncoding.DecodeString(keys[1].X)
	assert.Len(t, x, 32, "EC coordinates must be left-padded to the curve size")
}

func TestKid_IsRFC7638Thumbprint(t *testing.T) {
	// Arrange
	ks := mustKeySet(t, mustGenerate(t, jwtkeys.AlgRS256))
	jwk := ks.JWKS().Keys[0]

	// Act: canonical form = required members only, sorted, no whitespace
	// (encoding/json sorts map keys)
	canonical, err := json.Marshal(map[string]string{"e": jwk.E, "kty": jwk.Kty, "n": jwk.N})
	require.NoError(t, err)
	sum := sha256.Sum256(canonical)

	// Assert
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), jwk.Kid)
}

func TestParsePEM_SupportedEncodings_SameKidAcrossFormats(t *testing.T) {
	// Arrange
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	pkix, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	// Act
	fromPKCS1, err1 := jwtkeys.LoadFile(writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	fromPKCS8, err2 := jwtkeys.LoadFile(writePEM(t, "PRIVATE KEY", pkcs8))
	fromPKIX, err3 := jwtkeys.LoadFile(writePEM(t, "PUBLIC KEY", pkix))
	fromSEC1, err4 := jwtkeys.LoadFile(writePEM(t, "EC PRIVATE KEY", sec1))

	// Assert
	for _, err := range []error{err1, err2, err3, err4} {
		require.NoError(t, err)
	}
	assert.Equal(t, fromPKCS1.ID, fromPKCS8.ID)
	assert.Equal(t, fromPKCS1.ID, fromPKIX.ID)
	assert.True(t, fromPKCS8.CanSign())
	assert.False(t, fromPKIX.CanSign())
	assert.Equal(t, jwtkeys.AlgES256, fromSEC1.Alg)
}

func TestParsePEM_WeakOrUnsupportedKeys_Rejected(t *testing.T) {
	// Arrange
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalECPrivateKey(p384)
	require.NoError(t, err)

	// Act
	_, errWeak := jwtkeys.LoadFile(writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(weakRSA)))
	_, errCurve := jwtkeys.LoadFile(writePEM(t, "EC PRIVATE KEY", p384DER))
	_, errGarbage := jwtkeys.ParsePEM([]byte("not a pem"))

	// Assert
	assert.ErrorContains(t, errWeak, "minimum is 2048")
	assert.ErrorContains(t, errCurve, "P-256")
	assert.Error(t, errGarbage)
}

func TestLoad_Options(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaFile := writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))
	pkix, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	publicFile := writePEM(t, "PUBLIC KEY", pkix)
	nextKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	nextFile := writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(nextKey))

	t.Run("RS256 with key file and verification keys", func(t *testing.T) {
		ks, ephemeral, err := jwtkeys.Load(jwtkeys.Options{Alg: "rs256", SigningKeyFile: rsaFile, VerificationKeyFiles: " " + nextFile + " ,"})
		require.NoError(t, err)
		assert.False(t, ephemeral)
		assert.Len(t, ks.JWKS().Keys, 2)
	})
	t.Run("key file alg must match configured alg", func(t *testing.T) {
		_, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "ES256", SigningKeyFile: rsaFile})
		assert.ErrorContains(t, err, "signing alg is ES256")
	})
	t.Run("public key cannot sign", func(t *testing.T) {
		_, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "RS256", SigningKeyFile: publicFile})
		assert.ErrorContains(t, err, "must be a private key")
	})
	t.Run("same key twice is rejected", func(t *testing.T) {
		_, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "RS256", SigningKeyFile: rsaFile, VerificationKeyFiles: publicFile})
		assert.ErrorContains(t, err, "duplicate key id")
	})
	t.Run("missing key file fails without ephemeral", func(t *testing.T) {
		_, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "RS256"})
		assert.ErrorContains(t, err, "signing key file is required")
	})
	t.Run("missing key file generates ephemeral when allowed", func(t *testing.T) {
		ks, ephemeral, err := jwtkeys.Load(jwtkeys.Options{Alg: "ES256", AllowEphemeral: true})
		require.NoError(t, err)
		assert.True(t, ephemeral)
		assert.Equal(t, jwtkeys.AlgES256, ks.Algorithm())
	})
	t.Run("HS256 uses the secret and rejects key files", func(t *testing.T) {
		ks, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "HS256", HMACSecret: "secret"})
		require.NoError(t, err)
		assert.Equal(t, jwtkeys.AlgHS256, ks.Algorithm())
		_, _, err = jwtkeys.Load(jwtkeys.Options{Alg: "HS256", HMACSecret: "secret", SigningKeyFile: rsaFile})
		assert.Error(t, err)
	})
	t.Run("unknown alg", func(t *testing.T) {
		_, _, err := jwtkeys.Load(jwtkeys.Options{Alg: "PS512"})
		assert.ErrorContains(t, err, "unsupported signing alg")
	})
}

func TestSignTyped_AccessToken_TypHeaderDistinguishesFromJWT(t *testing.T) {
	// Arrange
	ks := mustKeySet(t, mustGenerate(t, jwtkeys.AlgRS256))

	// Act
	accessToken, err := ks.SignTyped(claims(), jwtkeys.TypeAccessToken)
	require.NoError(t, err)
	plain, err := ks.Sign(claims())
	require.NoError(t, err)
	parsedAccess, err := ks.Parse(accessToken, jwt.MapClaims{})
	require.NoError(t, err)
	parsedPlain, err := ks.Parse(plain, jwt.MapClaims{})
	require.NoError(t, err)

	// Assert
	assert.Equal(t, "at+jwt", parsedAccess.Header["typ"])
	assert.True(t, jwtkeys.HasType(parsedAccess, jwtkeys.TypeAccessToken))
	assert.False(t, jwtkeys.HasType(parsedPlain, jwtkeys.TypeAccessToken))
}

func TestHasType_MediaTypeForms_MatchCaseInsensitivelyWithOptionalPrefix(t *testing.T) {
	for typ, want := range map[string]bool{
		"at+jwt": true, "AT+JWT": true, "application/at+jwt": true,
		"JWT": false, "": false, "at+jwt2": false,
	} {
		token := &jwt.Token{Header: map[string]interface{}{"typ": typ}}
		assert.Equal(t, want, jwtkeys.HasType(token, jwtkeys.TypeAccessToken), typ)
	}
}
