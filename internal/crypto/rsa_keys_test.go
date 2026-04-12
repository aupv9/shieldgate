package crypto

import (
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyManager_InMemory(t *testing.T) {
	km, err := NewKeyManager("")
	require.NoError(t, err)
	assert.NotNil(t, km.PrivateKey())
	assert.NotNil(t, km.PublicKey())
	assert.NotEmpty(t, km.KID())
}

func TestNewKeyManager_GeneratesUniqueKIDs(t *testing.T) {
	km1, _ := NewKeyManager("")
	km2, _ := NewKeyManager("")
	assert.NotEqual(t, km1.KID(), km2.KID())
}

func TestKeyManager_JWK_Shape(t *testing.T) {
	km, err := NewKeyManager("")
	require.NoError(t, err)

	jwk := km.JWK()

	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "RS256", jwk["alg"])
	assert.Equal(t, km.KID(), jwk["kid"])

	n, ok := jwk["n"].(string)
	require.True(t, ok, "n should be a string")
	assert.NotEmpty(t, n)

	e, ok := jwk["e"].(string)
	require.True(t, ok, "e should be a string")
	assert.NotEmpty(t, e)

	// Verify that e decodes correctly (standard exponent 65537)
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	require.NoError(t, err)
	eBig := new(big.Int).SetBytes(eBytes)
	assert.Equal(t, int64(65537), eBig.Int64())
}

func TestNewKeyManager_PersistAndReload(t *testing.T) {
	dir := t.TempDir()

	// First call: generate and persist
	km1, err := NewKeyManager(dir)
	require.NoError(t, err)

	// Key files must exist
	assert.FileExists(t, filepath.Join(dir, privateKeyFile))
	assert.FileExists(t, filepath.Join(dir, publicKeyFile))
	assert.FileExists(t, filepath.Join(dir, "kid.txt"))

	// Second call: load from disk
	km2, err := NewKeyManager(dir)
	require.NoError(t, err)

	// Same KID means same key was loaded
	assert.Equal(t, km1.KID(), km2.KID())

	// Public key modulus must match
	n1 := km1.PublicKey().N.Bytes()
	n2 := km2.PublicKey().N.Bytes()
	assert.Equal(t, n1, n2, "reloaded public key should match original")
}

func TestNewKeyManager_RespectsPrivateKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	_, err := NewKeyManager(dir)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, privateKeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "private key should be owner-read-only")
}

func TestKeyManager_RSAKeySize(t *testing.T) {
	km, err := NewKeyManager("")
	require.NoError(t, err)
	assert.Equal(t, rsaKeySize, km.PrivateKey().N.BitLen())
}
