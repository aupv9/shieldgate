package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sgcrypto "shieldgate/internal/crypto"
)

func TestNewRSAKeyManager_AutoGenerate(t *testing.T) {
	km, err := sgcrypto.NewRSAKeyManager("", "")
	require.NoError(t, err)
	assert.NotNil(t, km.PrivateKey())
	assert.NotNil(t, km.PublicKey())
	assert.Equal(t, "auto-generated", km.KeyID())
}

func TestRSAKeyManager_JWKSet_Structure(t *testing.T) {
	km, err := sgcrypto.NewRSAKeyManager("", "")
	require.NoError(t, err)

	jwks := km.JWKSet()
	require.Contains(t, jwks, "keys")

	keys, ok := jwks["keys"].([]map[string]interface{})
	require.True(t, ok, "keys must be a []map[string]interface{}")
	require.Len(t, keys, 1)

	k := keys[0]
	assert.Equal(t, "RSA", k["kty"])
	assert.Equal(t, "sig", k["use"])
	assert.Equal(t, "RS256", k["alg"])
	assert.NotEmpty(t, k["n"])
	assert.NotEmpty(t, k["e"])
}

func TestRSAKeyManager_PublicKeyMatchesPrivate(t *testing.T) {
	km, err := sgcrypto.NewRSAKeyManager("", "")
	require.NoError(t, err)
	assert.Equal(t, &km.PrivateKey().PublicKey, km.PublicKey())
}

func TestNewRSAKeyManager_InvalidPEM(t *testing.T) {
	_, err := sgcrypto.NewRSAKeyManager("", "not-a-valid-pem")
	assert.Error(t, err)
}

func TestNewRSAKeyManager_FileNotFound(t *testing.T) {
	_, err := sgcrypto.NewRSAKeyManager("/nonexistent/path/rsa.pem", "")
	assert.Error(t, err)
}

func TestRSAKeyManager_KeyID_NotEmpty(t *testing.T) {
	km, err := sgcrypto.NewRSAKeyManager("", "")
	require.NoError(t, err)
	assert.NotEmpty(t, km.KeyID())
}
