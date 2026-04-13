package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTOTPSecret_Length(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	// Must decode back without error
	padded := secret
	for len(padded)%8 != 0 {
		padded += "="
	}
	_, err = decodeBase32(padded)
	require.NoError(t, err)
}

func TestGenerateTOTPSecret_Uniqueness(t *testing.T) {
	s1, _ := GenerateTOTPSecret()
	s2, _ := GenerateTOTPSecret()
	assert.NotEqual(t, s1, s2)
}

func TestValidateTOTP_CurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	code, err := GenerateTOTP(secret, 30, 6)
	require.NoError(t, err)
	assert.True(t, ValidateTOTP(secret, code, 30, 6))
}

func TestValidateTOTP_WrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	assert.False(t, ValidateTOTP(secret, "000000", 30, 6))
}

func TestValidateTOTP_InvalidSecret(t *testing.T) {
	assert.False(t, ValidateTOTP("not-base32!!!", "123456", 30, 6))
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("ShieldGate", "user@example.com", "JBSWY3DPEHPK3PXP", 30, 6)
	assert.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
	assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	assert.Contains(t, uri, "issuer=ShieldGate")
	assert.Contains(t, uri, "period=30")
	assert.Contains(t, uri, "digits=6")
}

func TestGenerateBackupCodes_Count(t *testing.T) {
	codes, err := GenerateBackupCodes(8)
	require.NoError(t, err)
	assert.Len(t, codes, 8)
}

func TestGenerateBackupCodes_Length(t *testing.T) {
	codes, _ := GenerateBackupCodes(4)
	for _, c := range codes {
		assert.Len(t, c, 10, "expected 10 hex chars per code")
	}
}

func TestGenerateBackupCodes_Unique(t *testing.T) {
	codes, _ := GenerateBackupCodes(8)
	seen := make(map[string]bool)
	for _, c := range codes {
		assert.False(t, seen[c], "duplicate backup code")
		seen[c] = true
	}
}

// helper exposed only for tests
func decodeBase32(s string) ([]byte, error) {
	import_base32 := strings.NewReplacer()
	_ = import_base32
	var b []byte
	var err error
	if b, err = base32decodeHelper(s); err != nil {
		return nil, err
	}
	return b, nil
}

func base32decodeHelper(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}
