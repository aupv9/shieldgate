package mfa

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfcSecret is the SHA-1 test secret of RFC 6238 Appendix B
var rfcSecret = []byte("12345678901234567890")

func TestCode_RFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B lists 8-digit codes; the 6-digit code is the
	// same value mod 10^6
	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tt := range tests {
		// Act
		got := Code(rfcSecret, Step(time.Unix(tt.unix, 0)))

		// Assert
		assert.Equal(t, tt.want, got, "T=%d", tt.unix)
	}
}

func TestVerify_AcceptsAdjacentStepsOnly(t *testing.T) {
	// Arrange
	now := time.Unix(1234567890, 0)
	current := Step(now)

	tests := []struct {
		name   string
		offset int64
		want   bool
	}{
		{"previous step", -1, true},
		{"current step", 0, true},
		{"next step", 1, true},
		{"two steps old", -2, false},
		{"two steps ahead", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			step, ok := Verify(rfcSecret, Code(rfcSecret, current+tt.offset), now)

			// Assert
			assert.Equal(t, tt.want, ok)
			if ok {
				assert.Equal(t, current+tt.offset, step, "the matched step is reported for replay checks")
			}
		})
	}
}

func TestVerify_MalformedInput_Rejected(t *testing.T) {
	for _, code := range []string{"", "12345", "1234567", "abcdef"} {
		_, ok := Verify(rfcSecret, code, time.Unix(59, 0))
		assert.False(t, ok, code)
	}
}

func TestKeyURI_ContainsSecretAndIssuer(t *testing.T) {
	// Act
	uri := KeyURI("Acme Corp", "alice@example.com", rfcSecret)

	// Assert
	assert.True(t, strings.HasPrefix(uri, "otpauth://totp/Acme%20Corp:alice@example.com?"), uri)
	assert.Contains(t, uri, "secret="+EncodeSecret(rfcSecret))
	assert.Contains(t, uri, "issuer=Acme+Corp")
	assert.Contains(t, uri, "digits=6")
}

func TestKeys_SealOpen_BoundToOwner(t *testing.T) {
	// Arrange
	keys, err := NewKeys(DeriveKey("master-secret-for-tests-0123456789"))
	require.NoError(t, err)
	secret, err := NewSecret()
	require.NoError(t, err)

	// Act
	sealed, err := keys.Seal(secret, "tenant|alice")
	require.NoError(t, err)
	opened, openErr := keys.Open(sealed, "tenant|alice")
	_, otherOwnerErr := keys.Open(sealed, "tenant|mallory")
	otherKeys, _ := NewKeys(DeriveKey("a-different-master-secret-987654"))
	_, otherKeyErr := otherKeys.Open(sealed, "tenant|alice")

	// Assert
	require.NoError(t, openErr)
	assert.Equal(t, secret, opened)
	assert.NotContains(t, sealed, EncodeSecret(secret))
	assert.ErrorIs(t, otherOwnerErr, ErrDecrypt)
	assert.ErrorIs(t, otherKeyErr, ErrDecrypt)
}

func TestParseKey(t *testing.T) {
	// 32 zero bytes, base64
	valid := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	key, err := ParseKey(valid)
	require.NoError(t, err)
	assert.Len(t, key, KeySize)

	_, err = ParseKey("c2hvcnQ=") // "short"
	assert.Error(t, err)
	_, err = ParseKey("not base64 !!")
	assert.Error(t, err)
}

func TestRecoveryCodes_FormatUniquenessAndNormalization(t *testing.T) {
	// Arrange
	keys, err := NewKeys(DeriveKey("master-secret-for-tests-0123456789"))
	require.NoError(t, err)

	// Act
	codes, err := NewRecoveryCodes()

	// Assert
	require.NoError(t, err)
	require.Len(t, codes, RecoveryCodeCount)
	seen := map[string]bool{}
	for _, code := range codes {
		assert.Regexp(t, `^[2-9A-HJKMNP-Z]{5}-[2-9A-HJKMNP-Z]{5}$`, code)
		assert.False(t, seen[code])
		seen[code] = true
	}
	typed := " " + strings.ToLower(strings.ReplaceAll(codes[0], "-", " ")) + " "
	assert.Equal(t, keys.HashRecoveryCode(codes[0]), keys.HashRecoveryCode(typed))
	assert.NotEqual(t, keys.HashRecoveryCode(codes[0]), keys.HashRecoveryCode(codes[1]))
}

func TestLooksLikeTOTP(t *testing.T) {
	assert.True(t, LooksLikeTOTP("123456"))
	assert.True(t, LooksLikeTOTP(" 123456 "))
	assert.False(t, LooksLikeTOTP("ABCDE-FGHJK"))
	assert.False(t, LooksLikeTOTP("12345"))
}
