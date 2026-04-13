package tests

import (
	"context"
	"testing"

	"shieldgate/internal/crypto"
	"shieldgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- in-memory MFASecret store for unit testing ---

type memMFASecretRepo struct {
	records map[string]*models.MFASecret // key: tenantID+":"+userID
}

func newMemMFASecretRepo() *memMFASecretRepo {
	return &memMFASecretRepo{records: make(map[string]*models.MFASecret)}
}

func (r *memMFASecretRepo) key(t, u uuid.UUID) string { return t.String() + ":" + u.String() }

func (r *memMFASecretRepo) Create(_ context.Context, s *models.MFASecret) error {
	r.records[r.key(s.TenantID, s.UserID)] = s
	return nil
}
func (r *memMFASecretRepo) GetByUserID(_ context.Context, t, u uuid.UUID) (*models.MFASecret, error) {
	s, ok := r.records[r.key(t, u)]
	if !ok {
		return nil, models.ErrMFANotSetup
	}
	return s, nil
}
func (r *memMFASecretRepo) Update(_ context.Context, s *models.MFASecret) error {
	r.records[r.key(s.TenantID, s.UserID)] = s
	return nil
}
func (r *memMFASecretRepo) Delete(_ context.Context, t, u uuid.UUID) error {
	delete(r.records, r.key(t, u))
	return nil
}

// --- tests ---

func TestTOTP_GenerateAndValidate(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	code, err := crypto.GenerateTOTP(secret, 30, 6)
	require.NoError(t, err)
	assert.Len(t, code, 6)

	assert.True(t, crypto.ValidateTOTP(secret, code, 30, 6), "freshly generated code must be valid")
}

func TestTOTP_WrongCodeRejected(t *testing.T) {
	secret, _ := crypto.GenerateTOTPSecret()
	assert.False(t, crypto.ValidateTOTP(secret, "000000", 30, 6))
}

func TestTOTP_InvalidSecretRejected(t *testing.T) {
	assert.False(t, crypto.ValidateTOTP("BAD!!!", "123456", 30, 6))
}

func TestBackupCodes_UniqueAndCorrectLength(t *testing.T) {
	codes, err := crypto.GenerateBackupCodes(8)
	require.NoError(t, err)
	assert.Len(t, codes, 8)
	seen := make(map[string]bool)
	for _, c := range codes {
		assert.Len(t, c, 10)
		assert.False(t, seen[c])
		seen[c] = true
	}
}

func TestProvisioningURI_Format(t *testing.T) {
	uri := crypto.TOTPProvisioningURI("Acme", "alice@acme.com", "JBSWY3DPEHPK3PXP", 30, 6)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "issuer=Acme")
	assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
}

func TestMFASecretRepo_CreateAndGet(t *testing.T) {
	repo := newMemMFASecretRepo()
	tenantID := uuid.New()
	userID := uuid.New()

	secret := &models.MFASecret{
		ID:       uuid.New(),
		TenantID: tenantID,
		UserID:   userID,
		Secret:   "TESTSECRET",
		Enabled:  false,
	}
	require.NoError(t, repo.Create(context.Background(), secret))

	got, err := repo.GetByUserID(context.Background(), tenantID, userID)
	require.NoError(t, err)
	assert.Equal(t, "TESTSECRET", got.Secret)
}

func TestMFASecretRepo_NotFound(t *testing.T) {
	repo := newMemMFASecretRepo()
	_, err := repo.GetByUserID(context.Background(), uuid.New(), uuid.New())
	assert.Error(t, err)
}

func TestMFASecretRepo_Delete(t *testing.T) {
	repo := newMemMFASecretRepo()
	tenantID, userID := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.MFASecret{
		ID: uuid.New(), TenantID: tenantID, UserID: userID, Secret: "X",
	})
	require.NoError(t, repo.Delete(context.Background(), tenantID, userID))
	_, err := repo.GetByUserID(context.Background(), tenantID, userID)
	assert.Error(t, err)
}
