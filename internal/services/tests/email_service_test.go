package tests

// email_service_test.go covers rendering and delivery in EmailService:
// built-in templates, escaping of user-controlled values, and retries.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/config"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

type fakeEmailTemplateRepo struct {
	templates map[string]*models.EmailTemplate
}

func (r *fakeEmailTemplateRepo) Create(ctx context.Context, t *models.EmailTemplate) error {
	r.templates[t.Name] = t
	return nil
}

func (r *fakeEmailTemplateRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.EmailTemplate, error) {
	if t, ok := r.templates[name]; ok && t.TenantID == tenantID {
		return t, nil
	}
	return nil, models.ErrResourceNotFound
}

func (r *fakeEmailTemplateRepo) Update(ctx context.Context, t *models.EmailTemplate) error {
	r.templates[t.Name] = t
	return nil
}

func (r *fakeEmailTemplateRepo) Delete(ctx context.Context, tenantID uuid.UUID, name string) error {
	delete(r.templates, name)
	return nil
}

func (r *fakeEmailTemplateRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.EmailTemplate, int64, error) {
	return nil, 0, nil
}

type fakeEmailQueueRepo struct {
	mu     sync.Mutex
	emails map[uuid.UUID]*models.EmailQueue
}

func (r *fakeEmailQueueRepo) Create(ctx context.Context, e *models.EmailQueue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *e
	r.emails[e.ID] = &stored
	return nil
}

func (r *fakeEmailQueueRepo) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*models.EmailQueue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.emails[id]; ok {
		copied := *e
		return &copied, nil
	}
	return nil, models.ErrResourceNotFound
}

func (r *fakeEmailQueueRepo) GetPendingEmails(ctx context.Context, limit int) ([]*models.EmailQueue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var due []*models.EmailQueue
	for _, e := range r.emails {
		if e.Status == "pending" && !e.ScheduledAt.After(time.Now()) {
			e.Status = "sending"
			copied := *e
			due = append(due, &copied)
		}
	}
	return due, nil
}

func (r *fakeEmailQueueRepo) Update(ctx context.Context, e *models.EmailQueue) error {
	return r.Create(ctx, e)
}

func (r *fakeEmailQueueRepo) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.emails, id)
	return nil
}

func (r *fakeEmailQueueRepo) GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	return nil, nil
}

func (r *fakeEmailQueueRepo) GetFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) ([]*models.EmailQueue, error) {
	return nil, nil
}

// only returns the single queued email
func (r *fakeEmailQueueRepo) only(t *testing.T) *models.EmailQueue {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.emails, 1)
	for _, e := range r.emails {
		copied := *e
		return &copied
	}
	return nil
}

func newEmailService(cfg *config.Config) (services.EmailService, *fakeEmailTemplateRepo, *fakeEmailQueueRepo) {
	templates := &fakeEmailTemplateRepo{templates: map[string]*models.EmailTemplate{}}
	queue := &fakeEmailQueueRepo{emails: map[uuid.UUID]*models.EmailQueue{}}
	if cfg == nil {
		cfg = &config.Config{SMTPFrom: "no-reply@auth.example", SMTPFromName: "ShieldGate"}
	}
	return services.NewEmailService(templates, queue, cfg, quietLogger()), templates, queue
}

func TestSendTemplateEmail_NoTenantTemplate_UsesBuiltInDefault(t *testing.T) {
	// Arrange
	svc, _, queue := newEmailService(nil)

	// Act
	err := svc.SendTemplateEmail(context.Background(), uuid.New(), "dave@example.com", "Dave",
		string(models.EmailTemplatePasswordReset),
		map[string]string{"user_name": "Dave", "reset_link": "https://auth.example/r?token=abc", "expires_minutes": "60"}, 1)

	// Assert
	require.NoError(t, err)
	email := queue.only(t)
	assert.Equal(t, "Reset your password", email.Subject)
	assert.Contains(t, email.BodyText, "https://auth.example/r?token=abc")
	assert.Contains(t, email.BodyHTML, `href="https://auth.example/r?token=abc"`)
	assert.Equal(t, "pending", email.Status)
}

func TestSendTemplateEmail_TenantTemplateOverridesDefault(t *testing.T) {
	// Arrange
	svc, templates, queue := newEmailService(nil)
	tenantID := uuid.New()
	templates.templates["password_reset"] = &models.EmailTemplate{
		TenantID: tenantID, Name: "password_reset", Subject: "Acme reset", BodyText: "{{reset_link}}", IsActive: true,
	}

	// Act
	err := svc.SendTemplateEmail(context.Background(), tenantID, "dave@example.com", "", "password_reset",
		map[string]string{"reset_link": "L"}, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "Acme reset", queue.only(t).Subject)
}

func TestSendTemplateEmail_UnknownTemplate_Fails(t *testing.T) {
	// Arrange
	svc, _, _ := newEmailService(nil)

	// Act
	err := svc.SendTemplateEmail(context.Background(), uuid.New(), "dave@example.com", "", "no_such_template", nil, 1)

	// Assert
	assert.ErrorIs(t, err, models.ErrResourceNotFound)
}

func TestSendTemplateEmail_UserControlledValues_EscapedInHTMLAndSubject(t *testing.T) {
	// Arrange
	svc, templates, queue := newEmailService(nil)
	tenantID := uuid.New()
	templates.templates["greeting"] = &models.EmailTemplate{
		TenantID: tenantID, Name: "greeting", IsActive: true,
		Subject:  "Hello {{user_name}}",
		BodyHTML: "<p>Hi {{user_name}}</p>",
		BodyText: "Hi {{user_name}}",
	}
	name := "<script>x</script>\r\nBcc: victim@example.com"

	// Act
	err := svc.SendTemplateEmail(context.Background(), tenantID, "dave@example.com", "", "greeting",
		map[string]string{"user_name": name}, 1)

	// Assert
	require.NoError(t, err)
	email := queue.only(t)
	assert.NotContains(t, email.BodyHTML, "<script>")
	assert.Contains(t, email.BodyHTML, "&lt;script&gt;")
	assert.NotContains(t, email.Subject, "\n")
	assert.NotContains(t, email.Subject, "\r")
}

func TestProcessQueue_SendFailure_RetriesWithBackoffThenFails(t *testing.T) {
	// Arrange: nothing listens on port 1, so every send fails fast
	cfg := &config.Config{SMTPHost: "127.0.0.1", SMTPPort: 1, SMTPFrom: "no-reply@auth.example"}
	svc, _, queue := newEmailService(cfg)
	ctx := context.Background()
	require.NoError(t, svc.SendTemplateEmail(ctx, uuid.New(), "dave@example.com", "", "password_changed",
		map[string]string{"user_name": "Dave"}, 1))

	// Act
	require.NoError(t, svc.ProcessQueue(ctx))
	afterFirst := queue.only(t)
	for i := 0; i < 5; i++ {
		e := queue.only(t)
		e.ScheduledAt = time.Now().Add(-time.Second)
		require.NoError(t, queue.Update(ctx, e))
		require.NoError(t, svc.ProcessQueue(ctx))
	}
	final := queue.only(t)

	// Assert
	assert.Equal(t, "pending", afterFirst.Status, "a failed send is retried")
	assert.True(t, afterFirst.ScheduledAt.After(time.Now()), "the retry is delayed")
	assert.NotEmpty(t, afterFirst.LastError)
	assert.Equal(t, "failed", final.Status)
	assert.Equal(t, final.MaxAttempts, final.Attempts, "no sends after max_attempts")
}

func TestProcessQueue_NoSMTPHost_MarksSent(t *testing.T) {
	// Arrange
	svc, _, queue := newEmailService(nil)
	ctx := context.Background()
	require.NoError(t, svc.SendTemplateEmail(ctx, uuid.New(), "dave@example.com", "", "password_changed",
		map[string]string{"user_name": "Dave"}, 1))

	// Act
	err := svc.ProcessQueue(ctx)

	// Assert
	require.NoError(t, err)
	email := queue.only(t)
	assert.Equal(t, "sent", email.Status)
	assert.NotNil(t, email.SentAt)
	assert.Empty(t, email.BodyText, "sent bodies may hold live links and are discarded")
	assert.Empty(t, email.BodyHTML)
}
