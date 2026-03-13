package services

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"shieldgate/config"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// EmailServiceImpl implements the EmailService interface
type EmailServiceImpl struct {
	templateRepo      repo.EmailTemplateRepository
	queueRepo         repo.EmailQueueRepository
	verificationRepo  repo.EmailVerificationRepository
	passwordResetRepo repo.PasswordResetRepository
	userRepo          repo.UserRepository
	auditService      AuditService
	cfg               *config.Config
	logger            *logrus.Logger
}

// NewEmailService creates a new email service instance
func NewEmailService(
	templateRepo repo.EmailTemplateRepository,
	queueRepo repo.EmailQueueRepository,
	verificationRepo repo.EmailVerificationRepository,
	passwordResetRepo repo.PasswordResetRepository,
	userRepo repo.UserRepository,
	auditService AuditService,
	cfg *config.Config,
	logger *logrus.Logger,
) EmailService {
	return &EmailServiceImpl{
		templateRepo:      templateRepo,
		queueRepo:         queueRepo,
		verificationRepo:  verificationRepo,
		passwordResetRepo: passwordResetRepo,
		userRepo:          userRepo,
		auditService:      auditService,
		cfg:               cfg,
		logger:            logger,
	}
}

// CreateTemplate creates a new email template
func (s *EmailServiceImpl) CreateTemplate(ctx context.Context, tenantID uuid.UUID, template *models.EmailTemplate) error {
	template.ID = uuid.New()
	template.TenantID = tenantID
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	if err := s.templateRepo.Create(ctx, template); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id":     tenantID,
			"template_name": template.Name,
		}).Error("failed to create email template")
		return fmt.Errorf("failed to create email template: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":     tenantID,
		"template_id":   template.ID,
		"template_name": template.Name,
	}).Info("email template created successfully")

	return nil
}

// GetTemplate retrieves an email template by name
func (s *EmailServiceImpl) GetTemplate(ctx context.Context, tenantID uuid.UUID, name string) (*models.EmailTemplate, error) {
	template, err := s.templateRepo.GetByName(ctx, tenantID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get email template: %w", err)
	}

	return template, nil
}

// UpdateTemplate updates an existing email template
func (s *EmailServiceImpl) UpdateTemplate(ctx context.Context, tenantID uuid.UUID, name string, template *models.EmailTemplate) error {
	existing, err := s.templateRepo.GetByName(ctx, tenantID, name)
	if err != nil {
		return fmt.Errorf("failed to get existing template: %w", err)
	}

	// Update fields
	existing.Subject = template.Subject
	existing.BodyHTML = template.BodyHTML
	existing.BodyText = template.BodyText
	existing.Variables = template.Variables
	existing.IsActive = template.IsActive
	existing.UpdatedAt = time.Now()

	if err := s.templateRepo.Update(ctx, existing); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id":     tenantID,
			"template_name": name,
		}).Error("failed to update email template")
		return fmt.Errorf("failed to update email template: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":     tenantID,
		"template_id":   existing.ID,
		"template_name": name,
	}).Info("email template updated successfully")

	return nil
}

// DeleteTemplate deletes an email template
func (s *EmailServiceImpl) DeleteTemplate(ctx context.Context, tenantID uuid.UUID, name string) error {
	if err := s.templateRepo.Delete(ctx, tenantID, name); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id":     tenantID,
			"template_name": name,
		}).Error("failed to delete email template")
		return fmt.Errorf("failed to delete email template: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":     tenantID,
		"template_name": name,
	}).Info("email template deleted successfully")

	return nil
}

// ListTemplates lists email templates with pagination
func (s *EmailServiceImpl) ListTemplates(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	templates, totalCount, err := s.templateRepo.List(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list email templates: %w", err)
	}

	items := make([]interface{}, len(templates))
	for i, template := range templates {
		items[i] = template
	}

	return models.NewPaginatedResponse(items, limit, offset, totalCount), nil
}

// SendEmail sends an email by adding it to the queue
func (s *EmailServiceImpl) SendEmail(ctx context.Context, tenantID uuid.UUID, req *models.SendEmailRequest) error {
	// Get template
	template, err := s.templateRepo.GetByName(ctx, tenantID, req.Template)
	if err != nil {
		return fmt.Errorf("failed to get email template: %w", err)
	}

	if !template.IsActive {
		return fmt.Errorf("email template is not active")
	}

	// Process template variables
	subject := s.processTemplate(template.Subject, req.Variables)
	bodyHTML := s.processTemplate(template.BodyHTML, req.Variables)
	bodyText := s.processTemplate(template.BodyText, req.Variables)

	// Create email queue entry
	email := &models.EmailQueue{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ToEmail:     req.ToEmail,
		ToName:      req.ToName,
		FromEmail:   s.cfg.SMTPFrom,
		FromName:    s.cfg.SMTPFromName,
		Subject:     subject,
		BodyHTML:    bodyHTML,
		BodyText:    bodyText,
		Status:      "pending",
		Priority:    req.Priority,
		Attempts:    0,
		MaxAttempts: 3,
		ScheduledAt: time.Now(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if email.Priority <= 0 {
		email.Priority = 5 // default priority
	}

	if err := s.queueRepo.Create(ctx, email); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"to_email":  req.ToEmail,
			"template":  req.Template,
		}).Error("failed to queue email")
		return fmt.Errorf("failed to queue email: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"email_id":  email.ID,
		"to_email":  req.ToEmail,
		"template":  req.Template,
		"priority":  email.Priority,
	}).Info("email queued successfully")

	return nil
}

// SendTemplateEmail sends an email using a template
func (s *EmailServiceImpl) SendTemplateEmail(ctx context.Context, tenantID uuid.UUID, toEmail, toName, templateName string, variables map[string]string, priority int) error {
	req := &models.SendEmailRequest{
		ToEmail:   toEmail,
		ToName:    toName,
		Template:  templateName,
		Variables: variables,
		Priority:  priority,
	}

	return s.SendEmail(ctx, tenantID, req)
}

// ProcessQueue processes pending emails in the queue
func (s *EmailServiceImpl) ProcessQueue(ctx context.Context) error {
	// Get pending emails (limit to 100 at a time)
	emails, err := s.queueRepo.GetPendingEmails(ctx, 100)
	if err != nil {
		return fmt.Errorf("failed to get pending emails: %w", err)
	}

	s.logger.WithField("count", len(emails)).Info("processing email queue")

	for _, email := range emails {
		if err := s.processEmail(ctx, email); err != nil {
			s.logger.WithError(err).WithField("email_id", email.ID).Error("failed to process email")
		}
	}

	return nil
}

// GetQueueStatus returns the status of the email queue
func (s *EmailServiceImpl) GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	status, err := s.queueRepo.GetQueueStatus(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get queue status: %w", err)
	}

	return status, nil
}

// RetryFailedEmails retries failed emails
func (s *EmailServiceImpl) RetryFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) error {
	failedEmails, err := s.queueRepo.GetFailedEmails(ctx, tenantID, maxAttempts)
	if err != nil {
		return fmt.Errorf("failed to get failed emails: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"count":     len(failedEmails),
	}).Info("retrying failed emails")

	for _, email := range failedEmails {
		// Reset status and schedule for retry
		email.Status = "pending"
		email.ScheduledAt = time.Now()
		email.LastError = ""
		email.UpdatedAt = time.Now()

		if err := s.queueRepo.Update(ctx, email); err != nil {
			s.logger.WithError(err).WithField("email_id", email.ID).Error("failed to reset failed email")
		}
	}

	return nil
}

// SendVerificationEmail sends an email verification email
func (s *EmailServiceImpl) SendVerificationEmail(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Generate verification code
	code, err := s.generateVerificationCode()
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Create verification record
	verification := &models.EmailVerification{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Email:     user.Email,
		Code:      code,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours expiry
		CreatedAt: time.Now(),
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return fmt.Errorf("failed to create verification record: %w", err)
	}

	// Send verification email
	variables := map[string]string{
		"user_name":         user.GetFullName(),
		"verification_code": code,
		"verification_link": fmt.Sprintf("https://app.shieldgate.com/verify-email?code=%s", code),
	}

	if err := s.SendTemplateEmail(ctx, tenantID, user.Email, user.GetFullName(), string(models.EmailTemplateEmailVerification), variables, 1); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, userID, models.AuditActionEmailVerified, "user", &userID, true, map[string]interface{}{
			"email": user.Email,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"email":     user.Email,
	}).Info("verification email sent")

	return nil
}

// VerifyEmail verifies an email using the verification code
func (s *EmailServiceImpl) VerifyEmail(ctx context.Context, tenantID uuid.UUID, code string) (*models.User, error) {
	// Get verification record
	verification, err := s.verificationRepo.GetByCode(ctx, tenantID, code)
	if err != nil {
		return nil, fmt.Errorf("invalid verification code: %w", err)
	}

	// Check if already verified
	if verification.VerifiedAt != nil {
		return nil, models.ErrInvalidVerificationCode
	}

	// Check if expired
	if verification.IsExpired() {
		return nil, models.ErrVerificationExpired
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, tenantID, verification.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Update user email verification status
	user.EmailVerified = true
	if user.Status == models.UserStatusPending {
		user.Status = models.UserStatusActive
	}
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Mark verification as used
	now := time.Now()
	verification.VerifiedAt = &now
	if err := s.verificationRepo.Update(ctx, verification); err != nil {
		s.logger.WithError(err).Error("failed to update verification record")
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, verification.UserID, models.AuditActionEmailVerified, "user", &verification.UserID, true, map[string]interface{}{
			"email": user.Email,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   verification.UserID,
		"email":     user.Email,
	}).Info("email verified successfully")

	return user, nil
}

// SendPasswordResetEmail sends a password reset email
func (s *EmailServiceImpl) SendPasswordResetEmail(ctx context.Context, tenantID uuid.UUID, email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		// Don't reveal if user exists or not for security
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"email":     email,
		}).Warn("password reset requested for non-existent user")
		return nil
	}

	// Generate reset token
	token, err := s.generateResetToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Create password reset record
	reset := &models.PasswordReset{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		CreatedAt: time.Now(),
	}

	if err := s.passwordResetRepo.Create(ctx, reset); err != nil {
		return fmt.Errorf("failed to create password reset record: %w", err)
	}

	// Send password reset email
	variables := map[string]string{
		"user_name":  user.GetFullName(),
		"reset_link": fmt.Sprintf("https://app.shieldgate.com/reset-password?token=%s", token),
	}

	if err := s.SendTemplateEmail(ctx, tenantID, user.Email, user.GetFullName(), string(models.EmailTemplatePasswordReset), variables, 1); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, user.ID, models.AuditActionPasswordChanged, "user", &user.ID, true, map[string]interface{}{
			"email": user.Email,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("password reset email sent")

	return nil
}

// ResetPassword resets a user's password using the reset token
func (s *EmailServiceImpl) ResetPassword(ctx context.Context, tenantID uuid.UUID, token, newPassword string) (*models.User, error) {
	// Get password reset record
	reset, err := s.passwordResetRepo.GetByToken(ctx, tenantID, token)
	if err != nil {
		return nil, models.ErrInvalidVerificationCode
	}

	// Check if already used
	if reset.IsUsed() {
		return nil, models.ErrInvalidVerificationCode
	}

	// Check if expired
	if reset.IsExpired() {
		return nil, models.ErrVerificationExpired
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, tenantID, reset.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user password: %w", err)
	}

	// Mark reset as used
	now := time.Now()
	reset.UsedAt = &now
	if err := s.passwordResetRepo.Update(ctx, reset); err != nil {
		s.logger.WithError(err).Error("failed to update password reset record")
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, user.ID, models.AuditActionPasswordChanged, "user", &user.ID, true, map[string]interface{}{
			"email": user.Email,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("password reset successfully")

	return user, nil
}

// Helper methods

func (s *EmailServiceImpl) processTemplate(template string, variables map[string]string) string {
	result := template
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func (s *EmailServiceImpl) processEmail(ctx context.Context, email *models.EmailQueue) error {
	email.Attempts++
	email.UpdatedAt = time.Now()

	if err := s.sendViaSMTP(email); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"email_id": email.ID,
			"to_email": email.ToEmail,
			"attempts": email.Attempts,
		}).Error("SMTP send failed")

		email.Status = "failed"
		if err2 := s.queueRepo.Update(ctx, email); err2 != nil {
			s.logger.WithError(err2).Error("failed to update email status after send failure")
		}
		return fmt.Errorf("SMTP send failed: %w", err)
	}

	email.Status = "sent"
	now := time.Now()
	email.SentAt = &now

	if err := s.queueRepo.Update(ctx, email); err != nil {
		return fmt.Errorf("failed to update email status: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"email_id": email.ID,
		"to_email": email.ToEmail,
		"subject":  email.Subject,
	}).Info("email sent successfully")

	return nil
}

// sendViaSMTP delivers a single email via SMTP using net/smtp.
// If SMTPHost is empty, the send is skipped and the email is marked sent (dev mode).
func (s *EmailServiceImpl) sendViaSMTP(email *models.EmailQueue) error {
	host := s.cfg.SMTPHost
	if host == "" {
		s.logger.WithField("email_id", email.ID).Warn("SMTP host not configured, skipping send (dev mode)")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", host, s.cfg.SMTPPort)

	// Build RFC 2822 message
	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, host)
	}

	from := fmt.Sprintf("%s <%s>", s.cfg.SMTPFromName, s.cfg.SMTPFrom)
	to := email.ToEmail
	if email.ToName != "" {
		to = fmt.Sprintf("%s <%s>", email.ToName, email.ToEmail)
	}

	body := buildMIMEMessage(from, to, email.Subject, email.BodyHTML, email.BodyText)

	if s.cfg.SMTPUseTLS {
		// Implicit TLS (port 465)
		tlsCfg := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS dial failed: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("SMTP client creation failed: %w", err)
		}
		defer client.Quit()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}
		if err := client.Mail(s.cfg.SMTPFrom); err != nil {
			return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
		}
		if err := client.Rcpt(email.ToEmail); err != nil {
			return fmt.Errorf("SMTP RCPT TO failed: %w", err)
		}
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA failed: %w", err)
		}
		defer w.Close()
		_, err = w.Write([]byte(body))
		return err
	}

	// STARTTLS / plain (port 587 or 25)
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %w", err)
	}
	defer client.Quit()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: host}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}
	if err := client.Mail(s.cfg.SMTPFrom); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(email.ToEmail); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	defer w.Close()
	_, err = w.Write([]byte(body))
	return err
}

// buildMIMEMessage constructs a multipart/alternative MIME message.
func buildMIMEMessage(from, to, subject, bodyHTML, bodyText string) string {
	boundary := "ShieldGate_" + fmt.Sprintf("%d", time.Now().UnixNano())
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", to))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
	sb.WriteString("\r\n")

	if bodyText != "" {
		sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		sb.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
		sb.WriteString(bodyText)
		sb.WriteString("\r\n")
	}

	if bodyHTML != "" {
		sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		sb.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
		sb.WriteString(bodyHTML)
		sb.WriteString("\r\n")
	}

	sb.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	return sb.String()
}


func (s *EmailServiceImpl) generateVerificationCode() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *EmailServiceImpl) generateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
