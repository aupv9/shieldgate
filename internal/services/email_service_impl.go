package services

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"mime"
	"net/smtp"
	"strings"
	"time"

	"shieldgate/config"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// EmailServiceImpl implements the EmailService interface
type EmailServiceImpl struct {
	templateRepo repo.EmailTemplateRepository
	queueRepo    repo.EmailQueueRepository
	cfg          *config.Config
	logger       *logrus.Logger
}

// NewEmailService creates a new email service instance
func NewEmailService(
	templateRepo repo.EmailTemplateRepository,
	queueRepo repo.EmailQueueRepository,
	cfg *config.Config,
	logger *logrus.Logger,
) EmailService {
	return &EmailServiceImpl{
		templateRepo: templateRepo,
		queueRepo:    queueRepo,
		cfg:          cfg,
		logger:       logger,
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
	// A tenant's own template overrides the built-in default
	template, err := s.templateRepo.GetByName(ctx, tenantID, req.Template)
	if errors.Is(err, models.ErrResourceNotFound) {
		if fallback, ok := defaultEmailTemplates[req.Template]; ok {
			template, err = &fallback, nil
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get email template: %w", err)
	}

	if !template.IsActive {
		return fmt.Errorf("email template is not active")
	}

	// Variables often carry user-controlled data (names), so they are
	// HTML-escaped in the HTML body and stripped of line breaks in the subject
	subject := sanitizeHeader(processTemplate(template.Subject, req.Variables, nil))
	bodyHTML := processTemplate(template.BodyHTML, req.Variables, html.EscapeString)
	bodyText := processTemplate(template.BodyText, req.Variables, nil)

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

// Helper methods

// processTemplate replaces {{name}} placeholders, passing each value through
// escape when it is non-nil
func processTemplate(template string, variables map[string]string, escape func(string) string) string {
	result := template
	for key, value := range variables {
		if escape != nil {
			value = escape(value)
		}
		result = strings.ReplaceAll(result, "{{"+key+"}}", value)
	}
	return result
}

// sanitizeHeader removes CR and LF so a value cannot inject mail headers
func sanitizeHeader(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
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

		email.LastError = err.Error()
		if email.Attempts < email.MaxAttempts {
			// Exponential backoff: 1, 2, 4... minutes
			email.Status = "pending"
			email.ScheduledAt = time.Now().Add(time.Minute << (email.Attempts - 1))
		} else {
			email.Status = "failed"
		}
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
	sb.WriteString(fmt.Sprintf("From: %s\r\n", sanitizeHeader(from)))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", sanitizeHeader(to)))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", sanitizeHeader(subject))))
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
