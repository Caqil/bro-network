package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"path/filepath"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// EmailConfig represents email configuration
type EmailConfig struct {
	SMTPHost    string
	SMTPPort    string
	Username    string
	Password    string
	FromEmail   string
	FromName    string
	UseTLS      bool
	UseSSL      bool
	TemplateDir string
	DefaultLang string
}

// EmailService represents email service
type EmailService struct {
	config    *EmailConfig
	templates map[string]*template.Template
}

// EmailTemplate represents email template data
type EmailTemplate struct {
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Template    string
	Data        interface{}
	Language    string
	Priority    EmailPriority
	Headers     map[string]string
	Attachments []EmailAttachment
}

// EmailAttachment represents email attachment
type EmailAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
	Inline      bool
	ContentID   string
}

// EmailPriority represents email priority levels
type EmailPriority string

const (
	EmailPriorityLow    EmailPriority = "low"
	EmailPriorityNormal EmailPriority = "normal"
	EmailPriorityHigh   EmailPriority = "high"
	EmailPriorityUrgent EmailPriority = "urgent"
)

// EmailType represents different types of emails
type EmailType string

const (
	EmailTypeWelcome            EmailType = "welcome"
	EmailTypeEmailVerification  EmailType = "email_verification"
	EmailTypePasswordReset      EmailType = "password_reset"
	EmailTypePasswordChanged    EmailType = "password_changed"
	EmailTypeLoginAlert         EmailType = "login_alert"
	EmailTypeSecurityAlert      EmailType = "security_alert"
	EmailTypeNewFollower        EmailType = "new_follower"
	EmailTypeNewComment         EmailType = "new_comment"
	EmailTypeNewLike            EmailType = "new_like"
	EmailTypeNewMessage         EmailType = "new_message"
	EmailTypeMention            EmailType = "mention"
	EmailTypeDigest             EmailType = "digest"
	EmailTypeNewsletter         EmailType = "newsletter"
	EmailTypeAccountSuspended   EmailType = "account_suspended"
	EmailTypeAccountReactivated EmailType = "account_reactivated"
	EmailTypeDataExport         EmailType = "data_export"
	EmailTypeInvoice            EmailType = "invoice"
	EmailTypeReceipt            EmailType = "receipt"
)

// WelcomeEmailData represents data for welcome email
type WelcomeEmailData struct {
	UserID     primitive.ObjectID `json:"user_id"`
	FirstName  string             `json:"first_name"`
	LastName   string             `json:"last_name"`
	Username   string             `json:"username"`
	Email      string             `json:"email"`
	VerifyURL  string             `json:"verify_url"`
	LoginURL   string             `json:"login_url"`
	AppName    string             `json:"app_name"`
	SupportURL string             `json:"support_url"`
	Year       int                `json:"year"`
}

// PasswordResetEmailData represents data for password reset email
type PasswordResetEmailData struct {
	UserID     primitive.ObjectID `json:"user_id"`
	FirstName  string             `json:"first_name"`
	Email      string             `json:"email"`
	ResetURL   string             `json:"reset_url"`
	ExpiresAt  time.Time          `json:"expires_at"`
	IPAddress  string             `json:"ip_address"`
	UserAgent  string             `json:"user_agent"`
	AppName    string             `json:"app_name"`
	SupportURL string             `json:"support_url"`
}

// NotificationEmailData represents data for notification emails
type NotificationEmailData struct {
	UserID         primitive.ObjectID `json:"user_id"`
	RecipientName  string             `json:"recipient_name"`
	ActorName      string             `json:"actor_name"`
	ActorUsername  string             `json:"actor_username"`
	ContentType    string             `json:"content_type"`
	ContentURL     string             `json:"content_url"`
	ActionType     string             `json:"action_type"`
	Message        string             `json:"message"`
	UnsubscribeURL string             `json:"unsubscribe_url"`
	SettingsURL    string             `json:"settings_url"`
	AppName        string             `json:"app_name"`
	Timestamp      time.Time          `json:"timestamp"`
}

// DigestEmailData represents data for digest emails
type DigestEmailData struct {
	UserID             primitive.ObjectID `json:"user_id"`
	RecipientName      string             `json:"recipient_name"`
	Period             string             `json:"period"`
	TopPosts           []DigestPost       `json:"top_posts"`
	NewFollowers       []DigestUser       `json:"new_followers"`
	TotalNotifications int64              `json:"total_notifications"`
	Stats              DigestStats        `json:"stats"`
	UnsubscribeURL     string             `json:"unsubscribe_url"`
	AppURL             string             `json:"app_url"`
	AppName            string             `json:"app_name"`
}

// DigestPost represents a post in digest email
type DigestPost struct {
	ID            primitive.ObjectID `json:"id"`
	AuthorName    string             `json:"author_name"`
	Content       string             `json:"content"`
	LikesCount    int64              `json:"likes_count"`
	CommentsCount int64              `json:"comments_count"`
	URL           string             `json:"url"`
	CreatedAt     time.Time          `json:"created_at"`
}

// DigestUser represents a user in digest email
type DigestUser struct {
	ID         primitive.ObjectID `json:"id"`
	Name       string             `json:"name"`
	Username   string             `json:"username"`
	ProfileURL string             `json:"profile_url"`
	AvatarURL  string             `json:"avatar_url"`
}

// DigestStats represents stats in digest email
type DigestStats struct {
	PostsCreated     int64 `json:"posts_created"`
	LikesReceived    int64 `json:"likes_received"`
	CommentsReceived int64 `json:"comments_received"`
	NewFollowers     int64 `json:"new_followers"`
	ProfileViews     int64 `json:"profile_views"`
}

// NewEmailService creates a new email service
func NewEmailService(config *EmailConfig) *EmailService {
	return &EmailService{
		config:    config,
		templates: make(map[string]*template.Template),
	}
}

// LoadTemplates loads email templates from directory
func (es *EmailService) LoadTemplates() error {
	if es.config.TemplateDir == "" {
		return fmt.Errorf("template directory not configured")
	}

	templates := []string{
		"welcome",
		"email_verification",
		"password_reset",
		"password_changed",
		"login_alert",
		"security_alert",
		"new_follower",
		"new_comment",
		"new_like",
		"new_message",
		"mention",
		"digest",
		"newsletter",
		"account_suspended",
		"account_reactivated",
		"data_export",
	}

	for _, tmplName := range templates {
		tmplPath := filepath.Join(es.config.TemplateDir, tmplName+".html")
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return fmt.Errorf("failed to load template %s: %w", tmplName, err)
		}
		es.templates[tmplName] = tmpl
	}

	return nil
}

// SendEmail sends an email using the configured SMTP server
func (es *EmailService) SendEmail(emailTemplate *EmailTemplate) error {
	if len(emailTemplate.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Render template
	body, err := es.renderTemplate(emailTemplate)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Build message
	message, err := es.buildMessage(emailTemplate, body)
	if err != nil {
		return fmt.Errorf("failed to build message: %w", err)
	}

	// Send email
	return es.sendSMTP(emailTemplate.To, message)
}

// SendWelcomeEmail sends welcome email to new user
func (es *EmailService) SendWelcomeEmail(data *WelcomeEmailData) error {
	emailTemplate := &EmailTemplate{
		To:       []string{data.Email},
		Subject:  fmt.Sprintf("Welcome to %s, %s!", data.AppName, data.FirstName),
		Template: "welcome",
		Data:     data,
		Priority: EmailPriorityNormal,
	}

	return es.SendEmail(emailTemplate)
}

// SendPasswordResetEmail sends password reset email
func (es *EmailService) SendPasswordResetEmail(data *PasswordResetEmailData) error {
	emailTemplate := &EmailTemplate{
		To:       []string{data.Email},
		Subject:  fmt.Sprintf("Reset your %s password", data.AppName),
		Template: "password_reset",
		Data:     data,
		Priority: EmailPriorityHigh,
	}

	return es.SendEmail(emailTemplate)
}

// SendEmailVerification sends email verification
func (es *EmailService) SendEmailVerification(userID primitive.ObjectID, email, firstName, verifyURL, appName string) error {
	data := map[string]interface{}{
		"user_id":    userID,
		"first_name": firstName,
		"email":      email,
		"verify_url": verifyURL,
		"app_name":   appName,
	}

	emailTemplate := &EmailTemplate{
		To:       []string{email},
		Subject:  fmt.Sprintf("Verify your %s email address", appName),
		Template: "email_verification",
		Data:     data,
		Priority: EmailPriorityHigh,
	}

	return es.SendEmail(emailTemplate)
}

// SendNotificationEmail sends notification email
func (es *EmailService) SendNotificationEmail(data *NotificationEmailData, emailType EmailType) error {
	subject := es.getNotificationSubject(emailType, data)

	emailTemplate := &EmailTemplate{
		To:       []string{}, // Will be set based on user preferences
		Subject:  subject,
		Template: string(emailType),
		Data:     data,
		Priority: EmailPriorityNormal,
	}

	return es.SendEmail(emailTemplate)
}

// SendDigestEmail sends digest email
func (es *EmailService) SendDigestEmail(data *DigestEmailData) error {
	subject := fmt.Sprintf("Your %s %s digest", data.AppName, data.Period)

	emailTemplate := &EmailTemplate{
		To:       []string{}, // Will be set based on user email
		Subject:  subject,
		Template: "digest",
		Data:     data,
		Priority: EmailPriorityLow,
	}

	return es.SendEmail(emailTemplate)
}

// SendBulkEmail sends bulk email to multiple recipients
func (es *EmailService) SendBulkEmail(recipients []string, subject, templateName string, data interface{}) error {
	emailTemplate := &EmailTemplate{
		BCC:      recipients,
		Subject:  subject,
		Template: templateName,
		Data:     data,
		Priority: EmailPriorityLow,
	}

	return es.SendEmail(emailTemplate)
}

// renderTemplate renders email template with data
func (es *EmailService) renderTemplate(emailTemplate *EmailTemplate) (string, error) {
	tmpl, exists := es.templates[emailTemplate.Template]
	if !exists {
		return "", fmt.Errorf("template %s not found", emailTemplate.Template)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, emailTemplate.Data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// buildMessage builds email message with headers
func (es *EmailService) buildMessage(emailTemplate *EmailTemplate, body string) ([]byte, error) {
	var message bytes.Buffer

	// Headers
	message.WriteString(fmt.Sprintf("From: %s <%s>\r\n", es.config.FromName, es.config.FromEmail))

	if len(emailTemplate.To) > 0 {
		message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(emailTemplate.To, ", ")))
	}

	if len(emailTemplate.CC) > 0 {
		message.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(emailTemplate.CC, ", ")))
	}

	message.WriteString(fmt.Sprintf("Subject: %s\r\n", emailTemplate.Subject))
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")

	// Priority headers
	switch emailTemplate.Priority {
	case EmailPriorityHigh:
		message.WriteString("X-Priority: 2\r\n")
		message.WriteString("Importance: high\r\n")
	case EmailPriorityUrgent:
		message.WriteString("X-Priority: 1\r\n")
		message.WriteString("Importance: high\r\n")
	case EmailPriorityLow:
		message.WriteString("X-Priority: 4\r\n")
		message.WriteString("Importance: low\r\n")
	}

	// Custom headers
	for key, value := range emailTemplate.Headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Message ID and Date
	message.WriteString(fmt.Sprintf("Message-ID: <%d@%s>\r\n", time.Now().Unix(), es.config.FromEmail))
	message.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))

	message.WriteString("\r\n")
	message.WriteString(body)

	return message.Bytes(), nil
}

// sendSMTP sends email via SMTP
func (es *EmailService) sendSMTP(to []string, message []byte) error {
	auth := smtp.PlainAuth("", es.config.Username, es.config.Password, es.config.SMTPHost)

	addr := es.config.SMTPHost + ":" + es.config.SMTPPort

	if es.config.UseTLS {
		return es.sendWithTLS(addr, auth, to, message)
	}

	return smtp.SendMail(addr, auth, es.config.FromEmail, to, message)
}

// sendWithTLS sends email with TLS encryption
func (es *EmailService) sendWithTLS(addr string, auth smtp.Auth, to []string, message []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if es.config.UseSSL {
		tlsConfig := &tls.Config{
			ServerName: es.config.SMTPHost,
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}

	if err = client.Auth(auth); err != nil {
		return err
	}

	if err = client.Mail(es.config.FromEmail); err != nil {
		return err
	}

	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = writer.Write(message)
	return err
}

// getNotificationSubject returns subject line for notification emails
func (es *EmailService) getNotificationSubject(emailType EmailType, data *NotificationEmailData) string {
	switch emailType {
	case EmailTypeNewFollower:
		return fmt.Sprintf("%s started following you", data.ActorName)
	case EmailTypeNewComment:
		return fmt.Sprintf("%s commented on your post", data.ActorName)
	case EmailTypeNewLike:
		return fmt.Sprintf("%s liked your post", data.ActorName)
	case EmailTypeNewMessage:
		return fmt.Sprintf("New message from %s", data.ActorName)
	case EmailTypeMention:
		return fmt.Sprintf("%s mentioned you", data.ActorName)
	case EmailTypeLoginAlert:
		return "New login to your account"
	case EmailTypeSecurityAlert:
		return "Security alert for your account"
	case EmailTypePasswordChanged:
		return "Your password has been changed"
	default:
		return "Notification from " + data.AppName
	}
}

// ValidateEmail validates email address format
func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}

	// Basic email validation
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	if len(local) == 0 || len(local) > 64 {
		return false
	}

	if len(domain) == 0 || len(domain) > 255 {
		return false
	}

	if !strings.Contains(domain, ".") {
		return false
	}

	return true
}

// SanitizeEmailAddress sanitizes email address
func SanitizeEmailAddress(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ExtractDomain extracts domain from email address
func ExtractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// IsDisposableEmail checks if email is from a disposable email provider
func IsDisposableEmail(email string) bool {
	domain := ExtractDomain(email)
	if domain == "" {
		return false
	}

	// Common disposable email domains
	disposableDomains := map[string]bool{
		"10minutemail.com":      true,
		"guerrillamail.com":     true,
		"mailinator.com":        true,
		"tempmail.org":          true,
		"throwaway.email":       true,
		"temp-mail.org":         true,
		"fakemailgenerator.com": true,
		"mailnesia.com":         true,
		"yopmail.com":           true,
		"getairmail.com":        true,
	}

	return disposableDomains[strings.ToLower(domain)]
}

// GenerateUnsubscribeURL generates unsubscribe URL for email
func GenerateUnsubscribeURL(baseURL string, userID primitive.ObjectID, emailType EmailType) string {
	return fmt.Sprintf("%s/unsubscribe?user_id=%s&type=%s", baseURL, userID.Hex(), emailType)
}

// GenerateEmailVerificationToken generates email verification token
func GenerateEmailVerificationToken() string {
	return GenerateRandomString(32)
}
