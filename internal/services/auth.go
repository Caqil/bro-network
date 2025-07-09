package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"bro-network/internal/models"
	"bro-network/internal/utils"

	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication business logic
type AuthService struct {
	userRepo     repositories.UserRepositoryInterface
	sessionRepo  repositories.SessionRepositoryInterface
	apiKeyRepo   repositories.APIKeyRepositoryInterface
	jwtService   *utils.JWTService
	emailService EmailServiceInterface
	smsService   SMSServiceInterface
	auditService AuditServiceInterface
	cacheService CacheServiceInterface
	config       *AuthConfig
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTSecret              string
	JWTExpiryHours         int
	RefreshTokenExpiryDays int
	MaxLoginAttempts       int
	LockoutDuration        time.Duration
	PasswordMinLength      int
	RequireEmailVerify     bool
	Enable2FA              bool
	SessionTimeout         time.Duration
	MaxActiveSessions      int
	PasswordResetExpiry    time.Duration
	EmailVerifyExpiry      time.Duration
	BCryptCost             int
}

// AuthServiceInterface defines auth service methods
type AuthServiceInterface interface {
	// Authentication
	Register(ctx context.Context, req *models.UserRegisterRequest) (*models.UserAuthResponse, error)
	Login(ctx context.Context, req *models.UserLoginRequest) (*models.UserAuthResponse, error)
	Logout(ctx context.Context, userID primitive.ObjectID, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken string) (*models.UserAuthResponse, error)

	// Email verification
	VerifyEmail(ctx context.Context, token string, email string) error
	ResendVerification(ctx context.Context, email string) error

	// Password management
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token string, newPassword string) error
	ChangePassword(ctx context.Context, userID primitive.ObjectID, currentPassword, newPassword string) error

	// Two-Factor Authentication
	EnableTwoFactor(ctx context.Context, userID primitive.ObjectID) (*TwoFactorResponse, error)
	DisableTwoFactor(ctx context.Context, userID primitive.ObjectID, code string) error
	VerifyTwoFactor(ctx context.Context, userID primitive.ObjectID, code string, backupCode string) error
	GenerateBackupCodes(ctx context.Context, userID primitive.ObjectID) ([]string, error)

	// Session management
	GetActiveSessions(ctx context.Context, userID primitive.ObjectID) ([]*Session, error)
	RevokeSession(ctx context.Context, userID primitive.ObjectID, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID primitive.ObjectID) error

	// Security
	CheckPassword(ctx context.Context, userID primitive.ObjectID, password string) error
	GetSecurityLog(ctx context.Context, userID primitive.ObjectID) ([]*SecurityEvent, error)

	// Account management
	DeactivateAccount(ctx context.Context, userID primitive.ObjectID, password string) error
	ReactivateAccount(ctx context.Context, token string) error
	DeleteAccount(ctx context.Context, userID primitive.ObjectID, password, confirmation string) error

	// API Keys
	GetAPIKeys(ctx context.Context, userID primitive.ObjectID) ([]*APIKey, error)
	CreateAPIKey(ctx context.Context, userID primitive.ObjectID, req *CreateAPIKeyRequest) (*APIKey, error)
	UpdateAPIKey(ctx context.Context, userID primitive.ObjectID, keyID string, req *UpdateAPIKeyRequest) error
	RevokeAPIKey(ctx context.Context, userID primitive.ObjectID, keyID string) error
	ValidateAPIKey(ctx context.Context, apiKey string) (*models.User, error)

	// Identity verification
	VerifyIdentity(ctx context.Context, userID primitive.ObjectID, req *IdentityVerificationRequest) error
	GetVerificationStatus(ctx context.Context, userID primitive.ObjectID) (*VerificationStatus, error)

	// Data export
	RequestDataExport(ctx context.Context, userID primitive.ObjectID) (*DataExportRequest, error)
	GetDataExport(ctx context.Context, userID primitive.ObjectID, exportID string) (*DataExport, error)
	RequestDataPortability(ctx context.Context, userID primitive.ObjectID, req *DataPortabilityRequest) error

	// OAuth
	GoogleLogin(ctx context.Context) (string, error)
	GoogleCallback(ctx context.Context, code string) (*models.UserAuthResponse, error)
	FacebookLogin(ctx context.Context) (string, error)
	FacebookCallback(ctx context.Context, code string) (*models.UserAuthResponse, error)
	TwitterLogin(ctx context.Context) (string, error)
	TwitterCallback(ctx context.Context, code string) (*models.UserAuthResponse, error)

	// Helper methods
	GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error)
	IsUserActive(ctx context.Context, userID primitive.ObjectID) (bool, error)
	UpdateLastSeen(ctx context.Context, userID primitive.ObjectID) error
}

// Supporting structs
type TwoFactorResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

type Session struct {
	ID        string             `json:"id"`
	UserID    primitive.ObjectID `json:"user_id"`
	DeviceID  string             `json:"device_id"`
	IPAddress string             `json:"ip_address"`
	UserAgent string             `json:"user_agent"`
	Location  string             `json:"location"`
	IsActive  bool               `json:"is_active"`
	CreatedAt time.Time          `json:"created_at"`
	LastUsed  time.Time          `json:"last_used"`
	ExpiresAt time.Time          `json:"expires_at"`
}

type SecurityEvent struct {
	ID        primitive.ObjectID     `json:"id"`
	UserID    primitive.ObjectID     `json:"user_id"`
	EventType string                 `json:"event_type"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Location  string                 `json:"location"`
	Details   map[string]interface{} `json:"details"`
	CreatedAt time.Time              `json:"created_at"`
}

type APIKey struct {
	ID        string             `json:"id"`
	UserID    primitive.ObjectID `json:"user_id"`
	Name      string             `json:"name"`
	Key       string             `json:"key,omitempty"`
	Scopes    []string           `json:"scopes"`
	IsActive  bool               `json:"is_active"`
	LastUsed  *time.Time         `json:"last_used"`
	CreatedAt time.Time          `json:"created_at"`
	ExpiresAt *time.Time         `json:"expires_at"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type UpdateAPIKeyRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type IdentityVerificationRequest struct {
	DocumentType   string `json:"document_type"`
	DocumentNumber string `json:"document_number"`
	DocumentFront  string `json:"document_front"`
	DocumentBack   string `json:"document_back"`
	Selfie         string `json:"selfie"`
}

type VerificationStatus struct {
	IsVerified        bool       `json:"is_verified"`
	VerificationLevel string     `json:"verification_level"`
	DocumentsRequired []string   `json:"documents_required"`
	SubmittedAt       *time.Time `json:"submitted_at"`
	ReviewedAt        *time.Time `json:"reviewed_at"`
	Status            string     `json:"status"`
}

type DataExportRequest struct {
	ID          string             `json:"id"`
	UserID      primitive.ObjectID `json:"user_id"`
	Status      string             `json:"status"`
	Progress    int                `json:"progress"`
	DownloadURL string             `json:"download_url"`
	RequestedAt time.Time          `json:"requested_at"`
	CompletedAt *time.Time         `json:"completed_at"`
	ExpiresAt   time.Time          `json:"expires_at"`
}

type DataExport struct {
	ID        string                 `json:"id"`
	UserID    primitive.ObjectID     `json:"user_id"`
	Data      map[string]interface{} `json:"data"`
	FileURL   string                 `json:"file_url"`
	ExpiresAt time.Time              `json:"expires_at"`
}

type DataPortabilityRequest struct {
	Platform    string   `json:"platform"`
	DataTypes   []string `json:"data_types"`
	Destination string   `json:"destination"`
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo repositories.UserRepositoryInterface,
	sessionRepo repositories.SessionRepositoryInterface,
	apiKeyRepo repositories.APIKeyRepositoryInterface,
	jwtService *utils.JWTService,
	emailService EmailServiceInterface,
	smsService SMSServiceInterface,
	auditService AuditServiceInterface,
	cacheService CacheServiceInterface,
	config *AuthConfig,
) AuthServiceInterface {
	return &AuthService{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		apiKeyRepo:   apiKeyRepo,
		jwtService:   jwtService,
		emailService: emailService,
		smsService:   smsService,
		auditService: auditService,
		cacheService: cacheService,
		config:       config,
	}
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req *models.UserRegisterRequest) (*models.UserAuthResponse, error) {
	// Validate request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	if exists, err := s.userRepo.ExistsByEmail(ctx, req.Email); err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	} else if exists {
		return nil, errors.New("user with this email already exists")
	}

	if exists, err := s.userRepo.ExistsByUsername(ctx, req.Username); err != nil {
		return nil, fmt.Errorf("failed to check username existence: %w", err)
	} else if exists {
		return nil, errors.New("user with this username already exists")
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Parse date of birth
	dob, err := time.Parse("2006-01-02", req.DateOfBirth)
	if err != nil {
		return nil, fmt.Errorf("invalid date of birth format: %w", err)
	}

	// Create user
	user := &models.User{
		Username:      req.Username,
		Email:         req.Email,
		Password:      hashedPassword,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		DisplayName:   fmt.Sprintf("%s %s", req.FirstName, req.LastName),
		DateOfBirth:   &dob,
		IsVerified:    false,
		IsPrivate:     false,
		IsActive:      true,
		IsBanned:      false,
		Role:          models.RoleUser,
		EmailVerified: !s.config.RequireEmailVerify,
		Settings:      s.getDefaultUserSettings(),
		Stats:         models.UserStats{},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Generate email verification token if required
	if s.config.RequireEmailVerify {
		token, err := s.generateVerificationToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate verification token: %w", err)
		}
		user.EmailVerifyToken = token
	}

	// Save user
	userID, err := s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	user.ID = userID

	// Send verification email if required
	if s.config.RequireEmailVerify {
		if err := s.sendVerificationEmail(user.Email, user.EmailVerifyToken); err != nil {
			// Log error but don't fail registration
			fmt.Printf("Failed to send verification email: %v\n", err)
		}
	}

	// Generate tokens
	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create session
	session := &Session{
		UserID:    user.ID,
		IsActive:  true,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.SessionTimeout),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		// Log error but don't fail
		fmt.Printf("Failed to create session: %v\n", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, user.ID, "user_registered", "", "", nil)

	return &models.UserAuthResponse{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int64(s.config.JWTExpiryHours * 3600),
	}, nil
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, req *models.UserLoginRequest) (*models.UserAuthResponse, error) {
	// Find user by email or username
	user, err := s.findUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, errors.New("account is temporarily locked")
	}

	// Check if account is active
	if !user.IsActive || user.IsBanned {
		return nil, errors.New("account is not active")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		// Increment login attempts
		s.incrementLoginAttempts(ctx, user.ID)
		return nil, errors.New("invalid credentials")
	}

	// Reset login attempts on successful login
	s.resetLoginAttempts(ctx, user.ID)

	// Check email verification if required
	if s.config.RequireEmailVerify && !user.EmailVerified {
		return nil, errors.New("email verification required")
	}

	// Generate tokens
	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last seen
	s.UpdateLastSeen(ctx, user.ID)

	// Create session
	session := &Session{
		UserID:    user.ID,
		IsActive:  true,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.SessionTimeout),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		fmt.Printf("Failed to create session: %v\n", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, user.ID, "user_login", "", "", nil)

	return &models.UserAuthResponse{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int64(s.config.JWTExpiryHours * 3600),
	}, nil
}

// Logout invalidates user session
func (s *AuthService) Logout(ctx context.Context, userID primitive.ObjectID, sessionID string) error {
	// Revoke session
	if err := s.sessionRepo.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, userID, "user_logout", "", "", nil)

	return nil
}

// RefreshToken generates new access token using refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*models.UserAuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is active
	if !user.IsActive || user.IsBanned {
		return nil, errors.New("account is not active")
	}

	// Generate new tokens
	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last seen
	s.UpdateLastSeen(ctx, user.ID)

	return &models.UserAuthResponse{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int64(s.config.JWTExpiryHours * 3600),
	}, nil
}

// VerifyEmail verifies user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, token string, email string) error {
	// Find user by email and token
	user, err := s.userRepo.GetByEmailAndVerifyToken(ctx, email, token)
	if err != nil {
		return errors.New("invalid verification token")
	}

	// Update user
	update := bson.M{
		"$set": bson.M{
			"email_verified":     true,
			"email_verify_token": "",
			"updated_at":         time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, user.ID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, user.ID, "email_verified", "", "", nil)

	return nil
}

// ResendVerification sends new verification email
func (s *AuthService) ResendVerification(ctx context.Context, email string) error {
	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return errors.New("user not found")
	}

	// Check if already verified
	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Generate new token
	token, err := s.generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Update user with new token
	update := bson.M{
		"$set": bson.M{
			"email_verify_token": token,
			"updated_at":         time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, user.ID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Send verification email
	if err := s.sendVerificationEmail(email, token); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// ForgotPassword initiates password reset process
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	// Generate reset token
	token, err := s.generateResetToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Update user with reset token
	expiresAt := time.Now().Add(s.config.PasswordResetExpiry)
	update := bson.M{
		"$set": bson.M{
			"password_reset_token": token,
			"password_reset_exp":   expiresAt,
			"updated_at":           time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, user.ID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Send reset email
	if err := s.sendPasswordResetEmail(email, token); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, user.ID, "password_reset_requested", "", "", nil)

	return nil
}

// ResetPassword resets user password using reset token
func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	// Find user by reset token
	user, err := s.userRepo.GetByPasswordResetToken(ctx, token)
	if err != nil {
		return errors.New("invalid reset token")
	}

	// Check if token is expired
	if user.PasswordResetExp == nil || time.Now().After(*user.PasswordResetExp) {
		return errors.New("reset token has expired")
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user
	update := bson.M{
		"$set": bson.M{
			"password":             hashedPassword,
			"password_reset_token": "",
			"password_reset_exp":   nil,
			"updated_at":           time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, user.ID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Revoke all sessions for security
	s.RevokeAllSessions(ctx, user.ID)

	// Log security event
	s.logSecurityEvent(ctx, user.ID, "password_reset", "", "", nil)

	return nil
}

// ChangePassword changes user password
func (s *AuthService) ChangePassword(ctx context.Context, userID primitive.ObjectID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user
	update := bson.M{
		"$set": bson.M{
			"password":   hashedPassword,
			"updated_at": time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, userID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, userID, "password_changed", "", "", nil)

	return nil
}

// EnableTwoFactor enables 2FA for user
func (s *AuthService) EnableTwoFactor(ctx context.Context, userID primitive.ObjectID) (*TwoFactorResponse, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate secret
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "BroNetwork",
		AccountName: user.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Update user with secret (not enabled yet)
	update := bson.M{
		"$set": bson.M{
			"two_factor_secret": secret.Secret(),
			"updated_at":        time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, userID, update); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &TwoFactorResponse{
		Secret:      secret.Secret(),
		QRCode:      secret.URL(),
		BackupCodes: backupCodes,
	}, nil
}

// DisableTwoFactor disables 2FA for user
func (s *AuthService) DisableTwoFactor(ctx context.Context, userID primitive.ObjectID, code string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify code
	if !totp.Validate(code, user.TwoFactorSecret) {
		return errors.New("invalid 2FA code")
	}

	// Update user
	update := bson.M{
		"$set": bson.M{
			"two_factor_enabled": false,
			"two_factor_secret":  "",
			"updated_at":         time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, userID, update); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Log security event
	s.logSecurityEvent(ctx, userID, "2fa_disabled", "", "", nil)

	return nil
}

// VerifyTwoFactor verifies 2FA code
func (s *AuthService) VerifyTwoFactor(ctx context.Context, userID primitive.ObjectID, code string, backupCode string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Check if code is valid
	if code != "" && totp.Validate(code, user.TwoFactorSecret) {
		// Enable 2FA if not already enabled
		if !user.TwoFactorEnabled {
			update := bson.M{
				"$set": bson.M{
					"two_factor_enabled": true,
					"updated_at":         time.Now(),
				},
			}
			s.userRepo.UpdateByID(ctx, userID, update)
		}

		s.logSecurityEvent(ctx, userID, "2fa_verified", "", "", nil)
		return nil
	}

	// Check backup code if provided
	if backupCode != "" {
		// Implement backup code validation
		// This would typically involve checking against stored backup codes
		// and marking them as used
		s.logSecurityEvent(ctx, userID, "2fa_backup_used", "", "", nil)
		return nil
	}

	return errors.New("invalid 2FA code")
}

// GenerateBackupCodes generates new backup codes
func (s *AuthService) GenerateBackupCodes(ctx context.Context, userID primitive.ObjectID) ([]string, error) {
	codes, err := s.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes (implement based on your storage strategy)
	// You might want to hash them and store in a separate collection

	s.logSecurityEvent(ctx, userID, "backup_codes_generated", "", "", nil)

	return codes, nil
}

// GetActiveSessions retrieves user's active sessions
func (s *AuthService) GetActiveSessions(ctx context.Context, userID primitive.ObjectID) ([]*Session, error) {
	return s.sessionRepo.GetActiveByUserID(ctx, userID)
}

// RevokeSession revokes a specific session
func (s *AuthService) RevokeSession(ctx context.Context, userID primitive.ObjectID, sessionID string) error {
	// Verify session belongs to user
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return errors.New("session not found")
	}

	if session.UserID != userID {
		return errors.New("unauthorized")
	}

	// Revoke session
	if err := s.sessionRepo.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logSecurityEvent(ctx, userID, "session_revoked", "", "", map[string]interface{}{
		"session_id": sessionID,
	})

	return nil
}

// RevokeAllSessions revokes all user sessions
func (s *AuthService) RevokeAllSessions(ctx context.Context, userID primitive.ObjectID) error {
	if err := s.sessionRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke sessions: %w", err)
	}

	s.logSecurityEvent(ctx, userID, "all_sessions_revoked", "", "", nil)

	return nil
}

// CheckPassword verifies user password
func (s *AuthService) CheckPassword(ctx context.Context, userID primitive.ObjectID, password string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return errors.New("incorrect password")
	}

	return nil
}

// GetSecurityLog retrieves user's security events
func (s *AuthService) GetSecurityLog(ctx context.Context, userID primitive.ObjectID) ([]*SecurityEvent, error) {
	return s.auditService.GetSecurityEventsByUserID(ctx, userID)
}

// DeactivateAccount deactivates user account
func (s *AuthService) DeactivateAccount(ctx context.Context, userID primitive.ObjectID, password string) error {
	// Verify password
	if err := s.CheckPassword(ctx, userID, password); err != nil {
		return err
	}

	// Update user
	update := bson.M{
		"$set": bson.M{
			"is_active":  false,
			"updated_at": time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, userID, update); err != nil {
		return fmt.Errorf("failed to deactivate account: %w", err)
	}

	// Revoke all sessions
	s.RevokeAllSessions(ctx, userID)

	s.logSecurityEvent(ctx, userID, "account_deactivated", "", "", nil)

	return nil
}

// ReactivateAccount reactivates user account
func (s *AuthService) ReactivateAccount(ctx context.Context, token string) error {
	// Implement token-based reactivation
	// This would typically involve a token sent to user's email
	return errors.New("not implemented")
}

// DeleteAccount permanently deletes user account
func (s *AuthService) DeleteAccount(ctx context.Context, userID primitive.ObjectID, password, confirmation string) error {
	// Verify password
	if err := s.CheckPassword(ctx, userID, password); err != nil {
		return err
	}

	// Verify confirmation
	if confirmation != "DELETE" {
		return errors.New("invalid confirmation")
	}

	// Soft delete user
	update := bson.M{
		"$set": bson.M{
			"deleted_at": time.Now(),
			"is_active":  false,
			"updated_at": time.Now(),
		},
	}

	if err := s.userRepo.UpdateByID(ctx, userID, update); err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	// Revoke all sessions
	s.RevokeAllSessions(ctx, userID)

	s.logSecurityEvent(ctx, userID, "account_deleted", "", "", nil)

	return nil
}

// GetAPIKeys retrieves user's API keys
func (s *AuthService) GetAPIKeys(ctx context.Context, userID primitive.ObjectID) ([]*APIKey, error) {
	return s.apiKeyRepo.GetByUserID(ctx, userID)
}

// CreateAPIKey creates new API key
func (s *AuthService) CreateAPIKey(ctx context.Context, userID primitive.ObjectID, req *CreateAPIKeyRequest) (*APIKey, error) {
	// Generate API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	key := "bro_" + hex.EncodeToString(keyBytes)

	apiKey := &APIKey{
		UserID:    userID,
		Name:      req.Name,
		Key:       key,
		Scopes:    req.Scopes,
		IsActive:  true,
		CreatedAt: time.Now(),
		ExpiresAt: req.ExpiresAt,
	}

	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	s.logSecurityEvent(ctx, userID, "api_key_created", "", "", map[string]interface{}{
		"key_name": req.Name,
		"scopes":   req.Scopes,
	})

	return apiKey, nil
}

// UpdateAPIKey updates existing API key
func (s *AuthService) UpdateAPIKey(ctx context.Context, userID primitive.ObjectID, keyID string, req *UpdateAPIKeyRequest) error {
	// Verify key belongs to user
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return errors.New("API key not found")
	}

	if apiKey.UserID != userID {
		return errors.New("unauthorized")
	}

	// Update key
	update := map[string]interface{}{
		"name":   req.Name,
		"scopes": req.Scopes,
	}

	if err := s.apiKeyRepo.UpdateByID(ctx, keyID, update); err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}

	s.logSecurityEvent(ctx, userID, "api_key_updated", "", "", map[string]interface{}{
		"key_id": keyID,
	})

	return nil
}

// RevokeAPIKey revokes API key
func (s *AuthService) RevokeAPIKey(ctx context.Context, userID primitive.ObjectID, keyID string) error {
	// Verify key belongs to user
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return errors.New("API key not found")
	}

	if apiKey.UserID != userID {
		return errors.New("unauthorized")
	}

	// Revoke key
	if err := s.apiKeyRepo.RevokeByID(ctx, keyID); err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	s.logSecurityEvent(ctx, userID, "api_key_revoked", "", "", map[string]interface{}{
		"key_id": keyID,
	})

	return nil
}

// ValidateAPIKey validates API key and returns associated user
func (s *AuthService) ValidateAPIKey(ctx context.Context, apiKey string) (*models.User, error) {
	// Get API key details
	key, err := s.apiKeyRepo.GetByKey(ctx, apiKey)
	if err != nil {
		return nil, errors.New("invalid API key")
	}

	// Check if key is active and not expired
	if !key.IsActive {
		return nil, errors.New("API key is inactive")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, errors.New("API key has expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, key.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Update last used
	s.apiKeyRepo.UpdateLastUsed(ctx, key.ID)

	return user, nil
}

// VerifyIdentity handles identity verification
func (s *AuthService) VerifyIdentity(ctx context.Context, userID primitive.ObjectID, req *IdentityVerificationRequest) error {
	// This would typically involve:
	// 1. Storing document images
	// 2. Running them through verification service
	// 3. Updating user verification status
	// 4. Notifying user of result

	s.logSecurityEvent(ctx, userID, "identity_verification_submitted", "", "", map[string]interface{}{
		"document_type": req.DocumentType,
	})

	return nil
}

// GetVerificationStatus returns user's verification status
func (s *AuthService) GetVerificationStatus(ctx context.Context, userID primitive.ObjectID) (*VerificationStatus, error) {
	// Implement based on your verification system
	return &VerificationStatus{
		IsVerified:        false,
		VerificationLevel: "none",
		Status:            "pending",
	}, nil
}

// RequestDataExport initiates data export
func (s *AuthService) RequestDataExport(ctx context.Context, userID primitive.ObjectID) (*DataExportRequest, error) {
	// Generate export request
	exportReq := &DataExportRequest{
		ID:          primitive.NewObjectID().Hex(),
		UserID:      userID,
		Status:      "pending",
		Progress:    0,
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
	}

	// Start background export process
	// This would typically be handled by a background job

	s.logSecurityEvent(ctx, userID, "data_export_requested", "", "", nil)

	return exportReq, nil
}

// GetDataExport retrieves data export
func (s *AuthService) GetDataExport(ctx context.Context, userID primitive.ObjectID, exportID string) (*DataExport, error) {
	// Implement data export retrieval
	return nil, errors.New("not implemented")
}

// RequestDataPortability handles data portability request
func (s *AuthService) RequestDataPortability(ctx context.Context, userID primitive.ObjectID, req *DataPortabilityRequest) error {
	// Implement data portability
	s.logSecurityEvent(ctx, userID, "data_portability_requested", "", "", map[string]interface{}{
		"platform": req.Platform,
	})

	return nil
}

// OAuth methods (simplified implementations)
func (s *AuthService) GoogleLogin(ctx context.Context) (string, error) {
	// Return OAuth URL
	return "https://accounts.google.com/oauth/authorize?...", nil
}

func (s *AuthService) GoogleCallback(ctx context.Context, code string) (*models.UserAuthResponse, error) {
	// Handle OAuth callback
	return nil, errors.New("not implemented")
}

func (s *AuthService) FacebookLogin(ctx context.Context) (string, error) {
	return "https://www.facebook.com/v18.0/dialog/oauth?...", nil
}

func (s *AuthService) FacebookCallback(ctx context.Context, code string) (*models.UserAuthResponse, error) {
	return nil, errors.New("not implemented")
}

func (s *AuthService) TwitterLogin(ctx context.Context) (string, error) {
	return "https://api.twitter.com/oauth/authorize?...", nil
}

func (s *AuthService) TwitterCallback(ctx context.Context, code string) (*models.UserAuthResponse, error) {
	return nil, errors.New("not implemented")
}

// Helper methods

func (s *AuthService) GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

func (s *AuthService) IsUserActive(ctx context.Context, userID primitive.ObjectID) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.IsActive && !user.IsBanned, nil
}

func (s *AuthService) UpdateLastSeen(ctx context.Context, userID primitive.ObjectID) error {
	update := bson.M{
		"$set": bson.M{
			"last_seen": time.Now(),
		},
	}
	return s.userRepo.UpdateByID(ctx, userID, update)
}

// Private helper methods

func (s *AuthService) validateRegistrationRequest(req *models.UserRegisterRequest) error {
	if len(req.Password) < s.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", s.config.PasswordMinLength)
	}

	if req.Password != req.ConfirmPassword {
		return errors.New("passwords do not match")
	}

	if !req.AcceptTerms {
		return errors.New("terms of service must be accepted")
	}

	return nil
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), s.config.BCryptCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func (s *AuthService) generateVerificationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *AuthService) generateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *AuthService) generateBackupCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		bytes := make([]byte, 4)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		codes[i] = fmt.Sprintf("%08d", int(bytes[0])<<24|int(bytes[1])<<16|int(bytes[2])<<8|int(bytes[3]))
	}
	return codes, nil
}

func (s *AuthService) generateTokenPair(user *models.User) (*utils.TokenPair, error) {
	return s.jwtService.GenerateTokenPair(
		user.ID,
		user.Username,
		user.Email,
		string(user.Role),
		user.Permissions,
		"", // deviceID
		"", // ipAddress
	)
}

func (s *AuthService) findUserByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	// Try email first
	if strings.Contains(identifier, "@") {
		return s.userRepo.GetByEmail(ctx, identifier)
	}
	// Try username
	return s.userRepo.GetByUsername(ctx, identifier)
}

func (s *AuthService) incrementLoginAttempts(ctx context.Context, userID primitive.ObjectID) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return
	}

	attempts := user.LoginAttempts + 1
	update := bson.M{
		"$set": bson.M{
			"login_attempts": attempts,
		},
	}

	// Lock account if too many attempts
	if attempts >= s.config.MaxLoginAttempts {
		lockUntil := time.Now().Add(s.config.LockoutDuration)
		update["$set"].(bson.M)["locked_until"] = lockUntil
	}

	s.userRepo.UpdateByID(ctx, userID, update)
}

func (s *AuthService) resetLoginAttempts(ctx context.Context, userID primitive.ObjectID) {
	update := bson.M{
		"$set": bson.M{
			"login_attempts": 0,
			"locked_until":   nil,
		},
	}
	s.userRepo.UpdateByID(ctx, userID, update)
}

func (s *AuthService) getDefaultUserSettings() models.UserSettings {
	return models.UserSettings{
		Theme:               "light",
		Language:            "en",
		TimeZone:            "UTC",
		EmailNotifications:  true,
		PushNotifications:   true,
		SMSNotifications:    false,
		ShowOnlineStatus:    true,
		ShowReadReceipts:    true,
		AllowDirectMessages: true,
		ShowActivityStatus:  true,
		ContentDiscovery:    true,
		SensitiveContent:    false,
		PersonalizedAds:     true,
		DataSharing:         false,
	}
}

func (s *AuthService) sendVerificationEmail(email, token string) error {
	if s.emailService != nil {
		return s.emailService.SendVerificationEmail(email, token)
	}
	return nil
}

func (s *AuthService) sendPasswordResetEmail(email, token string) error {
	if s.emailService != nil {
		return s.emailService.SendPasswordResetEmail(email, token)
	}
	return nil
}

func (s *AuthService) logSecurityEvent(ctx context.Context, userID primitive.ObjectID, eventType, ipAddress, userAgent string, details map[string]interface{}) {
	if s.auditService != nil {
		event := &SecurityEvent{
			UserID:    userID,
			EventType: eventType,
			IPAddress: ipAddress,
			UserAgent: userAgent,
			Details:   details,
			CreatedAt: time.Now(),
		}
		s.auditService.LogSecurityEvent(ctx, event)
	}
}
