package handlers

import (
	"net/http"
	"strconv"

	"bro-network/internal/middleware"
	"bro-network/internal/models"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService    services.AuthServiceInterface
	authMiddleware *middleware.AuthMiddleware
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService services.AuthServiceInterface, authMiddleware *middleware.AuthMiddleware) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		authMiddleware: authMiddleware,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &models.UserRegisterRequest{
		Username:        validatedData["username"].(string),
		Email:           validatedData["email"].(string),
		Password:        validatedData["password"].(string),
		ConfirmPassword: validatedData["confirm_password"].(string),
		FirstName:       validatedData["first_name"].(string),
		LastName:        validatedData["last_name"].(string),
		DateOfBirth:     validatedData["date_of_birth"].(string),
		AcceptTerms:     validatedData["accept_terms"].(bool),
	}

	// Call service
	response, err := h.authService.Register(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "REGISTRATION_FAILED", err.Error())
		return
	}

	// Set authentication cookie if configured
	h.setAuthCookie(c, response.AccessToken)

	utils.SendSuccess(c, response, "User registered successfully")
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &models.UserLoginRequest{
		Identifier: validatedData["identifier"].(string),
		Password:   validatedData["password"].(string),
	}

	// Handle optional remember_me field
	if rememberMe, exists := validatedData["remember_me"]; exists {
		req.RememberMe = rememberMe.(bool)
	}

	// Call service
	response, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusUnauthorized, "LOGIN_FAILED", err.Error())
		return
	}

	// Set authentication cookie if configured
	h.setAuthCookie(c, response.AccessToken)

	// Set session context for audit logging
	c.Set("user_id", response.User.ID)
	c.Set("ip_address", c.ClientIP())
	c.Set("user_agent", c.GetHeader("User-Agent"))

	utils.SendSuccess(c, response, "Login successful")
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get session ID from context
	sessionID := h.authMiddleware.GetSessionID(c)

	// Call service
	if err := h.authService.Logout(c.Request.Context(), userID, sessionID); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "LOGOUT_FAILED", err.Error())
		return
	}

	// Clear authentication cookie
	h.clearAuthCookie(c)

	utils.SendSuccess(c, "Logout successful")
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Get refresh token from body or cookie
	var refreshToken string

	// Try to get from request body first
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&requestBody); err == nil && requestBody.RefreshToken != "" {
		refreshToken = requestBody.RefreshToken
	} else {
		// Try to get from cookie
		refreshToken, _ = c.Cookie("refresh_token")
	}

	if refreshToken == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_REFRESH_TOKEN", "Refresh token is required")
		return
	}

	// Call service
	response, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		utils.SendError(c, http.StatusUnauthorized, "TOKEN_REFRESH_FAILED", err.Error())
		return
	}

	// Set new authentication cookie
	h.setAuthCookie(c, response.AccessToken)

	utils.SendSuccess(c, response, "Token refreshed successfully")
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	token := validatedData["token"].(string)
	email := validatedData["email"].(string)

	// Call service
	if err := h.authService.VerifyEmail(c.Request.Context(), token, email); err != nil {
		utils.SendError(c, http.StatusBadRequest, "EMAIL_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Email verified successfully")
}

// ResendVerification handles verification email resend
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	email := validatedData["email"].(string)

	// Call service
	if err := h.authService.ResendVerification(c.Request.Context(), email); err != nil {
		utils.SendError(c, http.StatusBadRequest, "RESEND_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Verification email sent successfully")
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	email := validatedData["email"].(string)

	// Call service
	if err := h.authService.ForgotPassword(c.Request.Context(), email); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "PASSWORD_RESET_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Password reset email sent successfully")
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	token := validatedData["token"].(string)
	password := validatedData["password"].(string)

	// Call service
	if err := h.authService.ResetPassword(c.Request.Context(), token, password); err != nil {
		utils.SendError(c, http.StatusBadRequest, "PASSWORD_RESET_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Password reset successfully")
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	currentPassword := validatedData["current_password"].(string)
	newPassword := validatedData["new_password"].(string)

	// Call service
	if err := h.authService.ChangePassword(c.Request.Context(), userID, currentPassword, newPassword); err != nil {
		utils.SendError(c, http.StatusBadRequest, "PASSWORD_CHANGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Password changed successfully")
}

// EnableTwoFactor handles 2FA enablement
func (h *AuthHandler) EnableTwoFactor(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	response, err := h.authService.EnableTwoFactor(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "2FA_ENABLE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Two-factor authentication enabled")
}

// DisableTwoFactor handles 2FA disablement
func (h *AuthHandler) DisableTwoFactor(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	code := validatedData["code"].(string)

	// Call service
	if err := h.authService.DisableTwoFactor(c.Request.Context(), userID, code); err != nil {
		utils.SendError(c, http.StatusBadRequest, "2FA_DISABLE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Two-factor authentication disabled")
}

// VerifyTwoFactor handles 2FA verification
func (h *AuthHandler) VerifyTwoFactor(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	code := validatedData["code"].(string)
	backupCode := ""

	if bc, exists := validatedData["backup_code"]; exists {
		backupCode = bc.(string)
	}

	// Call service
	if err := h.authService.VerifyTwoFactor(c.Request.Context(), userID, code, backupCode); err != nil {
		utils.SendError(c, http.StatusBadRequest, "2FA_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Two-factor authentication verified")
}

// GenerateBackupCodes handles backup code generation
func (h *AuthHandler) GenerateBackupCodes(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	_, err := h.authService.GenerateBackupCodes(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "BACKUP_CODES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Backup codes generated")
}

// GoogleLogin handles Google OAuth login initiation
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	// Call service to get OAuth URL
	url, err := h.authService.GoogleLogin(c.Request.Context())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "OAUTH_FAILED", err.Error())
		return
	}

	// Redirect to OAuth provider
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallback handles Google OAuth callback
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_CODE", "Authorization code is required")
		return
	}

	// Call service
	response, err := h.authService.GoogleCallback(c.Request.Context(), code)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "OAUTH_CALLBACK_FAILED", err.Error())
		return
	}

	// Set authentication cookie
	h.setAuthCookie(c, response.AccessToken)

	utils.SendSuccess(c, response, "Google login successful")
}

// FacebookLogin handles Facebook OAuth login initiation
func (h *AuthHandler) FacebookLogin(c *gin.Context) {
	url, err := h.authService.FacebookLogin(c.Request.Context())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "OAUTH_FAILED", err.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, url)
}

// FacebookCallback handles Facebook OAuth callback
func (h *AuthHandler) FacebookCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_CODE", "Authorization code is required")
		return
	}

	response, err := h.authService.FacebookCallback(c.Request.Context(), code)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "OAUTH_CALLBACK_FAILED", err.Error())
		return
	}

	h.setAuthCookie(c, response.AccessToken)
	utils.SendSuccess(c, response, "Facebook login successful")
}

// TwitterLogin handles Twitter OAuth login initiation
func (h *AuthHandler) TwitterLogin(c *gin.Context) {
	url, err := h.authService.TwitterLogin(c.Request.Context())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "OAUTH_FAILED", err.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, url)
}

// TwitterCallback handles Twitter OAuth callback
func (h *AuthHandler) TwitterCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_CODE", "Authorization code is required")
		return
	}

	response, err := h.authService.TwitterCallback(c.Request.Context(), code)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "OAUTH_CALLBACK_FAILED", err.Error())
		return
	}

	h.setAuthCookie(c, response.AccessToken)
	utils.SendSuccess(c, response, "Twitter login successful")
}

// GetActiveSessions handles getting user's active sessions
func (h *AuthHandler) GetActiveSessions(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	sessions, err := h.authService.GetActiveSessions(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SESSIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, gin.H{"sessions": sessions}, "Active sessions retrieved successfully")
}

// RevokeSession handles session revocation
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	sessionID := c.Param("session_id")
	if sessionID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_SESSION_ID", "Session ID is required")
		return
	}

	// Call service
	if err := h.authService.RevokeSession(c.Request.Context(), userID, sessionID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REVOKE_SESSION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Session revoked successfully")
}

// RevokeAllSessions handles revoking all user sessions
func (h *AuthHandler) RevokeAllSessions(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	if err := h.authService.RevokeAllSessions(c.Request.Context(), userID); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REVOKE_SESSIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "All sessions revoked successfully")
}

// CheckPassword handles password verification
func (h *AuthHandler) CheckPassword(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	password := validatedData["password"].(string)

	// Call service
	if err := h.authService.CheckPassword(c.Request.Context(), userID, password); err != nil {
		utils.SendError(c, http.StatusBadRequest, "PASSWORD_CHECK_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Password verified")
}

// GetSecurityLog handles getting user's security log
func (h *AuthHandler) GetSecurityLog(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get pagination parameters
	page := 1
	limit := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	// Call service
	events, err := h.authService.GetSecurityLog(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SECURITY_LOG_FAILED", err.Error())
		return
	}

	// Apply pagination (this should ideally be done in the service/repository layer)
	start := (page - 1) * limit
	end := start + limit

	if start >= len(events) {
		events = []*services.SecurityEvent{}
	} else if end > len(events) {
		events = events[start:]
	} else {
		events = events[start:end]
	}

	utils.SendSuccess(c, gin.H{
		"events": events,
		"page":   page,
		"limit":  limit,
	}, "Security log retrieved successfully")
}

// DeactivateAccount handles account deactivation
func (h *AuthHandler) DeactivateAccount(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	password := validatedData["password"].(string)

	// Call service
	if err := h.authService.DeactivateAccount(c.Request.Context(), userID, password); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DEACTIVATE_FAILED", err.Error())
		return
	}

	// Clear authentication cookie
	h.clearAuthCookie(c)

	utils.SendSuccess(c, "Account deactivated successfully")
}

// ReactivateAccount handles account reactivation
func (h *AuthHandler) ReactivateAccount(c *gin.Context) {
	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	token := validatedData["token"].(string)

	// Call service
	if err := h.authService.ReactivateAccount(c.Request.Context(), token); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REACTIVATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Account reactivated successfully")
}

// DeleteAccount handles account deletion
func (h *AuthHandler) DeleteAccount(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	password := validatedData["password"].(string)
	confirmation := validatedData["confirmation"].(string)

	// Call service
	if err := h.authService.DeleteAccount(c.Request.Context(), userID, password, confirmation); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DELETE_ACCOUNT_FAILED", err.Error())
		return
	}

	// Clear authentication cookie
	h.clearAuthCookie(c)

	utils.SendSuccess(c, "Account deleted successfully")
}

// GetAPIKeys handles getting user's API keys
func (h *AuthHandler) GetAPIKeys(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	apiKeys, err := h.authService.GetAPIKeys(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "API_KEYS_FAILED", err.Error())
		return
	}

	// Remove sensitive data before sending response
	for _, key := range apiKeys {
		key.Key = "" // Don't expose the actual key in list response
	}

	utils.SendSuccess(c, gin.H{"api_keys": apiKeys}, "API keys retrieved successfully")
}

// CreateAPIKey handles API key creation
func (h *AuthHandler) CreateAPIKey(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateAPIKeyRequest{
		Name:   validatedData["name"].(string),
		Scopes: validatedData["scopes"].([]string),
	}

	// Handle optional expires_at
	if expiresAt, exists := validatedData["expires_at"]; exists && expiresAt != nil {
		// Parse date if provided
		// req.ExpiresAt = parsed date
	}

	// Call service
	apiKey, err := h.authService.CreateAPIKey(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "CREATE_API_KEY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, apiKey, "API key created successfully")
}

// UpdateAPIKey handles API key updates
func (h *AuthHandler) UpdateAPIKey(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	keyID := c.Param("key_id")
	if keyID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_KEY_ID", "API key ID is required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateAPIKeyRequest{
		Name:   validatedData["name"].(string),
		Scopes: validatedData["scopes"].([]string),
	}

	// Call service
	if err := h.authService.UpdateAPIKey(c.Request.Context(), userID, keyID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_API_KEY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "API key updated successfully")
}

// RevokeAPIKey handles API key revocation
func (h *AuthHandler) RevokeAPIKey(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	keyID := c.Param("key_id")
	if keyID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_KEY_ID", "API key ID is required")
		return
	}

	// Call service
	if err := h.authService.RevokeAPIKey(c.Request.Context(), userID, keyID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REVOKE_API_KEY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "API key revoked successfully")
}

// VerifyIdentity handles identity verification
func (h *AuthHandler) VerifyIdentity(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.IdentityVerificationRequest{
		DocumentType:   validatedData["document_type"].(string),
		DocumentNumber: validatedData["document_number"].(string),
		DocumentFront:  validatedData["document_front"].(string),
		Selfie:         validatedData["selfie"].(string),
	}

	// Handle optional document_back
	if docBack, exists := validatedData["document_back"]; exists {
		req.DocumentBack = docBack.(string)
	}

	// Call service
	if err := h.authService.VerifyIdentity(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "IDENTITY_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Identity verification submitted successfully")
}

// GetVerificationStatus handles getting verification status
func (h *AuthHandler) GetVerificationStatus(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	status, err := h.authService.GetVerificationStatus(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "VERIFICATION_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, status, "Verification status retrieved successfully")
}

// RequestDataExport handles data export request
func (h *AuthHandler) RequestDataExport(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	exportRequest, err := h.authService.RequestDataExport(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DATA_EXPORT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, exportRequest, "Data export requested successfully")
}

// GetDataExport handles getting data export
func (h *AuthHandler) GetDataExport(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	exportID := c.Param("export_id")
	if exportID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_EXPORT_ID", "Export ID is required")
		return
	}

	// Call service
	dataExport, err := h.authService.GetDataExport(c.Request.Context(), userID, exportID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "GET_DATA_EXPORT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, dataExport, "Data export retrieved successfully")
}

// RequestDataPortability handles data portability request
func (h *AuthHandler) RequestDataPortability(c *gin.Context) {
	// Get current user from middleware
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.DataPortabilityRequest{
		Platform:    validatedData["platform"].(string),
		DataTypes:   validatedData["data_types"].([]string),
		Destination: validatedData["destination"].(string),
	}

	// Call service
	if err := h.authService.RequestDataPortability(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DATA_PORTABILITY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Data portability requested successfully")
}

// Helper methods

// setAuthCookie sets authentication cookie
func (h *AuthHandler) setAuthCookie(c *gin.Context, token string) {
	c.SetCookie(
		"access_token", // name
		token,          // value
		3600*24,        // max age (24 hours)
		"/",            // path
		"",             // domain
		false,          // secure (set to true in production with HTTPS)
		true,           // httpOnly
	)
}

// clearAuthCookie clears authentication cookie
func (h *AuthHandler) clearAuthCookie(c *gin.Context) {
	c.SetCookie(
		"access_token", // name
		"",             // value
		-1,             // max age (delete)
		"/",            // path
		"",             // domain
		false,          // secure
		true,           // httpOnly
	)
}
