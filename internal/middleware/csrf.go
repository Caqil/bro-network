package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
)

// CSRFConfig represents CSRF protection configuration
type CSRFConfig struct {
	TokenLookup    string        // Where to find token: "header:X-CSRF-Token", "form:csrf_token", "query:csrf_token"
	CookieName     string        // CSRF cookie name
	CookiePath     string        // Cookie path
	CookieDomain   string        // Cookie domain
	CookieSecure   bool          // Cookie secure flag
	CookieHTTPOnly bool          // Cookie HTTP only flag
	CookieSameSite http.SameSite // Cookie SameSite attribute
	TokenLength    int           // Token length in bytes
	TokenLifetime  time.Duration // Token lifetime
	ErrorHandler   gin.HandlerFunc
	Skipper        func(*gin.Context) bool
	TrustedOrigins []string // Trusted origins for CORS
	SkipPaths      []string // Paths to skip CSRF check
	SecretKey      string   // Secret key for token generation
	IgnoreMethods  []string // HTTP methods to ignore
}

// DefaultCSRFConfig returns default CSRF configuration
func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		TokenLookup:    "header:X-CSRF-Token",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieSecure:   false, // Set to true in production with HTTPS
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		TokenLength:    32,
		TokenLifetime:  24 * time.Hour,
		ErrorHandler:   defaultCSRFErrorHandler,
		Skipper:        defaultCSRFSkipper,
		TrustedOrigins: []string{},
		SkipPaths:      []string{"/api/health", "/api/auth/login", "/api/auth/register"},
		IgnoreMethods:  []string{http.MethodGet, http.MethodHead, http.MethodOptions},
	}
}

// ProductionCSRFConfig returns production-ready CSRF configuration
func ProductionCSRFConfig(secretKey string, trustedOrigins []string) *CSRFConfig {
	config := DefaultCSRFConfig()
	config.CookieSecure = true
	config.CookieSameSite = http.SameSiteStrictMode
	config.SecretKey = secretKey
	config.TrustedOrigins = trustedOrigins
	return config
}

// CSRFMiddleware represents CSRF protection middleware
type CSRFMiddleware struct {
	config     *CSRFConfig
	tokenStore map[string]*csrfToken
	mutex      sync.RWMutex
}

// csrfToken represents a CSRF token with metadata
type csrfToken struct {
	Value     string
	UserID    string
	SessionID string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

// NewCSRFMiddleware creates a new CSRF middleware instance
func NewCSRFMiddleware(config *CSRFConfig) *CSRFMiddleware {
	if config == nil {
		config = DefaultCSRFConfig()
	}

	return &CSRFMiddleware{
		config:     config,
		tokenStore: make(map[string]*csrfToken),
		mutex:      sync.RWMutex{},
	}
}

// CSRF returns the CSRF protection middleware
func (cm *CSRFMiddleware) CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if configured to skip
		if cm.config.Skipper != nil && cm.config.Skipper(c) {
			c.Next()
			return
		}

		// Skip certain paths
		if cm.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Skip safe methods
		if cm.isSafeMethod(c.Request.Method) {
			cm.setCSRFToken(c)
			c.Next()
			return
		}

		// Validate CSRF token for unsafe methods
		if !cm.validateCSRFToken(c) {
			if cm.config.ErrorHandler != nil {
				cm.config.ErrorHandler(c)
			} else {
				utils.SendForbidden(c, "CSRF token mismatch")
			}
			c.Abort()
			return
		}

		// Set new token for next request
		cm.setCSRFToken(c)
		c.Next()
	}
}

// CSRFToken returns the CSRF token for the current request
func (cm *CSRFMiddleware) CSRFToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := cm.getOrCreateToken(c)
		c.JSON(http.StatusOK, gin.H{
			"csrf_token": token,
		})
	}
}

// setCSRFToken generates and sets a new CSRF token
func (cm *CSRFMiddleware) setCSRFToken(c *gin.Context) {
	token := cm.getOrCreateToken(c)

	// Set cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cm.config.CookieName,
		Value:    token,
		Path:     cm.config.CookiePath,
		Domain:   cm.config.CookieDomain,
		Secure:   cm.config.CookieSecure,
		HttpOnly: cm.config.CookieHTTPOnly,
		SameSite: cm.config.CookieSameSite,
		MaxAge:   int(cm.config.TokenLifetime.Seconds()),
	})

	// Set in context for templates/responses
	c.Set("csrf_token", token)
	c.Header("X-CSRF-Token", token)
}

// getOrCreateToken gets existing token or creates a new one
func (cm *CSRFMiddleware) getOrCreateToken(c *gin.Context) string {
	// Try to get existing token from cookie
	if cookie, err := c.Cookie(cm.config.CookieName); err == nil && cookie != "" {
		if cm.isValidToken(cookie, c) {
			return cookie
		}
	}

	// Generate new token
	return cm.generateToken(c)
}

// generateToken generates a new CSRF token
func (cm *CSRFMiddleware) generateToken(c *gin.Context) string {
	// Generate random bytes
	bytes := make([]byte, cm.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based token
		return cm.generateFallbackToken()
	}

	token := base64.URLEncoding.EncodeToString(bytes)

	// Store token with metadata
	cm.storeToken(token, c)

	return token
}

// generateFallbackToken generates a fallback token when crypto/rand fails
func (cm *CSRFMiddleware) generateFallbackToken() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// storeToken stores token with metadata
func (cm *CSRFMiddleware) storeToken(token string, c *gin.Context) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Clean expired tokens
	cm.cleanExpiredTokens()

	// Get user and session info
	userID := ""
	sessionID := ""

	if uid, exists := c.Get("user_id"); exists {
		userID = fmt.Sprintf("%v", uid)
	}

	if sid, exists := c.Get("session_id"); exists {
		sessionID = fmt.Sprintf("%v", sid)
	}

	// Store token
	cm.tokenStore[token] = &csrfToken{
		Value:     token,
		UserID:    userID,
		SessionID: sessionID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.config.TokenLifetime),
		Used:      false,
	}
}

// validateCSRFToken validates the CSRF token from request
func (cm *CSRFMiddleware) validateCSRFToken(c *gin.Context) bool {
	// Extract token from request
	token := cm.extractTokenFromRequest(c)
	if token == "" {
		return false
	}

	// Validate token
	return cm.isValidToken(token, c)
}

// extractTokenFromRequest extracts CSRF token from request based on TokenLookup
func (cm *CSRFMiddleware) extractTokenFromRequest(c *gin.Context) string {
	parts := strings.Split(cm.config.TokenLookup, ":")
	if len(parts) != 2 {
		return ""
	}

	switch parts[0] {
	case "header":
		return c.GetHeader(parts[1])
	case "form":
		return c.PostForm(parts[1])
	case "query":
		return c.Query(parts[1])
	case "cookie":
		if cookie, err := c.Cookie(parts[1]); err == nil {
			return cookie
		}
	}

	return ""
}

// isValidToken checks if token is valid
func (cm *CSRFMiddleware) isValidToken(token string, c *gin.Context) bool {
	if token == "" {
		return false
	}

	cm.mutex.RLock()
	storedToken, exists := cm.tokenStore[token]
	cm.mutex.RUnlock()

	if !exists {
		return false
	}

	// Check expiration
	if time.Now().After(storedToken.ExpiresAt) {
		cm.removeToken(token)
		return false
	}

	// Check if token is used (optional, for single-use tokens)
	if storedToken.Used && cm.isSingleUse() {
		return false
	}

	// Validate user context (optional)
	if storedToken.UserID != "" {
		if uid, exists := c.Get("user_id"); exists {
			currentUserID := fmt.Sprintf("%v", uid)
			if storedToken.UserID != currentUserID {
				return false
			}
		}
	}

	// Validate session context (optional)
	if storedToken.SessionID != "" {
		if sid, exists := c.Get("session_id"); exists {
			currentSessionID := fmt.Sprintf("%v", sid)
			if storedToken.SessionID != currentSessionID {
				return false
			}
		}
	}

	// Mark as used if single-use
	if cm.isSingleUse() {
		cm.markTokenAsUsed(token)
	}

	return true
}

// shouldSkipPath checks if CSRF should be skipped for the path
func (cm *CSRFMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range cm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// isSafeMethod checks if HTTP method is safe (doesn't need CSRF protection)
func (cm *CSRFMiddleware) isSafeMethod(method string) bool {
	for _, ignoreMethod := range cm.config.IgnoreMethods {
		if method == ignoreMethod {
			return true
		}
	}
	return false
}

// isSingleUse returns whether tokens should be single-use
func (cm *CSRFMiddleware) isSingleUse() bool {
	// For most applications, CSRF tokens can be reused within their lifetime
	// Set to true for higher security (single-use tokens)
	return false
}

// markTokenAsUsed marks a token as used
func (cm *CSRFMiddleware) markTokenAsUsed(token string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if storedToken, exists := cm.tokenStore[token]; exists {
		storedToken.Used = true
	}
}

// removeToken removes a token from storage
func (cm *CSRFMiddleware) removeToken(token string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.tokenStore, token)
}

// cleanExpiredTokens removes expired tokens from storage
func (cm *CSRFMiddleware) cleanExpiredTokens() {
	now := time.Now()
	for token, storedToken := range cm.tokenStore {
		if now.After(storedToken.ExpiresAt) {
			delete(cm.tokenStore, token)
		}
	}
}

// ValidateOrigin validates request origin against trusted origins
func (cm *CSRFMiddleware) ValidateOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = c.GetHeader("Referer")
		}

		if origin != "" && !cm.isOriginTrusted(origin) {
			utils.SendForbidden(c, "Request origin not allowed")
			c.Abort()
			return
		}

		c.Next()
	}
}

// isOriginTrusted checks if origin is in trusted origins list
func (cm *CSRFMiddleware) isOriginTrusted(origin string) bool {
	if len(cm.config.TrustedOrigins) == 0 {
		return true // Allow all if no trusted origins configured
	}

	for _, trustedOrigin := range cm.config.TrustedOrigins {
		if origin == trustedOrigin {
			return true
		}
		// Support wildcard matching
		if strings.Contains(trustedOrigin, "*") {
			pattern := strings.ReplaceAll(trustedOrigin, "*", "")
			if strings.Contains(origin, pattern) {
				return true
			}
		}
	}

	return false
}

// SecureHeaders adds security headers
func (cm *CSRFMiddleware) SecureHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// CSRF protection headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// CSRF-specific headers
		c.Header("X-CSRF-Protection", "1")

		c.Next()
	}
}

// GetTokenInfo returns information about a CSRF token
func (cm *CSRFMiddleware) GetTokenInfo(token string) *csrfToken {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if storedToken, exists := cm.tokenStore[token]; exists {
		// Return copy to prevent external modification
		return &csrfToken{
			Value:     storedToken.Value,
			UserID:    storedToken.UserID,
			SessionID: storedToken.SessionID,
			CreatedAt: storedToken.CreatedAt,
			ExpiresAt: storedToken.ExpiresAt,
			Used:      storedToken.Used,
		}
	}

	return nil
}

// ClearUserTokens removes all tokens for a specific user
func (cm *CSRFMiddleware) ClearUserTokens(userID string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for token, storedToken := range cm.tokenStore {
		if storedToken.UserID == userID {
			delete(cm.tokenStore, token)
		}
	}
}

// ClearSessionTokens removes all tokens for a specific session
func (cm *CSRFMiddleware) ClearSessionTokens(sessionID string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for token, storedToken := range cm.tokenStore {
		if storedToken.SessionID == sessionID {
			delete(cm.tokenStore, token)
		}
	}
}

// TokenStats returns statistics about stored tokens
func (cm *CSRFMiddleware) TokenStats() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	total := len(cm.tokenStore)
	expired := 0
	used := 0
	now := time.Now()

	for _, token := range cm.tokenStore {
		if now.After(token.ExpiresAt) {
			expired++
		}
		if token.Used {
			used++
		}
	}

	return map[string]interface{}{
		"total":   total,
		"expired": expired,
		"used":    used,
		"active":  total - expired - used,
	}
}

// Default handlers

// defaultCSRFSkipper is the default skipper function
func defaultCSRFSkipper(c *gin.Context) bool {
	// Skip for health checks and public endpoints
	path := c.Request.URL.Path
	return strings.HasPrefix(path, "/health") ||
		strings.HasPrefix(path, "/metrics") ||
		strings.HasPrefix(path, "/api/public")
}

// defaultCSRFErrorHandler is the default error handler
func defaultCSRFErrorHandler(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":   "CSRF token mismatch",
		"code":    "CSRF_TOKEN_MISMATCH",
		"message": "Invalid or missing CSRF token",
	})
}

// Utility functions

// compareTokens securely compares two tokens using constant time comparison
func compareTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CSRFProtect is a convenience function to create CSRF middleware with default config
func CSRFProtect() gin.HandlerFunc {
	middleware := NewCSRFMiddleware(DefaultCSRFConfig())
	return middleware.CSRF()
}

// CSRFProtectWithConfig creates CSRF middleware with custom config
func CSRFProtectWithConfig(config *CSRFConfig) gin.HandlerFunc {
	middleware := NewCSRFMiddleware(config)
	return middleware.CSRF()
}
