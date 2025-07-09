package middleware

import (
	"errors"
	"strings"
	"time"

	"bro-network/internal/models"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthConfig represents authentication middleware configuration
type AuthConfig struct {
	JWTService     *utils.JWTService
	UserService    UserServiceInterface
	TokenBlacklist TokenBlacklistInterface
	SkipPaths      []string
	CookieName     string
	HeaderName     string
}

// UserServiceInterface defines user service methods needed by auth middleware
type UserServiceInterface interface {
	GetUserByID(userID primitive.ObjectID) (*models.User, error)
	IsUserActive(userID primitive.ObjectID) (bool, error)
	UpdateLastSeen(userID primitive.ObjectID) error
	ValidateAPIKey(apiKey string) (*models.User, error)
}

// TokenBlacklistInterface defines token blacklist methods
type TokenBlacklistInterface interface {
	IsBlacklisted(tokenID string) bool
	AddToBlacklist(tokenID string, expiresAt time.Time) error
}

// AuthMiddleware represents authentication middleware
type AuthMiddleware struct {
	config *AuthConfig
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthConfig) *AuthMiddleware {
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}
	if config.CookieName == "" {
		config.CookieName = "access_token"
	}

	return &AuthMiddleware{
		config: config,
	}
}

// Auth validates JWT tokens and sets user context
func (am *AuthMiddleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for certain paths
		if am.shouldSkipAuth(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Extract token from request
		token, err := am.extractToken(c)
		if err != nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		// Validate token
		claims, err := am.config.JWTService.ValidateToken(token)
		if err != nil {
			utils.SendUnauthorized(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Check if token is blacklisted
		if am.config.TokenBlacklist != nil && am.config.TokenBlacklist.IsBlacklisted(claims.ID) {
			utils.SendUnauthorized(c, "Token has been revoked")
			c.Abort()
			return
		}

		// Get user details
		user, err := am.config.UserService.GetUserByID(claims.UserID)
		if err != nil {
			utils.SendUnauthorized(c, "User not found")
			c.Abort()
			return
		}

		// Check if user is active
		if !user.IsActive || user.IsBanned {
			utils.SendUnauthorized(c, "Account is not active")
			c.Abort()
			return
		}

		// Set user context
		am.setUserContext(c, user, claims)

		// Update last seen (async)
		go am.updateLastSeen(user.ID)

		c.Next()
	}
}

// OptionalAuth validates JWT tokens but doesn't require authentication
func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := am.extractToken(c)
		if err != nil {
			// No token provided, continue without authentication
			c.Next()
			return
		}

		claims, err := am.config.JWTService.ValidateToken(token)
		if err != nil {
			// Invalid token, continue without authentication
			c.Next()
			return
		}

		// Check if token is blacklisted
		if am.config.TokenBlacklist != nil && am.config.TokenBlacklist.IsBlacklisted(claims.ID) {
			c.Next()
			return
		}

		// Get user details
		user, err := am.config.UserService.GetUserByID(claims.UserID)
		if err != nil {
			c.Next()
			return
		}

		// Check if user is active
		if !user.IsActive || user.IsBanned {
			c.Next()
			return
		}

		// Set user context
		am.setUserContext(c, user, claims)

		c.Next()
	}
}

// RequireRole middleware that requires specific user role
func (am *AuthMiddleware) RequireRole(roles ...models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		// Check if user has required role
		hasRole := false
		for _, role := range roles {
			if user.Role == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			utils.SendForbidden(c, "Insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// Admin middleware that requires admin role
func (am *AuthMiddleware) Admin() gin.HandlerFunc {
	return am.RequireRole(models.RoleAdmin, models.RoleSuperAdmin)
}

// Moderator middleware that requires moderator role or higher
func (am *AuthMiddleware) Moderator() gin.HandlerFunc {
	return am.RequireRole(models.RoleModerator, models.RoleAdmin, models.RoleSuperAdmin)
}

// RequireVerification middleware that requires verified account
func (am *AuthMiddleware) RequireVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		if !user.IsVerified {
			utils.SendForbidden(c, "Account verification required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireEmailVerification middleware that requires verified email
func (am *AuthMiddleware) RequireEmailVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		if !user.EmailVerified {
			utils.SendForbidden(c, "Email verification required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission middleware that requires specific permission
func (am *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		// Check if user has permission
		if !am.hasPermission(user, permission) {
			utils.SendForbidden(c, "Insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyAuth middleware for API key authentication
func (am *AuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			utils.SendUnauthorized(c, "API key required")
			c.Abort()
			return
		}

		// Validate API key
		user, err := am.config.UserService.ValidateAPIKey(apiKey)
		if err != nil {
			utils.SendUnauthorized(c, "Invalid API key")
			c.Abort()
			return
		}

		// Set user context
		c.Set("user", user)
		c.Set("user_id", user.ID)
		c.Set("auth_type", "api_key")

		c.Next()
	}
}

// RateLimitByUser applies rate limiting per user
func (am *AuthMiddleware) RateLimitByUser(requests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			c.Next()
			return
		}

		// Apply user-specific rate limiting
		key := "rate_limit:user:" + user.ID.Hex()

		// Check rate limit
		if am.isRateLimited(key, requests, window) {
			utils.SendError(c, 429, "RATE_LIMIT_EXCEEDED", "User rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// SessionTimeout middleware that checks session timeout
func (am *AuthMiddleware) SessionTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.GetCurrentUser(c)
		if user == nil {
			c.Next()
			return
		}

		lastActivity, exists := c.Get("last_activity")
		if !exists {
			c.Next()
			return
		}

		lastActivityTime, ok := lastActivity.(time.Time)
		if !ok {
			c.Next()
			return
		}

		if time.Since(lastActivityTime) > timeout {
			utils.SendUnauthorized(c, "Session expired due to inactivity")
			c.Abort()
			return
		}

		// Update last activity
		c.Set("last_activity", time.Now())
		c.Next()
	}
}

// Private helper methods

// extractToken extracts token from Authorization header or cookie
func (am *AuthMiddleware) extractToken(c *gin.Context) (string, error) {
	// Try Authorization header first
	authHeader := c.GetHeader(am.config.HeaderName)
	if authHeader != "" {
		return am.config.JWTService.ExtractTokenFromHeader(authHeader)
	}

	// Try cookie
	cookie, err := c.Cookie(am.config.CookieName)
	if err == nil && cookie != "" {
		return cookie, nil
	}

	// Try query parameter as fallback
	token := c.Query("token")
	if token != "" {
		return token, nil
	}

	return "", errors.New("no authentication token found")
}

// setUserContext sets user information in context
func (am *AuthMiddleware) setUserContext(c *gin.Context, user *models.User, claims *utils.Claims) {
	c.Set("user", user)
	c.Set("user_id", user.ID)
	c.Set("user_role", user.Role)
	c.Set("claims", claims)
	c.Set("authenticated", true)
	c.Set("session_id", claims.SessionID)
	c.Set("device_id", claims.DeviceID)
	c.Set("ip_address", claims.IPAddress)
	c.Set("auth_type", "jwt")
	c.Set("token_id", claims.ID)
}

// updateLastSeen updates user's last seen timestamp
func (am *AuthMiddleware) updateLastSeen(userID primitive.ObjectID) {
	if am.config.UserService != nil {
		_ = am.config.UserService.UpdateLastSeen(userID)
	}
}

// shouldSkipAuth checks if authentication should be skipped for the path
func (am *AuthMiddleware) shouldSkipAuth(path string) bool {
	for _, skipPath := range am.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
		// Support wildcard matching
		if strings.Contains(skipPath, "*") {
			pattern := strings.ReplaceAll(skipPath, "*", "")
			if strings.Contains(path, pattern) {
				return true
			}
		}
	}
	return false
}

// hasPermission checks if user has specific permission
func (am *AuthMiddleware) hasPermission(user *models.User, permission string) bool {
	// Implementation depends on your permission system
	// This is a basic role-based check
	switch permission {
	case "admin":
		return user.Role == models.RoleAdmin || user.Role == models.RoleSuperAdmin
	case "moderator":
		return user.Role == models.RoleModerator || user.Role == models.RoleAdmin || user.Role == models.RoleSuperAdmin
	case "verified":
		return user.IsVerified
	case "email_verified":
		return user.EmailVerified
	default:
		// For custom permissions, check user's permissions array
		if user.Permissions != nil {
			for _, perm := range user.Permissions {
				if perm == permission {
					return true
				}
			}
		}
	}
	return false
}

// isRateLimited checks if user is rate limited (placeholder implementation)
func (am *AuthMiddleware) isRateLimited(key string, requests int, window time.Duration) bool {
	// Implement with Redis or in-memory cache
	// This is a placeholder implementation
	return false
}

// Context helper functions

// GetCurrentUser retrieves current user from context
func (am *AuthMiddleware) GetCurrentUser(c *gin.Context) *models.User {
	user, exists := c.Get("user")
	if !exists {
		return nil
	}

	if u, ok := user.(*models.User); ok {
		return u
	}

	return nil
}

// GetCurrentUserID retrieves current user ID from context
func (am *AuthMiddleware) GetCurrentUserID(c *gin.Context) primitive.ObjectID {
	userID, exists := c.Get("user_id")
	if !exists {
		return primitive.NilObjectID
	}

	if id, ok := userID.(primitive.ObjectID); ok {
		return id
	}

	return primitive.NilObjectID
}

// GetUserRole retrieves current user role from context
func (am *AuthMiddleware) GetUserRole(c *gin.Context) models.UserRole {
	role, exists := c.Get("user_role")
	if !exists {
		return models.RoleUser
	}

	if r, ok := role.(models.UserRole); ok {
		return r
	}

	return models.RoleUser
}

// IsAuthenticated checks if user is authenticated
func (am *AuthMiddleware) IsAuthenticated(c *gin.Context) bool {
	authenticated, exists := c.Get("authenticated")
	if !exists {
		return false
	}

	if auth, ok := authenticated.(bool); ok {
		return auth
	}

	return false
}

// GetClaims retrieves JWT claims from context
func (am *AuthMiddleware) GetClaims(c *gin.Context) *utils.Claims {
	claims, exists := c.Get("claims")
	if !exists {
		return nil
	}

	if c, ok := claims.(*utils.Claims); ok {
		return c
	}

	return nil
}

// GetSessionID retrieves session ID from context
func (am *AuthMiddleware) GetSessionID(c *gin.Context) string {
	sessionID, exists := c.Get("session_id")
	if !exists {
		return ""
	}

	if id, ok := sessionID.(string); ok {
		return id
	}

	return ""
}

// GetDeviceID retrieves device ID from context
func (am *AuthMiddleware) GetDeviceID(c *gin.Context) string {
	deviceID, exists := c.Get("device_id")
	if !exists {
		return ""
	}

	if id, ok := deviceID.(string); ok {
		return id
	}

	return ""
}

// IsAdmin checks if current user is admin
func (am *AuthMiddleware) IsAdmin(c *gin.Context) bool {
	role := am.GetUserRole(c)
	return role == models.RoleAdmin || role == models.RoleSuperAdmin
}

// IsModerator checks if current user is moderator or higher
func (am *AuthMiddleware) IsModerator(c *gin.Context) bool {
	role := am.GetUserRole(c)
	return role == models.RoleModerator || role == models.RoleAdmin || role == models.RoleSuperAdmin
}
