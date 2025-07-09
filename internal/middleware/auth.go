package middleware

import (
	"strings"
	"time"

	"your-project/internal/models"
	"your-project/internal/utils"

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

		// Check if user has permission (this would be implemented based on your permission system)
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

		// Validate API key (this would integrate with your API key service)
		user, err := am.validateAPIKey(apiKey)
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

		// This would integrate with your rate limiting service
		if am.isRateLimited(key, requests, window) {
			utils.SendTooManyRequests(c, "Rate limit exceeded")
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
			utils.SendUnauthorized(c, "Session expired")
			c.Abort()
			return
		}

		// Update last activity
		c.Set("last_activity", time.Now())
		c.Next()
	}
}

// Helper methods

// extractToken extracts JWT token from request
func (am *AuthMiddleware) extractToken(c *gin.Context) (string, error) {
	// Try Authorization header first
	authHeader := c.GetHeader(am.config.HeaderName)
	if authHeader != "" {
		token, err := am.config.JWTService.ExtractTokenFromHeader(authHeader)
		if err == nil {
			return token, nil
		}
	}

	// Try cookie
	if am.config.CookieName != "" {
		cookie, err := c.Cookie(am.config.CookieName)
		if err == nil && cookie != "" {
			return cookie, nil
		}
	}

	// Try query parameter (for specific cases like websocket)
	queryToken := c.Query("token")
	if queryToken != "" {
		return queryToken, nil
	}

	return "", utils.ErrTokenNotFound
}

// setUserContext sets user information in context
func (am *AuthMiddleware) setUserContext(c *gin.Context, user *models.User, claims *utils.Claims) {
	c.Set("user", user)
	c.Set("user_id", user.ID)
	c.Set("user_role", user.Role)
	c.Set("claims", claims)
	c.Set("session_id", claims.SessionID)
	c.Set("device_id", claims.DeviceID)
	c.Set("authenticated", true)
	c.Set("auth_type", "jwt")
}

// shouldSkipAuth checks if authentication should be skipped for the path
func (am *AuthMiddleware) shouldSkipAuth(path string) bool {
	for _, skipPath := range am.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// updateLastSeen updates user's last seen timestamp
func (am *AuthMiddleware) updateLastSeen(userID primitive.ObjectID) {
	if am.config.UserService != nil {
		am.config.UserService.UpdateLastSeen(userID)
	}
}

// hasPermission checks if user has specific permission
func (am *AuthMiddleware) hasPermission(user *models.User, permission string) bool {
	// This would be implemented based on your permission system
	// For now, just check role-based permissions
	switch permission {
	case "admin":
		return user.Role == models.RoleAdmin || user.Role == models.RoleSuperAdmin
	case "moderator":
		return user.Role == models.RoleModerator || user.Role == models.RoleAdmin || user.Role == models.RoleSuperAdmin
	default:
		return true
	}
}

// validateAPIKey validates API key and returns associated user
func (am *AuthMiddleware) validateAPIKey(apiKey string) (*models.User, error) {
	// This would integrate with your API key service
	// For now, return an error
	return nil, utils.ErrInvalidAPIKey
}

// isRateLimited checks if request is rate limited
func (am *AuthMiddleware) isRateLimited(key string, requests int, window time.Duration) bool {
	// This would integrate with your rate limiting service (Redis, etc.)
	// For now, return false
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

// Error definitions
var (
	ErrTokenNotFound           = utils.NewError("TOKEN_NOT_FOUND", "Authentication token not found")
	ErrInvalidAPIKey           = utils.NewError("INVALID_API_KEY", "Invalid API key")
	ErrSessionExpired          = utils.NewError("SESSION_EXPIRED", "Session has expired")
	ErrInsufficientPermissions = utils.NewError("INSUFFICIENT_PERMISSIONS", "Insufficient permissions")
)
