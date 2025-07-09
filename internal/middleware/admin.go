package middleware

import (
	"fmt"
	"strings"
	"time"

	"bro-network/internal/models"
	"bro-network/internal/utils"
	"bro-network/pkg/constants"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AdminConfig represents admin middleware configuration
type AdminConfig struct {
	AuditService     AuditServiceInterface
	UserService      UserServiceInterface
	SecurityService  SecurityServiceInterface
	MinRole          models.UserRole
	RequiredPerms    []string
	AllowedIPs       []string
	SessionTimeout   time.Duration
	LogActions       bool
	CheckIPWhitelist bool
}

// AuditServiceInterface defines audit service methods
type AuditServiceInterface interface {
	LogAdminAction(userID primitive.ObjectID, action, resource, details string, metadata map[string]interface{}) error
	LogSecurityEvent(userID primitive.ObjectID, event, details string, metadata map[string]interface{}) error
}

// SecurityServiceInterface defines security service methods
type SecurityServiceInterface interface {
	IsIPWhitelisted(ip string) bool
	CheckRateLimit(userID primitive.ObjectID, action string) error
	ValidateAdminSession(userID primitive.ObjectID) error
	RecordFailedAttempt(userID primitive.ObjectID, action string) error
}

// AdminMiddleware represents admin-specific middleware
type AdminMiddleware struct {
	config *AdminConfig
}

// NewAdminMiddleware creates a new admin middleware
func NewAdminMiddleware(config *AdminConfig) *AdminMiddleware {
	if config.MinRole == "" {
		config.MinRole = models.RoleAdmin
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 2 * time.Hour // Default 2 hour admin session
	}
	if config.LogActions == false {
		config.LogActions = true // Default to logging admin actions
	}

	return &AdminMiddleware{
		config: config,
	}
}

// RequireAdmin middleware that requires admin privileges
func (am *AdminMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get current user from auth middleware context
		user := GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		// Check if user has admin role
		if !am.hasAdminRole(user) {
			am.logUnauthorizedAttempt(c, user, "admin_access_denied")
			utils.SendForbidden(c, "Admin access required")
			c.Abort()
			return
		}

		// Check if user account is active and not banned
		if !user.IsActive || user.IsBanned {
			am.logSecurityEvent(c, user, "inactive_admin_attempt", "Inactive or banned user attempted admin access")
			utils.SendForbidden(c, "Account is not active")
			c.Abort()
			return
		}

		// Validate admin session if security service is available
		if am.config.SecurityService != nil {
			if err := am.config.SecurityService.ValidateAdminSession(user.ID); err != nil {
				am.logSecurityEvent(c, user, "invalid_admin_session", err.Error())
				utils.SendUnauthorized(c, "Admin session expired or invalid")
				c.Abort()
				return
			}
		}

		// Check IP whitelist if enabled
		if am.config.CheckIPWhitelist && !am.isIPAllowed(c) {
			am.logSecurityEvent(c, user, "ip_not_whitelisted", fmt.Sprintf("Access from non-whitelisted IP: %s", c.ClientIP()))
			utils.SendForbidden(c, "Access from this IP address is not allowed")
			c.Abort()
			return
		}

		// Check rate limiting
		if am.config.SecurityService != nil {
			if err := am.config.SecurityService.CheckRateLimit(user.ID, "admin_action"); err != nil {
				am.logSecurityEvent(c, user, "admin_rate_limit_exceeded", err.Error())
				utils.SendError(c, 429, "RATE_LIMIT_EXCEEDED", "Admin action rate limit exceeded")
				c.Abort()
				return
			}
		}

		// Set admin context
		am.setAdminContext(c, user)

		c.Next()

		// Log admin action after request completion
		if am.config.LogActions && am.config.AuditService != nil {
			go am.logAdminAction(c, user)
		}
	}
}

// RequireSuperAdmin middleware that requires super admin privileges
func (am *AdminMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		if user.Role != models.RoleSuperAdmin {
			am.logUnauthorizedAttempt(c, user, "super_admin_access_denied")
			utils.SendForbidden(c, "Super admin access required")
			c.Abort()
			return
		}

		am.setAdminContext(c, user)
		c.Next()

		if am.config.LogActions && am.config.AuditService != nil {
			go am.logAdminAction(c, user)
		}
	}
}

// RequirePermissions middleware that requires specific permissions
func (am *AdminMiddleware) RequirePermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		if !am.hasAdminRole(user) {
			am.logUnauthorizedAttempt(c, user, "permission_check_failed")
			utils.SendForbidden(c, "Admin access required")
			c.Abort()
			return
		}

		// Check specific permissions (this would require a permission system)
		if !am.hasPermissions(user, permissions) {
			am.logUnauthorizedAttempt(c, user, fmt.Sprintf("insufficient_permissions_%s", strings.Join(permissions, "_")))
			utils.SendForbidden(c, fmt.Sprintf("Required permissions: %s", strings.Join(permissions, ", ")))
			c.Abort()
			return
		}

		am.setAdminContext(c, user)
		c.Next()

		if am.config.LogActions && am.config.AuditService != nil {
			go am.logAdminAction(c, user)
		}
	}
}

// RequireRole middleware that requires specific admin role
func (am *AdminMiddleware) RequireRole(minRole models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		if !am.hasMinimumRole(user, minRole) {
			am.logUnauthorizedAttempt(c, user, fmt.Sprintf("insufficient_role_%s", minRole))
			utils.SendForbidden(c, fmt.Sprintf("Minimum role required: %s", minRole))
			c.Abort()
			return
		}

		am.setAdminContext(c, user)
		c.Next()

		if am.config.LogActions && am.config.AuditService != nil {
			go am.logAdminAction(c, user)
		}
	}
}

// AdminSecurityHeaders adds security headers for admin routes
func (am *AdminMiddleware) AdminSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers for admin panel
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}

// AuditLogging middleware for comprehensive admin action logging
func (am *AdminMiddleware) AuditLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Capture request details
		requestID := c.GetHeader(constants.HeaderXRequestID)
		if requestID == "" {
			requestID = primitive.NewObjectID().Hex()
			c.Header(constants.HeaderXRequestID, requestID)
		}

		c.Next()

		// Log after request completion
		if am.config.AuditService != nil {
			user := GetCurrentUser(c)
			if user != nil {
				go am.logDetailedAuditEvent(c, user, start, requestID)
			}
		}
	}
}

// Helper methods

func (am *AdminMiddleware) hasAdminRole(user *models.User) bool {
	return user.Role == models.RoleAdmin ||
		user.Role == models.RoleSuperAdmin ||
		user.Role == models.RoleModerator
}

func (am *AdminMiddleware) hasMinimumRole(user *models.User, minRole models.UserRole) bool {
	roleHierarchy := map[models.UserRole]int{
		models.RoleUser:       0,
		models.RoleModerator:  1,
		models.RoleAdmin:      2,
		models.RoleSuperAdmin: 3,
	}

	userLevel, exists := roleHierarchy[user.Role]
	if !exists {
		return false
	}

	minLevel, exists := roleHierarchy[minRole]
	if !exists {
		return false
	}

	return userLevel >= minLevel
}

func (am *AdminMiddleware) hasPermissions(user *models.User, permissions []string) bool {
	// Implement permission checking logic based on your permission system
	// For now, super admin has all permissions, admin has most permissions
	if user.Role == models.RoleSuperAdmin {
		return true
	}

	if user.Role == models.RoleAdmin {
		// Define restricted permissions for regular admins
		restrictedPerms := []string{"super_admin_only", "system_config", "delete_admin"}
		for _, perm := range permissions {
			for _, restricted := range restrictedPerms {
				if perm == restricted {
					return false
				}
			}
		}
		return true
	}

	return false
}

func (am *AdminMiddleware) isIPAllowed(c *gin.Context) bool {
	if len(am.config.AllowedIPs) == 0 {
		return true // No IP restrictions
	}

	clientIP := c.ClientIP()
	for _, allowedIP := range am.config.AllowedIPs {
		if clientIP == allowedIP || strings.HasPrefix(clientIP, allowedIP) {
			return true
		}
	}

	return false
}

func (am *AdminMiddleware) setAdminContext(c *gin.Context, user *models.User) {
	c.Set("admin_user", user)
	c.Set("admin_role", user.Role)
	c.Set("admin_session_start", time.Now())
	c.Set("is_admin", true)
}

func (am *AdminMiddleware) logAdminAction(c *gin.Context, user *models.User) {
	if am.config.AuditService == nil {
		return
	}

	action := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
	resource := am.extractResourceFromPath(c.Request.URL.Path)
	details := fmt.Sprintf("Admin action performed by %s (%s)", user.Username, user.Role)

	metadata := map[string]interface{}{
		"user_id":     user.ID.Hex(),
		"username":    user.Username,
		"role":        user.Role,
		"method":      c.Request.Method,
		"path":        c.Request.URL.Path,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.Request.UserAgent(),
		"status_code": c.Writer.Status(),
		"timestamp":   time.Now(),
	}

	am.config.AuditService.LogAdminAction(user.ID, action, resource, details, metadata)
}

func (am *AdminMiddleware) logUnauthorizedAttempt(c *gin.Context, user *models.User, reason string) {
	if am.config.AuditService == nil {
		return
	}

	details := fmt.Sprintf("Unauthorized admin access attempt: %s", reason)
	metadata := map[string]interface{}{
		"user_id":    user.ID.Hex(),
		"username":   user.Username,
		"role":       user.Role,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"ip_address": c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"reason":     reason,
		"timestamp":  time.Now(),
	}

	am.config.AuditService.LogSecurityEvent(user.ID, "unauthorized_admin_attempt", details, metadata)
}

func (am *AdminMiddleware) logSecurityEvent(c *gin.Context, user *models.User, event, details string) {
	if am.config.AuditService == nil {
		return
	}

	metadata := map[string]interface{}{
		"user_id":    user.ID.Hex(),
		"username":   user.Username,
		"role":       user.Role,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"ip_address": c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"timestamp":  time.Now(),
	}

	am.config.AuditService.LogSecurityEvent(user.ID, event, details, metadata)
}

func (am *AdminMiddleware) logDetailedAuditEvent(c *gin.Context, user *models.User, startTime time.Time, requestID string) {
	if am.config.AuditService == nil {
		return
	}

	duration := time.Since(startTime)
	action := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)

	metadata := map[string]interface{}{
		"request_id":     requestID,
		"user_id":        user.ID.Hex(),
		"username":       user.Username,
		"role":           user.Role,
		"method":         c.Request.Method,
		"path":           c.Request.URL.Path,
		"query":          c.Request.URL.RawQuery,
		"ip_address":     c.ClientIP(),
		"user_agent":     c.Request.UserAgent(),
		"status_code":    c.Writer.Status(),
		"duration_ms":    duration.Milliseconds(),
		"start_time":     startTime,
		"end_time":       time.Now(),
		"content_length": c.Request.ContentLength,
	}

	details := fmt.Sprintf("Admin request completed in %v with status %d", duration, c.Writer.Status())
	am.config.AuditService.LogAdminAction(user.ID, action, "admin_request", details, metadata)
}

func (am *AdminMiddleware) extractResourceFromPath(path string) string {
	// Extract resource type from admin path
	// e.g., /api/v1/admin/users/123 -> users
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 4 && parts[0] == "api" && parts[2] == "admin" {
		return parts[3]
	}
	return "unknown"
}

// GetCurrentUser retrieves the current user from context
func GetCurrentUser(c *gin.Context) *models.User {
	if user, exists := c.Get("user"); exists {
		if u, ok := user.(*models.User); ok {
			return u
		}
	}
	return nil
}

// GetAdminUser retrieves the current admin user from context
func GetAdminUser(c *gin.Context) *models.User {
	if user, exists := c.Get("admin_user"); exists {
		if u, ok := user.(*models.User); ok {
			return u
		}
	}
	return GetCurrentUser(c) // Fallback to regular user context
}

// IsAdmin checks if the current user is an admin
func IsAdmin(c *gin.Context) bool {
	if isAdmin, exists := c.Get("is_admin"); exists {
		if admin, ok := isAdmin.(bool); ok {
			return admin
		}
	}

	user := GetCurrentUser(c)
	if user == nil {
		return false
	}

	return user.Role == models.RoleAdmin ||
		user.Role == models.RoleSuperAdmin ||
		user.Role == models.RoleModerator
}

// GetAdminRole retrieves the current admin user's role
func GetAdminRole(c *gin.Context) models.UserRole {
	if role, exists := c.Get("admin_role"); exists {
		if r, ok := role.(models.UserRole); ok {
			return r
		}
	}

	user := GetCurrentUser(c)
	if user != nil {
		return user.Role
	}

	return ""
}

// AdminRoleGuard creates a middleware that checks for specific admin roles
func AdminRoleGuard(allowedRoles ...models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			utils.SendUnauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		hasRole := false
		for _, role := range allowedRoles {
			if user.Role == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			utils.SendForbidden(c, "Insufficient admin privileges")
			c.Abort()
			return
		}

		c.Next()
	}
}
