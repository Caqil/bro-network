package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// APIConfig holds configuration for API routes
type APIConfig struct {
	AuthHandler         *handlers.AuthHandler
	UserHandler         *handlers.UserHandler
	PostHandler         *handlers.PostHandler
	CommentHandler      *handlers.CommentHandler
	LikeHandler         *handlers.LikeHandler
	FollowHandler       *handlers.FollowHandler
	MessageHandler      *handlers.MessageHandler
	SearchHandler       *handlers.SearchHandler
	NotificationHandler *handlers.NotificationHandler
	UploadHandler       *handlers.UploadHandler
	AdminHandler        *handlers.AdminHandler
	HealthHandler       *handlers.HealthHandler
}

// SetupRoutes initializes all API routes
func SetupRoutes(router *gin.Engine, config *APIConfig, middlewares *middleware.Middlewares) {
	// API version prefix
	api := router.Group("/api/v1")

	// Apply global middlewares
	api.Use(middlewares.CORS())
	api.Use(middlewares.RateLimit())
	api.Use(middlewares.Logging())
	api.Use(middlewares.RequestID())
	api.Use(middlewares.Security())

	// Public routes (no authentication required)
	setupPublicRoutes(api, config)

	// Protected routes (authentication required)
	protected := api.Group("")
	protected.Use(middlewares.Auth())
	setupProtectedRoutes(protected, config, middlewares)

	// Admin routes (admin authentication required)
	admin := api.Group("/admin")
	admin.Use(middlewares.Auth())
	admin.Use(middlewares.Admin())
	setupAdminRoutes(admin, config)

	// Health and monitoring routes
	setupHealthRoutes(router, config)
}

// setupPublicRoutes sets up routes that don't require authentication
func setupPublicRoutes(api *gin.RouterGroup, config *APIConfig) {
	// Authentication routes
	SetupAuthRoutes(api, config.AuthHandler)

	// Public user routes
	SetupPublicUserRoutes(api, config.UserHandler)

	// Public post routes
	SetupPublicPostRoutes(api, config.PostHandler)

	// Public search routes
	SetupPublicSearchRoutes(api, config.SearchHandler)
}

// setupProtectedRoutes sets up routes that require authentication
func setupProtectedRoutes(api *gin.RouterGroup, config *APIConfig, middlewares *middleware.Middlewares) {
	// User routes
	SetupUserRoutes(api, config.UserHandler, middlewares)

	// Post routes
	SetupPostRoutes(api, config.PostHandler, middlewares)

	// Social interaction routes
	SetupSocialRoutes(api, config, middlewares)

	// Message routes
	SetupMessageRoutes(api, config.MessageHandler, middlewares)

	// Search routes
	SetupSearchRoutes(api, config.SearchHandler, middlewares)

	// Notification routes
	SetupNotificationRoutes(api, config.NotificationHandler, middlewares)

	// Upload routes
	SetupUploadRoutes(api, config.UploadHandler, middlewares)
}

// setupAdminRoutes sets up admin-only routes
func setupAdminRoutes(admin *gin.RouterGroup, config *APIConfig) {
	SetupAdminRoutes(admin, config.AdminHandler)
}

// setupHealthRoutes sets up health check routes
func setupHealthRoutes(router *gin.Engine, config *APIConfig) {
	SetupHealthRoutes(router, config.HealthHandler)
}

// Middleware application helpers
func applyValidation(validation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Apply validation middleware
		c.Next()
	}
}

func applyRateLimit(limit string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Apply specific rate limiting
		c.Next()
	}
}

func applyCache(duration string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Apply caching
		c.Next()
	}
}
