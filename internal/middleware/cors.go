package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
	AllowWildcard    bool
	AllowBrowserExt  bool
	AllowWebSockets  bool
	AllowFiles       bool
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Authorization",
			"Accept",
			"X-Requested-With",
			"X-Request-ID",
			"X-API-Key",
			"X-CSRF-Token",
			"X-Device-ID",
			"X-App-Version",
			"X-Platform",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"X-Request-ID",
			"X-Rate-Limit-Limit",
			"X-Rate-Limit-Remaining",
			"X-Rate-Limit-Reset",
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
		AllowWildcard:    true,
		AllowBrowserExt:  false,
		AllowWebSockets:  true,
		AllowFiles:       true,
	}
}

// DevelopmentCORSConfig returns permissive CORS config for development
func DevelopmentCORSConfig() *CORSConfig {
	config := DefaultCORSConfig()
	config.AllowOrigins = []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
	}
	config.AllowBrowserExt = true
	return config
}

// ProductionCORSConfig returns restrictive CORS config for production
func ProductionCORSConfig(allowedOrigins []string) *CORSConfig {
	config := DefaultCORSConfig()
	config.AllowOrigins = allowedOrigins
	config.AllowWildcard = false
	config.AllowBrowserExt = false
	return config
}

// CORS returns a CORS middleware with the given configuration
func CORS(config *CORSConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultCORSConfig()
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			handlePreflight(c, config, origin)
			return
		}

		// Handle actual requests
		handleActualRequest(c, config, origin)
		c.Next()
	}
}

// handlePreflight handles CORS preflight requests
func handlePreflight(c *gin.Context, config *CORSConfig, origin string) {
	// Check if origin is allowed
	if !isOriginAllowed(config, origin) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// Set CORS headers for preflight
	setCORSHeaders(c, config, origin)

	// Handle preflight-specific headers
	requestMethod := c.Request.Header.Get("Access-Control-Request-Method")
	if requestMethod != "" {
		if isMethodAllowed(config, requestMethod) {
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
		} else {
			c.AbortWithStatus(http.StatusMethodNotAllowed)
			return
		}
	}

	requestHeaders := c.Request.Header.Get("Access-Control-Request-Headers")
	if requestHeaders != "" {
		if areHeadersAllowed(config, requestHeaders) {
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
		} else {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	// Set max age for preflight cache
	if config.MaxAge > 0 {
		c.Header("Access-Control-Max-Age", strconv.Itoa(int(config.MaxAge.Seconds())))
	}

	c.AbortWithStatus(http.StatusNoContent)
}

// handleActualRequest handles actual CORS requests
func handleActualRequest(c *gin.Context, config *CORSConfig, origin string) {
	// Check if origin is allowed
	if !isOriginAllowed(config, origin) {
		return
	}

	// Set CORS headers for actual request
	setCORSHeaders(c, config, origin)

	// Set exposed headers
	if len(config.ExposeHeaders) > 0 {
		c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
	}
}

// setCORSHeaders sets common CORS headers
func setCORSHeaders(c *gin.Context, config *CORSConfig, origin string) {
	// Set allowed origin
	if config.AllowCredentials {
		if origin != "" && isOriginAllowed(config, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		}
	} else {
		if config.AllowWildcard && len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" && isOriginAllowed(config, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		}
	}

	// Set credentials
	if config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}

	// Set vary header to handle caching properly
	c.Header("Vary", "Origin")
}

// isOriginAllowed checks if the origin is allowed
func isOriginAllowed(config *CORSConfig, origin string) bool {
	if origin == "" {
		return true
	}

	// Check for wildcard
	if config.AllowWildcard {
		for _, allowedOrigin := range config.AllowOrigins {
			if allowedOrigin == "*" {
				return true
			}
		}
	}

	// Check exact match
	for _, allowedOrigin := range config.AllowOrigins {
		if allowedOrigin == origin {
			return true
		}

		// Check for pattern match (e.g., *.example.com)
		if strings.Contains(allowedOrigin, "*") {
			if matchWildcardOrigin(allowedOrigin, origin) {
				return true
			}
		}
	}

	// Special handling for browser extensions
	if config.AllowBrowserExt {
		if strings.HasPrefix(origin, "chrome-extension://") ||
			strings.HasPrefix(origin, "moz-extension://") ||
			strings.HasPrefix(origin, "safari-extension://") {
			return true
		}
	}

	// Special handling for file URLs
	if config.AllowFiles && origin == "file://" {
		return true
	}

	return false
}

// isMethodAllowed checks if the HTTP method is allowed
func isMethodAllowed(config *CORSConfig, method string) bool {
	for _, allowedMethod := range config.AllowMethods {
		if allowedMethod == method {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if the headers are allowed
func areHeadersAllowed(config *CORSConfig, requestHeaders string) bool {
	headers := strings.Split(requestHeaders, ",")
	for _, header := range headers {
		header = strings.TrimSpace(header)
		if !isHeaderAllowed(config, header) {
			return false
		}
	}
	return true
}

// isHeaderAllowed checks if a specific header is allowed
func isHeaderAllowed(config *CORSConfig, header string) bool {
	header = strings.ToLower(header)

	// Always allow simple headers
	simpleHeaders := []string{
		"accept",
		"accept-language",
		"content-language",
		"content-type",
	}

	for _, simpleHeader := range simpleHeaders {
		if header == simpleHeader {
			return true
		}
	}

	// Check configured headers
	for _, allowedHeader := range config.AllowHeaders {
		if strings.ToLower(allowedHeader) == header {
			return true
		}
	}

	return false
}

// matchWildcardOrigin checks if origin matches wildcard pattern
func matchWildcardOrigin(pattern, origin string) bool {
	// Simple wildcard matching for subdomains
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		return strings.HasSuffix(origin, "."+domain) || origin == domain
	}

	return false
}

// CORSWithCredentials returns CORS middleware that allows credentials
func CORSWithCredentials(allowedOrigins []string) gin.HandlerFunc {
	config := &CORSConfig{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept", "X-Requested-With"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	return CORS(config)
}

// CORSForAPI returns CORS middleware optimized for API usage
func CORSForAPI() gin.HandlerFunc {
	config := &CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Authorization",
			"Accept",
			"X-Requested-With",
			"X-API-Key",
			"X-Request-ID",
			"X-Device-ID",
		},
		ExposeHeaders: []string{
			"X-Request-ID",
			"X-Rate-Limit-Limit",
			"X-Rate-Limit-Remaining",
			"X-Rate-Limit-Reset",
		},
		AllowCredentials: false,
		MaxAge:           24 * time.Hour,
		AllowWildcard:    true,
	}
	return CORS(config)
}

// CORSForWebSocket returns CORS middleware for WebSocket connections
func CORSForWebSocket(allowedOrigins []string) gin.HandlerFunc {
	config := &CORSConfig{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Upgrade",
			"Connection",
			"Sec-WebSocket-Key",
			"Sec-WebSocket-Version",
			"Sec-WebSocket-Protocol",
			"Authorization",
		},
		AllowCredentials: true,
		AllowWebSockets:  true,
	}
	return CORS(config)
}

// CORSForUpload returns CORS middleware optimized for file uploads
func CORSForUpload(allowedOrigins []string) gin.HandlerFunc {
	config := &CORSConfig{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Content-Length",
			"Authorization",
			"Accept",
			"X-Requested-With",
			"X-File-Name",
			"X-File-Size",
			"X-Upload-ID",
		},
		ExposeHeaders: []string{
			"X-Upload-ID",
			"X-File-URL",
		},
		AllowCredentials: true,
		MaxAge:           1 * time.Hour, // Shorter cache for uploads
		AllowFiles:       true,
	}
	return CORS(config)
}

// SecurityHeaders adds security-related CORS headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent embedding in frames from other domains
		c.Header("X-Frame-Options", "SAMEORIGIN")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy for API
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Content-Security-Policy", "default-src 'none'")
		}

		c.Next()
	}
}

// ValidateOrigin validates origin against configuration
func ValidateOrigin(config *CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin != "" && !isOriginAllowed(config, origin) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Origin not allowed",
				"code":  "CORS_ORIGIN_NOT_ALLOWED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CORSDebug returns CORS middleware with debug logging
func CORSDebug(config *CORSConfig) gin.HandlerFunc {
	corsMiddleware := CORS(config)

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		method := c.Request.Method

		// Log CORS request details
		if origin != "" {
			c.Set("cors_origin", origin)
			c.Set("cors_method", method)
			c.Set("cors_allowed", isOriginAllowed(config, origin))
		}

		corsMiddleware(c)
	}
}
