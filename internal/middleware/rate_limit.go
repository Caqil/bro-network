package middleware

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Store             RateLimitStore
	KeyGenerator      func(*gin.Context) string
	ErrorHandler      func(*gin.Context, RateLimitInfo)
	SkipSuccessful    bool
	SkipFailedRequest bool
	Headers           RateLimitHeaders
}

// RateLimitStore interface for rate limit storage
type RateLimitStore interface {
	Get(key string) (int, time.Time, error)
	Increment(key string, window time.Duration) (int, time.Time, error)
	Reset(key string) error
}

// RateLimitInfo contains rate limit information
type RateLimitInfo struct {
	Key       string
	Limit     int
	Remaining int
	ResetTime time.Time
	Total     int
}

// RateLimitHeaders configuration for rate limit headers
type RateLimitHeaders struct {
	Enable          bool
	LimitHeader     string
	RemainingHeader string
	ResetHeader     string
	TotalHeader     string
}

// DefaultRateLimitHeaders returns default header configuration
func DefaultRateLimitHeaders() RateLimitHeaders {
	return RateLimitHeaders{
		Enable:          true,
		LimitHeader:     "X-Rate-Limit-Limit",
		RemainingHeader: "X-Rate-Limit-Remaining",
		ResetHeader:     "X-Rate-Limit-Reset",
		TotalHeader:     "X-Rate-Limit-Total",
	}
}

// RateLimit creates a rate limiting middleware
func RateLimit(limit int, window time.Duration, config *RateLimitConfig) gin.HandlerFunc {
	if config == nil {
		config = &RateLimitConfig{}
	}

	if config.KeyGenerator == nil {
		config.KeyGenerator = defaultKeyGenerator
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}

	if config.Headers.LimitHeader == "" {
		config.Headers = DefaultRateLimitHeaders()
	}

	return func(c *gin.Context) {
		key := config.KeyGenerator(c)

		// Get current count and reset time
		count, resetTime, err := config.Store.Increment(key, window)
		if err != nil {
			// On error, allow the request to proceed
			c.Next()
			return
		}

		remaining := limit - count
		if remaining < 0 {
			remaining = 0
		}

		rateLimitInfo := RateLimitInfo{
			Key:       key,
			Limit:     limit,
			Remaining: remaining,
			ResetTime: resetTime,
			Total:     count,
		}

		// Set rate limit headers
		if config.Headers.Enable {
			setRateLimitHeaders(c, rateLimitInfo, config.Headers)
		}

		// Check if limit exceeded
		if count > limit {
			config.ErrorHandler(c, rateLimitInfo)
			return
		}

		// Store rate limit info in context
		c.Set("rate_limit_info", rateLimitInfo)
		c.Next()

		// Handle post-request logic
		if config.SkipSuccessful && c.Writer.Status() < 400 {
			// Optionally decrement counter for successful requests
		}
	}
}

// RateLimitByIP creates IP-based rate limiting
func RateLimitByIP(limit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			return "rate_limit:ip:" + getClientIP(c)
		},
		Headers: DefaultRateLimitHeaders(),
	}
	return RateLimit(limit, window, config)
}

// RateLimitByUser creates user-based rate limiting
func RateLimitByUser(limit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			userID := getUserID(c)
			if userID.IsZero() {
				return "rate_limit:anonymous:" + getClientIP(c)
			}
			return "rate_limit:user:" + userID.Hex()
		},
		Headers: DefaultRateLimitHeaders(),
	}
	return RateLimit(limit, window, config)
}

// RateLimitByAPIKey creates API key-based rate limiting
func RateLimitByAPIKey(limit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			apiKey := c.GetHeader("X-API-Key")
			if apiKey == "" {
				return "rate_limit:no_key:" + getClientIP(c)
			}
			return "rate_limit:api_key:" + apiKey
		},
		Headers: DefaultRateLimitHeaders(),
	}
	return RateLimit(limit, window, config)
}

// RateLimitByEndpoint creates endpoint-specific rate limiting
func RateLimitByEndpoint(limits map[string]EndpointLimit, store RateLimitStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		endpoint := getEndpointKey(c)
		endpointLimit, exists := limits[endpoint]
		if !exists {
			c.Next()
			return
		}

		config := &RateLimitConfig{
			Store: store,
			KeyGenerator: func(c *gin.Context) string {
				userID := getUserID(c)
				if userID.IsZero() {
					return fmt.Sprintf("rate_limit:endpoint:%s:ip:%s", endpoint, getClientIP(c))
				}
				return fmt.Sprintf("rate_limit:endpoint:%s:user:%s", endpoint, userID.Hex())
			},
			Headers: DefaultRateLimitHeaders(),
		}

		rateLimitHandler := RateLimit(endpointLimit.Limit, endpointLimit.Window, config)
		rateLimitHandler(c)
	}
}

// EndpointLimit represents rate limit configuration for an endpoint
type EndpointLimit struct {
	Limit  int
	Window time.Duration
}

// AdaptiveRateLimit creates adaptive rate limiting based on user behavior
func AdaptiveRateLimit(baseLimit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			userID := getUserID(c)
			if userID.IsZero() {
				return "rate_limit:adaptive:ip:" + getClientIP(c)
			}
			return "rate_limit:adaptive:user:" + userID.Hex()
		},
		Headers: DefaultRateLimitHeaders(),
	}

	return func(c *gin.Context) {
		// Calculate adaptive limit based on user behavior
		adaptiveLimit := calculateAdaptiveLimit(c, baseLimit)

		rateLimitHandler := RateLimit(adaptiveLimit, window, config)
		rateLimitHandler(c)
	}
}

// SlidingWindowRateLimit creates sliding window rate limiting
func SlidingWindowRateLimit(limit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			userID := getUserID(c)
			if userID.IsZero() {
				return "rate_limit:sliding:ip:" + getClientIP(c)
			}
			return "rate_limit:sliding:user:" + userID.Hex()
		},
		Headers: DefaultRateLimitHeaders(),
	}

	return RateLimit(limit, window, config)
}

// TokenBucketRateLimit creates token bucket rate limiting
func TokenBucketRateLimit(capacity int, refillRate time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store: store,
		KeyGenerator: func(c *gin.Context) string {
			userID := getUserID(c)
			if userID.IsZero() {
				return "rate_limit:bucket:ip:" + getClientIP(c)
			}
			return "rate_limit:bucket:user:" + userID.Hex()
		},
		Headers: DefaultRateLimitHeaders(),
	}

	return func(c *gin.Context) {
		key := config.KeyGenerator(c)

		// Implement token bucket logic
		allowed, remaining, resetTime := checkTokenBucket(key, capacity, refillRate, store)

		rateLimitInfo := RateLimitInfo{
			Key:       key,
			Limit:     capacity,
			Remaining: remaining,
			ResetTime: resetTime,
		}

		setRateLimitHeaders(c, rateLimitInfo, config.Headers)

		if !allowed {
			config.ErrorHandler(c, rateLimitInfo)
			return
		}

		c.Set("rate_limit_info", rateLimitInfo)
		c.Next()
	}
}

// Helper functions

// defaultKeyGenerator generates default rate limit key
func defaultKeyGenerator(c *gin.Context) string {
	userID := getUserID(c)
	if userID.IsZero() {
		return "rate_limit:ip:" + getClientIP(c)
	}
	return "rate_limit:user:" + userID.Hex()
}

// defaultErrorHandler handles rate limit exceeded
func defaultErrorHandler(c *gin.Context, info RateLimitInfo) {
	utils.SetRateLimitInfo(c, int64(info.Limit), int64(info.Remaining), info.ResetTime, "")
	utils.SendError(c, 429, "RATE_LIMIT_EXCEEDED", "Admin action rate limit exceeded")
	c.Abort()
}

// setRateLimitHeaders sets rate limit headers
func setRateLimitHeaders(c *gin.Context, info RateLimitInfo, headers RateLimitHeaders) {
	if headers.LimitHeader != "" {
		c.Header(headers.LimitHeader, strconv.Itoa(info.Limit))
	}
	if headers.RemainingHeader != "" {
		c.Header(headers.RemainingHeader, strconv.Itoa(info.Remaining))
	}
	if headers.ResetHeader != "" {
		c.Header(headers.ResetHeader, strconv.FormatInt(info.ResetTime.Unix(), 10))
	}
	if headers.TotalHeader != "" {
		c.Header(headers.TotalHeader, strconv.Itoa(info.Total))
	}
}

// getClientIP extracts client IP address
func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := c.GetHeader("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Check CF-Connecting-IP header (Cloudflare)
	cfIP := c.GetHeader("CF-Connecting-IP")
	if cfIP != "" {
		return cfIP
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}

// getUserID extracts user ID from context
func getUserID(c *gin.Context) primitive.ObjectID {
	userID, exists := c.Get("user_id")
	if !exists {
		return primitive.NilObjectID
	}

	if id, ok := userID.(primitive.ObjectID); ok {
		return id
	}

	return primitive.NilObjectID
}

// getEndpointKey generates endpoint key for rate limiting
func getEndpointKey(c *gin.Context) string {
	method := c.Request.Method
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	return method + ":" + path
}

// calculateAdaptiveLimit calculates adaptive rate limit based on user behavior
func calculateAdaptiveLimit(c *gin.Context, baseLimit int) int {
	// This could be based on user role, reputation, subscription level, etc.
	user, exists := c.Get("user")
	if !exists {
		return baseLimit
	}

	// Type assertion to get user model
	// This would depend on your user model structure
	// For now, return base limit
	_ = user
	return baseLimit
}

// checkTokenBucket implements token bucket algorithm
func checkTokenBucket(key string, capacity int, refillRate time.Duration, store RateLimitStore) (bool, int, time.Time) {
	// This is a simplified implementation
	// In practice, you'd implement proper token bucket logic with store
	count, resetTime, err := store.Get(key)
	if err != nil {
		return true, capacity, time.Now().Add(refillRate)
	}

	if count >= capacity {
		return false, 0, resetTime
	}

	// Increment token usage
	newCount, newResetTime, _ := store.Increment(key, refillRate)
	remaining := capacity - newCount
	if remaining < 0 {
		remaining = 0
	}

	return newCount <= capacity, remaining, newResetTime
}

// RateLimitByRole creates role-based rate limiting
func RateLimitByRole(limits map[string]int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := getUserRole(c)
		limit, exists := limits[string(role)]
		if !exists {
			limit = limits["default"]
		}

		config := &RateLimitConfig{
			Store: store,
			KeyGenerator: func(c *gin.Context) string {
				userID := getUserID(c)
				if userID.IsZero() {
					return "rate_limit:role:" + string(role) + ":ip:" + getClientIP(c)
				}
				return "rate_limit:role:" + string(role) + ":user:" + userID.Hex()
			},
			Headers: DefaultRateLimitHeaders(),
		}

		rateLimitHandler := RateLimit(limit, window, config)
		rateLimitHandler(c)
	}
}

// getUserRole extracts user role from context
func getUserRole(c *gin.Context) string {
	role, exists := c.Get("user_role")
	if !exists {
		return "anonymous"
	}

	if r, ok := role.(string); ok {
		return r
	}

	return "user"
}

// RateLimitWithWhitelist creates rate limiting with IP whitelist
func RateLimitWithWhitelist(limit int, window time.Duration, whitelist []string, store RateLimitStore) gin.HandlerFunc {
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelist {
		whitelistMap[ip] = true
	}

	config := &RateLimitConfig{
		Store:        store,
		KeyGenerator: defaultKeyGenerator,
		Headers:      DefaultRateLimitHeaders(),
	}

	return func(c *gin.Context) {
		clientIP := getClientIP(c)

		// Skip rate limiting for whitelisted IPs
		if whitelistMap[clientIP] {
			c.Next()
			return
		}

		rateLimitHandler := RateLimit(limit, window, config)
		rateLimitHandler(c)
	}
}

// CircuitBreakerRateLimit combines rate limiting with circuit breaker pattern
func CircuitBreakerRateLimit(limit int, window time.Duration, store RateLimitStore) gin.HandlerFunc {
	config := &RateLimitConfig{
		Store:        store,
		KeyGenerator: defaultKeyGenerator,
		Headers:      DefaultRateLimitHeaders(),
		ErrorHandler: func(c *gin.Context, info RateLimitInfo) {
			// Implement circuit breaker logic
			setCircuitBreakerHeaders(c, info)
			utils.SendBadRequest(c, "Service temporarily unavailable due to high load")
			c.Abort()
		},
	}

	return RateLimit(limit, window, config)
}

// setCircuitBreakerHeaders sets circuit breaker specific headers
func setCircuitBreakerHeaders(c *gin.Context, info RateLimitInfo) {
	c.Header("X-Circuit-Breaker-State", "OPEN")
	c.Header("X-Retry-After", strconv.FormatInt(info.ResetTime.Unix()-time.Now().Unix(), 10))
}

// DynamicRateLimit creates dynamic rate limiting based on system load
func DynamicRateLimit(baseLimit int, window time.Duration, store RateLimitStore, loadFunc func() float64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Adjust limit based on system load
		load := loadFunc()
		adjustedLimit := int(float64(baseLimit) * (1.0 - load))
		if adjustedLimit < 1 {
			adjustedLimit = 1
		}

		config := &RateLimitConfig{
			Store:        store,
			KeyGenerator: defaultKeyGenerator,
			Headers:      DefaultRateLimitHeaders(),
		}

		rateLimitHandler := RateLimit(adjustedLimit, window, config)
		rateLimitHandler(c)
	}
}
