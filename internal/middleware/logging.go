package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LogConfig represents logging configuration
type LogConfig struct {
	Logger           LoggerInterface
	SkipPaths        []string
	LogBody          bool
	LogHeaders       bool
	LogQuery         bool
	LogResponse      bool
	MaxBodySize      int64
	SensitiveHeaders []string
	RedactFields     []string
	RequestIDKey     string
	TimeFormat       string
}

// LoggerInterface defines logger methods
type LoggerInterface interface {
	Info(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Debug(msg string, fields map[string]interface{})
}

// LogEntry represents a log entry
type LogEntry struct {
	RequestID    string                 `json:"request_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Method       string                 `json:"method"`
	Path         string                 `json:"path"`
	Query        string                 `json:"query,omitempty"`
	UserAgent    string                 `json:"user_agent"`
	ClientIP     string                 `json:"client_ip"`
	StatusCode   int                    `json:"status_code"`
	Duration     time.Duration          `json:"duration"`
	RequestSize  int64                  `json:"request_size"`
	ResponseSize int64                  `json:"response_size"`
	UserID       string                 `json:"user_id,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`
	RequestBody  string                 `json:"request_body,omitempty"`
	ResponseBody string                 `json:"response_body,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

// ResponseWriter wraps gin.ResponseWriter to capture response data
type ResponseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	size       int64
}

// DefaultLogConfig returns default logging configuration
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		SkipPaths: []string{
			"/health",
			"/ready",
			"/live",
			"/metrics",
		},
		LogBody:     false,
		LogHeaders:  true,
		LogQuery:    true,
		LogResponse: false,
		MaxBodySize: 1024 * 1024, // 1MB
		SensitiveHeaders: []string{
			"authorization",
			"cookie",
			"x-api-key",
			"x-auth-token",
		},
		RedactFields: []string{
			"password",
			"token",
			"secret",
			"key",
			"authorization",
		},
		RequestIDKey: "X-Request-ID",
		TimeFormat:   time.RFC3339,
	}
}

// NewResponseWriter creates a new response writer wrapper
func NewResponseWriter(w gin.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		body:           bytes.NewBuffer([]byte{}),
		statusCode:     http.StatusOK,
	}
}

// Write captures response body
func (w *ResponseWriter) Write(data []byte) (int, error) {
	if w.body != nil {
		w.body.Write(data)
	}
	size, err := w.ResponseWriter.Write(data)
	w.size += int64(size)
	return size, err
}

// WriteHeader captures status code
func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// GetStatusCode returns captured status code
func (w *ResponseWriter) GetStatusCode() int {
	return w.statusCode
}

// GetSize returns response size
func (w *ResponseWriter) GetSize() int64 {
	return w.size
}

// GetBody returns response body
func (w *ResponseWriter) GetBody() string {
	if w.body != nil {
		return w.body.String()
	}
	return ""
}

// Logging creates a logging middleware
func Logging(config *LogConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultLogConfig()
	}

	return func(c *gin.Context) {
		// Skip logging for certain paths
		if shouldSkipLogging(c.Request.URL.Path, config.SkipPaths) {
			c.Next()
			return
		}

		startTime := time.Now()

		// Capture request data
		entry := &LogEntry{
			RequestID: getOrGenerateRequestID(c, config.RequestIDKey),
			Timestamp: startTime,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			UserAgent: c.Request.UserAgent(),
			ClientIP:  getClientIP(c),
		}

		// Log query parameters
		if config.LogQuery && c.Request.URL.RawQuery != "" {
			entry.Query = redactSensitiveQuery(c.Request.URL.RawQuery, config.RedactFields)
		}

		// Log headers
		if config.LogHeaders {
			entry.Headers = filterHeaders(c.Request.Header, config.SensitiveHeaders)
		}

		// Log request body
		if config.LogBody && shouldLogBody(c.Request) {
			body, size := captureRequestBody(c, config.MaxBodySize)
			entry.RequestBody = redactSensitiveData(body, config.RedactFields)
			entry.RequestSize = size
		} else {
			entry.RequestSize = getRequestSize(c)
		}

		// Get user context if available
		if userID := getUserID(c); !userID.IsZero() {
			entry.UserID = userID.Hex()
		}

		if sessionID := getSessionID(c); sessionID != "" {
			entry.SessionID = sessionID
		}

		// Wrap response writer to capture response data
		var responseWriter *ResponseWriter
		if config.LogResponse {
			responseWriter = NewResponseWriter(c.Writer)
			c.Writer = responseWriter
		}

		// Process request
		c.Next()

		// Calculate duration
		entry.Duration = time.Since(startTime)

		// Capture response data
		if responseWriter != nil {
			entry.StatusCode = responseWriter.GetStatusCode()
			entry.ResponseSize = responseWriter.GetSize()
			if config.LogResponse {
				entry.ResponseBody = redactSensitiveData(responseWriter.GetBody(), config.RedactFields)
			}
		} else {
			entry.StatusCode = c.Writer.Status()
			entry.ResponseSize = int64(c.Writer.Size())
		}

		// Capture errors
		if len(c.Errors) > 0 {
			entry.Error = c.Errors.String()
		}

		// Add extra context
		entry.Extra = extractExtraContext(c)

		// Log the entry
		logEntry(config.Logger, entry)
	}
}

// AccessLogging creates simplified access logging
func AccessLogging(logger LoggerInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		path := c.Request.URL.Path

		c.Next()

		duration := time.Since(startTime)
		statusCode := c.Writer.Status()

		fields := map[string]interface{}{
			"method":     c.Request.Method,
			"path":       path,
			"status":     statusCode,
			"duration":   duration.Milliseconds(),
			"client_ip":  getClientIP(c),
			"user_agent": c.Request.UserAgent(),
		}

		if userID := getUserID(c); !userID.IsZero() {
			fields["user_id"] = userID.Hex()
		}

		message := fmt.Sprintf("%s %s %d %dms", c.Request.Method, path, statusCode, duration.Milliseconds())

		if statusCode >= 500 {
			logger.Error(message, fields)
		} else if statusCode >= 400 {
			logger.Warn(message, fields)
		} else {
			logger.Info(message, fields)
		}
	}
}

// ErrorLogging logs detailed error information
func ErrorLogging(logger LoggerInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log errors if any occurred
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				fields := map[string]interface{}{
					"error":      err.Error(),
					"type":       err.Type,
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"status":     c.Writer.Status(),
					"client_ip":  getClientIP(c),
					"user_agent": c.Request.UserAgent(),
				}

				if userID := getUserID(c); !userID.IsZero() {
					fields["user_id"] = userID.Hex()
				}

				if requestID := getRequestID(c); requestID != "" {
					fields["request_id"] = requestID
				}

				logger.Error("Request error occurred", fields)
			}
		}
	}
}

// SecurityLogging logs security-related events
func SecurityLogging(logger LoggerInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log security events before processing
		if isSecurityRelevant(c) {
			fields := map[string]interface{}{
				"event":      "security_check",
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"client_ip":  getClientIP(c),
				"user_agent": c.Request.UserAgent(),
			}

			if userID := getUserID(c); !userID.IsZero() {
				fields["user_id"] = userID.Hex()
			}

			logger.Info("Security relevant request", fields)
		}

		c.Next()

		// Log failed authentication attempts
		if c.Writer.Status() == http.StatusUnauthorized {
			fields := map[string]interface{}{
				"event":      "auth_failure",
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"status":     c.Writer.Status(),
				"client_ip":  getClientIP(c),
				"user_agent": c.Request.UserAgent(),
			}

			logger.Warn("Authentication failure", fields)
		}

		// Log privilege escalation attempts
		if c.Writer.Status() == http.StatusForbidden {
			fields := map[string]interface{}{
				"event":      "privilege_escalation",
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"status":     c.Writer.Status(),
				"client_ip":  getClientIP(c),
				"user_agent": c.Request.UserAgent(),
			}

			if userID := getUserID(c); !userID.IsZero() {
				fields["user_id"] = userID.Hex()
			}

			logger.Warn("Privilege escalation attempt", fields)
		}
	}
}

// PerformanceLogging logs performance metrics
func PerformanceLogging(logger LoggerInterface, threshold time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		duration := time.Since(startTime)

		// Log slow requests
		if duration > threshold {
			fields := map[string]interface{}{
				"event":     "slow_request",
				"method":    c.Request.Method,
				"path":      c.Request.URL.Path,
				"duration":  duration.Milliseconds(),
				"threshold": threshold.Milliseconds(),
				"status":    c.Writer.Status(),
				"client_ip": getClientIP(c),
			}

			if userID := getUserID(c); !userID.IsZero() {
				fields["user_id"] = userID.Hex()
			}

			logger.Warn("Slow request detected", fields)
		}
	}
}

// Helper functions

// shouldSkipLogging checks if logging should be skipped for the path
func shouldSkipLogging(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// getOrGenerateRequestID gets or generates request ID
func getOrGenerateRequestID(c *gin.Context, headerKey string) string {
	// Try to get from header
	requestID := c.GetHeader(headerKey)
	if requestID != "" {
		return requestID
	}

	// Try to get from context
	if id, exists := c.Get("request_id"); exists {
		if requestID, ok := id.(string); ok {
			return requestID
		}
	}

	// Generate new request ID
	requestID = primitive.NewObjectID().Hex()
	c.Set("request_id", requestID)
	c.Header(headerKey, requestID)

	return requestID
}

// captureRequestBody captures and returns request body
func captureRequestBody(c *gin.Context, maxSize int64) (string, int64) {
	if c.Request.Body == nil {
		return "", 0
	}

	// Read body
	bodyBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, maxSize))
	if err != nil {
		return "", 0
	}

	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return string(bodyBytes), int64(len(bodyBytes))
}

// getRequestSize estimates request size
func getRequestSize(c *gin.Context) int64 {
	size := int64(0)

	// Add content length if available
	if c.Request.ContentLength > 0 {
		size += c.Request.ContentLength
	}

	// Add header size estimation
	for key, values := range c.Request.Header {
		for _, value := range values {
			size += int64(len(key) + len(value) + 4) // +4 for ": " and "\r\n"
		}
	}

	// Add URL size
	size += int64(len(c.Request.URL.String()))

	return size
}

// filterHeaders filters out sensitive headers
func filterHeaders(headers http.Header, sensitiveHeaders []string) map[string]string {
	filtered := make(map[string]string)
	sensitive := make(map[string]bool)

	for _, header := range sensitiveHeaders {
		sensitive[strings.ToLower(header)] = true
	}

	for key, values := range headers {
		if sensitive[strings.ToLower(key)] {
			filtered[key] = "[REDACTED]"
		} else {
			filtered[key] = strings.Join(values, ", ")
		}
	}

	return filtered
}

// redactSensitiveQuery redacts sensitive data from query string
func redactSensitiveQuery(query string, redactFields []string) string {
	values, err := url.ParseQuery(query)
	if err != nil {
		return query
	}

	redactMap := make(map[string]bool)
	for _, field := range redactFields {
		redactMap[strings.ToLower(field)] = true
	}

	for key := range values {
		if redactMap[strings.ToLower(key)] {
			values[key] = []string{"[REDACTED]"}
		}
	}

	return values.Encode()
}

// redactSensitiveData redacts sensitive data from JSON
func redactSensitiveData(data string, redactFields []string) string {
	if data == "" {
		return data
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &jsonData); err != nil {
		return data // Return original if not JSON
	}

	redactMap := make(map[string]bool)
	for _, field := range redactFields {
		redactMap[strings.ToLower(field)] = true
	}

	redactJSONFields(jsonData, redactMap)

	redacted, err := json.Marshal(jsonData)
	if err != nil {
		return data
	}

	return string(redacted)
}

// redactJSONFields recursively redacts sensitive fields in JSON
func redactJSONFields(data interface{}, redactMap map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if redactMap[strings.ToLower(key)] {
				v[key] = "[REDACTED]"
			} else {
				redactJSONFields(value, redactMap)
			}
		}
	case []interface{}:
		for _, item := range v {
			redactJSONFields(item, redactMap)
		}
	}
}

// shouldLogBody determines if request body should be logged
func shouldLogBody(req *http.Request) bool {
	// Don't log body for GET, HEAD, OPTIONS requests
	if req.Method == "GET" || req.Method == "HEAD" || req.Method == "OPTIONS" {
		return false
	}

	// Don't log binary content
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/octet-stream") ||
		strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") {
		return false
	}

	return true
}

// extractExtraContext extracts additional context from request
func extractExtraContext(c *gin.Context) map[string]interface{} {
	extra := make(map[string]interface{})

	// Add rate limit info if available
	if rateLimitInfo, exists := c.Get("rate_limit_info"); exists {
		extra["rate_limit"] = rateLimitInfo
	}

	// Add cache info if available
	if cacheInfo, exists := c.Get("cache_info"); exists {
		extra["cache"] = cacheInfo
	}

	// Add feature flags if available
	if features, exists := c.Get("feature_flags"); exists {
		extra["features"] = features
	}

	return extra
}

// logEntry logs the entry using the configured logger
func logEntry(logger LoggerInterface, entry *LogEntry) {
	if logger == nil {
		return
	}

	fields := map[string]interface{}{
		"request_id":    entry.RequestID,
		"timestamp":     entry.Timestamp,
		"method":        entry.Method,
		"path":          entry.Path,
		"status":        entry.StatusCode,
		"duration":      entry.Duration.Milliseconds(),
		"client_ip":     entry.ClientIP,
		"user_agent":    entry.UserAgent,
		"request_size":  entry.RequestSize,
		"response_size": entry.ResponseSize,
	}

	if entry.Query != "" {
		fields["query"] = entry.Query
	}

	if entry.UserID != "" {
		fields["user_id"] = entry.UserID
	}

	if entry.SessionID != "" {
		fields["session_id"] = entry.SessionID
	}

	if entry.Headers != nil {
		fields["headers"] = entry.Headers
	}

	if entry.RequestBody != "" {
		fields["request_body"] = entry.RequestBody
	}

	if entry.ResponseBody != "" {
		fields["response_body"] = entry.ResponseBody
	}

	if entry.Error != "" {
		fields["error"] = entry.Error
	}

	if entry.Extra != nil {
		for key, value := range entry.Extra {
			fields[key] = value
		}
	}

	message := fmt.Sprintf("%s %s %d %dms", entry.Method, entry.Path, entry.StatusCode, entry.Duration.Milliseconds())

	if entry.StatusCode >= 500 {
		logger.Error(message, fields)
	} else if entry.StatusCode >= 400 {
		logger.Warn(message, fields)
	} else {
		logger.Info(message, fields)
	}
}

// isSecurityRelevant checks if request is security relevant
func isSecurityRelevant(c *gin.Context) bool {
	path := c.Request.URL.Path

	securityPaths := []string{
		"/api/auth/",
		"/api/admin/",
		"/api/users/me",
		"/api/settings/",
	}

	for _, secPath := range securityPaths {
		if strings.HasPrefix(path, secPath) {
			return true
		}
	}

	return false
}

// getSessionID gets session ID from context
func getSessionID(c *gin.Context) string {
	if sessionID, exists := c.Get("session_id"); exists {
		if id, ok := sessionID.(string); ok {
			return id
		}
	}
	return ""
}

// getRequestID gets request ID from context
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}
