package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success   bool          `json:"success"`
	Message   string        `json:"message,omitempty"`
	Data      interface{}   `json:"data,omitempty"`
	Error     *ErrorDetail  `json:"error,omitempty"`
	Meta      *ResponseMeta `json:"meta,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	RequestID string        `json:"request_id,omitempty"`
	Version   string        `json:"version,omitempty"`
}

// ErrorDetail represents detailed error information
type ErrorDetail struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Details    string            `json:"details,omitempty"`
	Field      string            `json:"field,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Validation []ValidationError `json:"validation,omitempty"`
	Internal   string            `json:"internal,omitempty"`
	Stack      string            `json:"stack,omitempty"`
	Help       string            `json:"help,omitempty"`
	Docs       string            `json:"docs,omitempty"`
}

// ValidationError represents field validation errors
type ValidationError struct {
	Field   string      `json:"field"`
	Rule    string      `json:"rule"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ResponseMeta represents metadata for API responses
type ResponseMeta struct {
	Pagination *PaginationResult `json:"pagination,omitempty"`
	Filters    interface{}       `json:"filters,omitempty"`
	Sort       interface{}       `json:"sort,omitempty"`
	Stats      interface{}       `json:"stats,omitempty"`
	Cache      *CacheInfo        `json:"cache,omitempty"`
	RateLimit  *RateLimitInfo    `json:"rate_limit,omitempty"`
	Debug      *DebugInfo        `json:"debug,omitempty"`
}

// CacheInfo represents cache information
type CacheInfo struct {
	Hit       bool      `json:"hit"`
	Key       string    `json:"key,omitempty"`
	TTL       int64     `json:"ttl,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// RateLimitInfo represents rate limiting information
type RateLimitInfo struct {
	Limit     int64     `json:"limit"`
	Remaining int64     `json:"remaining"`
	Reset     time.Time `json:"reset"`
	Window    string    `json:"window"`
}

// DebugInfo represents debug information (only in development)
type DebugInfo struct {
	QueryTime    time.Duration     `json:"query_time,omitempty"`
	DBQueries    int               `json:"db_queries,omitempty"`
	MemoryUsage  int64             `json:"memory_usage,omitempty"`
	RequestSize  int64             `json:"request_size,omitempty"`
	ResponseSize int64             `json:"response_size,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Environment  string            `json:"environment,omitempty"`
}

// StatusResponse represents a simple status response
type StatusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string                   `json:"status"`
	Version   string                   `json:"version"`
	Timestamp time.Time                `json:"timestamp"`
	Uptime    time.Duration            `json:"uptime"`
	Services  map[string]ServiceHealth `json:"services"`
	System    *SystemHealth            `json:"system,omitempty"`
}

// ServiceHealth represents individual service health
type ServiceHealth struct {
	Status       string        `json:"status"`
	ResponseTime time.Duration `json:"response_time,omitempty"`
	LastCheck    time.Time     `json:"last_check"`
	Error        string        `json:"error,omitempty"`
	Version      string        `json:"version,omitempty"`
}

// SystemHealth represents system health metrics
type SystemHealth struct {
	CPU            float64 `json:"cpu_usage"`
	Memory         float64 `json:"memory_usage"`
	Disk           float64 `json:"disk_usage"`
	Connections    int     `json:"active_connections"`
	Goroutines     int     `json:"goroutines"`
	RequestsPerSec float64 `json:"requests_per_sec"`
}

// Common error codes
const (
	ErrorCodeValidation         = "VALIDATION_ERROR"
	ErrorCodeAuthentication     = "AUTHENTICATION_ERROR"
	ErrorCodeAuthorization      = "AUTHORIZATION_ERROR"
	ErrorCodeNotFound           = "NOT_FOUND"
	ErrorCodeConflict           = "CONFLICT"
	ErrorCodeRateLimit          = "RATE_LIMIT_EXCEEDED"
	ErrorCodeInternalServer     = "INTERNAL_SERVER_ERROR"
	ErrorCodeBadRequest         = "BAD_REQUEST"
	ErrorCodeForbidden          = "FORBIDDEN"
	ErrorCodeUnprocessable      = "UNPROCESSABLE_ENTITY"
	ErrorCodeTooLarge           = "REQUEST_TOO_LARGE"
	ErrorCodeUnsupportedMedia   = "UNSUPPORTED_MEDIA_TYPE"
	ErrorCodeTimeout            = "REQUEST_TIMEOUT"
	ErrorCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// ResponseBuilder helps build standardized API responses
type ResponseBuilder struct {
	ctx       *gin.Context
	requestID string
	version   string
	debug     bool
}

// NewResponseBuilder creates a new response builder
func NewResponseBuilder(ctx *gin.Context) *ResponseBuilder {
	requestID := ctx.GetString("request_id")
	if requestID == "" {
		requestID = primitive.NewObjectID().Hex()
	}

	return &ResponseBuilder{
		ctx:       ctx,
		requestID: requestID,
		version:   ctx.GetString("api_version"),
		debug:     ctx.GetBool("debug_mode"),
	}
}

// Success sends a successful response
func (rb *ResponseBuilder) Success(data interface{}, message ...string) {
	msg := "Success"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}

	response := &APIResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		Timestamp: time.Now(),
		RequestID: rb.requestID,
		Version:   rb.version,
	}

	rb.addMeta(response)
	rb.ctx.JSON(http.StatusOK, response)
}

// Created sends a created response (201)
func (rb *ResponseBuilder) Created(data interface{}, message ...string) {
	msg := "Resource created successfully"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}

	response := &APIResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		Timestamp: time.Now(),
		RequestID: rb.requestID,
		Version:   rb.version,
	}

	rb.addMeta(response)
	rb.ctx.JSON(http.StatusCreated, response)
}

// NoContent sends a no content response (204)
func (rb *ResponseBuilder) NoContent() {
	rb.ctx.Status(http.StatusNoContent)
}

// Error sends an error response
func (rb *ResponseBuilder) Error(statusCode int, errorCode, message string, details ...interface{}) {
	errorDetail := &ErrorDetail{
		Code:    errorCode,
		Message: message,
	}

	// Add additional details if provided
	if len(details) > 0 {
		if detailStr, ok := details[0].(string); ok {
			errorDetail.Details = detailStr
		} else if validationErrors, ok := details[0].([]ValidationError); ok {
			errorDetail.Validation = validationErrors
		} else if fieldErrors, ok := details[0].(map[string]string); ok {
			errorDetail.Fields = fieldErrors
		}
	}

	response := &APIResponse{
		Success:   false,
		Error:     errorDetail,
		Timestamp: time.Now(),
		RequestID: rb.requestID,
		Version:   rb.version,
	}

	rb.addMeta(response)
	rb.ctx.JSON(statusCode, response)
}

// ValidationError sends a validation error response
func (rb *ResponseBuilder) ValidationError(errors []ValidationError, message ...string) {
	msg := "Validation failed"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}

	errorDetail := &ErrorDetail{
		Code:       ErrorCodeValidation,
		Message:    msg,
		Validation: errors,
	}

	response := &APIResponse{
		Success:   false,
		Error:     errorDetail,
		Timestamp: time.Now(),
		RequestID: rb.requestID,
		Version:   rb.version,
	}

	rb.addMeta(response)
	rb.ctx.JSON(http.StatusBadRequest, response)
}

// BadRequest sends a bad request error (400)
func (rb *ResponseBuilder) BadRequest(message string, details ...string) {
	detail := ""
	if len(details) > 0 {
		detail = details[0]
	}
	rb.Error(http.StatusBadRequest, ErrorCodeBadRequest, message, detail)
}

// Unauthorized sends an unauthorized error (401)
func (rb *ResponseBuilder) Unauthorized(message ...string) {
	msg := "Authentication required"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}
	rb.Error(http.StatusUnauthorized, ErrorCodeAuthentication, msg)
}

// Forbidden sends a forbidden error (403)
func (rb *ResponseBuilder) Forbidden(message ...string) {
	msg := "Access denied"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}
	rb.Error(http.StatusForbidden, ErrorCodeForbidden, msg)
}

// NotFound sends a not found error (404)
func (rb *ResponseBuilder) NotFound(resource ...string) {
	msg := "Resource not found"
	if len(resource) > 0 && resource[0] != "" {
		msg = fmt.Sprintf("%s not found", resource[0])
	}
	rb.Error(http.StatusNotFound, ErrorCodeNotFound, msg)
}

// Conflict sends a conflict error (409)
func (rb *ResponseBuilder) Conflict(message string, details ...string) {
	detail := ""
	if len(details) > 0 {
		detail = details[0]
	}
	rb.Error(http.StatusConflict, ErrorCodeConflict, message, detail)
}

// UnprocessableEntity sends an unprocessable entity error (422)
func (rb *ResponseBuilder) UnprocessableEntity(message string, details ...interface{}) {
	detail := interface{}(nil)
	if len(details) > 0 {
		detail = details[0]
	}
	rb.Error(http.StatusUnprocessableEntity, ErrorCodeUnprocessable, message, detail)
}

// TooManyRequests sends a rate limit error (429)
func (rb *ResponseBuilder) TooManyRequests(message ...string) {
	msg := "Rate limit exceeded"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}
	rb.Error(http.StatusTooManyRequests, ErrorCodeRateLimit, msg)
}

// InternalServerError sends an internal server error (500)
func (rb *ResponseBuilder) InternalServerError(message ...string) {
	msg := "Internal server error"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}
	rb.Error(http.StatusInternalServerError, ErrorCodeInternalServer, msg)
}

// ServiceUnavailable sends a service unavailable error (503)
func (rb *ResponseBuilder) ServiceUnavailable(message ...string) {
	msg := "Service temporarily unavailable"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}
	rb.Error(http.StatusServiceUnavailable, ErrorCodeServiceUnavailable, msg)
}

// Paginated sends a paginated response
func (rb *ResponseBuilder) Paginated(paginationResult *PaginationResult, message ...string) {
	msg := "Success"
	if len(message) > 0 && message[0] != "" {
		msg = message[0]
	}

	response := &APIResponse{
		Success:   true,
		Message:   msg,
		Data:      paginationResult.Data,
		Timestamp: time.Now(),
		RequestID: rb.requestID,
		Version:   rb.version,
		Meta: &ResponseMeta{
			Pagination: paginationResult,
		},
	}

	rb.addMeta(response)
	rb.ctx.JSON(http.StatusOK, response)
}

// WithMeta adds metadata to response
func (rb *ResponseBuilder) WithMeta(meta *ResponseMeta) *ResponseBuilder {
	rb.ctx.Set("response_meta", meta)
	return rb
}

// addMeta adds metadata to response
func (rb *ResponseBuilder) addMeta(response *APIResponse) {
	if response.Meta == nil {
		response.Meta = &ResponseMeta{}
	}

	// Add cache info if available
	if cacheInfo, exists := rb.ctx.Get("cache_info"); exists {
		if ci, ok := cacheInfo.(*CacheInfo); ok {
			response.Meta.Cache = ci
		}
	}

	// Add rate limit info if available
	if rateLimitInfo, exists := rb.ctx.Get("rate_limit_info"); exists {
		if rli, ok := rateLimitInfo.(*RateLimitInfo); ok {
			response.Meta.RateLimit = rli
		}
	}

	// Add debug info in development mode
	if rb.debug {
		response.Meta.Debug = rb.getDebugInfo()
	}

	// Merge with existing meta
	if existingMeta, exists := rb.ctx.Get("response_meta"); exists {
		if em, ok := existingMeta.(*ResponseMeta); ok {
			if em.Filters != nil {
				response.Meta.Filters = em.Filters
			}
			if em.Sort != nil {
				response.Meta.Sort = em.Sort
			}
			if em.Stats != nil {
				response.Meta.Stats = em.Stats
			}
		}
	}
}

// getDebugInfo collects debug information
func (rb *ResponseBuilder) getDebugInfo() *DebugInfo {
	debug := &DebugInfo{
		Environment: rb.ctx.GetString("environment"),
	}

	// Query time
	if startTime, exists := rb.ctx.Get("start_time"); exists {
		if st, ok := startTime.(time.Time); ok {
			debug.QueryTime = time.Since(st)
		}
	}

	// DB queries count
	if dbQueries, exists := rb.ctx.Get("db_queries"); exists {
		if dq, ok := dbQueries.(int); ok {
			debug.DBQueries = dq
		}
	}

	// Memory usage
	if memUsage, exists := rb.ctx.Get("memory_usage"); exists {
		if mu, ok := memUsage.(int64); ok {
			debug.MemoryUsage = mu
		}
	}

	return debug
}

// Helper functions for quick responses

// SendSuccess sends a quick success response
func SendSuccess(ctx *gin.Context, data interface{}, message ...string) {
	NewResponseBuilder(ctx).Success(data, message...)
}

// SendCreated sends a quick created response
func SendCreated(ctx *gin.Context, data interface{}, message ...string) {
	NewResponseBuilder(ctx).Created(data, message...)
}

// SendError sends a quick error response
func SendError(ctx *gin.Context, statusCode int, errorCode, message string, details ...interface{}) {
	NewResponseBuilder(ctx).Error(statusCode, errorCode, message, details...)
}

// SendBadRequest sends a quick bad request response
func SendBadRequest(ctx *gin.Context, message string, details ...string) {
	NewResponseBuilder(ctx).BadRequest(message, details...)
}

// SendUnauthorized sends a quick unauthorized response
func SendUnauthorized(ctx *gin.Context, message ...string) {
	NewResponseBuilder(ctx).Unauthorized(message...)
}

// SendForbidden sends a quick forbidden response
func SendForbidden(ctx *gin.Context, message ...string) {
	NewResponseBuilder(ctx).Forbidden(message...)
}

// SendNotFound sends a quick not found response
func SendNotFound(ctx *gin.Context, resource ...string) {
	NewResponseBuilder(ctx).NotFound(resource...)
}

// SendConflict sends a quick conflict response
func SendConflict(ctx *gin.Context, message string, details ...string) {
	NewResponseBuilder(ctx).Conflict(message, details...)
}

// SendInternalServerError sends a quick internal server error response
func SendInternalServerError(ctx *gin.Context, message ...string) {
	NewResponseBuilder(ctx).InternalServerError(message...)
}

// SendValidationError sends a quick validation error response
func SendValidationError(ctx *gin.Context, errors []ValidationError, message ...string) {
	NewResponseBuilder(ctx).ValidationError(errors, message...)
}

// SendPaginated sends a quick paginated response
func SendPaginated(ctx *gin.Context, paginationResult *PaginationResult, message ...string) {
	NewResponseBuilder(ctx).Paginated(paginationResult, message...)
}

// Health check responses

// SendHealthy sends a healthy status response
func SendHealthy(ctx *gin.Context, services map[string]ServiceHealth, system *SystemHealth) {
	response := &HealthResponse{
		Status:    "healthy",
		Version:   ctx.GetString("api_version"),
		Timestamp: time.Now(),
		Uptime:    time.Since(ctx.GetTime("start_time")),
		Services:  services,
		System:    system,
	}
	ctx.JSON(http.StatusOK, response)
}

// SendUnhealthy sends an unhealthy status response
func SendUnhealthy(ctx *gin.Context, services map[string]ServiceHealth, system *SystemHealth) {
	response := &HealthResponse{
		Status:    "unhealthy",
		Version:   ctx.GetString("api_version"),
		Timestamp: time.Now(),
		Uptime:    time.Since(ctx.GetTime("start_time")),
		Services:  services,
		System:    system,
	}
	ctx.JSON(http.StatusServiceUnavailable, response)
}

// Utility functions

// CreateValidationError creates a validation error
func CreateValidationError(field, rule, message string, value interface{}) ValidationError {
	return ValidationError{
		Field:   field,
		Rule:    rule,
		Message: message,
		Value:   value,
	}
}

// CreateValidationErrors creates multiple validation errors from a map
func CreateValidationErrors(fieldErrors map[string]string) []ValidationError {
	var errors []ValidationError
	for field, message := range fieldErrors {
		errors = append(errors, ValidationError{
			Field:   field,
			Message: message,
		})
	}
	return errors
}

// FormatValidationErrors formats validation errors from gin validation
func FormatValidationErrors(err error) []ValidationError {
	var errors []ValidationError

	// This would typically parse gin/validator errors
	// Implementation depends on your validation library

	return errors
}

// SetCacheInfo sets cache information in context
func SetCacheInfo(ctx *gin.Context, hit bool, key string, ttl int64) {
	cacheInfo := &CacheInfo{
		Hit: hit,
		Key: key,
		TTL: ttl,
	}

	if hit {
		cacheInfo.CreatedAt = time.Now().Add(-time.Duration(ttl) * time.Second)
	} else {
		cacheInfo.CreatedAt = time.Now()
	}

	cacheInfo.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	ctx.Set("cache_info", cacheInfo)
}

// SetRateLimitInfo sets rate limit information in context
func SetRateLimitInfo(ctx *gin.Context, limit, remaining int64, reset time.Time, window string) {
	rateLimitInfo := &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		Reset:     reset,
		Window:    window,
	}
	ctx.Set("rate_limit_info", rateLimitInfo)
}

// GetResponseSize calculates response size for debugging
func GetResponseSize(data interface{}) int64 {
	if data == nil {
		return 0
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0
	}

	return int64(len(jsonData))
}

// SetDebugInfo sets debug information in context
func SetDebugInfo(ctx *gin.Context, key string, value interface{}) {
	ctx.Set(key, value)
}

// IsSuccessStatusCode checks if status code indicates success
func IsSuccessStatusCode(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// GetErrorCodeFromStatus returns appropriate error code for HTTP status
func GetErrorCodeFromStatus(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return ErrorCodeBadRequest
	case http.StatusUnauthorized:
		return ErrorCodeAuthentication
	case http.StatusForbidden:
		return ErrorCodeForbidden
	case http.StatusNotFound:
		return ErrorCodeNotFound
	case http.StatusConflict:
		return ErrorCodeConflict
	case http.StatusUnprocessableEntity:
		return ErrorCodeUnprocessable
	case http.StatusTooManyRequests:
		return ErrorCodeRateLimit
	case http.StatusRequestEntityTooLarge:
		return ErrorCodeTooLarge
	case http.StatusUnsupportedMediaType:
		return ErrorCodeUnsupportedMedia
	case http.StatusRequestTimeout:
		return ErrorCodeTimeout
	case http.StatusServiceUnavailable:
		return ErrorCodeServiceUnavailable
	case http.StatusInternalServerError:
		fallthrough
	default:
		return ErrorCodeInternalServer
	}
}
