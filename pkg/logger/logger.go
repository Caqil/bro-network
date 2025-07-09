package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Logger represents the application logger
type Logger struct {
	*logrus.Logger
	config *Config
}

// Config represents logger configuration
type Config struct {
	Level            string                 `json:"level" mapstructure:"level"`
	Format           string                 `json:"format" mapstructure:"format"` // json, text
	Output           string                 `json:"output" mapstructure:"output"` // stdout, file, both
	FilePath         string                 `json:"file_path" mapstructure:"file_path"`
	MaxSize          int                    `json:"max_size" mapstructure:"max_size"` // MB
	MaxBackups       int                    `json:"max_backups" mapstructure:"max_backups"`
	MaxAge           int                    `json:"max_age" mapstructure:"max_age"` // days
	Compress         bool                   `json:"compress" mapstructure:"compress"`
	EnableCaller     bool                   `json:"enable_caller" mapstructure:"enable_caller"`
	EnableStacktrace bool                   `json:"enable_stacktrace" mapstructure:"enable_stacktrace"`
	Fields           map[string]interface{} `json:"fields" mapstructure:"fields"`
	Hooks            []string               `json:"hooks" mapstructure:"hooks"`
}

// ContextKey represents context keys for logger
type ContextKey string

const (
	// Context keys
	RequestIDKey   ContextKey = "request_id"
	UserIDKey      ContextKey = "user_id"
	CorrelationKey ContextKey = "correlation_id"
	SessionKey     ContextKey = "session_id"
	IPAddressKey   ContextKey = "ip_address"
	UserAgentKey   ContextKey = "user_agent"

	// Log levels
	PanicLevel = "panic"
	FatalLevel = "fatal"
	ErrorLevel = "error"
	WarnLevel  = "warn"
	InfoLevel  = "info"
	DebugLevel = "debug"
	TraceLevel = "trace"
)

// Fields represents log fields
type Fields map[string]interface{}

var (
	// Default logger instance
	defaultLogger *Logger

	// Default configuration
	defaultConfig = &Config{
		Level:            InfoLevel,
		Format:           "json",
		Output:           "stdout",
		EnableCaller:     true,
		EnableStacktrace: false,
		Fields:           make(map[string]interface{}),
	}
)

// NewLogger creates a new logger instance
func NewLogger(config *Config) *Logger {
	if config == nil {
		config = defaultConfig
	}

	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set formatter
	if config.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05.000",
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})
	}

	// Set output
	switch config.Output {
	case "file":
		if config.FilePath != "" {
			file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				logger.SetOutput(file)
			}
		}
	case "both":
		if config.FilePath != "" {
			file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				logger.SetOutput(io.MultiWriter(os.Stdout, file))
			}
		}
	default:
		logger.SetOutput(os.Stdout)
	}

	// Enable caller reporting
	if config.EnableCaller {
		logger.SetReportCaller(true)
	}

	return &Logger{
		Logger: logger,
		config: config,
	}
}

// Init initializes the default logger
func Init(config *Config) {
	defaultLogger = NewLogger(config)
}

// GetLogger returns the default logger
func GetLogger() *Logger {
	if defaultLogger == nil {
		defaultLogger = NewLogger(nil)
	}
	return defaultLogger
}

// WithContext creates a logger with context fields
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.WithFields(Fields{})

	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		entry = entry.WithField("request_id", requestID)
	}

	if userID := ctx.Value(UserIDKey); userID != nil {
		entry = entry.WithField("user_id", userID)
	}

	if correlationID := ctx.Value(CorrelationKey); correlationID != nil {
		entry = entry.WithField("correlation_id", correlationID)
	}

	if sessionID := ctx.Value(SessionKey); sessionID != nil {
		entry = entry.WithField("session_id", sessionID)
	}

	if ipAddress := ctx.Value(IPAddressKey); ipAddress != nil {
		entry = entry.WithField("ip_address", ipAddress)
	}

	if userAgent := ctx.Value(UserAgentKey); userAgent != nil {
		entry = entry.WithField("user_agent", userAgent)
	}

	return entry
}

// WithFields creates a logger with custom fields
func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// WithField creates a logger with a single field
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithError creates a logger with error field
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithUserID creates a logger with user ID field
func (l *Logger) WithUserID(userID primitive.ObjectID) *logrus.Entry {
	return l.WithField("user_id", userID.Hex())
}

// WithRequestID creates a logger with request ID field
func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.WithField("request_id", requestID)
}

// Debug logs debug level messages
func (l *Logger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

// Debugf logs debug level formatted messages
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

// Info logs info level messages
func (l *Logger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

// Infof logs info level formatted messages
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

// Warn logs warning level messages
func (l *Logger) Warn(args ...interface{}) {
	l.Logger.Warn(args...)
}

// Warnf logs warning level formatted messages
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

// Error logs error level messages
func (l *Logger) Error(args ...interface{}) {
	l.Logger.Error(args...)
}

// Errorf logs error level formatted messages
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

// Fatal logs fatal level messages and exits
func (l *Logger) Fatal(args ...interface{}) {
	l.Logger.Fatal(args...)
}

// Fatalf logs fatal level formatted messages and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

// Panic logs panic level messages and panics
func (l *Logger) Panic(args ...interface{}) {
	l.Logger.Panic(args...)
}

// Panicf logs panic level formatted messages and panics
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.Logger.Panicf(format, args...)
}

// LogRequest logs HTTP request information
func (l *Logger) LogRequest(c *gin.Context, duration time.Duration, statusCode int) {
	entry := l.WithFields(Fields{
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"query":      c.Request.URL.RawQuery,
		"ip":         c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"status":     statusCode,
		"duration":   duration.String(),
		"size":       c.Writer.Size(),
	})

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		entry = entry.WithField("request_id", requestID)
	}

	// Add user ID if available
	if userID := c.GetString("user_id"); userID != "" {
		entry = entry.WithField("user_id", userID)
	}

	// Log based on status code
	switch {
	case statusCode >= 500:
		entry.Error("Server error")
	case statusCode >= 400:
		entry.Warn("Client error")
	case statusCode >= 300:
		entry.Info("Redirect")
	default:
		entry.Info("Request completed")
	}
}

// LogError logs application errors with context
func (l *Logger) LogError(ctx context.Context, err error, message string, fields Fields) {
	entry := l.WithContext(ctx).WithError(err)

	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}

	// Add stack trace for debugging
	if l.config.EnableStacktrace {
		entry = entry.WithField("stack", getStackTrace())
	}

	entry.Error(message)
}

// LogDBQuery logs database query information
func (l *Logger) LogDBQuery(operation, collection string, duration time.Duration, err error) {
	entry := l.WithFields(Fields{
		"operation":  operation,
		"collection": collection,
		"duration":   duration.String(),
	})

	if err != nil {
		entry.WithError(err).Error("Database query failed")
	} else {
		entry.Debug("Database query completed")
	}
}

// LogCacheOperation logs cache operation information
func (l *Logger) LogCacheOperation(operation, key string, hit bool, duration time.Duration) {
	l.WithFields(Fields{
		"operation": operation,
		"key":       key,
		"hit":       hit,
		"duration":  duration.String(),
	}).Debug("Cache operation")
}

// LogUserAction logs user actions for audit trail
func (l *Logger) LogUserAction(userID primitive.ObjectID, action, resource string, details map[string]interface{}) {
	fields := Fields{
		"user_id":  userID.Hex(),
		"action":   action,
		"resource": resource,
	}

	for k, v := range details {
		fields[k] = v
	}

	l.WithFields(fields).Info("User action")
}

// LogSecurityEvent logs security-related events
func (l *Logger) LogSecurityEvent(eventType, userID, ipAddress string, details Fields) {
	entry := l.WithFields(Fields{
		"event_type": eventType,
		"user_id":    userID,
		"ip_address": ipAddress,
		"category":   "security",
	})

	if details != nil {
		entry = entry.WithFields(logrus.Fields(details))
	}

	entry.Warn("Security event")
}

// LogPerformanceMetric logs performance metrics
func (l *Logger) LogPerformanceMetric(metric string, value float64, unit string, tags map[string]string) {
	fields := Fields{
		"metric": metric,
		"value":  value,
		"unit":   unit,
		"type":   "performance",
	}

	for k, v := range tags {
		fields[k] = v
	}

	l.WithFields(fields).Info("Performance metric")
}

// LogBusinessEvent logs business logic events
func (l *Logger) LogBusinessEvent(event string, userID primitive.ObjectID, data map[string]interface{}) {
	fields := Fields{
		"event":    event,
		"user_id":  userID.Hex(),
		"category": "business",
	}

	for k, v := range data {
		fields[k] = v
	}

	l.WithFields(fields).Info("Business event")
}

// Global logger functions for convenience
func Debug(args ...interface{}) {
	GetLogger().Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

func Info(args ...interface{}) {
	GetLogger().Info(args...)
}

func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

func Warn(args ...interface{}) {
	GetLogger().Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

func Error(args ...interface{}) {
	GetLogger().Error(args...)
}

func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

func Fatal(args ...interface{}) {
	GetLogger().Fatal(args...)
}

func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}

func WithContext(ctx context.Context) *logrus.Entry {
	return GetLogger().WithContext(ctx)
}

func WithFields(fields Fields) *logrus.Entry {
	return GetLogger().WithFields(fields)
}

func WithField(key string, value interface{}) *logrus.Entry {
	return GetLogger().WithField(key, value)
}

func WithError(err error) *logrus.Entry {
	return GetLogger().WithError(err)
}

func WithUserID(userID primitive.ObjectID) *logrus.Entry {
	return GetLogger().WithUserID(userID)
}

func WithRequestID(requestID string) *logrus.Entry {
	return GetLogger().WithRequestID(requestID)
}

func LogRequest(c *gin.Context, duration time.Duration, statusCode int) {
	GetLogger().LogRequest(c, duration, statusCode)
}

func LogError(ctx context.Context, err error, message string, fields Fields) {
	GetLogger().LogError(ctx, err, message, fields)
}

func LogDBQuery(operation, collection string, duration time.Duration, err error) {
	GetLogger().LogDBQuery(operation, collection, duration, err)
}

func LogCacheOperation(operation, key string, hit bool, duration time.Duration) {
	GetLogger().LogCacheOperation(operation, key, hit, duration)
}

func LogUserAction(userID primitive.ObjectID, action, resource string, details map[string]interface{}) {
	GetLogger().LogUserAction(userID, action, resource, details)
}

func LogSecurityEvent(eventType, userID, ipAddress string, details Fields) {
	GetLogger().LogSecurityEvent(eventType, userID, ipAddress, details)
}

func LogPerformanceMetric(metric string, value float64, unit string, tags map[string]string) {
	GetLogger().LogPerformanceMetric(metric, value, unit, tags)
}

func LogBusinessEvent(event string, userID primitive.ObjectID, data map[string]interface{}) {
	GetLogger().LogBusinessEvent(event, userID, data)
}

// Helper functions

// getStackTrace returns the current stack trace
func getStackTrace() string {
	var lines []string
	for i := 2; i <= 10; i++ { // Skip getStackTrace and the calling function
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		lines = append(lines, fmt.Sprintf("%s:%d", filepath.Base(file), line))
	}
	return strings.Join(lines, " -> ")
}

// StructuredError represents a structured error for logging
type StructuredError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Stack   string                 `json:"stack,omitempty"`
}

// NewStructuredError creates a new structured error
func NewStructuredError(code, message string, details map[string]interface{}) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: message,
		Details: details,
		Stack:   getStackTrace(),
	}
}

// Error implements the error interface
func (e *StructuredError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// GinLogger returns a gin middleware for request logging
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request
		end := time.Now()
		duration := end.Sub(start)
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		GetLogger().LogRequest(c, duration, statusCode)
	}
}

// ContextMiddleware adds logging context to gin context
func ContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = primitive.NewObjectID().Hex()
			c.Header("X-Request-ID", requestID)
		}

		// Store context values
		c.Set("request_id", requestID)

		// Create context with logging fields
		ctx := context.WithValue(c.Request.Context(), RequestIDKey, requestID)
		ctx = context.WithValue(ctx, IPAddressKey, c.ClientIP())
		ctx = context.WithValue(ctx, UserAgentKey, c.Request.UserAgent())

		// Update request context
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
