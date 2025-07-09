package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ErrorType represents different types of errors
type ErrorType string

const (
	// General error types
	ErrorTypeValidation     ErrorType = "validation_error"
	ErrorTypeAuthentication ErrorType = "authentication_error"
	ErrorTypeAuthorization  ErrorType = "authorization_error"
	ErrorTypeNotFound       ErrorType = "not_found_error"
	ErrorTypeConflict       ErrorType = "conflict_error"
	ErrorTypeRateLimit      ErrorType = "rate_limit_error"
	ErrorTypeInternal       ErrorType = "internal_error"
	ErrorTypeExternal       ErrorType = "external_error"
	ErrorTypeNetwork        ErrorType = "network_error"
	ErrorTypeDatabase       ErrorType = "database_error"
	ErrorTypeCache          ErrorType = "cache_error"
	ErrorTypeStorage        ErrorType = "storage_error"
	ErrorTypeBusiness       ErrorType = "business_error"
	ErrorTypeTimeout        ErrorType = "timeout_error"
	ErrorTypeUnavailable    ErrorType = "service_unavailable_error"
)

// ErrorCode represents specific error codes
type ErrorCode string

const (
	// Authentication errors
	CodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	CodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	CodeTokenInvalid       ErrorCode = "TOKEN_INVALID"
	CodeAccountLocked      ErrorCode = "ACCOUNT_LOCKED"
	CodeAccountDisabled    ErrorCode = "ACCOUNT_DISABLED"
	CodeTwoFactorRequired  ErrorCode = "TWO_FACTOR_REQUIRED"
	CodeTwoFactorInvalid   ErrorCode = "TWO_FACTOR_INVALID"

	// Authorization errors
	CodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"
	CodeAccessDenied            ErrorCode = "ACCESS_DENIED"
	CodeResourceForbidden       ErrorCode = "RESOURCE_FORBIDDEN"
	CodeAdminRequired           ErrorCode = "ADMIN_REQUIRED"

	// Validation errors
	CodeValidationFailed     ErrorCode = "VALIDATION_FAILED"
	CodeRequiredFieldMissing ErrorCode = "REQUIRED_FIELD_MISSING"
	CodeInvalidFieldFormat   ErrorCode = "INVALID_FIELD_FORMAT"
	CodeFieldTooLong         ErrorCode = "FIELD_TOO_LONG"
	CodeFieldTooShort        ErrorCode = "FIELD_TOO_SHORT"
	CodeInvalidEmail         ErrorCode = "INVALID_EMAIL"
	CodeInvalidPhone         ErrorCode = "INVALID_PHONE"
	CodeInvalidURL           ErrorCode = "INVALID_URL"
	CodeInvalidDate          ErrorCode = "INVALID_DATE"

	// Resource errors
	CodeUserNotFound         ErrorCode = "USER_NOT_FOUND"
	CodePostNotFound         ErrorCode = "POST_NOT_FOUND"
	CodeCommentNotFound      ErrorCode = "COMMENT_NOT_FOUND"
	CodeMessageNotFound      ErrorCode = "MESSAGE_NOT_FOUND"
	CodeConversationNotFound ErrorCode = "CONVERSATION_NOT_FOUND"
	CodeNotificationNotFound ErrorCode = "NOTIFICATION_NOT_FOUND"
	CodeFileNotFound         ErrorCode = "FILE_NOT_FOUND"

	// Conflict errors
	CodeEmailExists      ErrorCode = "EMAIL_EXISTS"
	CodeUsernameExists   ErrorCode = "USERNAME_EXISTS"
	CodePhoneExists      ErrorCode = "PHONE_EXISTS"
	CodeAlreadyFollowing ErrorCode = "ALREADY_FOLLOWING"
	CodeAlreadyLiked     ErrorCode = "ALREADY_LIKED"
	CodeAlreadyExists    ErrorCode = "ALREADY_EXISTS"

	// Business logic errors
	CodeCannotFollowSelf  ErrorCode = "CANNOT_FOLLOW_SELF"
	CodeCannotLikeOwnPost ErrorCode = "CANNOT_LIKE_OWN_POST"
	CodePrivateAccount    ErrorCode = "PRIVATE_ACCOUNT"
	CodeBlockedUser       ErrorCode = "BLOCKED_USER"
	CodeInactiveUser      ErrorCode = "INACTIVE_USER"
	CodeContentDeleted    ErrorCode = "CONTENT_DELETED"
	CodeContentHidden     ErrorCode = "CONTENT_HIDDEN"

	// File upload errors
	CodeFileTooLarge     ErrorCode = "FILE_TOO_LARGE"
	CodeInvalidFileType  ErrorCode = "INVALID_FILE_TYPE"
	CodeUploadFailed     ErrorCode = "UPLOAD_FAILED"
	CodeProcessingFailed ErrorCode = "PROCESSING_FAILED"
	CodeStorageFull      ErrorCode = "STORAGE_FULL"

	// Rate limiting errors
	CodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"
	CodeTooManyRequests   ErrorCode = "TOO_MANY_REQUESTS"
	CodeQuotaExceeded     ErrorCode = "QUOTA_EXCEEDED"

	// System errors
	CodeInternalError        ErrorCode = "INTERNAL_ERROR"
	CodeDatabaseError        ErrorCode = "DATABASE_ERROR"
	CodeCacheError           ErrorCode = "CACHE_ERROR"
	CodeExternalServiceError ErrorCode = "EXTERNAL_SERVICE_ERROR"
	CodeNetworkError         ErrorCode = "NETWORK_ERROR"
	CodeTimeoutError         ErrorCode = "TIMEOUT_ERROR"
	CodeServiceUnavailable   ErrorCode = "SERVICE_UNAVAILABLE"
	CodeMaintenanceMode      ErrorCode = "MAINTENANCE_MODE"
)

// AppError represents a custom application error
type AppError struct {
	Type       ErrorType              `json:"type"`
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Field      string                 `json:"field,omitempty"`
	Fields     map[string]string      `json:"fields,omitempty"`
	Validation []ValidationError      `json:"validation,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	StatusCode int                    `json:"status_code"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
	UserID     primitive.ObjectID     `json:"user_id,omitempty"`
	Internal   error                  `json:"-"` // Internal error (not exposed)
	Stack      string                 `json:"stack,omitempty"`
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string      `json:"field"`
	Rule    string      `json:"rule"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// WithField adds a field context to the error
func (e *AppError) WithField(field string) *AppError {
	e.Field = field
	return e
}

// WithFields adds multiple field errors
func (e *AppError) WithFields(fields map[string]string) *AppError {
	e.Fields = fields
	return e
}

// WithValidation adds validation errors
func (e *AppError) WithValidation(validation []ValidationError) *AppError {
	e.Validation = validation
	return e
}

// WithDetails adds additional details
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// WithMetadata adds metadata to the error
func (e *AppError) WithMetadata(metadata map[string]interface{}) *AppError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	for k, v := range metadata {
		e.Metadata[k] = v
	}
	return e
}

// WithRequestID adds request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds user ID to the error
func (e *AppError) WithUserID(userID primitive.ObjectID) *AppError {
	e.UserID = userID
	return e
}

// WithInternal adds internal error details
func (e *AppError) WithInternal(err error) *AppError {
	e.Internal = err
	return e
}

// NewAppError creates a new application error
func NewAppError(errorType ErrorType, code ErrorCode, message string, statusCode int) *AppError {
	return &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Timestamp:  time.Now(),
		Stack:      getCallerInfo(),
	}
}

// Predefined error constructors

// NewValidationError creates a validation error
func NewValidationError(message string, fields map[string]string) *AppError {
	return NewAppError(
		ErrorTypeValidation,
		CodeValidationFailed,
		message,
		http.StatusBadRequest,
	).WithFields(fields)
}

// NewValidationErrorWithDetails creates a validation error with validation details
func NewValidationErrorWithDetails(message string, validation []ValidationError) *AppError {
	return NewAppError(
		ErrorTypeValidation,
		CodeValidationFailed,
		message,
		http.StatusBadRequest,
	).WithValidation(validation)
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(code ErrorCode, message string) *AppError {
	return NewAppError(
		ErrorTypeAuthentication,
		code,
		message,
		http.StatusUnauthorized,
	)
}

// NewAuthorizationError creates an authorization error
func NewAuthorizationError(code ErrorCode, message string) *AppError {
	return NewAppError(
		ErrorTypeAuthorization,
		code,
		message,
		http.StatusForbidden,
	)
}

// NewNotFoundError creates a not found error
func NewNotFoundError(code ErrorCode, message string) *AppError {
	return NewAppError(
		ErrorTypeNotFound,
		code,
		message,
		http.StatusNotFound,
	)
}

// NewConflictError creates a conflict error
func NewConflictError(code ErrorCode, message string) *AppError {
	return NewAppError(
		ErrorTypeConflict,
		code,
		message,
		http.StatusConflict,
	)
}

// NewRateLimitError creates a rate limit error
func NewRateLimitError(message string) *AppError {
	return NewAppError(
		ErrorTypeRateLimit,
		CodeRateLimitExceeded,
		message,
		http.StatusTooManyRequests,
	)
}

// NewInternalError creates an internal server error
func NewInternalError(message string, internal error) *AppError {
	return NewAppError(
		ErrorTypeInternal,
		CodeInternalError,
		message,
		http.StatusInternalServerError,
	).WithInternal(internal)
}

// NewDatabaseError creates a database error
func NewDatabaseError(message string, internal error) *AppError {
	return NewAppError(
		ErrorTypeDatabase,
		CodeDatabaseError,
		message,
		http.StatusInternalServerError,
	).WithInternal(internal)
}

// NewExternalError creates an external service error
func NewExternalError(message string, internal error) *AppError {
	return NewAppError(
		ErrorTypeExternal,
		CodeExternalServiceError,
		message,
		http.StatusBadGateway,
	).WithInternal(internal)
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(message string) *AppError {
	return NewAppError(
		ErrorTypeTimeout,
		CodeTimeoutError,
		message,
		http.StatusRequestTimeout,
	)
}

// NewServiceUnavailableError creates a service unavailable error
func NewServiceUnavailableError(message string) *AppError {
	return NewAppError(
		ErrorTypeUnavailable,
		CodeServiceUnavailable,
		message,
		http.StatusServiceUnavailable,
	)
}

// Specific business logic errors

// NewUserNotFoundError creates a user not found error
func NewUserNotFoundError(userID string) *AppError {
	return NewNotFoundError(
		CodeUserNotFound,
		fmt.Sprintf("User with ID '%s' not found", userID),
	)
}

// NewPostNotFoundError creates a post not found error
func NewPostNotFoundError(postID string) *AppError {
	return NewNotFoundError(
		CodePostNotFound,
		fmt.Sprintf("Post with ID '%s' not found", postID),
	)
}

// NewEmailExistsError creates an email exists error
func NewEmailExistsError(email string) *AppError {
	return NewConflictError(
		CodeEmailExists,
		fmt.Sprintf("Email '%s' is already registered", email),
	)
}

// NewUsernameExistsError creates a username exists error
func NewUsernameExistsError(username string) *AppError {
	return NewConflictError(
		CodeUsernameExists,
		fmt.Sprintf("Username '%s' is already taken", username),
	)
}

// NewInvalidCredentialsError creates invalid credentials error
func NewInvalidCredentialsError() *AppError {
	return NewAuthenticationError(
		CodeInvalidCredentials,
		"Invalid email/username or password",
	)
}

// NewTokenExpiredError creates token expired error
func NewTokenExpiredError() *AppError {
	return NewAuthenticationError(
		CodeTokenExpired,
		"Authentication token has expired",
	)
}

// NewInsufficientPermissionsError creates insufficient permissions error
func NewInsufficientPermissionsError(action string) *AppError {
	return NewAuthorizationError(
		CodeInsufficientPermissions,
		fmt.Sprintf("Insufficient permissions to %s", action),
	)
}

// NewBlockedUserError creates blocked user error
func NewBlockedUserError() *AppError {
	return NewAuthorizationError(
		CodeBlockedUser,
		"Cannot perform this action because you have been blocked",
	)
}

// NewPrivateAccountError creates private account error
func NewPrivateAccountError() *AppError {
	return NewAuthorizationError(
		CodePrivateAccount,
		"This account is private",
	)
}

// NewFileTooLargeError creates file too large error
func NewFileTooLargeError(maxSize string) *AppError {
	return NewValidationError(
		fmt.Sprintf("File size exceeds maximum allowed size of %s", maxSize),
		map[string]string{"file": "File too large"},
	)
}

// NewInvalidFileTypeError creates invalid file type error
func NewInvalidFileTypeError(allowedTypes []string) *AppError {
	return NewValidationError(
		fmt.Sprintf("Invalid file type. Allowed types: %s", strings.Join(allowedTypes, ", ")),
		map[string]string{"file": "Invalid file type"},
	)
}

// Error wrapping and unwrapping

// Wrap wraps an error with additional context
func Wrap(err error, code ErrorCode, message string) *AppError {
	if appErr, ok := err.(*AppError); ok {
		// If it's already an AppError, preserve the original but add context
		appErr.Details = message
		return appErr
	}

	return NewInternalError(message, err).WithInternal(err)
}

// WrapWithType wraps an error with a specific type
func WrapWithType(err error, errorType ErrorType, code ErrorCode, message string, statusCode int) *AppError {
	return NewAppError(errorType, code, message, statusCode).WithInternal(err)
}

// Unwrap returns the underlying error
func Unwrap(err error) error {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Internal
	}
	return err
}

// Is checks if the error is of a specific type
func Is(err error, errorType ErrorType) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
}

// HasCode checks if the error has a specific code
func HasCode(err error, code ErrorCode) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == code
	}
	return false
}

// GetStatusCode returns the HTTP status code for an error
func GetStatusCode(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.StatusCode
	}
	return http.StatusInternalServerError
}

// ToJSON converts error to JSON format
func ToJSON(err error) ([]byte, error) {
	if appErr, ok := err.(*AppError); ok {
		return json.Marshal(appErr)
	}

	// Convert generic error to AppError
	appErr := NewInternalError(err.Error(), err)
	return json.Marshal(appErr)
}

// FromJSON creates an AppError from JSON
func FromJSON(data []byte) (*AppError, error) {
	var appErr AppError
	err := json.Unmarshal(data, &appErr)
	if err != nil {
		return nil, err
	}
	return &appErr, nil
}

// Error collection for handling multiple errors

// ErrorCollection represents a collection of errors
type ErrorCollection struct {
	Errors []error `json:"errors"`
}

// NewErrorCollection creates a new error collection
func NewErrorCollection() *ErrorCollection {
	return &ErrorCollection{
		Errors: make([]error, 0),
	}
}

// Add adds an error to the collection
func (ec *ErrorCollection) Add(err error) {
	if err != nil {
		ec.Errors = append(ec.Errors, err)
	}
}

// HasErrors returns true if the collection has errors
func (ec *ErrorCollection) HasErrors() bool {
	return len(ec.Errors) > 0
}

// First returns the first error in the collection
func (ec *ErrorCollection) First() error {
	if len(ec.Errors) > 0 {
		return ec.Errors[0]
	}
	return nil
}

// Error implements the error interface
func (ec *ErrorCollection) Error() string {
	if len(ec.Errors) == 0 {
		return "no errors"
	}

	if len(ec.Errors) == 1 {
		return ec.Errors[0].Error()
	}

	var messages []string
	for _, err := range ec.Errors {
		messages = append(messages, err.Error())
	}

	return fmt.Sprintf("multiple errors: %s", strings.Join(messages, "; "))
}

// ToAppError converts the collection to a single AppError
func (ec *ErrorCollection) ToAppError() *AppError {
	if len(ec.Errors) == 0 {
		return nil
	}

	if len(ec.Errors) == 1 {
		if appErr, ok := ec.Errors[0].(*AppError); ok {
			return appErr
		}
		return NewInternalError(ec.Errors[0].Error(), ec.Errors[0])
	}

	// Multiple errors - create a validation error
	var validationErrors []ValidationError
	var messages []string

	for _, err := range ec.Errors {
		messages = append(messages, err.Error())
		if appErr, ok := err.(*AppError); ok {
			if appErr.Type == ErrorTypeValidation {
				validationErrors = append(validationErrors, appErr.Validation...)
			}
		}
	}

	message := fmt.Sprintf("Multiple validation errors: %s", strings.Join(messages, "; "))
	return NewValidationErrorWithDetails(message, validationErrors)
}

// Helper functions

// getCallerInfo returns information about the caller
func getCallerInfo() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}

	// Get just the filename, not the full path
	parts := strings.Split(file, "/")
	filename := parts[len(parts)-1]

	return fmt.Sprintf("%s:%d", filename, line)
}

// Recovery middleware helper

// RecoverWithError recovers from panic and converts to AppError
func RecoverWithError() *AppError {
	if r := recover(); r != nil {
		var err error
		switch x := r.(type) {
		case string:
			err = fmt.Errorf(x)
		case error:
			err = x
		default:
			err = fmt.Errorf("unknown panic: %v", x)
		}

		return NewInternalError("Internal server error", err).WithDetails(
			fmt.Sprintf("Panic recovered: %v", r),
		)
	}
	return nil
}

// Validation helpers

// NewValidationErrorFromField creates validation error for a specific field
func NewValidationErrorFromField(field, rule, message string, value interface{}) ValidationError {
	return ValidationError{
		Field:   field,
		Rule:    rule,
		Message: message,
		Value:   value,
	}
}

// ValidateRequired checks if a field is required and not empty
func ValidateRequired(field string, value interface{}) *ValidationError {
	if value == nil {
		return &ValidationError{
			Field:   field,
			Rule:    "required",
			Message: fmt.Sprintf("%s is required", field),
		}
	}

	if str, ok := value.(string); ok && strings.TrimSpace(str) == "" {
		return &ValidationError{
			Field:   field,
			Rule:    "required",
			Message: fmt.Sprintf("%s is required", field),
			Value:   value,
		}
	}

	return nil
}

// ValidateEmail validates email format
func ValidateEmail(field, email string) *ValidationError {
	if email == "" {
		return nil // Use required validation separately
	}

	// Basic email validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return &ValidationError{
			Field:   field,
			Rule:    "email",
			Message: fmt.Sprintf("%s must be a valid email address", field),
			Value:   email,
		}
	}

	return nil
}

// ValidateLength validates string length
func ValidateLength(field, value string, min, max int) *ValidationError {
	length := len(value)

	if min > 0 && length < min {
		return &ValidationError{
			Field:   field,
			Rule:    "min_length",
			Message: fmt.Sprintf("%s must be at least %d characters long", field, min),
			Value:   value,
		}
	}

	if max > 0 && length > max {
		return &ValidationError{
			Field:   field,
			Rule:    "max_length",
			Message: fmt.Sprintf("%s must not exceed %d characters", field, max),
			Value:   value,
		}
	}

	return nil
}

// Error code mappings

// GetHTTPStatusFromCode returns HTTP status code for error code
func GetHTTPStatusFromCode(code ErrorCode) int {
	switch code {
	case CodeInvalidCredentials, CodeTokenExpired, CodeTokenInvalid, CodeTwoFactorRequired, CodeTwoFactorInvalid:
		return http.StatusUnauthorized
	case CodeInsufficientPermissions, CodeAccessDenied, CodeResourceForbidden, CodeAdminRequired, CodeBlockedUser, CodePrivateAccount:
		return http.StatusForbidden
	case CodeUserNotFound, CodePostNotFound, CodeCommentNotFound, CodeMessageNotFound, CodeFileNotFound:
		return http.StatusNotFound
	case CodeEmailExists, CodeUsernameExists, CodePhoneExists, CodeAlreadyFollowing, CodeAlreadyLiked:
		return http.StatusConflict
	case CodeValidationFailed, CodeRequiredFieldMissing, CodeInvalidFieldFormat, CodeFileTooLarge, CodeInvalidFileType:
		return http.StatusBadRequest
	case CodeRateLimitExceeded, CodeTooManyRequests:
		return http.StatusTooManyRequests
	case CodeTimeoutError:
		return http.StatusRequestTimeout
	case CodeServiceUnavailable, CodeMaintenanceMode:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
