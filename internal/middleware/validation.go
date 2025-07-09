package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
)

// ValidationConfig represents validation middleware configuration
type ValidationConfig struct {
	SchemaStore        map[string]ValidationSchema
	DefaultErrorCode   string
	DefaultMessage     string
	SkipPaths          []string
	MaxRequestSize     int64
	AllowUnknownFields bool
	StrictMode         bool
}

// ValidationSchema represents a validation schema
type ValidationSchema struct {
	Fields   map[string]string         `json:"fields"`   // field -> validation rules
	Messages map[string]string         `json:"messages"` // field -> custom error message
	Required []string                  `json:"required"` // required fields
	Optional []string                  `json:"optional"` // optional fields
	Custom   map[string]ValidationRule `json:"custom"`   // custom validation rules
}

// ValidationRule represents a custom validation rule
type ValidationRule struct {
	Rule    string   `json:"rule"`
	Message string   `json:"message"`
	Params  []string `json:"params"`
}

// ValidationMiddleware represents the validation middleware
type ValidationMiddleware struct {
	config *ValidationConfig
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		SchemaStore:        make(map[string]ValidationSchema),
		DefaultErrorCode:   "VALIDATION_ERROR",
		DefaultMessage:     "Validation failed",
		SkipPaths:          []string{"/health", "/metrics"},
		MaxRequestSize:     10 * 1024 * 1024, // 10MB
		AllowUnknownFields: false,
		StrictMode:         true,
	}
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(config *ValidationConfig) *ValidationMiddleware {
	if config == nil {
		config = DefaultValidationConfig()
	}

	// Initialize with built-in schemas
	vm := &ValidationMiddleware{config: config}
	vm.initializeBuiltinSchemas()
	return vm
}

// Validate returns validation middleware for a specific schema
func (vm *ValidationMiddleware) Validate(schemaName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for certain paths
		if vm.shouldSkipValidation(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get validation schema
		schema, exists := vm.config.SchemaStore[schemaName]
		if !exists {
			utils.SendError(c, http.StatusInternalServerError, "SCHEMA_NOT_FOUND",
				fmt.Sprintf("Validation schema '%s' not found", schemaName))
			c.Abort()
			return
		}

		// Extract request data
		data, err := vm.extractRequestData(c)
		if err != nil {
			utils.SendError(c, http.StatusBadRequest, "INVALID_REQUEST_DATA",
				"Failed to parse request data: "+err.Error())
			c.Abort()
			return
		}

		// Validate data against schema
		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		// Set validated data in context
		c.Set("validated_data", data)
		c.Next()
	}
}

// ValidateJSON validates JSON request body
func (vm *ValidationMiddleware) ValidateJSON(schema ValidationSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data map[string]interface{}

		if err := c.ShouldBindJSON(&data); err != nil {
			utils.SendError(c, http.StatusBadRequest, "INVALID_JSON",
				"Invalid JSON format: "+err.Error())
			c.Abort()
			return
		}

		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		c.Set("validated_data", data)
		c.Next()
	}
}

// ValidateForm validates form data
func (vm *ValidationMiddleware) ValidateForm(schema ValidationSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := make(map[string]interface{})

		// Parse form data
		if err := c.Request.ParseForm(); err != nil {
			utils.SendError(c, http.StatusBadRequest, "INVALID_FORM",
				"Failed to parse form data: "+err.Error())
			c.Abort()
			return
		}

		// Convert form values to map
		for key, values := range c.Request.Form {
			if len(values) == 1 {
				data[key] = values[0]
			} else {
				data[key] = values
			}
		}

		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		c.Set("validated_data", data)
		c.Next()
	}
}

// ValidateMultipart validates multipart form data including files
func (vm *ValidationMiddleware) ValidateMultipart(schema ValidationSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse multipart form
		if err := c.Request.ParseMultipartForm(vm.config.MaxRequestSize); err != nil {
			utils.SendError(c, http.StatusBadRequest, "INVALID_MULTIPART",
				"Failed to parse multipart form: "+err.Error())
			c.Abort()
			return
		}

		data := make(map[string]interface{})

		// Extract form values
		if c.Request.MultipartForm != nil {
			for key, values := range c.Request.MultipartForm.Value {
				if len(values) == 1 {
					data[key] = values[0]
				} else {
					data[key] = values
				}
			}

			// Extract file information
			for key, files := range c.Request.MultipartForm.File {
				if len(files) == 1 {
					data[key] = vm.createFileInfo(files[0])
				} else {
					fileInfos := make([]map[string]interface{}, len(files))
					for i, file := range files {
						fileInfos[i] = vm.createFileInfo(file)
					}
					data[key] = fileInfos
				}
			}
		}

		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		c.Set("validated_data", data)
		c.Next()
	}
}

// ValidateQuery validates query parameters
func (vm *ValidationMiddleware) ValidateQuery(schema ValidationSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := make(map[string]interface{})

		// Extract query parameters
		for key, values := range c.Request.URL.Query() {
			if len(values) == 1 {
				data[key] = values[0]
			} else {
				data[key] = values
			}
		}

		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		c.Set("validated_query", data)
		c.Next()
	}
}

// ValidateParams validates URL parameters
func (vm *ValidationMiddleware) ValidateParams(schema ValidationSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := make(map[string]interface{})

		// Extract URL parameters
		for _, param := range c.Params {
			data[param.Key] = param.Value
		}

		if err := vm.validateData(data, schema); err != nil {
			vm.handleValidationError(c, err)
			c.Abort()
			return
		}

		c.Set("validated_params", data)
		c.Next()
	}
}

// AddSchema adds a validation schema to the store
func (vm *ValidationMiddleware) AddSchema(name string, schema ValidationSchema) {
	vm.config.SchemaStore[name] = schema
}

// RemoveSchema removes a validation schema from the store
func (vm *ValidationMiddleware) RemoveSchema(name string) {
	delete(vm.config.SchemaStore, name)
}

// LoadSchemaFromJSON loads validation schema from JSON string
func (vm *ValidationMiddleware) LoadSchemaFromJSON(name, jsonSchema string) error {
	var schema ValidationSchema
	if err := json.Unmarshal([]byte(jsonSchema), &schema); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	vm.AddSchema(name, schema)
	return nil
}

// Private helper methods

// extractRequestData extracts data from request based on content type
func (vm *ValidationMiddleware) extractRequestData(c *gin.Context) (map[string]interface{}, error) {
	contentType := c.GetHeader("Content-Type")

	switch {
	case strings.Contains(contentType, "application/json"):
		return vm.extractJSONData(c)
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		return vm.extractFormData(c)
	case strings.Contains(contentType, "multipart/form-data"):
		return vm.extractMultipartData(c)
	default:
		// Try to parse as JSON for API endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			return vm.extractJSONData(c)
		}
		return vm.extractFormData(c)
	}
}

// extractJSONData extracts JSON data from request body
func (vm *ValidationMiddleware) extractJSONData(c *gin.Context) (map[string]interface{}, error) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if len(body) == 0 {
		return make(map[string]interface{}), nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return data, nil
}

// extractFormData extracts form data from request
func (vm *ValidationMiddleware) extractFormData(c *gin.Context) (map[string]interface{}, error) {
	if err := c.Request.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	data := make(map[string]interface{})
	for key, values := range c.Request.Form {
		if len(values) == 1 {
			data[key] = values[0]
		} else {
			data[key] = values
		}
	}

	return data, nil
}

// extractMultipartData extracts multipart form data
func (vm *ValidationMiddleware) extractMultipartData(c *gin.Context) (map[string]interface{}, error) {
	if err := c.Request.ParseMultipartForm(vm.config.MaxRequestSize); err != nil {
		return nil, fmt.Errorf("failed to parse multipart form: %w", err)
	}

	data := make(map[string]interface{})

	// Extract form values
	if c.Request.MultipartForm != nil {
		for key, values := range c.Request.MultipartForm.Value {
			if len(values) == 1 {
				data[key] = values[0]
			} else {
				data[key] = values
			}
		}

		// Extract file information
		for key, files := range c.Request.MultipartForm.File {
			if len(files) == 1 {
				data[key] = vm.createFileInfo(files[0])
			} else {
				fileInfos := make([]map[string]interface{}, len(files))
				for i, file := range files {
					fileInfos[i] = vm.createFileInfo(file)
				}
				data[key] = fileInfos
			}
		}
	}

	return data, nil
}

// createFileInfo creates file information map from multipart.FileHeader
func (vm *ValidationMiddleware) createFileInfo(file *multipart.FileHeader) map[string]interface{} {
	return map[string]interface{}{
		"filename": file.Filename,
		"size":     file.Size,
		"header":   file.Header,
	}
}

// validateData validates data against schema using the utils.Validator
func (vm *ValidationMiddleware) validateData(data map[string]interface{}, schema ValidationSchema) error {
	validator := utils.NewValidator()


	// Validate required fields
	for _, field := range schema.Required {
		if _, exists := data[field]; !exists {
			return fmt.Errorf("field '%s' is required", field)
		}
	}

	// Check for unknown fields in strict mode
	if !vm.config.AllowUnknownFields {
		allowedFields := make(map[string]bool)
		for field := range schema.Fields {
			allowedFields[field] = true
		}
		for _, field := range schema.Required {
			allowedFields[field] = true
		}
		for _, field := range schema.Optional {
			allowedFields[field] = true
		}

		for field := range data {
			if !allowedFields[field] {
				return fmt.Errorf("unknown field '%s'", field)
			}
		}
	}

	// Set data to validator if required by your implementation
	validator.SetData(data)

	// Perform validation
	result := validator.Validate()
	if !result.IsValid {
		var errors []string
		for field, message := range result.Errors {
			errors = append(errors, fmt.Sprintf("%s: %s", field, message))
		}
		return fmt.Errorf("validation failed: %s", strings.Join(errors, ", "))
	}

	return nil
}

// shouldSkipValidation checks if validation should be skipped for the path
func (vm *ValidationMiddleware) shouldSkipValidation(path string) bool {
	for _, skipPath := range vm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// handleValidationError handles validation errors
func (vm *ValidationMiddleware) handleValidationError(c *gin.Context, err error) {
	// Parse error to extract individual field errors if possible
	errorMessage := err.Error()

	if strings.Contains(errorMessage, "validation failed:") {
		// Extract field errors
		fieldErrors := make(map[string]string)
		errorParts := strings.Split(strings.TrimPrefix(errorMessage, "validation failed: "), ", ")

		for _, part := range errorParts {
			if colonIndex := strings.Index(part, ": "); colonIndex != -1 {
				field := part[:colonIndex]
				message := part[colonIndex+2:]
				fieldErrors[field] = message
			}
		}

		// Convert map[string]string to []utils.ValidationError
		var validationErrors []utils.ValidationError
		for field, message := range fieldErrors {
			validationErrors = append(validationErrors, utils.ValidationError{
				Field:   field,
				Message: message,
			})
		}
		utils.SendValidationError(c, validationErrors)
		return
	}

	// Single error
	utils.SendError(c, http.StatusBadRequest, vm.config.DefaultErrorCode, errorMessage)
}

// initializeBuiltinSchemas initializes built-in validation schemas
func (vm *ValidationMiddleware) initializeBuiltinSchemas() {
	// User registration schema
	vm.AddSchema("register", ValidationSchema{
		Fields: map[string]string{
			"username":         "required|username|min:3|max:30|unique",
			"email":            "required|email|unique",
			"password":         "required|min:8",
			"confirm_password": "required|same:password",
			"first_name":       "required|min:1|max:50",
			"last_name":        "required|min:1|max:50",
			"date_of_birth":    "required|date",
		},
		Required: []string{"username", "email", "password", "confirm_password", "first_name", "last_name"},
	})

	// User login schema
	vm.AddSchema("login", ValidationSchema{
		Fields: map[string]string{
			"identifier":  "required", // email or username
			"password":    "required",
			"remember_me": "boolean",
		},
		Required: []string{"identifier", "password"},
	})

	// Profile update schema
	vm.AddSchema("update_profile", ValidationSchema{
		Fields: map[string]string{
			"first_name": "sometimes|min:1|max:50",
			"last_name":  "sometimes|min:1|max:50",
			"bio":        "sometimes|max:500",
			"location":   "sometimes|max:100",
			"website":    "sometimes|url",
			"avatar":     "sometimes|image|max:5242880", // 5MB
		},
	})

	// Post creation schema
	vm.AddSchema("create_post", ValidationSchema{
		Fields: map[string]string{
			"content":      "required|string|max:500",
			"content_type": "sometimes|in:text,image,video,audio,poll",
			"media_files":  "sometimes|array|max:10",
			"privacy":      "sometimes|in:public,friends,private",
			"location":     "sometimes|string|max:100",
			"tags":         "sometimes|array|max:20",
		},
		Required: []string{"content"},
	})

	// Comment creation schema
	vm.AddSchema("create_comment", ValidationSchema{
		Fields: map[string]string{
			"content":   "required|string|max:500",
			"parent_id": "sometimes|objectid",
		},
		Required: []string{"content"},
	})

	// Message creation schema
	vm.AddSchema("create_message", ValidationSchema{
		Fields: map[string]string{
			"content":      "required|string|max:1000",
			"recipient_id": "required|objectid",
			"message_type": "sometimes|in:text,image,file,voice",
			"reply_to":     "sometimes|objectid",
			"attachments":  "sometimes|array|max:5",
		},
		Required: []string{"content", "recipient_id"},
	})

	// File upload schema
	vm.AddSchema("upload_file", ValidationSchema{
		Fields: map[string]string{
			"file":        "required|file|max:104857600", // 100MB
			"description": "sometimes|string|max:200",
			"category":    "sometimes|in:document,image,video,audio,archive",
			"public":      "sometimes|boolean",
		},
		Required: []string{"file"},
	})

	// Change password schema
	vm.AddSchema("change_password", ValidationSchema{
		Fields: map[string]string{
			"current_password": "required",
			"new_password":     "required|min:8|different:current_password",
			"confirm_password": "required|same:new_password",
		},
		Required: []string{"current_password", "new_password", "confirm_password"},
	})

	// Search schema
	vm.AddSchema("search", ValidationSchema{
		Fields: map[string]string{
			"q":     "required|string|min:2|max:100",
			"type":  "sometimes|in:all,users,posts,hashtags,locations",
			"page":  "sometimes|integer|min:1",
			"limit": "sometimes|integer|min:1|max:50",
		},
		Required: []string{"q"},
	})

	// Pagination schema
	vm.AddSchema("pagination", ValidationSchema{
		Fields: map[string]string{
			"page":   "sometimes|integer|min:1",
			"limit":  "sometimes|integer|min:1|max:100",
			"sort":   "sometimes|string",
			"order":  "sometimes|in:asc,desc",
			"cursor": "sometimes|string",
		},
	})

	// ID validation schema
	vm.AddSchema("validate_id", ValidationSchema{
		Fields: map[string]string{
			"id": "required|objectid",
		},
		Required: []string{"id"},
	})
}

// GetValidatedData retrieves validated data from context
func GetValidatedData(c *gin.Context) (map[string]interface{}, bool) {
	data, exists := c.Get("validated_data")
	if !exists {
		return nil, false
	}

	validatedData, ok := data.(map[string]interface{})
	return validatedData, ok
}

// GetValidatedQuery retrieves validated query data from context
func GetValidatedQuery(c *gin.Context) (map[string]interface{}, bool) {
	data, exists := c.Get("validated_query")
	if !exists {
		return nil, false
	}

	validatedData, ok := data.(map[string]interface{})
	return validatedData, ok
}

// GetValidatedParams retrieves validated params data from context
func GetValidatedParams(c *gin.Context) (map[string]interface{}, bool) {
	data, exists := c.Get("validated_params")
	if !exists {
		return nil, false
	}

	validatedData, ok := data.(map[string]interface{})
	return validatedData, ok
}

// Utility functions for common validation scenarios

// ValidateObjectID validates MongoDB ObjectID parameter
func ValidateObjectID(paramName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param(paramName)
		if id == "" {
			utils.SendError(c, http.StatusBadRequest, "MISSING_ID",
				fmt.Sprintf("Parameter '%s' is required", paramName))
			c.Abort()
			return
		}

		validator := utils.NewValidator()
		validator.SetData(map[string]interface{}{paramName: id})
		result := validator.Validate()

		if !result.IsValid {
			if err, exists := result.Errors[paramName]; exists {
				utils.SendError(c, http.StatusBadRequest, "INVALID_ID", err)
			} else {
				utils.SendError(c, http.StatusBadRequest, "INVALID_ID", "Invalid ID format")
			}
			c.Abort()
			return
		}

		c.Next()
	}
}

// ValidatePagination validates pagination parameters
func ValidatePagination() gin.HandlerFunc {
	vm := NewValidationMiddleware(nil)
	return vm.ValidateQuery(ValidationSchema{
		Fields: map[string]string{
			"page":  "sometimes|integer|min:1",
			"limit": "sometimes|integer|min:1|max:100",
		},
	})
}

// ValidateSearch validates search parameters
func ValidateSearch() gin.HandlerFunc {
	vm := NewValidationMiddleware(nil)
	return vm.Validate("search")
}

// RequireJSON ensures request has JSON content type
func RequireJSON() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.GetHeader("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			utils.SendError(c, http.StatusBadRequest, "INVALID_CONTENT_TYPE",
				"Content-Type must be application/json")
			c.Abort()
			return
		}
		c.Next()
	}
}

// LimitRequestSize limits request body size
func LimitRequestSize(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			utils.SendError(c, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE",
				fmt.Sprintf("Request body too large. Maximum size: %d bytes", maxSize))
			c.Abort()
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}
