package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ValidationResult represents validation result
type ValidationResult struct {
	IsValid bool              `json:"is_valid"`
	Errors  map[string]string `json:"errors"`
	Value   interface{}       `json:"value,omitempty"`
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	Field    string      `json:"field"`
	Rules    []string    `json:"rules"`
	Message  string      `json:"message,omitempty"`
	Required bool        `json:"required"`
	Value    interface{} `json:"value"`
}

// Validator provides data validation functionality
type Validator struct {
	rules  map[string][]ValidationRule
	errors map[string]string
	data   map[string]interface{}
	locale string
}

// FieldValidator represents individual field validation functions
type FieldValidator func(value interface{}, params ...string) error

// Common validation patterns
var (
	EmailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	PhoneRegex    = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	UsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,30}$`)
	SlugRegex     = regexp.MustCompile(`^[a-z0-9-]+$`)
	UUIDRegex     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	URLRegex      = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	IPv4Regex     = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	IPv6Regex     = regexp.MustCompile(`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	HexColorRegex = regexp.MustCompile(`^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`)
	Base64Regex   = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	AlphaRegex    = regexp.MustCompile(`^[a-zA-Z]+$`)
	AlphaNumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	NumericRegex  = regexp.MustCompile(`^[0-9]+$`)
)

// Built-in field validators
var BuiltinValidators = map[string]FieldValidator{
	"required":   validateRequired,
	"email":      validateEmail,
	"phone":      validatePhone,
	"username":   validateUsername,
	"url":        validateURL,
	"ip":         validateIP,
	"ipv4":       validateIPv4,
	"ipv6":       validateIPv6,
	"alpha":      validateAlpha,
	"alphanum":   validateAlphaNum,
	"numeric":    validateNumeric,
	"integer":    validateInteger,
	"float":      validateFloat,
	"boolean":    validateBoolean,
	"date":       validateDate,
	"datetime":   validateDateTime,
	"time":       validateTime,
	"json":       validateJSON,
	"base64":     validateBase64,
	"hex":        validateHex,
	"uuid":       validateUUID,
	"objectid":   validateObjectID,
	"slug":       validateSlug,
	"color":      validateColor,
	"min":        validateMin,
	"max":        validateMax,
	"between":    validateBetween,
	"minlength":  validateMinLength,
	"maxlength":  validateMaxLength,
	"length":     validateLength,
	"contains":   validateContains,
	"startswith": validateStartsWith,
	"endswith":   validateEndsWith,
	"regex":      validateRegex,
	"in":         validateIn,
	"notin":      validateNotIn,
	"unique":     validateUnique,
	"exists":     validateExists,
	"confirmed":  validateConfirmed,
	"different":  validateDifferent,
	"same":       validateSame,
	"file":       validateFile,
	"image":      validateImage,
	"mimes":      validateMimes,
	"dimensions": validateDimensions,
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		rules:  make(map[string][]ValidationRule),
		errors: make(map[string]string),
		data:   make(map[string]interface{}),
		locale: "en",
	}
}

// SetData sets the data to be validated
func (v *Validator) SetData(data map[string]interface{}) *Validator {
	v.data = data
	return v
}

// SetLocale sets the validation locale for error messages
func (v *Validator) SetLocale(locale string) *Validator {
	v.locale = locale
	return v
}

// Rules sets validation rules for fields
func (v *Validator) Rules(rules map[string]string) *Validator {
	for field, ruleString := range rules {
		v.parseRules(field, ruleString)
	}
	return v
}

// Rule adds a validation rule for a specific field
func (v *Validator) Rule(field, rules string) *Validator {
	v.parseRules(field, rules)
	return v
}

// Validate performs validation and returns result
func (v *Validator) Validate() *ValidationResult {
	v.errors = make(map[string]string)

	for field, rules := range v.rules {
		value := v.getValue(field)

		for _, rule := range rules {
			if err := v.validateField(field, value, rule); err != nil {
				v.errors[field] = err.Error()
				break // Stop at first error for this field
			}
		}
	}

	return &ValidationResult{
		IsValid: len(v.errors) == 0,
		Errors:  v.errors,
		Value:   v.data,
	}
}

// ValidateField validates a single field with rules
func (v *Validator) ValidateField(field string, value interface{}, rules string) error {
	v.parseRules(field, rules)
	fieldRules := v.rules[field]

	for _, rule := range fieldRules {
		if err := v.validateField(field, value, rule); err != nil {
			return err
		}
	}
	return nil
}

// GetErrors returns validation errors
func (v *Validator) GetErrors() map[string]string {
	return v.errors
}

// HasErrors checks if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// parseRules parses rule string into ValidationRule structs
func (v *Validator) parseRules(field, ruleString string) {
	rules := strings.Split(ruleString, "|")
	var fieldRules []ValidationRule

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		validationRule := ValidationRule{
			Field: field,
		}

		// Check if rule has parameters
		if strings.Contains(rule, ":") {
			parts := strings.SplitN(rule, ":", 2)
			validationRule.Rules = []string{parts[0]}
			if parts[1] != "" {
				validationRule.Rules = append(validationRule.Rules, strings.Split(parts[1], ",")...)
			}
		} else {
			validationRule.Rules = []string{rule}
		}

		if rule == "required" {
			validationRule.Required = true
		}

		fieldRules = append(fieldRules, validationRule)
	}

	v.rules[field] = fieldRules
}

// validateField validates a field against a rule
func (v *Validator) validateField(field string, value interface{}, rule ValidationRule) error {
	ruleName := rule.Rules[0]
	params := rule.Rules[1:]

	// Skip validation if field is empty and not required
	if !rule.Required && v.isEmpty(value) {
		return nil
	}

	// Get validator function
	validator, exists := BuiltinValidators[ruleName]
	if !exists {
		return fmt.Errorf("unknown validation rule: %s", ruleName)
	}

	// Execute validation
	if err := validator(value, params...); err != nil {
		if rule.Message != "" {
			return fmt.Errorf(rule.Message)
		}
		return fmt.Errorf("%s: %s", field, err.Error())
	}

	return nil
}

// getValue gets value from data map
func (v *Validator) getValue(field string) interface{} {
	// Support nested fields like "user.email"
	keys := strings.Split(field, ".")
	current := v.data

	for i, key := range keys {
		if i == len(keys)-1 {
			return current[key]
		}

		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return nil
		}
	}

	return nil
}

// isEmpty checks if value is empty
func (v *Validator) isEmpty(value interface{}) bool {
	if value == nil {
		return true
	}

	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case []interface{}:
		return len(v) == 0
	case map[string]interface{}:
		return len(v) == 0
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Array, reflect.Slice, reflect.Map, reflect.Chan:
			return rv.Len() == 0
		case reflect.Ptr, reflect.Interface:
			return rv.IsNil()
		}
	}

	return false
}

// Built-in validator functions

func validateRequired(value interface{}, params ...string) error {
	if value == nil {
		return fmt.Errorf("field is required")
	}

	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("field is required")
		}
	case []interface{}:
		if len(v) == 0 {
			return fmt.Errorf("field is required")
		}
	case map[string]interface{}:
		if len(v) == 0 {
			return fmt.Errorf("field is required")
		}
	}

	return nil
}

func validateEmail(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !EmailRegex.MatchString(str) {
		return fmt.Errorf("must be a valid email address")
	}

	// Additional validation using net/mail
	if _, err := mail.ParseAddress(str); err != nil {
		return fmt.Errorf("must be a valid email address")
	}

	return nil
}

func validatePhone(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	// Remove common formatting characters
	cleaned := strings.ReplaceAll(str, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")

	if !PhoneRegex.MatchString(cleaned) {
		return fmt.Errorf("must be a valid phone number")
	}

	return nil
}

func validateUsername(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !UsernameRegex.MatchString(str) {
		return fmt.Errorf("must contain only letters, numbers, and underscores (3-30 characters)")
	}

	return nil
}

func validateURL(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if _, err := url.ParseRequestURI(str); err != nil {
		return fmt.Errorf("must be a valid URL")
	}

	return nil
}

func validateIP(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if ip := net.ParseIP(str); ip == nil {
		return fmt.Errorf("must be a valid IP address")
	}

	return nil
}

func validateIPv4(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if ip := net.ParseIP(str); ip == nil || ip.To4() == nil {
		return fmt.Errorf("must be a valid IPv4 address")
	}

	return nil
}

func validateIPv6(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if ip := net.ParseIP(str); ip == nil || ip.To4() != nil {
		return fmt.Errorf("must be a valid IPv6 address")
	}

	return nil
}

func validateAlpha(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !AlphaRegex.MatchString(str) {
		return fmt.Errorf("must contain only letters")
	}

	return nil
}

func validateAlphaNum(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !AlphaNumRegex.MatchString(str) {
		return fmt.Errorf("must contain only letters and numbers")
	}

	return nil
}

func validateNumeric(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !NumericRegex.MatchString(str) {
		return fmt.Errorf("must be numeric")
	}

	return nil
}

func validateInteger(value interface{}, params ...string) error {
	switch v := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case float32, float64:
		if v != float64(int64(v.(float64))) {
			return fmt.Errorf("must be an integer")
		}
		return nil
	case string:
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("must be an integer")
		}
		return nil
	default:
		return fmt.Errorf("must be an integer")
	}
}

func validateFloat(value interface{}, params ...string) error {
	switch v := value.(type) {
	case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case string:
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return fmt.Errorf("must be a number")
		}
		return nil
	default:
		return fmt.Errorf("must be a number")
	}
}

func validateBoolean(value interface{}, params ...string) error {
	switch v := value.(type) {
	case bool:
		return nil
	case string:
		if _, err := strconv.ParseBool(v); err != nil {
			return fmt.Errorf("must be a boolean")
		}
		return nil
	default:
		return fmt.Errorf("must be a boolean")
	}
}

func validateDate(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	format := "2006-01-02"
	if len(params) > 0 {
		format = params[0]
	}

	if _, err := time.Parse(format, str); err != nil {
		return fmt.Errorf("must be a valid date")
	}

	return nil
}

func validateDateTime(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	format := time.RFC3339
	if len(params) > 0 {
		format = params[0]
	}

	if _, err := time.Parse(format, str); err != nil {
		return fmt.Errorf("must be a valid datetime")
	}

	return nil
}

func validateTime(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	format := "15:04:05"
	if len(params) > 0 {
		format = params[0]
	}

	if _, err := time.Parse(format, str); err != nil {
		return fmt.Errorf("must be a valid time")
	}

	return nil
}

func validateJSON(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	var js interface{}
	if err := json.Unmarshal([]byte(str), &js); err != nil {
		return fmt.Errorf("must be valid JSON")
	}

	return nil
}

func validateBase64(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !Base64Regex.MatchString(str) {
		return fmt.Errorf("must be valid base64")
	}

	return nil
}

func validateHex(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if _, err := strconv.ParseInt(str, 16, 64); err != nil {
		return fmt.Errorf("must be valid hexadecimal")
	}

	return nil
}

func validateUUID(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !UUIDRegex.MatchString(str) {
		return fmt.Errorf("must be a valid UUID")
	}

	return nil
}

func validateObjectID(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !primitive.IsValidObjectID(str) {
		return fmt.Errorf("must be a valid ObjectID")
	}

	return nil
}

func validateSlug(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !SlugRegex.MatchString(str) {
		return fmt.Errorf("must be a valid slug (lowercase letters, numbers, and hyphens only)")
	}

	return nil
}

func validateColor(value interface{}, params ...string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a string")
	}

	if !HexColorRegex.MatchString(str) {
		return fmt.Errorf("must be a valid hex color")
	}

	return nil
}

func validateMin(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("min rule requires a parameter")
	}

	min, err := strconv.ParseFloat(params[0], 64)
	if err != nil {
		return fmt.Errorf("invalid min parameter")
	}

	switch v := value.(type) {
	case string:
		if float64(utf8.RuneCountInString(v)) < min {
			return fmt.Errorf("must be at least %.0f characters", min)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		val := getFloat64(v)
		if val < min {
			return fmt.Errorf("must be at least %.0f", min)
		}
	case []interface{}:
		if float64(len(v)) < min {
			return fmt.Errorf("must have at least %.0f items", min)
		}
	default:
		return fmt.Errorf("min rule not applicable to this type")
	}

	return nil
}

func validateMax(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("max rule requires a parameter")
	}

	max, err := strconv.ParseFloat(params[0], 64)
	if err != nil {
		return fmt.Errorf("invalid max parameter")
	}

	switch v := value.(type) {
	case string:
		if float64(utf8.RuneCountInString(v)) > max {
			return fmt.Errorf("must be at most %.0f characters", max)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		val := getFloat64(v)
		if val > max {
			return fmt.Errorf("must be at most %.0f", max)
		}
	case []interface{}:
		if float64(len(v)) > max {
			return fmt.Errorf("must have at most %.0f items", max)
		}
	default:
		return fmt.Errorf("max rule not applicable to this type")
	}

	return nil
}

func validateBetween(value interface{}, params ...string) error {
	if len(params) < 2 {
		return fmt.Errorf("between rule requires two parameters")
	}

	min, err := strconv.ParseFloat(params[0], 64)
	if err != nil {
		return fmt.Errorf("invalid min parameter")
	}

	max, err := strconv.ParseFloat(params[1], 64)
	if err != nil {
		return fmt.Errorf("invalid max parameter")
	}

	switch v := value.(type) {
	case string:
		length := float64(utf8.RuneCountInString(v))
		if length < min || length > max {
			return fmt.Errorf("must be between %.0f and %.0f characters", min, max)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		val := getFloat64(v)
		if val < min || val > max {
			return fmt.Errorf("must be between %.0f and %.0f", min, max)
		}
	default:
		return fmt.Errorf("between rule not applicable to this type")
	}

	return nil
}

func validateMinLength(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("minlength rule requires a parameter")
	}

	minLen, err := strconv.Atoi(params[0])
	if err != nil {
		return fmt.Errorf("invalid minlength parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("minlength rule only applies to strings")
	}

	if utf8.RuneCountInString(str) < minLen {
		return fmt.Errorf("must be at least %d characters long", minLen)
	}

	return nil
}

func validateMaxLength(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("maxlength rule requires a parameter")
	}

	maxLen, err := strconv.Atoi(params[0])
	if err != nil {
		return fmt.Errorf("invalid maxlength parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("maxlength rule only applies to strings")
	}

	if utf8.RuneCountInString(str) > maxLen {
		return fmt.Errorf("must be at most %d characters long", maxLen)
	}

	return nil
}

func validateLength(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("length rule requires a parameter")
	}

	length, err := strconv.Atoi(params[0])
	if err != nil {
		return fmt.Errorf("invalid length parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("length rule only applies to strings")
	}

	if utf8.RuneCountInString(str) != length {
		return fmt.Errorf("must be exactly %d characters long", length)
	}

	return nil
}

func validateContains(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("contains rule requires a parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("contains rule only applies to strings")
	}

	if !strings.Contains(str, params[0]) {
		return fmt.Errorf("must contain '%s'", params[0])
	}

	return nil
}

func validateStartsWith(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("startswith rule requires a parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("startswith rule only applies to strings")
	}

	if !strings.HasPrefix(str, params[0]) {
		return fmt.Errorf("must start with '%s'", params[0])
	}

	return nil
}

func validateEndsWith(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("endswith rule requires a parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("endswith rule only applies to strings")
	}

	if !strings.HasSuffix(str, params[0]) {
		return fmt.Errorf("must end with '%s'", params[0])
	}

	return nil
}

func validateRegex(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("regex rule requires a parameter")
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("regex rule only applies to strings")
	}

	regex, err := regexp.Compile(params[0])
	if err != nil {
		return fmt.Errorf("invalid regex pattern")
	}

	if !regex.MatchString(str) {
		return fmt.Errorf("does not match required pattern")
	}

	return nil
}

func validateIn(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("in rule requires parameters")
	}

	str := fmt.Sprintf("%v", value)
	for _, param := range params {
		if str == param {
			return nil
		}
	}

	return fmt.Errorf("must be one of: %s", strings.Join(params, ", "))
}

func validateNotIn(value interface{}, params ...string) error {
	if len(params) == 0 {
		return fmt.Errorf("notin rule requires parameters")
	}

	str := fmt.Sprintf("%v", value)
	for _, param := range params {
		if str == param {
			return fmt.Errorf("must not be one of: %s", strings.Join(params, ", "))
		}
	}

	return nil
}

// Placeholder implementations for database-dependent validators
func validateUnique(value interface{}, params ...string) error {
	// Implement based on your database
	return nil
}

func validateExists(value interface{}, params ...string) error {
	// Implement based on your database
	return nil
}

func validateConfirmed(value interface{}, params ...string) error {
	// Implement confirmation field validation
	return nil
}

func validateDifferent(value interface{}, params ...string) error {
	// Implement field comparison validation
	return nil
}

func validateSame(value interface{}, params ...string) error {
	// Implement field comparison validation
	return nil
}

func validateFile(value interface{}, params ...string) error {
	// Implement file validation
	return nil
}

func validateImage(value interface{}, params ...string) error {
	// Implement image validation
	return nil
}

func validateMimes(value interface{}, params ...string) error {
	// Implement MIME type validation
	return nil
}

func validateDimensions(value interface{}, params ...string) error {
	// Implement image dimensions validation
	return nil
}

// Helper functions

func getFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}

// Sanitization functions

// SanitizeString removes HTML tags and trims whitespace
func SanitizeString(input string) string {
	// Remove HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	cleaned := htmlRegex.ReplaceAllString(input, "")

	// Trim whitespace
	cleaned = strings.TrimSpace(cleaned)

	// Remove multiple consecutive spaces
	spaceRegex := regexp.MustCompile(`\s+`)
	cleaned = spaceRegex.ReplaceAllString(cleaned, " ")

	return cleaned
}

// SanitizeEmail normalizes email address
func SanitizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	return email
}

// SanitizeUsername normalizes username
func SanitizeUsername(username string) string {
	username = strings.TrimSpace(username)
	username = strings.ToLower(username)

	// Remove invalid characters
	validChars := regexp.MustCompile(`[^a-z0-9_]`)
	username = validChars.ReplaceAllString(username, "")

	return username
}

// SanitizeHTML removes dangerous HTML tags and attributes
func SanitizeHTML(input string) string {
	// This is a basic implementation
	// For production, use a proper HTML sanitizer library

	// Remove script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	cleaned := scriptRegex.ReplaceAllString(input, "")

	// Remove on* attributes
	onRegex := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*['""][^'""]*['"]`)
	cleaned = onRegex.ReplaceAllString(cleaned, "")

	// Remove javascript: URLs
	jsRegex := regexp.MustCompile(`(?i)javascript:`)
	cleaned = jsRegex.ReplaceAllString(cleaned, "")

	return cleaned
}

// RemoveSpecialChars removes special characters from string
func RemoveSpecialChars(input string) string {
	// Keep only alphanumeric characters and spaces
	regex := regexp.MustCompile(`[^a-zA-Z0-9\s]`)
	return regex.ReplaceAllString(input, "")
}

// ValidateAndSanitize performs validation and sanitization
func ValidateAndSanitize(data map[string]interface{}, rules map[string]string) (*ValidationResult, map[string]interface{}) {
	validator := NewValidator()
	validator.SetData(data)
	validator.Rules(rules)

	result := validator.Validate()

	// Sanitize data if validation passes
	sanitized := make(map[string]interface{})
	if result.IsValid {
		for key, value := range data {
			if str, ok := value.(string); ok {
				sanitized[key] = SanitizeString(str)
			} else {
				sanitized[key] = value
			}
		}
	}

	return result, sanitized
}

// IsValidPassword checks password strength
func IsValidPassword(password string) (bool, []string) {
	var errors []string

	if len(password) < 8 {
		errors = append(errors, "Password must be at least 8 characters long")
	}

	if len(password) > 128 {
		errors = append(errors, "Password must not exceed 128 characters")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}
	if !hasLower {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}
	if !hasDigit {
		errors = append(errors, "Password must contain at least one digit")
	}
	if !hasSpecial {
		errors = append(errors, "Password must contain at least one special character")
	}

	return len(errors) == 0, errors
}

// NormalizePhone normalizes phone number format
func NormalizePhone(phone string) string {
	// Remove all non-digit characters except +
	regex := regexp.MustCompile(`[^\d+]`)
	normalized := regex.ReplaceAllString(phone, "")

	// Add + if not present and starts with country code
	if !strings.HasPrefix(normalized, "+") && len(normalized) > 10 {
		normalized = "+" + normalized
	}

	return normalized
}

// GenerateSlug generates URL-friendly slug from string
func GenerateSlug(input string) string {
	// Convert to lowercase
	slug := strings.ToLower(input)

	// Replace spaces with hyphens
	slug = strings.ReplaceAll(slug, " ", "-")

	// Remove special characters
	regex := regexp.MustCompile(`[^a-z0-9\-]`)
	slug = regex.ReplaceAllString(slug, "")

	// Remove multiple consecutive hyphens
	hyphenRegex := regexp.MustCompile(`-+`)
	slug = hyphenRegex.ReplaceAllString(slug, "-")

	// Trim hyphens from start and end
	slug = strings.Trim(slug, "-")

	return slug
}
