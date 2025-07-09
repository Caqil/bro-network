package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// PasswordConfig represents password hashing configuration
type PasswordConfig struct {
	Algorithm      PasswordAlgorithm
	BcryptCost     int
	ScryptN        int
	ScryptR        int
	ScryptP        int
	ScryptKeyLen   int
	Argon2Memory   uint32
	Argon2Time     uint32
	Argon2Threads  uint8
	Argon2KeyLen   uint32
	SaltLength     int
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
}

// PasswordAlgorithm represents password hashing algorithms
type PasswordAlgorithm string

const (
	AlgorithmBcrypt PasswordAlgorithm = "bcrypt"
	AlgorithmScrypt PasswordAlgorithm = "scrypt"
	AlgorithmArgon2 PasswordAlgorithm = "argon2id"
)

// PasswordStrength represents password strength levels
type PasswordStrength int

const (
	PasswordVeryWeak PasswordStrength = iota
	PasswordWeak
	PasswordModerate
	PasswordStrong
	PasswordVeryStrong
)

// PasswordValidationResult represents password validation result
type PasswordValidationResult struct {
	IsValid  bool             `json:"is_valid"`
	Strength PasswordStrength `json:"strength"`
	Score    int              `json:"score"`
	Errors   []string         `json:"errors"`
	Warnings []string         `json:"warnings"`
	Checks   map[string]bool  `json:"checks"`
}

// PasswordHash represents a hashed password with metadata
type PasswordHash struct {
	Hash      string                 `json:"hash"`
	Algorithm PasswordAlgorithm      `json:"algorithm"`
	Salt      string                 `json:"salt,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// CommonPasswords contains commonly used weak passwords
var CommonPasswords = map[string]bool{
	"123456":     true,
	"password":   true,
	"123456789":  true,
	"12345678":   true,
	"12345":      true,
	"1234567":    true,
	"1234567890": true,
	"qwerty":     true,
	"abc123":     true,
	"111111":     true,
	"123123":     true,
	"admin":      true,
	"letmein":    true,
	"welcome":    true,
	"monkey":     true,
	"dragon":     true,
	"pass":       true,
	"master":     true,
	"hello":      true,
	"charlie":    true,
}

// DefaultPasswordConfig provides secure default settings
var DefaultPasswordConfig = &PasswordConfig{
	Algorithm:      AlgorithmArgon2,
	BcryptCost:     14,
	ScryptN:        32768,
	ScryptR:        8,
	ScryptP:        1,
	ScryptKeyLen:   32,
	Argon2Memory:   64 * 1024, // 64 MB
	Argon2Time:     3,
	Argon2Threads:  4,
	Argon2KeyLen:   32,
	SaltLength:     16,
	MinLength:      8,
	MaxLength:      128,
	RequireUpper:   true,
	RequireLower:   true,
	RequireDigit:   true,
	RequireSpecial: true,
}

// PasswordService provides password hashing and validation functionality
type PasswordService struct {
	config *PasswordConfig
}

// NewPasswordService creates a new password service
func NewPasswordService(config *PasswordConfig) *PasswordService {
	if config == nil {
		config = DefaultPasswordConfig
	}
	return &PasswordService{config: config}
}

// HashPassword hashes a password using the configured algorithm
func (ps *PasswordService) HashPassword(password string) (*PasswordHash, error) {
	switch ps.config.Algorithm {
	case AlgorithmBcrypt:
		return ps.hashWithBcrypt(password)
	case AlgorithmScrypt:
		return ps.hashWithScrypt(password)
	case AlgorithmArgon2:
		return ps.hashWithArgon2(password)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", ps.config.Algorithm)
	}
}

// VerifyPassword verifies a password against its hash
func (ps *PasswordService) VerifyPassword(password string, hashedPassword *PasswordHash) (bool, error) {
	switch hashedPassword.Algorithm {
	case AlgorithmBcrypt:
		return ps.verifyBcrypt(password, hashedPassword.Hash)
	case AlgorithmScrypt:
		return ps.verifyScrypt(password, hashedPassword)
	case AlgorithmArgon2:
		return ps.verifyArgon2(password, hashedPassword)
	default:
		return false, fmt.Errorf("unsupported algorithm: %s", hashedPassword.Algorithm)
	}
}

// ValidatePassword validates password against configured rules
func (ps *PasswordService) ValidatePassword(password string) *PasswordValidationResult {
	result := &PasswordValidationResult{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
		Checks:   make(map[string]bool),
	}

	// Check length
	if len(password) < ps.config.MinLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Password must be at least %d characters long", ps.config.MinLength))
		result.Checks["min_length"] = false
	} else {
		result.Checks["min_length"] = true
	}

	if len(password) > ps.config.MaxLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Password must not exceed %d characters", ps.config.MaxLength))
		result.Checks["max_length"] = false
	} else {
		result.Checks["max_length"] = true
	}

	// Check character requirements
	hasUpper := ps.config.RequireUpper && ps.hasUppercase(password)
	hasLower := ps.config.RequireLower && ps.hasLowercase(password)
	hasDigit := ps.config.RequireDigit && ps.hasDigit(password)
	hasSpecial := ps.config.RequireSpecial && ps.hasSpecialChar(password)

	result.Checks["has_uppercase"] = hasUpper || !ps.config.RequireUpper
	result.Checks["has_lowercase"] = hasLower || !ps.config.RequireLower
	result.Checks["has_digit"] = hasDigit || !ps.config.RequireDigit
	result.Checks["has_special"] = hasSpecial || !ps.config.RequireSpecial

	if ps.config.RequireUpper && !hasUpper {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one uppercase letter")
	}

	if ps.config.RequireLower && !hasLower {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one lowercase letter")
	}

	if ps.config.RequireDigit && !hasDigit {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one digit")
	}

	if ps.config.RequireSpecial && !hasSpecial {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one special character")
	}

	// Check for common passwords
	if ps.isCommonPassword(password) {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password is too common")
		result.Checks["not_common"] = false
	} else {
		result.Checks["not_common"] = true
	}

	// Check for sequential characters
	if ps.hasSequentialChars(password) {
		result.Warnings = append(result.Warnings, "Password contains sequential characters")
		result.Checks["no_sequential"] = false
	} else {
		result.Checks["no_sequential"] = true
	}

	// Check for repeated characters
	if ps.hasRepeatedChars(password) {
		result.Warnings = append(result.Warnings, "Password contains repeated characters")
		result.Checks["no_repeated"] = false
	} else {
		result.Checks["no_repeated"] = true
	}

	// Calculate strength and score
	result.Strength, result.Score = ps.calculatePasswordStrength(password)

	return result
}

// GenerateSecurePassword generates a cryptographically secure random password
func (ps *PasswordService) GenerateSecurePassword(length int, includeSymbols bool) (string, error) {
	if length < ps.config.MinLength {
		length = ps.config.MinLength
	}
	if length > ps.config.MaxLength {
		length = ps.config.MaxLength
	}

	// Character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	var charset string
	var required []rune

	// Add required character types
	if ps.config.RequireLower {
		charset += lowercase
		required = append(required, rune(lowercase[0]))
	}
	if ps.config.RequireUpper {
		charset += uppercase
		required = append(required, rune(uppercase[0]))
	}
	if ps.config.RequireDigit {
		charset += digits
		required = append(required, rune(digits[0]))
	}
	if ps.config.RequireSpecial && includeSymbols {
		charset += symbols
		required = append(required, rune(symbols[0]))
	}

	if charset == "" {
		return "", errors.New("no character types enabled")
	}

	// Generate random password
	password := make([]rune, length)
	charsetRunes := []rune(charset)

	// Fill with random characters
	for i := 0; i < length; i++ {
		randIndex, err := ps.secureRandomInt(len(charsetRunes))
		if err != nil {
			return "", err
		}
		password[i] = charsetRunes[randIndex]
	}

	// Ensure required character types are present
	for i, requiredChar := range required {
		if i < length {
			randPos, err := ps.secureRandomInt(length)
			if err != nil {
				return "", err
			}
			password[randPos] = requiredChar
		}
	}

	return string(password), nil
}

// IsPasswordCompromised checks if password appears in common breach databases
func (ps *PasswordService) IsPasswordCompromised(password string) bool {
	// This is a simplified check against common passwords
	// In production, you might want to integrate with HaveIBeenPwned API
	return ps.isCommonPassword(password)
}

// GetPasswordAge calculates password age from creation time
func (ps *PasswordService) GetPasswordAge(createdAt time.Time) time.Duration {
	return time.Since(createdAt)
}

// ShouldChangePassword determines if password should be changed based on age
func (ps *PasswordService) ShouldChangePassword(createdAt time.Time, maxAge time.Duration) bool {
	return ps.GetPasswordAge(createdAt) > maxAge
}

// hashWithBcrypt hashes password using bcrypt
func (ps *PasswordService) hashWithBcrypt(password string) (*PasswordHash, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), ps.config.BcryptCost)
	if err != nil {
		return nil, err
	}

	return &PasswordHash{
		Hash:      string(hash),
		Algorithm: AlgorithmBcrypt,
		Params: map[string]interface{}{
			"cost": ps.config.BcryptCost,
		},
		CreatedAt: time.Now(),
	}, nil
}

// hashWithScrypt hashes password using scrypt
func (ps *PasswordService) hashWithScrypt(password string) (*PasswordHash, error) {
	salt := make([]byte, ps.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash, err := scrypt.Key([]byte(password), salt, ps.config.ScryptN, ps.config.ScryptR, ps.config.ScryptP, ps.config.ScryptKeyLen)
	if err != nil {
		return nil, err
	}

	return &PasswordHash{
		Hash:      base64.URLEncoding.EncodeToString(hash),
		Algorithm: AlgorithmScrypt,
		Salt:      base64.URLEncoding.EncodeToString(salt),
		Params: map[string]interface{}{
			"N":      ps.config.ScryptN,
			"r":      ps.config.ScryptR,
			"p":      ps.config.ScryptP,
			"keyLen": ps.config.ScryptKeyLen,
		},
		CreatedAt: time.Now(),
	}, nil
}

// hashWithArgon2 hashes password using Argon2id
func (ps *PasswordService) hashWithArgon2(password string) (*PasswordHash, error) {
	salt := make([]byte, ps.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey([]byte(password), salt, ps.config.Argon2Time, ps.config.Argon2Memory, ps.config.Argon2Threads, ps.config.Argon2KeyLen)

	return &PasswordHash{
		Hash:      base64.URLEncoding.EncodeToString(hash),
		Algorithm: AlgorithmArgon2,
		Salt:      base64.URLEncoding.EncodeToString(salt),
		Params: map[string]interface{}{
			"time":    ps.config.Argon2Time,
			"memory":  ps.config.Argon2Memory,
			"threads": ps.config.Argon2Threads,
			"keyLen":  ps.config.Argon2KeyLen,
		},
		CreatedAt: time.Now(),
	}, nil
}

// verifyBcrypt verifies password using bcrypt
func (ps *PasswordService) verifyBcrypt(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// verifyScrypt verifies password using scrypt
func (ps *PasswordService) verifyScrypt(password string, hashedPassword *PasswordHash) (bool, error) {
	salt, err := base64.URLEncoding.DecodeString(hashedPassword.Salt)
	if err != nil {
		return false, err
	}

	hash, err := base64.URLEncoding.DecodeString(hashedPassword.Hash)
	if err != nil {
		return false, err
	}

	// Get parameters from stored hash
	N := int(hashedPassword.Params["N"].(float64))
	r := int(hashedPassword.Params["r"].(float64))
	p := int(hashedPassword.Params["p"].(float64))
	keyLen := int(hashedPassword.Params["keyLen"].(float64))

	computedHash, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// verifyArgon2 verifies password using Argon2id
func (ps *PasswordService) verifyArgon2(password string, hashedPassword *PasswordHash) (bool, error) {
	salt, err := base64.URLEncoding.DecodeString(hashedPassword.Salt)
	if err != nil {
		return false, err
	}

	hash, err := base64.URLEncoding.DecodeString(hashedPassword.Hash)
	if err != nil {
		return false, err
	}

	// Get parameters from stored hash
	time := uint32(hashedPassword.Params["time"].(float64))
	memory := uint32(hashedPassword.Params["memory"].(float64))
	threads := uint8(hashedPassword.Params["threads"].(float64))
	keyLen := uint32(hashedPassword.Params["keyLen"].(float64))

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// Character type checking functions
func (ps *PasswordService) hasUppercase(password string) bool {
	for _, char := range password {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

func (ps *PasswordService) hasLowercase(password string) bool {
	for _, char := range password {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

func (ps *PasswordService) hasDigit(password string) bool {
	for _, char := range password {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

func (ps *PasswordService) hasSpecialChar(password string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, char := range password {
		if strings.ContainsRune(specialChars, char) {
			return true
		}
	}
	return false
}

// Password quality checking functions
func (ps *PasswordService) isCommonPassword(password string) bool {
	return CommonPasswords[strings.ToLower(password)]
}

func (ps *PasswordService) hasSequentialChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	for i := 0; i < len(password)-2; i++ {
		if password[i]+1 == password[i+1] && password[i+1]+1 == password[i+2] {
			return true
		}
		if password[i]-1 == password[i+1] && password[i+1]-1 == password[i+2] {
			return true
		}
	}
	return false
}

func (ps *PasswordService) hasRepeatedChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			return true
		}
	}
	return false
}

// calculatePasswordStrength calculates password strength and score
func (ps *PasswordService) calculatePasswordStrength(password string) (PasswordStrength, int) {
	score := 0

	// Length scoring
	length := len(password)
	if length >= 8 {
		score += 10
	}
	if length >= 12 {
		score += 10
	}
	if length >= 16 {
		score += 10
	}

	// Character diversity scoring
	if ps.hasLowercase(password) {
		score += 5
	}
	if ps.hasUppercase(password) {
		score += 5
	}
	if ps.hasDigit(password) {
		score += 5
	}
	if ps.hasSpecialChar(password) {
		score += 10
	}

	// Unique characters
	uniqueChars := make(map[rune]bool)
	for _, char := range password {
		uniqueChars[char] = true
	}
	if len(uniqueChars) >= length/2 {
		score += 10
	}

	// Penalty for common patterns
	if ps.isCommonPassword(password) {
		score -= 20
	}
	if ps.hasSequentialChars(password) {
		score -= 10
	}
	if ps.hasRepeatedChars(password) {
		score -= 10
	}

	// Dictionary words check
	if ps.containsDictionaryWord(password) {
		score -= 15
	}

	// Determine strength level
	switch {
	case score < 30:
		return PasswordVeryWeak, score
	case score < 50:
		return PasswordWeak, score
	case score < 70:
		return PasswordModerate, score
	case score < 85:
		return PasswordStrong, score
	default:
		return PasswordVeryStrong, score
	}
}

// containsDictionaryWord checks if password contains common dictionary words
func (ps *PasswordService) containsDictionaryWord(password string) bool {
	// Simple check for common words
	commonWords := []string{"password", "admin", "user", "login", "welcome", "hello", "world"}
	lowerPassword := strings.ToLower(password)

	for _, word := range commonWords {
		if strings.Contains(lowerPassword, word) {
			return true
		}
	}
	return false
}

// secureRandomInt generates a cryptographically secure random integer
func (ps *PasswordService) secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}

	// Calculate the range size
	rangeSize := uint32(max)

	// Calculate the maximum value that ensures uniform distribution
	maxValidValue := (^uint32(0)) - (^uint32(0))%rangeSize

	for {
		// Generate 4 random bytes
		randomBytes := make([]byte, 4)
		if _, err := rand.Read(randomBytes); err != nil {
			return 0, err
		}

		// Convert to uint32
		randomValue := uint32(randomBytes[0])<<24 | uint32(randomBytes[1])<<16 | uint32(randomBytes[2])<<8 | uint32(randomBytes[3])

		// Check if the value is within the valid range
		if randomValue < maxValidValue {
			return int(randomValue % rangeSize), nil
		}
	}
}

// EstimateHashTime estimates time to hash password with current settings
func (ps *PasswordService) EstimateHashTime() time.Duration {
	testPassword := "testpassword123"
	start := time.Now()
	_, _ = ps.HashPassword(testPassword)
	return time.Since(start)
}

// GetPasswordStrengthText returns human-readable password strength
func GetPasswordStrengthText(strength PasswordStrength) string {
	switch strength {
	case PasswordVeryWeak:
		return "Very Weak"
	case PasswordWeak:
		return "Weak"
	case PasswordModerate:
		return "Moderate"
	case PasswordStrong:
		return "Strong"
	case PasswordVeryStrong:
		return "Very Strong"
	default:
		return "Unknown"
	}
}

// ValidatePasswordPolicy validates password against a custom policy
func ValidatePasswordPolicy(password string, policy map[string]interface{}) []string {
	var errors []string

	if minLen, ok := policy["min_length"].(int); ok {
		if len(password) < minLen {
			errors = append(errors, fmt.Sprintf("Password must be at least %d characters", minLen))
		}
	}

	if maxLen, ok := policy["max_length"].(int); ok {
		if len(password) > maxLen {
			errors = append(errors, fmt.Sprintf("Password must not exceed %d characters", maxLen))
		}
	}

	if requireUpper, ok := policy["require_uppercase"].(bool); ok && requireUpper {
		if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
			errors = append(errors, "Password must contain uppercase letters")
		}
	}

	if requireLower, ok := policy["require_lowercase"].(bool); ok && requireLower {
		if !regexp.MustCompile(`[a-z]`).MatchString(password) {
			errors = append(errors, "Password must contain lowercase letters")
		}
	}

	if requireDigit, ok := policy["require_digit"].(bool); ok && requireDigit {
		if !regexp.MustCompile(`[0-9]`).MatchString(password) {
			errors = append(errors, "Password must contain digits")
		}
	}

	if requireSpecial, ok := policy["require_special"].(bool); ok && requireSpecial {
		if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]`).MatchString(password) {
			errors = append(errors, "Password must contain special characters")
		}
	}

	return errors
}
