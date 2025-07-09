package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// JWTConfig represents JWT configuration
type JWTConfig struct {
	SecretKey              string
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	Issuer                 string
	Audience               string
	PrivateKey             *rsa.PrivateKey
	PublicKey              *rsa.PublicKey
	SigningMethod          jwt.SigningMethod
}

// TokenType represents different types of tokens
type TokenType string

const (
	TokenTypeAccess        TokenType = "access"
	TokenTypeRefresh       TokenType = "refresh"
	TokenTypeEmailVerify   TokenType = "email_verify"
	TokenTypePasswordReset TokenType = "password_reset"
	TokenTypeInvite        TokenType = "invite"
	TokenTypeAPIKey        TokenType = "api_key"
)

// Claims represents JWT claims
type Claims struct {
	UserID      primitive.ObjectID `json:"user_id"`
	Username    string             `json:"username"`
	Email       string             `json:"email"`
	Role        string             `json:"role"`
	TokenType   TokenType          `json:"token_type"`
	Permissions []string           `json:"permissions,omitempty"`
	Scopes      []string           `json:"scopes,omitempty"`
	DeviceID    string             `json:"device_id,omitempty"`
	IPAddress   string             `json:"ip_address,omitempty"`
	SessionID   string             `json:"session_id,omitempty"`
	IsRefresh   bool               `json:"is_refresh,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// JWTService represents JWT service
type JWTService struct {
	config *JWTConfig
}

// NewJWTService creates a new JWT service
func NewJWTService(config *JWTConfig) *JWTService {
	// Set default signing method if not specified
	if config.SigningMethod == nil {
		if config.PrivateKey != nil {
			config.SigningMethod = jwt.SigningMethodRS256
		} else {
			config.SigningMethod = jwt.SigningMethodHS256
		}
	}

	return &JWTService{
		config: config,
	}
}

// GenerateTokenPair generates access and refresh token pair
func (j *JWTService) GenerateTokenPair(userID primitive.ObjectID, username, email, role string, permissions []string, deviceID, ipAddress string) (*TokenPair, error) {
	sessionID := GenerateRandomString(32)
	now := time.Now()

	// Generate access token
	accessClaims := &Claims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Role:        role,
		TokenType:   TokenTypeAccess,
		Permissions: permissions,
		DeviceID:    deviceID,
		IPAddress:   ipAddress,
		SessionID:   sessionID,
		IsRefresh:   false,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			Audience:  jwt.ClaimStrings{j.config.Audience},
			Subject:   userID.Hex(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.config.AccessTokenExpiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        GenerateJTI(),
		},
	}

	accessToken, err := j.signToken(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &Claims{
		UserID:    userID,
		Username:  username,
		Email:     email,
		Role:      role,
		TokenType: TokenTypeRefresh,
		DeviceID:  deviceID,
		IPAddress: ipAddress,
		SessionID: sessionID,
		IsRefresh: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			Audience:  jwt.ClaimStrings{j.config.Audience},
			Subject:   userID.Hex(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.config.RefreshTokenExpiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        GenerateJTI(),
		},
	}

	refreshToken, err := j.signToken(refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessClaims.ExpiresAt.Time,
		RefreshTokenExpiresAt: refreshClaims.ExpiresAt.Time,
		TokenType:             "Bearer",
	}, nil
}

// GenerateSpecialToken generates special purpose tokens (email verification, password reset, etc.)
func (j *JWTService) GenerateSpecialToken(userID primitive.ObjectID, email string, tokenType TokenType, expiration time.Duration, data map[string]interface{}) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			Audience:  jwt.ClaimStrings{j.config.Audience},
			Subject:   userID.Hex(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        GenerateJTI(),
		},
	}

	// Add custom data to claims
	if data != nil {
		token := jwt.NewWithClaims(j.config.SigningMethod, claims)
		for key, value := range data {
			token.Claims.(jwt.MapClaims)[key] = value
		}
		return j.signTokenWithClaims(token)
	}

	return j.signToken(claims)
}

// ValidateToken validates and parses JWT token
func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, j.getKeyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Validate token type and basic claims
	if err := j.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// RefreshTokens refreshes access token using refresh token
func (j *JWTService) RefreshTokens(refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, errors.New("not a refresh token")
	}

	// Generate new token pair
	return j.GenerateTokenPair(
		claims.UserID,
		claims.Username,
		claims.Email,
		claims.Role,
		claims.Permissions,
		claims.DeviceID,
		claims.IPAddress,
	)
}

// ExtractTokenFromHeader extracts token from Authorization header
func (j *JWTService) ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is empty")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	return authHeader[len(bearerPrefix):], nil
}

// GetTokenClaims extracts claims from token without validation (for expired tokens)
func (j *JWTService) GetTokenClaims(tokenString string) (*Claims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// BlacklistToken adds token to blacklist (implementation depends on storage)
func (j *JWTService) BlacklistToken(tokenString string) error {
	claims, err := j.GetTokenClaims(tokenString)
	if err != nil {
		return err
	}

	// Store token ID with expiration time in cache/database
	// This is a placeholder - implement based on your storage solution
	return j.addToBlacklist(claims.ID, claims.ExpiresAt.Time)
}

// IsTokenBlacklisted checks if token is blacklisted
func (j *JWTService) IsTokenBlacklisted(tokenString string) (bool, error) {
	claims, err := j.GetTokenClaims(tokenString)
	if err != nil {
		return false, err
	}

	// Check if token ID is in blacklist
	// This is a placeholder - implement based on your storage solution
	return j.isInBlacklist(claims.ID), nil
}

// signToken signs token with claims
func (j *JWTService) signToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(j.config.SigningMethod, claims)
	return j.signTokenWithClaims(token)
}

// signTokenWithClaims signs token with custom claims
func (j *JWTService) signTokenWithClaims(token *jwt.Token) (string, error) {
	switch j.config.SigningMethod {
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		if j.config.PrivateKey == nil {
			return "", errors.New("private key is required for RSA signing")
		}
		return token.SignedString(j.config.PrivateKey)
	default:
		if j.config.SecretKey == "" {
			return "", errors.New("secret key is required for HMAC signing")
		}
		return token.SignedString([]byte(j.config.SecretKey))
	}
}

// getKeyFunc returns the key function for token validation
func (j *JWTService) getKeyFunc(token *jwt.Token) (interface{}, error) {
	switch j.config.SigningMethod {
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		if j.config.PublicKey == nil {
			return nil, errors.New("public key is required for RSA verification")
		}
		return j.config.PublicKey, nil
	default:
		if j.config.SecretKey == "" {
			return nil, errors.New("secret key is required for HMAC verification")
		}
		return []byte(j.config.SecretKey), nil
	}
}

// validateClaims validates token claims
func (j *JWTService) validateClaims(claims *Claims) error {
	// Check if token is expired
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return errors.New("token is expired")
	}

	// Check if token is not yet valid
	if claims.NotBefore != nil && time.Now().Before(claims.NotBefore.Time) {
		return errors.New("token is not yet valid")
	}

	// Validate issuer
	if j.config.Issuer != "" && claims.Issuer != j.config.Issuer {
		return errors.New("invalid token issuer")
	}

	// Validate audience
	if j.config.Audience != "" {
		if claims.Audience == nil || len(claims.Audience) == 0 {
			return errors.New("token has no audience")
		}

		validAudience := false
		for _, aud := range claims.Audience {
			if aud == j.config.Audience {
				validAudience = true
				break
			}
		}

		if !validAudience {
			return errors.New("invalid token audience")
		}
	}

	return nil
}

// addToBlacklist adds token to blacklist (placeholder implementation)
func (j *JWTService) addToBlacklist(tokenID string, expiresAt time.Time) error {
	// Implement based on your storage solution (Redis, database, etc.)
	// Store tokenID with TTL based on expiresAt
	return nil
}

// isInBlacklist checks if token is in blacklist (placeholder implementation)
func (j *JWTService) isInBlacklist(tokenID string) bool {
	// Implement based on your storage solution
	return false
}

// GenerateJTI generates a unique JWT ID
func GenerateJTI() string {
	return fmt.Sprintf("%d_%s", time.Now().Unix(), GenerateRandomString(16))
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateKeyPair generates RSA key pair for JWT signing
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, errors.New("key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// EncodePrivateKeyToPEM encodes RSA private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(privKeyPEM)
}

// EncodePublicKeyToPEM encodes RSA public key to PEM format
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pubKeyPEM), nil
}

// DecodePrivateKeyFromPEM decodes RSA private key from PEM format
func DecodePrivateKeyFromPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// DecodePublicKeyFromPEM decodes RSA public key from PEM format
func DecodePublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPublicKey, nil
}

// GenerateSecretKey generates a random secret key for HMAC signing
func GenerateSecretKey(length int) string {
	if length < 32 {
		length = 32 // Minimum recommended length for HS256
	}

	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// ValidateSecretKey validates secret key strength
func ValidateSecretKey(secretKey string) error {
	if len(secretKey) < 32 {
		return errors.New("secret key must be at least 32 characters long")
	}

	// Decode base64 if applicable
	if decoded, err := base64.URLEncoding.DecodeString(secretKey); err == nil {
		if len(decoded) < 32 {
			return errors.New("decoded secret key must be at least 32 bytes long")
		}
	}

	return nil
}

// GetTokenExpiration returns token expiration time
func (j *JWTService) GetTokenExpiration(tokenType TokenType) time.Duration {
	switch tokenType {
	case TokenTypeAccess:
		return j.config.AccessTokenExpiration
	case TokenTypeRefresh:
		return j.config.RefreshTokenExpiration
	case TokenTypeEmailVerify:
		return 24 * time.Hour
	case TokenTypePasswordReset:
		return 1 * time.Hour
	case TokenTypeInvite:
		return 7 * 24 * time.Hour
	default:
		return j.config.AccessTokenExpiration
	}
}

// CreateAPIKeyToken creates a long-lived API key token
func (j *JWTService) CreateAPIKeyToken(userID primitive.ObjectID, name string, scopes []string, expiresAt *time.Time) (string, error) {
	now := time.Now()

	var expiry *jwt.NumericDate
	if expiresAt != nil {
		expiry = jwt.NewNumericDate(*expiresAt)
	} else {
		// Default to 1 year if no expiry specified
		expiry = jwt.NewNumericDate(now.Add(365 * 24 * time.Hour))
	}

	claims := &Claims{
		UserID:    userID,
		TokenType: TokenTypeAPIKey,
		Scopes:    scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			Audience:  jwt.ClaimStrings{j.config.Audience},
			Subject:   userID.Hex(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: expiry,
			NotBefore: jwt.NewNumericDate(now),
			ID:        GenerateJTI(),
		},
	}

	token := jwt.NewWithClaims(j.config.SigningMethod, claims)
	token.Claims.(jwt.MapClaims)["name"] = name

	return j.signTokenWithClaims(token)
}
