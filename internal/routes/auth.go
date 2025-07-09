package routes

import (
	"bro-network/internal/handlers"

	"github.com/gin-gonic/gin"
)

// SetupAuthRoutes sets up authentication-related routes
func SetupAuthRoutes(api *gin.RouterGroup, authHandler *handlers.AuthHandler) {
	auth := api.Group("/auth")

	// User Registration & Login
	auth.POST("/register",
		applyValidation("register"),
		applyRateLimit("auth:5/min"),
		authHandler.Register,
	)

	auth.POST("/login",
		applyValidation("login"),
		applyRateLimit("auth:10/min"),
		authHandler.Login,
	)

	auth.POST("/logout",
		authHandler.Logout,
	)

	auth.POST("/refresh",
		applyRateLimit("auth:20/min"),
		authHandler.RefreshToken,
	)

	// Email Verification
	auth.POST("/verify-email",
		applyValidation("verify_email"),
		applyRateLimit("auth:5/min"),
		authHandler.VerifyEmail,
	)

	auth.POST("/resend-verification",
		applyValidation("email"),
		applyRateLimit("auth:3/min"),
		authHandler.ResendVerification,
	)

	// Password Reset
	auth.POST("/forgot-password",
		applyValidation("email"),
		applyRateLimit("auth:3/min"),
		authHandler.ForgotPassword,
	)

	auth.POST("/reset-password",
		applyValidation("reset_password"),
		applyRateLimit("auth:3/min"),
		authHandler.ResetPassword,
	)

	auth.POST("/change-password",
		applyValidation("change_password"),
		authHandler.ChangePassword,
	)

	// Two-Factor Authentication
	auth.POST("/2fa/enable",
		authHandler.EnableTwoFactor,
	)

	auth.POST("/2fa/disable",
		applyValidation("2fa_code"),
		authHandler.DisableTwoFactor,
	)

	auth.POST("/2fa/verify",
		applyValidation("2fa_verify"),
		authHandler.VerifyTwoFactor,
	)

	auth.POST("/2fa/backup-codes",
		authHandler.GenerateBackupCodes,
	)

	// Social Login (OAuth)
	auth.GET("/google",
		authHandler.GoogleLogin,
	)

	auth.GET("/google/callback",
		authHandler.GoogleCallback,
	)

	auth.GET("/facebook",
		authHandler.FacebookLogin,
	)

	auth.GET("/facebook/callback",
		authHandler.FacebookCallback,
	)

	auth.GET("/twitter",
		authHandler.TwitterLogin,
	)

	auth.GET("/twitter/callback",
		authHandler.TwitterCallback,
	)

	// Session Management
	auth.GET("/sessions",
		authHandler.GetActiveSessions,
	)

	auth.DELETE("/sessions/:session_id",
		authHandler.RevokeSession,
	)

	auth.DELETE("/sessions",
		authHandler.RevokeAllSessions,
	)

	// Account Security
	auth.POST("/check-password",
		applyValidation("password"),
		authHandler.CheckPassword,
	)

	auth.GET("/security-log",
		authHandler.GetSecurityLog,
	)

	auth.POST("/account/deactivate",
		applyValidation("password"),
		authHandler.DeactivateAccount,
	)

	auth.POST("/account/reactivate",
		applyValidation("reactivate"),
		authHandler.ReactivateAccount,
	)

	auth.DELETE("/account",
		applyValidation("delete_account"),
		authHandler.DeleteAccount,
	)

	// API Keys Management
	auth.GET("/api-keys",
		authHandler.GetAPIKeys,
	)

	auth.POST("/api-keys",
		applyValidation("create_api_key"),
		authHandler.CreateAPIKey,
	)

	auth.PUT("/api-keys/:key_id",
		applyValidation("update_api_key"),
		authHandler.UpdateAPIKey,
	)

	auth.DELETE("/api-keys/:key_id",
		authHandler.RevokeAPIKey,
	)

	// Account Verification & KYC
	auth.POST("/verify-identity",
		applyValidation("identity_verification"),
		authHandler.VerifyIdentity,
	)

	auth.GET("/verification-status",
		authHandler.GetVerificationStatus,
	)

	// Privacy & Data
	auth.GET("/data-export",
		authHandler.RequestDataExport,
	)

	auth.GET("/data-export/:export_id",
		authHandler.GetDataExport,
	)

	auth.POST("/data-portability",
		applyValidation("data_portability"),
		authHandler.RequestDataPortability,
	)
}

// Authentication validation rules that handlers will need:
/*
Required Validation Schemas:

1. register:
   - username: required,username,min:3,max:30,unique
   - email: required,email,unique
   - password: required,min:8,password_strength
   - confirm_password: required,same:password
   - first_name: required,min:1,max:50
   - last_name: required,min:1,max:50
   - date_of_birth: required,date
   - accept_terms: required,boolean,accepted

2. login:
   - identifier: required (email or username)
   - password: required
   - remember_me: boolean
   - captcha: sometimes,required

3. verify_email:
   - token: required,string
   - email: required,email

4. reset_password:
   - token: required,string
   - password: required,min:8,password_strength
   - confirm_password: required,same:password

5. change_password:
   - current_password: required
   - new_password: required,min:8,password_strength,different:current_password
   - confirm_password: required,same:new_password

6. 2fa_code:
   - code: required,numeric,length:6

7. 2fa_verify:
   - code: required,numeric,length:6
   - backup_code: sometimes,string

8. create_api_key:
   - name: required,string,max:100
   - scopes: required,array
   - expires_at: sometimes,date

9. identity_verification:
   - document_type: required,in:passport,license,id_card
   - document_number: required,string
   - document_front: required,file,image
   - document_back: sometimes,file,image
   - selfie: required,file,image

10. delete_account:
    - password: required
    - confirmation: required,string,exact:"DELETE"
    - reason: sometimes,string,max:500
*/
