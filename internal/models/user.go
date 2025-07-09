package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the social network
type User struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username           string             `bson:"username" json:"username" binding:"required,min=3,max=30"`
	Email              string             `bson:"email" json:"email" binding:"required,email"`
	Password           string             `bson:"password" json:"-"` // Never return in JSON
	FirstName          string             `bson:"first_name" json:"first_name" binding:"required,min=1,max=50"`
	LastName           string             `bson:"last_name" json:"last_name" binding:"required,min=1,max=50"`
	DisplayName        string             `bson:"display_name" json:"display_name" binding:"max=100"`
	Bio                string             `bson:"bio" json:"bio" binding:"max=500"`
	ProfileImage       string             `bson:"profile_image" json:"profile_image"`
	CoverImage         string             `bson:"cover_image" json:"cover_image"`
	Website            string             `bson:"website" json:"website" binding:"url"`
	Location           string             `bson:"location" json:"location" binding:"max=100"`
	DateOfBirth        *time.Time         `bson:"date_of_birth" json:"date_of_birth"`
	IsVerified         bool               `bson:"is_verified" json:"is_verified"`
	IsPrivate          bool               `bson:"is_private" json:"is_private"`
	IsActive           bool               `bson:"is_active" json:"is_active"`
	IsBanned           bool               `bson:"is_banned" json:"is_banned"`
	Role               UserRole           `bson:"role" json:"role"`
	Permissions        []string           `bson:"permissions,omitempty" json:"permissions,omitempty"`
	Settings           UserSettings       `bson:"settings" json:"settings"`
	Stats              UserStats          `bson:"stats" json:"stats"`
	SocialLinks        SocialLinks        `bson:"social_links" json:"social_links"`
	LastSeen           *time.Time         `bson:"last_seen" json:"last_seen"`
	EmailVerified      bool               `bson:"email_verified" json:"email_verified"`
	EmailVerifyToken   string             `bson:"email_verify_token" json:"-"`
	PasswordResetToken string             `bson:"password_reset_token" json:"-"`
	PasswordResetExp   *time.Time         `bson:"password_reset_exp" json:"-"`
	TwoFactorEnabled   bool               `bson:"two_factor_enabled" json:"two_factor_enabled"`
	TwoFactorSecret    string             `bson:"two_factor_secret" json:"-"`
	LoginAttempts      int                `bson:"login_attempts" json:"-"`
	LockedUntil        *time.Time         `bson:"locked_until" json:"-"`
	IPAddress          string             `bson:"ip_address" json:"-"`
	UserAgent          string             `bson:"user_agent" json:"-"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
	DeletedAt          *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// UserRole represents user roles
type UserRole string

const (
	RoleUser       UserRole = "user"
	RoleModerator  UserRole = "moderator"
	RoleAdmin      UserRole = "admin"
	RoleSuperAdmin UserRole = "super_admin"
)

// UserSettings represents user preferences and settings
type UserSettings struct {
	Theme               string `bson:"theme" json:"theme"` // light, dark, auto
	Language            string `bson:"language" json:"language"`
	TimeZone            string `bson:"timezone" json:"timezone"`
	EmailNotifications  bool   `bson:"email_notifications" json:"email_notifications"`
	PushNotifications   bool   `bson:"push_notifications" json:"push_notifications"`
	SMSNotifications    bool   `bson:"sms_notifications" json:"sms_notifications"`
	ShowOnlineStatus    bool   `bson:"show_online_status" json:"show_online_status"`
	ShowReadReceipts    bool   `bson:"show_read_receipts" json:"show_read_receipts"`
	AllowDirectMessages bool   `bson:"allow_direct_messages" json:"allow_direct_messages"`
	ShowActivityStatus  bool   `bson:"show_activity_status" json:"show_activity_status"`
	ContentDiscovery    bool   `bson:"content_discovery" json:"content_discovery"`
	SensitiveContent    bool   `bson:"sensitive_content" json:"sensitive_content"`
	PersonalizedAds     bool   `bson:"personalized_ads" json:"personalized_ads"`
	DataSharing         bool   `bson:"data_sharing" json:"data_sharing"`
}

// UserStats represents user statistics
type UserStats struct {
	PostsCount     int64 `bson:"posts_count" json:"posts_count"`
	FollowersCount int64 `bson:"followers_count" json:"followers_count"`
	FollowingCount int64 `bson:"following_count" json:"following_count"`
	LikesCount     int64 `bson:"likes_count" json:"likes_count"`
	CommentsCount  int64 `bson:"comments_count" json:"comments_count"`
	SharesCount    int64 `bson:"shares_count" json:"shares_count"`
	ViewsCount     int64 `bson:"views_count" json:"views_count"`
	ReportsCount   int64 `bson:"reports_count" json:"reports_count"`
	WarningsCount  int64 `bson:"warnings_count" json:"warnings_count"`
}

// SocialLinks represents user's social media links
type SocialLinks struct {
	Twitter   string `bson:"twitter" json:"twitter"`
	Instagram string `bson:"instagram" json:"instagram"`
	LinkedIn  string `bson:"linkedin" json:"linkedin"`
	GitHub    string `bson:"github" json:"github"`
	YouTube   string `bson:"youtube" json:"youtube"`
	TikTok    string `bson:"tiktok" json:"tiktok"`
	Facebook  string `bson:"facebook" json:"facebook"`
	Other     string `bson:"other" json:"other"`
}

// UserLoginRequest represents login request
type UserLoginRequest struct {
	Identifier string `json:"identifier" binding:"required"` // email or username
	Password   string `json:"password" binding:"required,min=8"`
	RememberMe bool   `json:"remember_me"`
}

// UserRegisterRequest represents registration request
type UserRegisterRequest struct {
	Username        string `json:"username" binding:"required,min=3,max=30"`
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required,min=8"`
	FirstName       string `json:"first_name" binding:"required,min=1,max=50"`
	LastName        string `json:"last_name" binding:"required,min=1,max=50"`
	DateOfBirth     string `json:"date_of_birth" binding:"required"`
	AcceptTerms     bool   `json:"accept_terms" binding:"required"`
}

// UserUpdateRequest represents user update request
type UserUpdateRequest struct {
	FirstName   string       `json:"first_name" binding:"min=1,max=50"`
	LastName    string       `json:"last_name" binding:"min=1,max=50"`
	DisplayName string       `json:"display_name" binding:"max=100"`
	Bio         string       `json:"bio" binding:"max=500"`
	Website     string       `json:"website" binding:"url"`
	Location    string       `json:"location" binding:"max=100"`
	IsPrivate   *bool        `json:"is_private"`
	SocialLinks SocialLinks  `json:"social_links"`
	Settings    UserSettings `json:"settings"`
}

// UserPasswordChangeRequest represents password change request
type UserPasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required,min=8"`
}

// UserSearchResult represents user search result
type UserSearchResult struct {
	ID           primitive.ObjectID `json:"id"`
	Username     string             `json:"username"`
	DisplayName  string             `json:"display_name"`
	ProfileImage string             `json:"profile_image"`
	IsVerified   bool               `json:"is_verified"`
	IsFollowing  bool               `json:"is_following"`
	IsFollower   bool               `json:"is_follower"`
	MutualCount  int64              `json:"mutual_count"`
}

// UserPublicProfile represents public user profile
type UserPublicProfile struct {
	ID           primitive.ObjectID `json:"id"`
	Username     string             `json:"username"`
	DisplayName  string             `json:"display_name"`
	Bio          string             `json:"bio"`
	ProfileImage string             `json:"profile_image"`
	CoverImage   string             `json:"cover_image"`
	Website      string             `json:"website"`
	Location     string             `json:"location"`
	IsVerified   bool               `json:"is_verified"`
	IsPrivate    bool               `json:"is_private"`
	Stats        UserStats          `json:"stats"`
	SocialLinks  SocialLinks        `json:"social_links"`
	IsFollowing  bool               `json:"is_following"`
	IsFollower   bool               `json:"is_follower"`
	CanMessage   bool               `json:"can_message"`
	JoinedAt     time.Time          `json:"joined_at"`
}

// UserAuthResponse represents authentication response
type UserAuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UserListResponse represents user list response
type UserListResponse struct {
	Users      []UserPublicProfile `json:"users"`
	TotalCount int64               `json:"total_count"`
	Page       int                 `json:"page"`
	Limit      int                 `json:"limit"`
	HasMore    bool                `json:"has_more"`
}
