package constants

import "time"

// =============================================================================
// APPLICATION CONSTANTS
// =============================================================================

const (
	// Application information
	AppName        = "Threads Social Network"
	AppVersion     = "1.0.0"
	AppDescription = "A modern social networking platform"

	// API versioning
	APIVersion   = "v1"
	APIPrefix    = "/api/v1"
	AdminPrefix  = "/api/v1/admin"
	HealthPrefix = "/health"

	// Environment constants
	EnvDevelopment = "development"
	EnvStaging     = "staging"
	EnvProduction  = "production"
	EnvTesting     = "testing"
)

// =============================================================================
// HTTP AND RESPONSE CONSTANTS
// =============================================================================

const (
	// Content types
	ContentTypeJSON = "application/json"
	ContentTypeXML  = "application/xml"
	ContentTypeHTML = "text/html"
	ContentTypeText = "text/plain"
	ContentTypeForm = "application/x-www-form-urlencoded"

	// HTTP headers
	HeaderContentType     = "Content-Type"
	HeaderAuthorization   = "Authorization"
	HeaderAcceptLanguage  = "Accept-Language"
	HeaderUserAgent       = "User-Agent"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXRealIP         = "X-Real-IP"
	HeaderXRequestID      = "X-Request-ID"
	HeaderXCorrelationID  = "X-Correlation-ID"
	HeaderCacheControl    = "Cache-Control"
	HeaderETag            = "ETag"
	HeaderLastModified    = "Last-Modified"
	HeaderIfNoneMatch     = "If-None-Match"
	HeaderIfModifiedSince = "If-Modified-Since"

	// CORS headers
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"

	// Rate limiting headers
	HeaderRateLimitLimit     = "X-RateLimit-Limit"
	HeaderRateLimitRemaining = "X-RateLimit-Remaining"
	HeaderRateLimitReset     = "X-RateLimit-Reset"
	HeaderRetryAfter         = "Retry-After"
)

// =============================================================================
// DATABASE CONSTANTS
// =============================================================================

const (
	// Collection names
	CollectionUsers         = "users"
	CollectionPosts         = "posts"
	CollectionComments      = "comments"
	CollectionLikes         = "likes"
	CollectionFollows       = "follows"
	CollectionMessages      = "messages"
	CollectionConversations = "conversations"
	CollectionNotifications = "notifications"
	CollectionReports       = "reports"
	CollectionAnalytics     = "analytics"
	CollectionAuditLogs     = "audit_logs"
	CollectionSessions      = "sessions"
	CollectionFiles         = "files"
	CollectionFolders       = "folders"
	CollectionAlbums        = "albums"
	CollectionHashtags      = "hashtags"
	CollectionLocations     = "locations"
	CollectionTopics        = "topics"

	// Database operation types
	DBOpCreate    = "create"
	DBOpRead      = "read"
	DBOpUpdate    = "update"
	DBOpDelete    = "delete"
	DBOpFind      = "find"
	DBOpCount     = "count"
	DBOpAggregate = "aggregate"

	// Index names
	IndexUserEmail       = "user_email_unique"
	IndexUserUsername    = "user_username_unique"
	IndexPostAuthor      = "post_author_1"
	IndexPostCreatedAt   = "post_created_at_-1"
	IndexCommentPost     = "comment_post_1"
	IndexLikeTarget      = "like_target_user_1"
	IndexFollowUsers     = "follow_follower_followee_1"
	IndexMessageConv     = "message_conversation_1"
	IndexNotifUser       = "notification_user_1"
	IndexReportTarget    = "report_target_1"
	IndexAnalyticsEntity = "analytics_entity_date_1"
	IndexAuditUser       = "audit_user_action_1"
	IndexFileUser        = "file_user_1"
	IndexHashtagName     = "hashtag_name_1"
)

// =============================================================================
// CACHE CONSTANTS
// =============================================================================

const (
	// Cache key prefixes
	CacheKeyUser         = "user:"
	CacheKeyPost         = "post:"
	CacheKeyComment      = "comment:"
	CacheKeyConversation = "conversation:"
	CacheKeyFeed         = "feed:"
	CacheKeyTrending     = "trending:"
	CacheKeyStats        = "stats:"
	CacheKeySession      = "session:"
	CacheKeyRateLimit    = "rate_limit:"
	CacheKeySearch       = "search:"
	CacheKeyNotification = "notification:"
	CacheKeyFile         = "file:"
	CacheKeyHashtag      = "hashtag:"
	CacheKeyLocation     = "location:"

	// Cache key patterns
	CacheKeyUserProfile      = CacheKeyUser + "profile:%s"
	CacheKeyUserStats        = CacheKeyUser + "stats:%s"
	CacheKeyUserFollowers    = CacheKeyUser + "followers:%s"
	CacheKeyUserFollowing    = CacheKeyUser + "following:%s"
	CacheKeyPostDetails      = CacheKeyPost + "details:%s"
	CacheKeyPostLikes        = CacheKeyPost + "likes:%s"
	CacheKeyPostComments     = CacheKeyPost + "comments:%s"
	CacheKeyUserFeed         = CacheKeyFeed + "user:%s"
	CacheKeyExploreFeed      = CacheKeyFeed + "explore"
	CacheKeyTrendingPosts    = CacheKeyTrending + "posts"
	CacheKeyTrendingHashtags = CacheKeyTrending + "hashtags"
	CacheKeyTrendingUsers    = CacheKeyTrending + "users"
	CacheKeySearchResults    = CacheKeySearch + "results:%s"
	CacheKeyUserNotifCount   = CacheKeyNotification + "count:%s"

	// Cache TTL durations
	CacheTTLShort     = 5 * time.Minute
	CacheTTLMedium    = 30 * time.Minute
	CacheTTLLong      = 2 * time.Hour
	CacheTTLExtended  = 24 * time.Hour
	CacheTTLPermanent = 7 * 24 * time.Hour
)

// =============================================================================
// RATE LIMITING CONSTANTS
// =============================================================================

const (
	// Rate limit keys
	RateLimitAuth    = "auth"
	RateLimitPost    = "post"
	RateLimitComment = "comment"
	RateLimitLike    = "like"
	RateLimitFollow  = "follow"
	RateLimitMessage = "message"
	RateLimitUpload  = "upload"
	RateLimitSearch  = "search"
	RateLimitAPI     = "api"
	RateLimitGlobal  = "global"

	// Rate limit values (requests per time window)
	RateLimitAuthRequests    = 10    // per minute
	RateLimitPostRequests    = 20    // per hour
	RateLimitCommentRequests = 60    // per hour
	RateLimitLikeRequests    = 100   // per minute
	RateLimitFollowRequests  = 50    // per hour
	RateLimitMessageRequests = 100   // per hour
	RateLimitUploadRequests  = 50    // per hour
	RateLimitSearchRequests  = 100   // per hour
	RateLimitAPIRequests     = 1000  // per hour
	RateLimitGlobalRequests  = 10000 // per hour

	// Rate limit windows
	RateLimitWindowMinute = time.Minute
	RateLimitWindowHour   = time.Hour
	RateLimitWindowDay    = 24 * time.Hour
)

// =============================================================================
// FILE UPLOAD CONSTANTS
// =============================================================================

const (
	// File size limits (in bytes)
	MaxAvatarSize   = 5 * 1024 * 1024    // 5MB
	MaxCoverSize    = 10 * 1024 * 1024   // 10MB
	MaxImageSize    = 20 * 1024 * 1024   // 20MB
	MaxVideoSize    = 500 * 1024 * 1024  // 500MB
	MaxAudioSize    = 100 * 1024 * 1024  // 100MB
	MaxDocumentSize = 50 * 1024 * 1024   // 50MB
	MaxTotalSize    = 1024 * 1024 * 1024 // 1GB per request

	// File type categories
	FileTypeImage    = "image"
	FileTypeVideo    = "video"
	FileTypeAudio    = "audio"
	FileTypeDocument = "document"
	FileTypeArchive  = "archive"
	FileTypeOther    = "other"

	// Supported file extensions
	ExtensionJPG  = ".jpg"
	ExtensionJPEG = ".jpeg"
	ExtensionPNG  = ".png"
	ExtensionGIF  = ".gif"
	ExtensionWEBP = ".webp"
	ExtensionMP4  = ".mp4"
	ExtensionWEBM = ".webm"
	ExtensionAVI  = ".avi"
	ExtensionMOV  = ".mov"
	ExtensionMP3  = ".mp3"
	ExtensionWAV  = ".wav"
	ExtensionOGG  = ".ogg"
	ExtensionPDF  = ".pdf"
	ExtensionDOC  = ".doc"
	ExtensionDOCX = ".docx"
	ExtensionTXT  = ".txt"

	// Image processing
	ImageQualityLow    = 60
	ImageQualityMedium = 80
	ImageQualityHigh   = 90
	ImageQualityMax    = 100

	ThumbnailSmall  = 150
	ThumbnailMedium = 300
	ThumbnailLarge  = 600
)

// =============================================================================
// VALIDATION CONSTANTS
// =============================================================================

const (
	// Field length limits
	MinUsernameLength = 3
	MaxUsernameLength = 30
	MinPasswordLength = 8
	MaxPasswordLength = 128
	MaxEmailLength    = 320
	MaxNameLength     = 50
	MaxBioLength      = 500
	MaxPostLength     = 500
	MaxCommentLength  = 500
	MaxMessageLength  = 1000
	MaxHashtagLength  = 50
	MaxLocationLength = 100

	// Collection size limits
	MaxHashtagsPerPost             = 30
	MaxMentionsPerPost             = 50
	MaxMediaPerPost                = 10
	MaxFilesPerMessage             = 10
	MaxParticipantsPerConversation = 100

	// Validation patterns
	UsernamePattern = `^[a-zA-Z0-9_]{3,30}$`
	EmailPattern    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	PhonePattern    = `^\+?[1-9]\d{1,14}$`
	URLPattern      = `^https?://[^\s/$.?#].[^\s]*$`
	HashtagPattern  = `^[a-zA-Z0-9_]+$`
	SlugPattern     = `^[a-z0-9-]+$`
	ColorPattern    = `^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`

	// Date formats
	DateFormat      = "2006-01-02"
	TimeFormat      = "15:04:05"
	DateTimeFormat  = "2006-01-02T15:04:05Z07:00"
	TimestampFormat = "2006-01-02 15:04:05"
)

// =============================================================================
// NOTIFICATION CONSTANTS
// =============================================================================

const (
	// Notification types
	NotificationTypeLike      = "like"
	NotificationTypeComment   = "comment"
	NotificationTypeFollow    = "follow"
	NotificationTypeMention   = "mention"
	NotificationTypeMessage   = "message"
	NotificationTypeShare     = "share"
	NotificationTypeSystem    = "system"
	NotificationTypeSecurity  = "security"
	NotificationTypePromotion = "promotion"
	NotificationTypeWelcome   = "welcome"

	// Notification channels
	NotificationChannelInApp   = "in_app"
	NotificationChannelPush    = "push"
	NotificationChannelEmail   = "email"
	NotificationChannelSMS     = "sms"
	NotificationChannelSlack   = "slack"
	NotificationChannelWebhook = "webhook"

	// Notification priorities
	NotificationPriorityLow      = "low"
	NotificationPriorityNormal   = "normal"
	NotificationPriorityHigh     = "high"
	NotificationPriorityCritical = "critical"

	// Notification statuses
	NotificationStatusPending   = "pending"
	NotificationStatusSent      = "sent"
	NotificationStatusDelivered = "delivered"
	NotificationStatusRead      = "read"
	NotificationStatusFailed    = "failed"

	// Notification limits
	MaxNotificationsPerUser  = 10000
	MaxNotificationBatchSize = 1000
	MaxNotificationRetries   = 3
	NotificationRetryDelay   = 5 * time.Minute
)

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

const (
	// JWT token types
	TokenTypeAccess        = "access"
	TokenTypeRefresh       = "refresh"
	TokenTypeEmailVerify   = "email_verify"
	TokenTypePasswordReset = "password_reset"
	TokenTypeInvite        = "invite"
	TokenTypeAPIKey        = "api_key"

	// Token expiration times
	AccessTokenExpiration        = 15 * time.Minute
	RefreshTokenExpiration       = 7 * 24 * time.Hour
	EmailVerifyTokenExpiration   = 24 * time.Hour
	PasswordResetTokenExpiration = 1 * time.Hour
	InviteTokenExpiration        = 7 * 24 * time.Hour
	APIKeyTokenExpiration        = 365 * 24 * time.Hour

	// Session constants
	SessionCookieName = "session_id"
	SessionExpiration = 7 * 24 * time.Hour
	MaxActiveSessions = 10

	// Security limits
	MaxLoginAttempts      = 5
	AccountLockDuration   = 30 * time.Minute
	MaxPasswordResets     = 3 // per hour
	MaxEmailVerifications = 5 // per hour

	// Encryption constants
	BcryptCost      = 14
	Argon2Memory    = 64 * 1024
	Argon2Time      = 3
	Argon2Threads   = 4
	Argon2KeyLength = 32
	SaltLength      = 16

	// Two-factor authentication
	TOTPSecretLength = 32
	TOTPCodeLength   = 6
	TOTPWindowSize   = 1
	BackupCodeLength = 8
	BackupCodeCount  = 10
)

// =============================================================================
// SEARCH CONSTANTS
// =============================================================================

const (
	// Search types
	SearchTypeAll       = "all"
	SearchTypeUsers     = "users"
	SearchTypePosts     = "posts"
	SearchTypeComments  = "comments"
	SearchTypeHashtags  = "hashtags"
	SearchTypeLocations = "locations"
	SearchTypeMedia     = "media"
	SearchTypeMessages  = "messages"

	// Search limits
	MaxSearchQueryLength = 100
	MaxSearchResults     = 1000
	DefaultSearchLimit   = 20
	MaxSearchFilters     = 10

	// Search caching
	SearchCacheTTL   = 5 * time.Minute
	TrendingCacheTTL = 15 * time.Minute

	// Search ranking factors
	SearchBoostExactMatch     = 2.0
	SearchBoostVerifiedUser   = 1.5
	SearchBoostRecentContent  = 1.3
	SearchBoostPopularContent = 1.2
)

// =============================================================================
// ANALYTICS CONSTANTS
// =============================================================================

const (
	// Analytics event types
	AnalyticsEventUserRegistration = "user_registration"
	AnalyticsEventUserLogin        = "user_login"
	AnalyticsEventPostCreate       = "post_create"
	AnalyticsEventPostView         = "post_view"
	AnalyticsEventPostLike         = "post_like"
	AnalyticsEventPostComment      = "post_comment"
	AnalyticsEventPostShare        = "post_share"
	AnalyticsEventUserFollow       = "user_follow"
	AnalyticsEventMessageSend      = "message_send"
	AnalyticsEventSearch           = "search"
	AnalyticsEventPageView         = "page_view"
	AnalyticsEventSessionStart     = "session_start"
	AnalyticsEventSessionEnd       = "session_end"
	AnalyticsEventError            = "error"

	// Analytics aggregation periods
	AnalyticsPeriodHourly  = "hourly"
	AnalyticsPeriodDaily   = "daily"
	AnalyticsPeriodWeekly  = "weekly"
	AnalyticsPeriodMonthly = "monthly"
	AnalyticsPeriodYearly  = "yearly"

	// Analytics retention periods
	RawAnalyticsRetention     = 30 * 24 * time.Hour
	HourlyAnalyticsRetention  = 90 * 24 * time.Hour
	DailyAnalyticsRetention   = 365 * 24 * time.Hour
	MonthlyAnalyticsRetention = 5 * 365 * 24 * time.Hour

	// Analytics batch sizes
	AnalyticsBatchSize     = 1000
	AnalyticsFlushInterval = 30 * time.Second
	AnalyticsWorkerCount   = 4
)

// =============================================================================
// MODERATION CONSTANTS
// =============================================================================

const (
	// Report categories
	ReportCategorySpam          = "spam"
	ReportCategoryHarassment    = "harassment"
	ReportCategoryHateSpeech    = "hate_speech"
	ReportCategoryViolence      = "violence"
	ReportCategorySelfHarm      = "self_harm"
	ReportCategoryNudity        = "nudity"
	ReportCategoryFakeNews      = "fake_news"
	ReportCategoryIntellectual  = "intellectual_property"
	ReportCategoryImpersonation = "impersonation"
	ReportCategoryMinorSafety   = "minor_safety"
	ReportCategoryOther         = "other"

	// Report statuses
	ReportStatusPending       = "pending"
	ReportStatusInReview      = "in_review"
	ReportStatusInvestigating = "investigating"
	ReportStatusResolved      = "resolved"
	ReportStatusDismissed     = "dismissed"
	ReportStatusEscalated     = "escalated"

	// Moderation actions
	ModerationActionWarning  = "warning"
	ModerationActionHide     = "hide"
	ModerationActionRemove   = "remove"
	ModerationActionSuspend  = "suspend"
	ModerationActionBan      = "ban"
	ModerationActionNoAction = "no_action"

	// Auto-moderation thresholds
	AutoModerationThresholdLow    = 0.3
	AutoModerationThresholdMedium = 0.6
	AutoModerationThresholdHigh   = 0.8

	// Moderation limits
	MaxReportsPerUser    = 10  // per day
	MaxModerationActions = 100 // per admin per day
	ModerationReviewSLA  = 24 * time.Hour
)

// =============================================================================
// FEED CONSTANTS
// =============================================================================

const (
	// Feed types
	FeedTypePersonalized = "personalized"
	FeedTypeFollowing    = "following"
	FeedTypeExplore      = "explore"
	FeedTypeTrending     = "trending"
	FeedTypeNearby       = "nearby"
	FeedTypeHashtag      = "hashtag"
	FeedTypeLocation     = "location"

	// Feed limits
	DefaultFeedLimit = 20
	MaxFeedLimit     = 100
	FeedCacheSize    = 1000

	// Feed refresh intervals
	PersonalizedFeedRefresh = 5 * time.Minute
	TrendingFeedRefresh     = 15 * time.Minute
	ExploreFeedRefresh      = 10 * time.Minute

	// Feed ranking factors
	FeedRankingRecency      = 0.3
	FeedRankingEngagement   = 0.4
	FeedRankingRelevance    = 0.2
	FeedRankingRelationship = 0.1
)

// =============================================================================
// MESSAGING CONSTANTS
// =============================================================================

const (
	// Message types
	MessageTypeText     = "text"
	MessageTypeImage    = "image"
	MessageTypeVideo    = "video"
	MessageTypeAudio    = "audio"
	MessageTypeFile     = "file"
	MessageTypeLocation = "location"
	MessageTypeContact  = "contact"
	MessageTypeSticker  = "sticker"
	MessageTypeGIF      = "gif"
	MessageTypeSystem   = "system"

	// Message statuses
	MessageStatusSent      = "sent"
	MessageStatusDelivered = "delivered"
	MessageStatusRead      = "read"
	MessageStatusDeleted   = "deleted"
	MessageStatusFailed    = "failed"

	// Conversation types
	ConversationTypeDirect  = "direct"
	ConversationTypeGroup   = "group"
	ConversationTypeChannel = "channel"

	// Message limits
	MaxAttachmentsPerMessage = 10
	MaxParticipantsPerGroup  = 100
	MessageRetentionDays     = 90

	// Real-time constants
	WebSocketBufferSize     = 1024
	WebSocketReadDeadline   = 60 * time.Second
	WebSocketWriteDeadline  = 10 * time.Second
	WebSocketPingInterval   = 30 * time.Second
	WebSocketMaxConnections = 10000
)

// =============================================================================
// LOCATION CONSTANTS
// =============================================================================

const (
	// Distance units
	DistanceUnitKM     = "km"
	DistanceUnitMiles  = "miles"
	DistanceUnitMeters = "meters"

	// Location precision levels
	LocationPrecisionCountry = "country"
	LocationPrecisionState   = "state"
	LocationPrecisionCity    = "city"
	LocationPrecisionExact   = "exact"

	// Default search radius
	DefaultSearchRadiusKM   = 50
	MaxSearchRadiusKM       = 500
	LocationCacheExpiration = 24 * time.Hour
)

// =============================================================================
// ADMIN CONSTANTS
// =============================================================================

const (
	// Admin roles
	AdminRoleModerator  = "moderator"
	AdminRoleAdmin      = "admin"
	AdminRoleSuperAdmin = "super_admin"

	// Admin permissions
	AdminPermissionUserManagement    = "user_management"
	AdminPermissionContentModeration = "content_moderation"
	AdminPermissionSystemSettings    = "system_settings"
	AdminPermissionAnalyticsAccess   = "analytics_access"
	AdminPermissionAuditLogAccess    = "audit_log_access"

	// Admin action limits
	MaxBulkUserActions    = 1000
	MaxBulkContentActions = 1000
	AdminSessionTimeout   = 4 * time.Hour
)

// =============================================================================
// HEALTH CHECK CONSTANTS
// =============================================================================

const (
	// Health check statuses
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusDegraded  = "degraded"
	HealthStatusUnknown   = "unknown"

	// Health check types
	HealthCheckDatabase = "database"
	HealthCheckRedis    = "redis"
	HealthCheckStorage  = "storage"
	HealthCheckEmail    = "email"
	HealthCheckExternal = "external"

	// Health check timeouts
	HealthCheckTimeout       = 5 * time.Second
	HealthCheckInterval      = 30 * time.Second
	HealthCheckRetries       = 3
	HealthCheckCacheDuration = 10 * time.Second
)

// =============================================================================
// FEATURE FLAGS
// =============================================================================

const (
	// Feature flag names
	FeatureFlagNewFeed           = "new_feed_algorithm"
	FeatureFlagAdvancedSearch    = "advanced_search"
	FeatureFlagVideoProcessing   = "video_processing"
	FeatureFlagRealtimeChat      = "realtime_chat"
	FeatureFlagAIModeration      = "ai_moderation"
	FeatureFlagStories           = "stories"
	FeatureFlagLiveStreaming     = "live_streaming"
	FeatureFlagAdvancedAnalytics = "advanced_analytics"
	FeatureFlagBetaFeatures      = "beta_features"
	FeatureFlagMaintenanceMode   = "maintenance_mode"
)

// =============================================================================
// CONFIGURATION KEYS
// =============================================================================

const (
	// Configuration sections
	ConfigDatabase     = "database"
	ConfigRedis        = "redis"
	ConfigAWS          = "aws"
	ConfigSMTP         = "smtp"
	ConfigAuth         = "auth"
	ConfigUpload       = "upload"
	ConfigNotification = "notification"
	ConfigSearch       = "search"
	ConfigAnalytics    = "analytics"
	ConfigLogging      = "logging"
	ConfigSecurity     = "security"

	// Environment variable keys
	EnvDatabaseURL   = "DATABASE_URL"
	EnvRedisURL      = "REDIS_URL"
	EnvAWSAccessKey  = "AWS_ACCESS_KEY_ID"
	EnvAWSSecretKey  = "AWS_SECRET_ACCESS_KEY"
	EnvAWSRegion     = "AWS_REGION"
	EnvAWSBucket     = "AWS_S3_BUCKET"
	EnvSMTPHost      = "SMTP_HOST"
	EnvSMTPPort      = "SMTP_PORT"
	EnvSMTPUsername  = "SMTP_USERNAME"
	EnvSMTPPassword  = "SMTP_PASSWORD"
	EnvJWTSecret     = "JWT_SECRET"
	EnvEncryptionKey = "ENCRYPTION_KEY"
	EnvPort          = "PORT"
	EnvEnvironment   = "ENVIRONMENT"
	EnvLogLevel      = "LOG_LEVEL"
)

// =============================================================================
// ERROR MESSAGES
// =============================================================================

const (
	// Generic error messages
	ErrInternalServer     = "Internal server error"
	ErrBadRequest         = "Bad request"
	ErrUnauthorized       = "Unauthorized"
	ErrForbidden          = "Forbidden"
	ErrNotFound           = "Not found"
	ErrConflict           = "Conflict"
	ErrTooManyRequests    = "Too many requests"
	ErrServiceUnavailable = "Service unavailable"

	// Validation error messages
	ErrRequiredField = "This field is required"
	ErrInvalidFormat = "Invalid format"
	ErrFieldTooShort = "Field is too short"
	ErrFieldTooLong  = "Field is too long"
	ErrInvalidEmail  = "Invalid email address"
	ErrInvalidPhone  = "Invalid phone number"
	ErrInvalidURL    = "Invalid URL"
	ErrInvalidDate   = "Invalid date"

	// Authentication error messages
	ErrInvalidCredentials = "Invalid credentials"
	ErrTokenExpired       = "Token has expired"
	ErrTokenInvalid       = "Invalid token"
	ErrAccountLocked      = "Account is locked"
	ErrAccountDisabled    = "Account is disabled"

	// Business logic error messages
	ErrUserNotFound     = "User not found"
	ErrPostNotFound     = "Post not found"
	ErrCommentNotFound  = "Comment not found"
	ErrEmailExists      = "Email already exists"
	ErrUsernameExists   = "Username already exists"
	ErrCannotFollowSelf = "Cannot follow yourself"
	ErrAlreadyFollowing = "Already following this user"
	ErrPrivateAccount   = "This account is private"
	ErrBlockedUser      = "User is blocked"
	ErrFileTooLarge     = "File is too large"
	ErrInvalidFileType  = "Invalid file type"
)

// =============================================================================
// SUCCESS MESSAGES
// =============================================================================

const (
	MsgCreatedSuccessfully    = "Created successfully"
	MsgUpdatedSuccessfully    = "Updated successfully"
	MsgDeletedSuccessfully    = "Deleted successfully"
	MsgLoginSuccessful        = "Login successful"
	MsgLogoutSuccessful       = "Logout successful"
	MsgEmailSent              = "Email sent successfully"
	MsgPasswordChanged        = "Password changed successfully"
	MsgAccountVerified        = "Account verified successfully"
	MsgFollowedSuccessfully   = "Followed successfully"
	MsgUnfollowedSuccessfully = "Unfollowed successfully"
	MsgLikedSuccessfully      = "Liked successfully"
	MsgUnlikedSuccessfully    = "Unliked successfully"
	MsgMessageSent            = "Message sent successfully"
	MsgFileUploaded           = "File uploaded successfully"
	MsgSettingsUpdated        = "Settings updated successfully"
)

// =============================================================================
// REGEX PATTERNS
// =============================================================================

var (
	// Validation regex patterns
	RegexUsername = `^[a-zA-Z0-9_]{3,30}$`
	RegexEmail    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	RegexPhone    = `^\+?[1-9]\d{1,14}$`
	RegexURL      = `^https?://[^\s/$.?#].[^\s]*$`
	RegexHashtag  = `#[a-zA-Z0-9_]+`
	RegexMention  = `@[a-zA-Z0-9_]+`
	RegexSlug     = `^[a-z0-9-]+$`
	RegexHexColor = `^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`
	RegexUUID     = `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	RegexObjectID = `^[0-9a-fA-F]{24}$`
)

// =============================================================================
// MIME TYPES
// =============================================================================

var (
	// Image MIME types
	MimeTypeJPEG = "image/jpeg"
	MimeTypePNG  = "image/png"
	MimeTypeGIF  = "image/gif"
	MimeTypeWEBP = "image/webp"
	MimeTypeSVG  = "image/svg+xml"

	// Video MIME types
	MimeTypeMP4  = "video/mp4"
	MimeTypeWEBM = "video/webm"
	MimeTypeAVI  = "video/avi"
	MimeTypeMOV  = "video/quicktime"

	// Audio MIME types
	MimeTypeMP3 = "audio/mpeg"
	MimeTypeWAV = "audio/wav"
	MimeTypeOGG = "audio/ogg"
	MimeTypeAAC = "audio/aac"

	// Document MIME types
	MimeTypePDF  = "application/pdf"
	MimeTypeDOC  = "application/msword"
	MimeTypeDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	MimeTypeXLS  = "application/vnd.ms-excel"
	MimeTypeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	MimeTypeTXT  = "text/plain"
	MimeTypeCSV  = "text/csv"

	// Archive MIME types
	MimeTypeZIP  = "application/zip"
	MimeTypeRAR  = "application/x-rar"
	MimeTypeTAR  = "application/x-tar"
	MimeTypeGZIP = "application/gzip"
	MimeType7ZIP = "application/x-7z-compressed"
)

// =============================================================================
// SUPPORTED LANGUAGES
// =============================================================================

var SupportedLanguages = map[string]string{
	"en": "English",
	"es": "Español",
	"fr": "Français",
	"de": "Deutsch",
	"it": "Italiano",
	"pt": "Português",
	"ru": "Русский",
	"zh": "中文",
	"ja": "日本語",
	"ko": "한국어",
	"ar": "العربية",
	"hi": "हिन्दी",
	"tr": "Türkçe",
	"pl": "Polski",
	"nl": "Nederlands",
}

// =============================================================================
// TIME ZONES
// =============================================================================

var CommonTimeZones = []string{
	"UTC",
	"America/New_York",
	"America/Chicago",
	"America/Denver",
	"America/Los_Angeles",
	"Europe/London",
	"Europe/Paris",
	"Europe/Berlin",
	"Asia/Tokyo",
	"Asia/Shanghai",
	"Asia/Kolkata",
	"Australia/Sydney",
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// GetFileTypeBySizeLimit returns appropriate file type limits
func GetFileTypeBySizeLimit() map[string]int64 {
	return map[string]int64{
		"avatar":   MaxAvatarSize,
		"cover":    MaxCoverSize,
		"image":    MaxImageSize,
		"video":    MaxVideoSize,
		"audio":    MaxAudioSize,
		"document": MaxDocumentSize,
	}
}

// GetSupportedImageExtensions returns supported image extensions
func GetSupportedImageExtensions() []string {
	return []string{ExtensionJPG, ExtensionJPEG, ExtensionPNG, ExtensionGIF, ExtensionWEBP}
}

// GetSupportedVideoExtensions returns supported video extensions
func GetSupportedVideoExtensions() []string {
	return []string{ExtensionMP4, ExtensionWEBM, ExtensionAVI, ExtensionMOV}
}

// GetSupportedAudioExtensions returns supported audio extensions
func GetSupportedAudioExtensions() []string {
	return []string{ExtensionMP3, ExtensionWAV, ExtensionOGG}
}

// GetSupportedDocumentExtensions returns supported document extensions
func GetSupportedDocumentExtensions() []string {
	return []string{ExtensionPDF, ExtensionDOC, ExtensionDOCX, ExtensionTXT}
}

// GetCacheTTLByType returns cache TTL by type
func GetCacheTTLByType(cacheType string) time.Duration {
	switch cacheType {
	case "user_profile":
		return CacheTTLMedium
	case "post_details":
		return CacheTTLShort
	case "feed":
		return CacheTTLShort
	case "trending":
		return CacheTTLMedium
	case "search":
		return CacheTTLShort
	case "analytics":
		return CacheTTLLong
	default:
		return CacheTTLMedium
	}
}

// GetRateLimitByType returns rate limit configuration by type
func GetRateLimitByType(limitType string) (int, time.Duration) {
	switch limitType {
	case RateLimitAuth:
		return RateLimitAuthRequests, RateLimitWindowMinute
	case RateLimitPost:
		return RateLimitPostRequests, RateLimitWindowHour
	case RateLimitComment:
		return RateLimitCommentRequests, RateLimitWindowHour
	case RateLimitLike:
		return RateLimitLikeRequests, RateLimitWindowMinute
	case RateLimitFollow:
		return RateLimitFollowRequests, RateLimitWindowHour
	case RateLimitMessage:
		return RateLimitMessageRequests, RateLimitWindowHour
	case RateLimitUpload:
		return RateLimitUploadRequests, RateLimitWindowHour
	case RateLimitSearch:
		return RateLimitSearchRequests, RateLimitWindowHour
	case RateLimitAPI:
		return RateLimitAPIRequests, RateLimitWindowHour
	default:
		return RateLimitGlobalRequests, RateLimitWindowHour
	}
}
