package services

import (
	"context"
	"time"

	"bro-network/internal/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AdminService interface {
	// Dashboard and Overview
	GetDashboard(ctx context.Context) (map[string]interface{}, error)
	GetOverview(ctx context.Context) (map[string]interface{}, error)
	GetSummary(ctx context.Context) (map[string]interface{}, error)
	GetAdminMetrics(ctx context.Context) (map[string]interface{}, error)
	GetKPIs(ctx context.Context) (map[string]interface{}, error)
	GetHealthSummary(ctx context.Context) (map[string]interface{}, error)

	// User Management
	GetUsers(ctx context.Context, page, limit int) ([]models.UserPublicProfile, int64, error)
	GetUserStats(ctx context.Context) (map[string]interface{}, error)
	GetRecentUsers(ctx context.Context, limit int) ([]models.UserPublicProfile, error)
	GetActiveUsers(ctx context.Context, page, limit int) ([]models.UserPublicProfile, int64, error)
	GetInactiveUsers(ctx context.Context, page, limit int) ([]models.UserPublicProfile, int64, error)
	GetUser(ctx context.Context, userID primitive.ObjectID) (*models.User, error)
	UpdateUser(ctx context.Context, userID primitive.ObjectID, updates map[string]interface{}) error
	DeleteUser(ctx context.Context, userID primitive.ObjectID) error
	BanUser(ctx context.Context, userID primitive.ObjectID, reason string, duration *int, permanent bool, notify bool) error
	UnbanUser(ctx context.Context, userID primitive.ObjectID) error
	SuspendUser(ctx context.Context, userID primitive.ObjectID, reason string, duration int) error
	UnsuspendUser(ctx context.Context, userID primitive.ObjectID) error
	VerifyUser(ctx context.Context, userID primitive.ObjectID) error
	UnverifyUser(ctx context.Context, userID primitive.ObjectID) error
	GetUserRoles(ctx context.Context, userID primitive.ObjectID) ([]string, error)
	AssignUserRole(ctx context.Context, userID primitive.ObjectID, role string) error
	RemoveUserRole(ctx context.Context, userID primitive.ObjectID, role string) error
	GetUserActivity(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]ActivityLog, error)
	GetUserLoginHistory(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]LoginHistory, error)
	GetUserSecurityLog(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]SecurityLog, error)
	GetUserPosts(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]Post, error)
	GetUserComments(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]Comment, error)
	GetUserMessages(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]Message, error)
	GetUserReports(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]Report, error)
	GetUserViolations(ctx context.Context, userID primitive.ObjectID, page, limit int) ([]Violation, error)
	BulkBanUsers(ctx context.Context, userIDs []primitive.ObjectID, reason string, duration *int) error
	BulkDeleteUsers(ctx context.Context, userIDs []primitive.ObjectID) error
	ExportUsers(ctx context.Context, filters map[string]interface{}) (string, error)
	SearchUsers(ctx context.Context, query string, page, limit int) ([]models.UserPublicProfile, int64, error)
	FilterUsers(ctx context.Context, filters map[string]interface{}, page, limit int) ([]models.UserPublicProfile, int64, error)

	// Content Management
	GetContentDashboard(ctx context.Context) (map[string]interface{}, error)
	GetContentStats(ctx context.Context) (map[string]interface{}, error)
	GetContentTrends(ctx context.Context) (map[string]interface{}, error)
	GetPosts(ctx context.Context, page, limit int) ([]Post, int64, error)
	GetFlaggedPosts(ctx context.Context, page, limit int) ([]Post, int64, error)
	GetReportedPosts(ctx context.Context, page, limit int) ([]Post, int64, error)
	GetTrendingPosts(ctx context.Context, page, limit int) ([]Post, int64, error)
	GetPost(ctx context.Context, postID primitive.ObjectID) (*Post, error)
	UpdatePost(ctx context.Context, postID primitive.ObjectID, updates map[string]interface{}) error
	DeletePost(ctx context.Context, postID primitive.ObjectID) error
	ApprovePost(ctx context.Context, postID primitive.ObjectID) error
	RejectPost(ctx context.Context, postID primitive.ObjectID, reason string, notify bool, action string) error
	HidePost(ctx context.Context, postID primitive.ObjectID) error
	UnhidePost(ctx context.Context, postID primitive.ObjectID) error
	FeaturePost(ctx context.Context, postID primitive.ObjectID) error
	UnfeaturePost(ctx context.Context, postID primitive.ObjectID) error
	GetPostReports(ctx context.Context, postID primitive.ObjectID, page, limit int) ([]Report, error)
	GetPostAnalytics(ctx context.Context, postID primitive.ObjectID) (map[string]interface{}, error)
	GetComments(ctx context.Context, page, limit int) ([]Comment, int64, error)
	GetFlaggedComments(ctx context.Context, page, limit int) ([]Comment, int64, error)
	GetReportedComments(ctx context.Context, page, limit int) ([]Comment, int64, error)
	GetComment(ctx context.Context, commentID primitive.ObjectID) (*Comment, error)
	UpdateComment(ctx context.Context, commentID primitive.ObjectID, updates map[string]interface{}) error
	DeleteComment(ctx context.Context, commentID primitive.ObjectID) error
	ApproveComment(ctx context.Context, commentID primitive.ObjectID) error
	RejectComment(ctx context.Context, commentID primitive.ObjectID, reason string) error
	HideComment(ctx context.Context, commentID primitive.ObjectID) error
	GetCommentReports(ctx context.Context, commentID primitive.ObjectID, page, limit int) ([]Report, error)
	GetMedia(ctx context.Context, page, limit int) ([]Media, int64, error)
	GetFlaggedMedia(ctx context.Context, page, limit int) ([]Media, int64, error)
	GetMediaStats(ctx context.Context) (map[string]interface{}, error)
	GetMediaFile(ctx context.Context, mediaID primitive.ObjectID) (*Media, error)
	DeleteMediaFile(ctx context.Context, mediaID primitive.ObjectID) error
	ScanMediaFile(ctx context.Context, mediaID primitive.ObjectID) (map[string]interface{}, error)
	GetStorageUsage(ctx context.Context) (map[string]interface{}, error)
	GetStorageBreakdown(ctx context.Context) (map[string]interface{}, error)
	CleanupStorage(ctx context.Context) error
	GetModerationQueue(ctx context.Context, page, limit int) ([]ModerationItem, int64, error)
	GetModerationQueueStats(ctx context.Context) (map[string]interface{}, error)
	AutoModerateContent(ctx context.Context, settings map[string]interface{}) error
	GetAutoModerationSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateAutoModerationSettings(ctx context.Context, settings map[string]interface{}) error
	GetModerationRules(ctx context.Context) ([]ModerationRule, error)
	CreateModerationRule(ctx context.Context, rule ModerationRule) error
	UpdateModerationRule(ctx context.Context, ruleID string, updates map[string]interface{}) error
	DeleteModerationRule(ctx context.Context, ruleID string) error
	GetBannedKeywords(ctx context.Context) ([]string, error)
	AddBannedKeyword(ctx context.Context, keyword string) error
	RemoveBannedKeyword(ctx context.Context, keywordID string) error

	// Reports Management
	GetReports(ctx context.Context, page, limit int) ([]Report, int64, error)
	GetReportsStats(ctx context.Context) (map[string]interface{}, error)
	GetPendingReports(ctx context.Context, page, limit int) ([]Report, int64, error)
	GetResolvedReports(ctx context.Context, page, limit int) ([]Report, int64, error)
	GetReport(ctx context.Context, reportID primitive.ObjectID) (*Report, error)
	UpdateReport(ctx context.Context, reportID primitive.ObjectID, updates map[string]interface{}) error
	DeleteReport(ctx context.Context, reportID primitive.ObjectID) error
	AssignReport(ctx context.Context, reportID primitive.ObjectID, adminID primitive.ObjectID) error
	ResolveReport(ctx context.Context, reportID primitive.ObjectID, action string, reason string, notifyReporter, notifyReportedUser bool) error
	EscalateReport(ctx context.Context, reportID primitive.ObjectID, reason string) error
	DismissReport(ctx context.Context, reportID primitive.ObjectID, reason string) error
	BulkAssignReports(ctx context.Context, reportIDs []primitive.ObjectID, adminID primitive.ObjectID) error
	BulkResolveReports(ctx context.Context, reportIDs []primitive.ObjectID, action string, reason string) error
	GetReportCategories(ctx context.Context) ([]string, error)
	GetCategoryStats(ctx context.Context, category string) (map[string]interface{}, error)
	GetReportsAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetReportsTrends(ctx context.Context) (map[string]interface{}, error)
	GetReportsResponseTimes(ctx context.Context) (map[string]interface{}, error)

	// Analytics and Insights
	GetAnalyticsOverview(ctx context.Context) (map[string]interface{}, error)
	GetAnalyticsDashboard(ctx context.Context) (map[string]interface{}, error)
	GetUserGrowthAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetUserEngagementAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetUserRetentionAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetUserDemographics(ctx context.Context) (map[string]interface{}, error)
	GetUserBehaviorAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetContentPerformanceAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetContentTrendsAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetViralContentAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetContentEngagementAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetPlatformUsageAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetPlatformPerformanceAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetErrorAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetAPIUsageAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetRevenueAnalytics(ctx context.Context) (map[string]interface{}, error)
	GetRevenueTrends(ctx context.Context) (map[string]interface{}, error)
	GetRevenueSources(ctx context.Context) (map[string]interface{}, error)
	GetCustomReports(ctx context.Context) ([]CustomReport, error)
	CreateCustomReport(ctx context.Context, report CustomReport) (string, error)
	GetCustomReport(ctx context.Context, reportID string) (*CustomReport, error)
	UpdateCustomReport(ctx context.Context, reportID string, updates map[string]interface{}) error
	DeleteCustomReport(ctx context.Context, reportID string) error
	ExportAnalyticsData(ctx context.Context, startDate, endDate time.Time, metrics []string, format string, emailResults bool) (string, error)
	GetAnalyticsExports(ctx context.Context) ([]AnalyticsExport, error)
	GetAnalyticsExport(ctx context.Context, exportID string) (*AnalyticsExport, error)

	// System Settings and Configuration
	GetSystemSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateSystemSettings(ctx context.Context, settings map[string]interface{}) error
	GetFeatureFlags(ctx context.Context) (map[string]interface{}, error)
	UpdateFeatureFlags(ctx context.Context, flags map[string]interface{}) error
	EnableFeature(ctx context.Context, feature string) error
	DisableFeature(ctx context.Context, feature string) error
	GetSecuritySettings(ctx context.Context) (map[string]interface{}, error)
	UpdateSecuritySettings(ctx context.Context, settings map[string]interface{}) error
	GetPrivacySettings(ctx context.Context) (map[string]interface{}, error)
	UpdatePrivacySettings(ctx context.Context, settings map[string]interface{}) error
	GetNotificationSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateNotificationSettings(ctx context.Context, settings map[string]interface{}) error
	GetRateLimitSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateRateLimitSettings(ctx context.Context, settings map[string]interface{}) error
	GetEmailSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateEmailSettings(ctx context.Context, settings map[string]interface{}) error
	TestEmailSettings(ctx context.Context, email string) error
	GetStorageSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateStorageSettings(ctx context.Context, settings map[string]interface{}) error
	GetCacheSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateCacheSettings(ctx context.Context, settings map[string]interface{}) error
	ClearCache(ctx context.Context) error
	WarmCache(ctx context.Context) error

	// Admin User Management
	GetAdminUsers(ctx context.Context, page, limit int) ([]AdminUser, int64, error)
	GetAdminUser(ctx context.Context, adminID primitive.ObjectID) (*AdminUser, error)
	CreateAdminUser(ctx context.Context, admin AdminUser) (string, error)
	UpdateAdminUser(ctx context.Context, adminID primitive.ObjectID, updates map[string]interface{}) error
	DeleteAdminUser(ctx context.Context, adminID primitive.ObjectID) error
	GetAdminRoles(ctx context.Context) ([]AdminRole, error)
	CreateAdminRole(ctx context.Context, role AdminRole) error
	UpdateAdminRole(ctx context.Context, roleID string, updates map[string]interface{}) error
	DeleteAdminRole(ctx context.Context, roleID string) error
	GetAdminPermissions(ctx context.Context) ([]AdminPermission, error)
	CreateAdminPermission(ctx context.Context, permission AdminPermission) error
	UpdateAdminPermission(ctx context.Context, permissionID string, updates map[string]interface{}) error
	DeleteAdminPermission(ctx context.Context, permissionID string) error
	GetAdminActivity(ctx context.Context, page, limit int) ([]AdminActivity, error)
	GetAdminUserActivity(ctx context.Context, adminID primitive.ObjectID, page, limit int) ([]AdminActivity, error)
	GetAdminSessions(ctx context.Context) ([]AdminSession, error)
	RevokeAdminSession(ctx context.Context, sessionID string) error

	// Audit Logs
	GetAuditLogs(ctx context.Context, page, limit int) ([]AuditLog, int64, error)
	GetAuditLog(ctx context.Context, logID primitive.ObjectID) (*AuditLog, error)
	ExportAuditLogs(ctx context.Context, filters map[string]interface{}) (string, error)
	GetAdminAuditLogs(ctx context.Context, page, limit int) ([]AuditLog, int64, error)
	GetUserAuditLogs(ctx context.Context, page, limit int) ([]AuditLog, int64, error)
	GetContentAuditLogs(ctx context.Context, page, limit int) ([]AuditLog, int64, error)
	GetSecurityAuditLogs(ctx context.Context, page, limit int) ([]AuditLog, int64, error)
	SearchAuditLogs(ctx context.Context, query string, page, limit int) ([]AuditLog, int64, error)
	FilterAuditLogs(ctx context.Context, filters map[string]interface{}, page, limit int) ([]AuditLog, int64, error)
	GetAuditStats(ctx context.Context) (map[string]interface{}, error)
	GetAuditTrends(ctx context.Context) (map[string]interface{}, error)
	GetAuditSettings(ctx context.Context) (map[string]interface{}, error)
	UpdateAuditSettings(ctx context.Context, settings map[string]interface{}) error

	// System Maintenance
	GetMaintenanceStatus(ctx context.Context) (map[string]interface{}, error)
	EnableMaintenanceMode(ctx context.Context, settings map[string]interface{}) error
	DisableMaintenanceMode(ctx context.Context) error
	OptimizeDatabase(ctx context.Context) error
	CleanupDatabase(ctx context.Context) error
	ReindexDatabase(ctx context.Context) error
	GetDatabaseStats(ctx context.Context) (map[string]interface{}, error)
	ClearAllCaches(ctx context.Context) error
	RebuildCache(ctx context.Context) error
	GetCacheStats(ctx context.Context) (map[string]interface{}, error)
	CleanupFiles(ctx context.Context) error
	OptimizeFiles(ctx context.Context) error
	GetOrphanedFiles(ctx context.Context) ([]string, error)
	RotateLogs(ctx context.Context) error
	ArchiveLogs(ctx context.Context) error
	CleanupLogs(ctx context.Context) error
	CreateBackup(ctx context.Context) (string, error)
	GetBackupStatus(ctx context.Context) (map[string]interface{}, error)
	GetBackups(ctx context.Context) ([]Backup, error)
	RestoreBackup(ctx context.Context, backupID string) error
}

// Additional types for admin-specific models
type ActivityLog struct {
	ID        primitive.ObjectID     `bson:"_id"`
	UserID    primitive.ObjectID     `bson:"user_id"`
	Action    string                 `bson:"action"`
	Timestamp time.Time              `bson:"timestamp"`
	Details   map[string]interface{} `bson:"details"`
}

type LoginHistory struct {
	ID        primitive.ObjectID `bson:"_id"`
	UserID    primitive.ObjectID `bson:"user_id"`
	IP        string             `bson:"ip"`
	Device    string             `bson:"device"`
	Timestamp time.Time          `bson:"timestamp"`
}

type Violation struct {
	ID        primitive.ObjectID `bson:"_id"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Type      string             `bson:"type"`
	Reason    string             `bson:"reason"`
	CreatedAt time.Time          `bson:"created_at"`
}

type Media struct {
	ID        primitive.ObjectID `bson:"_id"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Type      string             `bson:"type"`
	URL       string             `bson:"url"`
	CreatedAt time.Time          `bson:"created_at"`
}

type ModerationItem struct {
	ID        primitive.ObjectID `bson:"_id"`
	Type      string             `bson:"type"`
	ContentID primitive.ObjectID `bson:"content_id"`
	Reason    string             `bson:"reason"`
	CreatedAt time.Time          `bson:"created_at"`
}

type ModerationRule struct {
	ID          string                 `bson:"id"`
	Name        string                 `bson:"name"`
	Description string                 `bson:"description"`
	Condition   map[string]interface{} `bson:"condition"`
	Action      string                 `bson:"action"`
	Enabled     bool                   `bson:"enabled"`
}

type CustomReport struct {
	ID        string                 `bson:"id"`
	Name      string                 `bson:"name"`
	Metrics   []string               `bson:"metrics"`
	Filters   map[string]interface{} `bson:"filters"`
	CreatedAt time.Time              `bson:"created_at"`
}

type AnalyticsExport struct {
	ID        string    `bson:"id"`
	Status    string    `bson:"status"`
	Format    string    `bson:"format"`
	CreatedAt time.Time `bson:"created_at"`
}

type AdminUser struct {
	ID        primitive.ObjectID `bson:"_id"`
	Username  string             `bson:"username"`
	Email     string             `bson:"email"`
	Role      string             `bson:"role"`
	CreatedAt time.Time          `bson:"created_at"`
}

type AdminRole struct {
	ID          string   `bson:"id"`
	Name        string   `bson:"name"`
	Permissions []string `bson:"permissions"`
}

type AdminPermission struct {
	ID          string `bson:"id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`
}

type AdminActivity struct {
	ID        primitive.ObjectID     `bson:"_id"`
	AdminID   primitive.ObjectID     `bson:"admin_id"`
	Action    string                 `bson:"action"`
	Timestamp time.Time              `bson:"timestamp"`
	Details   map[string]interface{} `bson:"details"`
}

type AdminSession struct {
	ID        string             `bson:"id"`
	AdminID   primitive.ObjectID `bson:"admin_id"`
	IP        string             `bson:"ip"`
	Device    string             `bson:"device"`
	CreatedAt time.Time          `bson:"created_at"`
}

type AuditLog struct {
	ID        primitive.ObjectID     `bson:"_id"`
	Type      string                 `bson:"type"`
	Action    string                 `bson:"action"`
	ActorID   primitive.ObjectID     `bson:"actor_id"`
	TargetID  primitive.ObjectID     `bson:"target_id"`
	Details   map[string]interface{} `bson:"details"`
	Timestamp time.Time              `bson:"timestamp"`
}

type Backup struct {
	ID        string    `bson:"id"`
	Name      string    `bson:"name"`
	CreatedAt time.Time `bson:"created_at"`
}
