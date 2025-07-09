package routes

import (
	"bro-network/internal/handlers"

	"github.com/gin-gonic/gin"
)

// SetupAdminRoutes sets up admin-only routes
func SetupAdminRoutes(admin *gin.RouterGroup, adminHandler *handlers.AdminHandler) {
	// =============================================================================
	// ADMIN DASHBOARD AND OVERVIEW
	// =============================================================================

	// Dashboard overview
	admin.GET("/dashboard", adminHandler.GetDashboard)
	admin.GET("/overview", adminHandler.GetOverview)
	admin.GET("/summary", adminHandler.GetSummary)

	// Key metrics
	admin.GET("/metrics", adminHandler.GetAdminMetrics)
	admin.GET("/kpis", adminHandler.GetKPIs)
	admin.GET("/health-summary", adminHandler.GetHealthSummary)

	// =============================================================================
	// USER MANAGEMENT
	// =============================================================================

	users := admin.Group("/users")
	{
		// User overview
		users.GET("", adminHandler.GetUsers)
		users.GET("/stats", adminHandler.GetUserStats)
		users.GET("/recent", adminHandler.GetRecentUsers)
		users.GET("/active", adminHandler.GetActiveUsers)
		users.GET("/inactive", adminHandler.GetInactiveUsers)

		// User details and management
		users.GET("/:user_id", adminHandler.GetUser)
		users.PUT("/:user_id",
			applyValidation("admin_update_user"),
			adminHandler.UpdateUser,
		)
		users.DELETE("/:user_id", adminHandler.DeleteUser)

		// User actions
		users.POST("/:user_id/ban",
			applyValidation("ban_user"),
			adminHandler.BanUser,
		)
		users.POST("/:user_id/unban", adminHandler.UnbanUser)
		users.POST("/:user_id/suspend",
			applyValidation("suspend_user"),
			adminHandler.SuspendUser,
		)
		users.POST("/:user_id/unsuspend", adminHandler.UnsuspendUser)
		users.POST("/:user_id/verify", adminHandler.VerifyUser)
		users.POST("/:user_id/unverify", adminHandler.UnverifyUser)

		// User roles and permissions
		users.GET("/:user_id/roles", adminHandler.GetUserRoles)
		users.POST("/:user_id/roles",
			applyValidation("assign_role"),
			adminHandler.AssignUserRole,
		)
		users.DELETE("/:user_id/roles/:role", adminHandler.RemoveUserRole)

		// User activity and history
		users.GET("/:user_id/activity", adminHandler.GetUserActivity)
		users.GET("/:user_id/login-history", adminHandler.GetUserLoginHistory)
		users.GET("/:user_id/security-log", adminHandler.GetUserSecurityLog)

		// User content
		users.GET("/:user_id/posts", adminHandler.GetUserPosts)
		users.GET("/:user_id/comments", adminHandler.GetUserComments)
		users.GET("/:user_id/messages", adminHandler.GetUserMessages)

		// User reports
		users.GET("/:user_id/reports", adminHandler.GetUserReports)
		users.GET("/:user_id/violations", adminHandler.GetUserViolations)

		// Bulk operations
		users.POST("/bulk/ban",
			applyValidation("bulk_ban_users"),
			adminHandler.BulkBanUsers,
		)
		users.POST("/bulk/delete",
			applyValidation("bulk_delete_users"),
			adminHandler.BulkDeleteUsers,
		)
		users.POST("/bulk/export",
			applyValidation("export_users"),
			adminHandler.ExportUsers,
		)

		// User search and filtering
		users.GET("/search",
			applyValidation("admin_search_users"),
			adminHandler.SearchUsers,
		)
		users.GET("/filter",
			applyValidation("filter_users"),
			adminHandler.FilterUsers,
		)
	}

	// =============================================================================
	// CONTENT MANAGEMENT
	// =============================================================================

	content := admin.Group("/content")
	{
		// Content overview
		content.GET("/dashboard", adminHandler.GetContentDashboard)
		content.GET("/stats", adminHandler.GetContentStats)
		content.GET("/trends", adminHandler.GetContentTrends)

		// Posts management
		posts := content.Group("/posts")
		{
			posts.GET("", adminHandler.GetPosts)
			posts.GET("/flagged", adminHandler.GetFlaggedPosts)
			posts.GET("/reported", adminHandler.GetReportedPosts)
			posts.GET("/trending", adminHandler.GetTrendingPosts)

			posts.GET("/:post_id", adminHandler.GetPost)
			posts.PUT("/:post_id",
				applyValidation("admin_update_post"),
				adminHandler.UpdatePost,
			)
			posts.DELETE("/:post_id", adminHandler.DeletePost)

			posts.POST("/:post_id/approve", adminHandler.ApprovePost)
			posts.POST("/:post_id/reject",
				applyValidation("reject_post"),
				adminHandler.RejectPost,
			)
			posts.POST("/:post_id/hide", adminHandler.HidePost)
			posts.POST("/:post_id/unhide", adminHandler.UnhidePost)
			posts.POST("/:post_id/feature", adminHandler.FeaturePost)
			posts.DELETE("/:post_id/feature", adminHandler.UnfeaturePost)

			posts.GET("/:post_id/reports", adminHandler.GetPostReports)
			posts.GET("/:post_id/analytics", adminHandler.GetPostAnalytics)
		}

		// Comments management
		comments := content.Group("/comments")
		{
			comments.GET("", adminHandler.GetComments)
			comments.GET("/flagged", adminHandler.GetFlaggedComments)
			comments.GET("/reported", adminHandler.GetReportedComments)

			comments.GET("/:comment_id", adminHandler.GetComment)
			comments.PUT("/:comment_id",
				applyValidation("admin_update_comment"),
				adminHandler.UpdateComment,
			)
			comments.DELETE("/:comment_id", adminHandler.DeleteComment)

			comments.POST("/:comment_id/approve", adminHandler.ApproveComment)
			comments.POST("/:comment_id/reject", adminHandler.RejectComment)
			comments.POST("/:comment_id/hide", adminHandler.HideComment)

			comments.GET("/:comment_id/reports", adminHandler.GetCommentReports)
		}

		// Media management
		media := content.Group("/media")
		{
			media.GET("", adminHandler.GetMedia)
			media.GET("/flagged", adminHandler.GetFlaggedMedia)
			media.GET("/stats", adminHandler.GetMediaStats)

			media.GET("/:media_id", adminHandler.GetMediaFile)
			media.DELETE("/:media_id", adminHandler.DeleteMediaFile)
			media.POST("/:media_id/scan", adminHandler.ScanMediaFile)

			media.GET("/storage/usage", adminHandler.GetStorageUsage)
			media.GET("/storage/breakdown", adminHandler.GetStorageBreakdown)
			media.POST("/storage/cleanup", adminHandler.CleanupStorage)
		}

		// Content moderation
		moderation := content.Group("/moderation")
		{
			moderation.GET("/queue", adminHandler.GetModerationQueue)
			moderation.GET("/queue/stats", adminHandler.GetModerationQueueStats)

			moderation.POST("/auto-moderate",
				applyValidation("auto_moderate"),
				adminHandler.AutoModerateContent,
			)
			moderation.GET("/auto-moderate/settings", adminHandler.GetAutoModerationSettings)
			moderation.PUT("/auto-moderate/settings",
				applyValidation("auto_moderation_settings"),
				adminHandler.UpdateAutoModerationSettings,
			)

			moderation.GET("/rules", adminHandler.GetModerationRules)
			moderation.POST("/rules",
				applyValidation("create_moderation_rule"),
				adminHandler.CreateModerationRule,
			)
			moderation.PUT("/rules/:rule_id",
				applyValidation("update_moderation_rule"),
				adminHandler.UpdateModerationRule,
			)
			moderation.DELETE("/rules/:rule_id", adminHandler.DeleteModerationRule)

			moderation.GET("/keywords", adminHandler.GetBannedKeywords)
			moderation.POST("/keywords",
				applyValidation("add_banned_keyword"),
				adminHandler.AddBannedKeyword,
			)
			moderation.DELETE("/keywords/:keyword_id", adminHandler.RemoveBannedKeyword)
		}
	}

	// =============================================================================
	// REPORTS MANAGEMENT
	// =============================================================================

	reports := admin.Group("/reports")
	{
		// Reports overview
		reports.GET("", adminHandler.GetReports)
		reports.GET("/stats", adminHandler.GetReportsStats)
		reports.GET("/pending", adminHandler.GetPendingReports)
		reports.GET("/resolved", adminHandler.GetResolvedReports)

		// Individual report management
		reports.GET("/:report_id", adminHandler.GetReport)
		reports.PUT("/:report_id",
			applyValidation("admin_update_report"),
			adminHandler.UpdateReport,
		)
		reports.DELETE("/:report_id", adminHandler.DeleteReport)

		// Report actions
		reports.POST("/:report_id/assign",
			applyValidation("assign_report"),
			adminHandler.AssignReport,
		)
		reports.POST("/:report_id/resolve",
			applyValidation("resolve_report"),
			adminHandler.ResolveReport,
		)
		reports.POST("/:report_id/escalate",
			applyValidation("escalate_report"),
			adminHandler.EscalateReport,
		)
		reports.POST("/:report_id/dismiss",
			applyValidation("dismiss_report"),
			adminHandler.DismissReport,
		)

		// Bulk report operations
		reports.POST("/bulk/assign",
			applyValidation("bulk_assign_reports"),
			adminHandler.BulkAssignReports,
		)
		reports.POST("/bulk/resolve",
			applyValidation("bulk_resolve_reports"),
			adminHandler.BulkResolveReports,
		)

		// Report categories and types
		reports.GET("/categories", adminHandler.GetReportCategories)
		reports.GET("/categories/:category/stats", adminHandler.GetCategoryStats)

		// Report analytics
		reports.GET("/analytics", adminHandler.GetReportsAnalytics)
		reports.GET("/trends", adminHandler.GetReportsTrends)
		reports.GET("/response-times", adminHandler.GetReportsResponseTimes)
	}

	// =============================================================================
	// ANALYTICS AND INSIGHTS
	// =============================================================================

	analytics := admin.Group("/analytics")
	{
		// General analytics
		analytics.GET("/overview", adminHandler.GetAnalyticsOverview)
		analytics.GET("/dashboard", adminHandler.GetAnalyticsDashboard)

		// User analytics
		analytics.GET("/users/growth", adminHandler.GetUserGrowthAnalytics)
		analytics.GET("/users/engagement", adminHandler.GetUserEngagementAnalytics)
		analytics.GET("/users/retention", adminHandler.GetUserRetentionAnalytics)
		analytics.GET("/users/demographics", adminHandler.GetUserDemographics)
		analytics.GET("/users/behavior", adminHandler.GetUserBehaviorAnalytics)

		// Content analytics
		analytics.GET("/content/performance", adminHandler.GetContentPerformanceAnalytics)
		analytics.GET("/content/trends", adminHandler.GetContentTrendsAnalytics)
		analytics.GET("/content/viral", adminHandler.GetViralContentAnalytics)
		analytics.GET("/content/engagement", adminHandler.GetContentEngagementAnalytics)

		// Platform analytics
		analytics.GET("/platform/usage", adminHandler.GetPlatformUsageAnalytics)
		analytics.GET("/platform/performance", adminHandler.GetPlatformPerformanceAnalytics)
		analytics.GET("/platform/errors", adminHandler.GetErrorAnalytics)
		analytics.GET("/platform/api-usage", adminHandler.GetAPIUsageAnalytics)

		// Revenue analytics
		analytics.GET("/revenue/overview", adminHandler.GetRevenueAnalytics)
		analytics.GET("/revenue/trends", adminHandler.GetRevenueTrends)
		analytics.GET("/revenue/sources", adminHandler.GetRevenueSources)

		// Custom reports
		analytics.GET("/reports", adminHandler.GetCustomReports)
		analytics.POST("/reports",
			applyValidation("create_custom_report"),
			adminHandler.CreateCustomReport,
		)
		analytics.GET("/reports/:report_id", adminHandler.GetCustomReport)
		analytics.PUT("/reports/:report_id",
			applyValidation("update_custom_report"),
			adminHandler.UpdateCustomReport,
		)
		analytics.DELETE("/reports/:report_id", adminHandler.DeleteCustomReport)

		// Data export
		analytics.POST("/export",
			applyValidation("export_analytics"),
			adminHandler.ExportAnalyticsData,
		)
		analytics.GET("/exports", adminHandler.GetAnalyticsExports)
		analytics.GET("/exports/:export_id", adminHandler.GetAnalyticsExport)
	}

	// =============================================================================
	// SYSTEM SETTINGS AND CONFIGURATION
	// =============================================================================

	settings := admin.Group("/settings")
	{
		// General settings
		settings.GET("", adminHandler.GetSystemSettings)
		settings.PUT("",
			applyValidation("update_system_settings"),
			adminHandler.UpdateSystemSettings,
		)

		// Feature flags
		settings.GET("/features", adminHandler.GetFeatureFlags)
		settings.PUT("/features",
			applyValidation("update_feature_flags"),
			adminHandler.UpdateFeatureFlags,
		)
		settings.POST("/features/:feature/enable", adminHandler.EnableFeature)
		settings.POST("/features/:feature/disable", adminHandler.DisableFeature)

		// Security settings
		settings.GET("/security", adminHandler.GetSecuritySettings)
		settings.PUT("/security",
			applyValidation("update_security_settings"),
			adminHandler.UpdateSecuritySettings,
		)

		// Privacy settings
		settings.GET("/privacy", adminHandler.GetPrivacySettings)
		settings.PUT("/privacy",
			applyValidation("update_privacy_settings"),
			adminHandler.UpdatePrivacySettings,
		)

		// Notification settings
		settings.GET("/notifications", adminHandler.GetNotificationSettings)
		settings.PUT("/notifications",
			applyValidation("update_notification_settings"),
			adminHandler.UpdateNotificationSettings,
		)

		// Rate limiting settings
		settings.GET("/rate-limits", adminHandler.GetRateLimitSettings)
		settings.PUT("/rate-limits",
			applyValidation("update_rate_limits"),
			adminHandler.UpdateRateLimitSettings,
		)

		// Email settings
		settings.GET("/email", adminHandler.GetEmailSettings)
		settings.PUT("/email",
			applyValidation("update_email_settings"),
			adminHandler.UpdateEmailSettings,
		)
		settings.POST("/email/test",
			applyValidation("test_email"),
			adminHandler.TestEmailSettings,
		)

		// Storage settings
		settings.GET("/storage", adminHandler.GetStorageSettings)
		settings.PUT("/storage",
			applyValidation("update_storage_settings"),
			adminHandler.UpdateStorageSettings,
		)

		// Cache settings
		settings.GET("/cache", adminHandler.GetCacheSettings)
		settings.PUT("/cache",
			applyValidation("update_cache_settings"),
			adminHandler.UpdateCacheSettings,
		)
		settings.POST("/cache/clear", adminHandler.ClearCache)
		settings.POST("/cache/warm", adminHandler.WarmCache)
	}

	// =============================================================================
	// ADMIN USER MANAGEMENT
	// =============================================================================

	admins := admin.Group("/admins")
	{
		// Admin users
		admins.GET("", adminHandler.GetAdminUsers)
		admins.GET("/:admin_id", adminHandler.GetAdminUser)
		admins.POST("",
			applyValidation("create_admin"),
			adminHandler.CreateAdminUser,
		)
		admins.PUT("/:admin_id",
			applyValidation("update_admin"),
			adminHandler.UpdateAdminUser,
		)
		admins.DELETE("/:admin_id", adminHandler.DeleteAdminUser)

		// Admin roles and permissions
		admins.GET("/roles", adminHandler.GetAdminRoles)
		admins.POST("/roles",
			applyValidation("create_admin_role"),
			adminHandler.CreateAdminRole,
		)
		admins.PUT("/roles/:role_id",
			applyValidation("update_admin_role"),
			adminHandler.UpdateAdminRole,
		)
		admins.DELETE("/roles/:role_id", adminHandler.DeleteAdminRole)

		// Admin permissions
		admins.GET("/permissions", adminHandler.GetAdminPermissions)
		admins.POST("/permissions",
			applyValidation("create_permission"),
			adminHandler.CreateAdminPermission,
		)
		admins.PUT("/permissions/:permission_id",
			applyValidation("update_permission"),
			adminHandler.UpdateAdminPermission,
		)
		admins.DELETE("/permissions/:permission_id", adminHandler.DeleteAdminPermission)

		// Admin activity
		admins.GET("/activity", adminHandler.GetAdminActivity)
		admins.GET("/activity/:admin_id", adminHandler.GetAdminUserActivity)

		// Admin sessions
		admins.GET("/sessions", adminHandler.GetAdminSessions)
		admins.DELETE("/sessions/:session_id", adminHandler.RevokeAdminSession)
	}

	// =============================================================================
	// AUDIT LOGS
	// =============================================================================

	audit := admin.Group("/audit")
	{
		// Audit logs
		audit.GET("/logs", adminHandler.GetAuditLogs)
		audit.GET("/logs/:log_id", adminHandler.GetAuditLog)
		audit.POST("/logs/export",
			applyValidation("export_audit_logs"),
			adminHandler.ExportAuditLogs,
		)

		// Audit by type
		audit.GET("/logs/admin", adminHandler.GetAdminAuditLogs)
		audit.GET("/logs/user", adminHandler.GetUserAuditLogs)
		audit.GET("/logs/content", adminHandler.GetContentAuditLogs)
		audit.GET("/logs/security", adminHandler.GetSecurityAuditLogs)

		// Audit search and filtering
		audit.GET("/search",
			applyValidation("search_audit_logs"),
			adminHandler.SearchAuditLogs,
		)
		audit.GET("/filter",
			applyValidation("filter_audit_logs"),
			adminHandler.FilterAuditLogs,
		)

		// Audit statistics
		audit.GET("/stats", adminHandler.GetAuditStats)
		audit.GET("/trends", adminHandler.GetAuditTrends)

		// Audit settings
		audit.GET("/settings", adminHandler.GetAuditSettings)
		audit.PUT("/settings",
			applyValidation("update_audit_settings"),
			adminHandler.UpdateAuditSettings,
		)
	}

	// =============================================================================
	// SYSTEM MAINTENANCE
	// =============================================================================

	maintenance := admin.Group("/maintenance")
	{
		// Maintenance operations
		maintenance.GET("/status", adminHandler.GetMaintenanceStatus)
		maintenance.POST("/enable",
			applyValidation("enable_maintenance"),
			adminHandler.EnableMaintenanceMode,
		)
		maintenance.POST("/disable", adminHandler.DisableMaintenanceMode)

		// Database maintenance
		maintenance.POST("/database/optimize", adminHandler.OptimizeDatabase)
		maintenance.POST("/database/cleanup", adminHandler.CleanupDatabase)
		maintenance.POST("/database/reindex", adminHandler.ReindexDatabase)
		maintenance.GET("/database/stats", adminHandler.GetDatabaseStats)

		// Cache maintenance
		maintenance.POST("/cache/clear-all", adminHandler.ClearAllCaches)
		maintenance.POST("/cache/rebuild", adminHandler.RebuildCache)
		maintenance.GET("/cache/stats", adminHandler.GetCacheStats)

		// File system maintenance
		maintenance.POST("/files/cleanup", adminHandler.CleanupFiles)
		maintenance.POST("/files/optimize", adminHandler.OptimizeFiles)
		maintenance.GET("/files/orphaned", adminHandler.GetOrphanedFiles)

		// Log maintenance
		maintenance.POST("/logs/rotate", adminHandler.RotateLogs)
		maintenance.POST("/logs/archive", adminHandler.ArchiveLogs)
		maintenance.POST("/logs/cleanup", adminHandler.CleanupLogs)

		// Backup operations
		maintenance.POST("/backup/create", adminHandler.CreateBackup)
		maintenance.GET("/backup/status", adminHandler.GetBackupStatus)
		maintenance.GET("/backups", adminHandler.GetBackups)
		maintenance.POST("/backup/:backup_id/restore", adminHandler.RestoreBackup)
	}
}

// Admin validation rules that handlers will need:
/*
Required Validation Schemas:

1. ban_user:
   - reason: required,string,max:500
   - duration: sometimes,integer,min:1
   - permanent: sometimes,boolean
   - notify_user: sometimes,boolean

2. bulk_ban_users:
   - user_ids: required,array,min:1,max:100
   - user_ids.*: required,objectid
   - reason: required,string,max:500
   - duration: sometimes,integer,min:1

3. admin_update_user:
   - first_name: sometimes,string,max:50
   - last_name: sometimes,string,max:50
   - email: sometimes,email
   - is_verified: sometimes,boolean
   - is_active: sometimes,boolean
   - role: sometimes,in:user,moderator,admin

4. reject_post:
   - reason: required,string,max:500
   - notify_user: sometimes,boolean
   - action: sometimes,in:hide,delete,flag

5. create_moderation_rule:
   - name: required,string,max:100
   - description: sometimes,string,max:500
   - condition: required,object
   - action: required,in:flag,hide,delete,review
   - enabled: sometimes,boolean

6. resolve_report:
   - action: required,in:approve,reject,escalate
   - reason: required,string,max:500
   - notify_reporter: sometimes,boolean
   - notify_reported_user: sometimes,boolean

7. update_system_settings:
   - site_name: sometimes,string,max:100
   - site_description: sometimes,string,max:500
   - maintenance_mode: sometimes,boolean
   - registration_enabled: sometimes,boolean
   - email_verification_required: sometimes,boolean

8. update_feature_flags:
   - features: required,object
   - features.*.enabled: required,boolean
   - features.*.rollout_percentage: sometimes,integer,min:0,max:100

9. create_admin:
   - username: required,string,min:3,max:30
   - email: required,email
   - password: required,string,min:8
   - role: required,in:moderator,admin,super_admin
   - permissions: sometimes,array

10. export_analytics:
    - start_date: required,date
    - end_date: required,date
    - metrics: required,array,min:1
    - format: sometimes,in:csv,json,xlsx
    - email_results: sometimes,boolean
*/
