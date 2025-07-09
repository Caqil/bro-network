package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupNotificationRoutes sets up notification management routes
func SetupNotificationRoutes(api *gin.RouterGroup, notificationHandler *handlers.NotificationHandler, middlewares *middleware.Middlewares) {
	notifications := api.Group("/notifications")

	// =============================================================================
	// NOTIFICATION MANAGEMENT
	// =============================================================================

	// Get notifications
	notifications.GET("",
		notificationHandler.GetNotifications,
	)

	notifications.GET("/unread",
		notificationHandler.GetUnreadNotifications,
	)

	notifications.GET("/read",
		notificationHandler.GetReadNotifications,
	)

	notifications.GET("/count",
		notificationHandler.GetNotificationCount,
	)

	notifications.GET("/count/unread",
		notificationHandler.GetUnreadCount,
	)

	// Individual notification management
	notifications.GET("/:notification_id",
		middlewares.NotificationAccess(),
		notificationHandler.GetNotification,
	)

	notifications.PUT("/:notification_id",
		applyValidation("update_notification"),
		middlewares.NotificationAccess(),
		notificationHandler.UpdateNotification,
	)

	notifications.DELETE("/:notification_id",
		middlewares.NotificationAccess(),
		notificationHandler.DeleteNotification,
	)

	// Notification actions
	notifications.POST("/:notification_id/read",
		middlewares.NotificationAccess(),
		notificationHandler.MarkAsRead,
	)

	notifications.POST("/:notification_id/unread",
		middlewares.NotificationAccess(),
		notificationHandler.MarkAsUnread,
	)

	notifications.POST("/:notification_id/archive",
		middlewares.NotificationAccess(),
		notificationHandler.ArchiveNotification,
	)

	notifications.POST("/:notification_id/unarchive",
		middlewares.NotificationAccess(),
		notificationHandler.UnarchiveNotification,
	)

	// Bulk operations
	notifications.POST("/mark-all-read",
		notificationHandler.MarkAllAsRead,
	)

	notifications.POST("/mark-read",
		applyValidation("bulk_mark_read"),
		notificationHandler.BulkMarkAsRead,
	)

	notifications.DELETE("/clear-all",
		notificationHandler.ClearAllNotifications,
	)

	notifications.POST("/bulk-delete",
		applyValidation("bulk_delete"),
		notificationHandler.BulkDeleteNotifications,
	)

	notifications.POST("/bulk-archive",
		applyValidation("bulk_archive"),
		notificationHandler.BulkArchiveNotifications,
	)

	// =============================================================================
	// NOTIFICATION CATEGORIES
	// =============================================================================

	categories := notifications.Group("/categories")
	{
		// Get notifications by category
		categories.GET("/likes",
			notificationHandler.GetLikeNotifications,
		)

		categories.GET("/comments",
			notificationHandler.GetCommentNotifications,
		)

		categories.GET("/follows",
			notificationHandler.GetFollowNotifications,
		)

		categories.GET("/mentions",
			notificationHandler.GetMentionNotifications,
		)

		categories.GET("/messages",
			notificationHandler.GetMessageNotifications,
		)

		categories.GET("/shares",
			notificationHandler.GetShareNotifications,
		)

		categories.GET("/security",
			notificationHandler.GetSecurityNotifications,
		)

		categories.GET("/system",
			notificationHandler.GetSystemNotifications,
		)

		categories.GET("/promotions",
			notificationHandler.GetPromotionNotifications,
		)

		// Category actions
		categories.POST("/:category/mark-read",
			notificationHandler.MarkCategoryAsRead,
		)

		categories.POST("/:category/clear",
			notificationHandler.ClearCategoryNotifications,
		)

		categories.POST("/:category/mute",
			applyValidation("mute_category"),
			notificationHandler.MuteCategoryNotifications,
		)

		categories.DELETE("/:category/mute",
			notificationHandler.UnmuteCategoryNotifications,
		)
	}

	// =============================================================================
	// NOTIFICATION FILTERS AND SEARCH
	// =============================================================================

	// Search notifications
	notifications.GET("/search",
		applyValidation("search_notifications"),
		applyRateLimit("search:100/hour"),
		notificationHandler.SearchNotifications,
	)

	// Filter notifications
	notifications.GET("/filter",
		applyValidation("filter_notifications"),
		notificationHandler.FilterNotifications,
	)

	// Archived notifications
	notifications.GET("/archived",
		notificationHandler.GetArchivedNotifications,
	)

	// =============================================================================
	// NOTIFICATION PREFERENCES
	// =============================================================================

	preferences := notifications.Group("/preferences")
	{
		// Get notification preferences
		preferences.GET("",
			notificationHandler.GetNotificationPreferences,
		)

		preferences.PUT("",
			applyValidation("notification_preferences"),
			notificationHandler.UpdateNotificationPreferences,
		)

		// Channel preferences
		preferences.GET("/channels",
			notificationHandler.GetChannelPreferences,
		)

		preferences.PUT("/channels",
			applyValidation("channel_preferences"),
			notificationHandler.UpdateChannelPreferences,
		)

		// Type-specific preferences
		preferences.GET("/types",
			notificationHandler.GetTypePreferences,
		)

		preferences.PUT("/types",
			applyValidation("type_preferences"),
			notificationHandler.UpdateTypePreferences,
		)

		// Quiet hours
		preferences.GET("/quiet-hours",
			notificationHandler.GetQuietHours,
		)

		preferences.PUT("/quiet-hours",
			applyValidation("quiet_hours"),
			notificationHandler.UpdateQuietHours,
		)

		// Frequency settings
		preferences.GET("/frequency",
			notificationHandler.GetFrequencySettings,
		)

		preferences.PUT("/frequency",
			applyValidation("frequency_settings"),
			notificationHandler.UpdateFrequencySettings,
		)

		// Custom notification rules
		preferences.GET("/rules",
			notificationHandler.GetNotificationRules,
		)

		preferences.POST("/rules",
			applyValidation("create_notification_rule"),
			notificationHandler.CreateNotificationRule,
		)

		preferences.PUT("/rules/:rule_id",
			applyValidation("update_notification_rule"),
			notificationHandler.UpdateNotificationRule,
		)

		preferences.DELETE("/rules/:rule_id",
			notificationHandler.DeleteNotificationRule,
		)
	}

	// =============================================================================
	// PUSH NOTIFICATIONS
	// =============================================================================

	push := notifications.Group("/push")
	{
		// Device registration
		push.POST("/register",
			applyValidation("register_device"),
			notificationHandler.RegisterDevice,
		)

		push.PUT("/devices/:device_id",
			applyValidation("update_device"),
			notificationHandler.UpdateDevice,
		)

		push.DELETE("/devices/:device_id",
			notificationHandler.UnregisterDevice,
		)

		push.GET("/devices",
			notificationHandler.GetRegisteredDevices,
		)

		// Test push notifications
		push.POST("/test",
			applyValidation("test_push"),
			notificationHandler.SendTestPushNotification,
		)

		// Push preferences
		push.GET("/preferences",
			notificationHandler.GetPushPreferences,
		)

		push.PUT("/preferences",
			applyValidation("push_preferences"),
			notificationHandler.UpdatePushPreferences,
		)

		// Push tokens
		push.POST("/tokens",
			applyValidation("register_push_token"),
			notificationHandler.RegisterPushToken,
		)

		push.DELETE("/tokens/:token",
			notificationHandler.UnregisterPushToken,
		)
	}

	// =============================================================================
	// EMAIL NOTIFICATIONS
	// =============================================================================

	email := notifications.Group("/email")
	{
		// Email preferences
		email.GET("/preferences",
			notificationHandler.GetEmailPreferences,
		)

		email.PUT("/preferences",
			applyValidation("email_preferences"),
			notificationHandler.UpdateEmailPreferences,
		)

		// Email digest settings
		email.GET("/digest",
			notificationHandler.GetEmailDigestSettings,
		)

		email.PUT("/digest",
			applyValidation("email_digest"),
			notificationHandler.UpdateEmailDigestSettings,
		)

		// Unsubscribe management
		email.POST("/unsubscribe",
			applyValidation("email_unsubscribe"),
			notificationHandler.UnsubscribeFromEmails,
		)

		email.POST("/resubscribe",
			applyValidation("email_resubscribe"),
			notificationHandler.ResubscribeToEmails,
		)

		email.GET("/unsubscribe-status",
			notificationHandler.GetUnsubscribeStatus,
		)

		// Email templates preview
		email.GET("/templates",
			notificationHandler.GetEmailTemplates,
		)

		email.GET("/templates/:template_id/preview",
			notificationHandler.PreviewEmailTemplate,
		)

		// Email delivery status
		email.GET("/delivery-status",
			notificationHandler.GetEmailDeliveryStatus,
		)

		email.GET("/:notification_id/delivery",
			middlewares.NotificationAccess(),
			notificationHandler.GetEmailDeliveryDetails,
		)
	}

	// =============================================================================
	// SMS NOTIFICATIONS
	// =============================================================================

	sms := notifications.Group("/sms")
	{
		// SMS preferences
		sms.GET("/preferences",
			notificationHandler.GetSMSPreferences,
		)

		sms.PUT("/preferences",
			applyValidation("sms_preferences"),
			notificationHandler.UpdateSMSPreferences,
		)

		// Phone number management
		sms.POST("/verify-phone",
			applyValidation("verify_phone"),
			applyRateLimit("sms:5/hour"),
			notificationHandler.VerifyPhoneNumber,
		)

		sms.POST("/confirm-phone",
			applyValidation("confirm_phone"),
			notificationHandler.ConfirmPhoneNumber,
		)

		sms.DELETE("/phone",
			notificationHandler.RemovePhoneNumber,
		)

		// SMS delivery status
		sms.GET("/delivery-status",
			notificationHandler.GetSMSDeliveryStatus,
		)

		sms.GET("/:notification_id/delivery",
			middlewares.NotificationAccess(),
			notificationHandler.GetSMSDeliveryDetails,
		)
	}

	// =============================================================================
	// NOTIFICATION TEMPLATES
	// =============================================================================

	templates := notifications.Group("/templates")
	{
		// Template management (admin only)
		templates.GET("",
			middlewares.Admin(),
			notificationHandler.GetNotificationTemplates,
		)

		templates.POST("",
			applyValidation("create_template"),
			middlewares.Admin(),
			notificationHandler.CreateNotificationTemplate,
		)

		templates.PUT("/:template_id",
			applyValidation("update_template"),
			middlewares.Admin(),
			notificationHandler.UpdateNotificationTemplate,
		)

		templates.DELETE("/:template_id",
			middlewares.Admin(),
			notificationHandler.DeleteNotificationTemplate,
		)

		// Template preview
		templates.POST("/:template_id/preview",
			applyValidation("preview_template"),
			middlewares.Admin(),
			notificationHandler.PreviewNotificationTemplate,
		)

		// Template testing
		templates.POST("/:template_id/test",
			applyValidation("test_template"),
			middlewares.Admin(),
			notificationHandler.TestNotificationTemplate,
		)
	}

	// =============================================================================
	// NOTIFICATION ANALYTICS
	// =============================================================================

	analytics := notifications.Group("/analytics")
	{
		// Notification statistics
		analytics.GET("/stats",
			notificationHandler.GetNotificationStats,
		)

		analytics.GET("/engagement",
			notificationHandler.GetNotificationEngagement,
		)

		analytics.GET("/delivery-rates",
			notificationHandler.GetDeliveryRates,
		)

		analytics.GET("/open-rates",
			notificationHandler.GetOpenRates,
		)

		// Channel performance
		analytics.GET("/channels/performance",
			notificationHandler.GetChannelPerformance,
		)

		analytics.GET("/channels/preferences",
			notificationHandler.GetChannelPreferenceStats,
		)

		// User behavior
		analytics.GET("/user-behavior",
			notificationHandler.GetUserNotificationBehavior,
		)

		analytics.GET("/interaction-patterns",
			notificationHandler.GetInteractionPatterns,
		)

		// Time-based analytics
		analytics.GET("/hourly",
			notificationHandler.GetHourlyNotificationStats,
		)

		analytics.GET("/daily",
			notificationHandler.GetDailyNotificationStats,
		)

		analytics.GET("/weekly",
			notificationHandler.GetWeeklyNotificationStats,
		)

		// A/B testing results
		analytics.GET("/ab-tests",
			middlewares.Admin(),
			notificationHandler.GetABTestResults,
		)
	}

	// =============================================================================
	// NOTIFICATION WEBHOOKS
	// =============================================================================

	webhooks := notifications.Group("/webhooks")
	{
		// Webhook management
		webhooks.GET("",
			notificationHandler.GetWebhooks,
		)

		webhooks.POST("",
			applyValidation("create_webhook"),
			notificationHandler.CreateWebhook,
		)

		webhooks.PUT("/:webhook_id",
			applyValidation("update_webhook"),
			notificationHandler.UpdateWebhook,
		)

		webhooks.DELETE("/:webhook_id",
			notificationHandler.DeleteWebhook,
		)

		// Webhook testing
		webhooks.POST("/:webhook_id/test",
			notificationHandler.TestWebhook,
		)

		webhooks.GET("/:webhook_id/logs",
			notificationHandler.GetWebhookLogs,
		)

		// Webhook events
		webhooks.GET("/events",
			notificationHandler.GetWebhookEvents,
		)

		webhooks.POST("/events/:webhook_id",
			applyValidation("webhook_event"),
			notificationHandler.TriggerWebhookEvent,
		)
	}

	// =============================================================================
	// REAL-TIME NOTIFICATIONS
	// =============================================================================

	realtime := notifications.Group("/realtime")
	{
		// WebSocket connection
		realtime.GET("/connect",
			notificationHandler.ConnectWebSocket,
		)

		// Server-Sent Events
		realtime.GET("/stream",
			notificationHandler.StreamNotifications,
		)

		// Real-time preferences
		realtime.GET("/preferences",
			notificationHandler.GetRealtimePreferences,
		)

		realtime.PUT("/preferences",
			applyValidation("realtime_preferences"),
			notificationHandler.UpdateRealtimePreferences,
		)

		// Connection management
		realtime.GET("/connections",
			notificationHandler.GetActiveConnections,
		)

		realtime.DELETE("/connections/:connection_id",
			notificationHandler.DisconnectConnection,
		)

		// Heartbeat and status
		realtime.POST("/heartbeat",
			notificationHandler.Heartbeat,
		)

		realtime.GET("/status",
			notificationHandler.GetConnectionStatus,
		)
	}
}

// Notification validation rules that handlers will need:
/*
Required Validation Schemas:

1. update_notification:
   - is_read: sometimes,boolean
   - is_archived: sometimes,boolean

2. bulk_mark_read:
   - notification_ids: required,array,max:100
   - notification_ids.*: required,objectid

3. bulk_delete:
   - notification_ids: required,array,max:100
   - notification_ids.*: required,objectid

4. search_notifications:
   - q: required,string,min:2,max:100
   - type: sometimes,in:like,comment,follow,mention,message,share,system
   - read: sometimes,boolean
   - date_from: sometimes,date
   - date_to: sometimes,date

5. notification_preferences:
   - email_notifications: sometimes,boolean
   - push_notifications: sometimes,boolean
   - sms_notifications: sometimes,boolean
   - in_app_notifications: sometimes,boolean
   - digest_frequency: sometimes,in:none,daily,weekly,monthly

6. channel_preferences:
   - likes: sometimes,object
   - comments: sometimes,object
   - follows: sometimes,object
   - mentions: sometimes,object
   - messages: sometimes,object

7. quiet_hours:
   - enabled: required,boolean
   - start_time: required_if:enabled,true,string,regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$
   - end_time: required_if:enabled,true,string,regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$
   - timezone: required_if:enabled,true,string

8. register_device:
   - device_token: required,string
   - device_type: required,in:ios,android,web
   - device_name: sometimes,string,max:100
   - app_version: sometimes,string

9. register_push_token:
   - token: required,string
   - platform: required,in:ios,android,web,huawei
   - environment: sometimes,in:development,production

10. email_preferences:
    - marketing_emails: sometimes,boolean
    - digest_emails: sometimes,boolean
    - security_alerts: sometimes,boolean
    - social_updates: sometimes,boolean
    - product_updates: sometimes,boolean

11. verify_phone:
    - phone_number: required,string,phone
    - country_code: required,string,size:2

12. create_webhook:
    - url: required,url
    - events: required,array,min:1
    - events.*: required,in:notification.created,notification.read,notification.deleted
    - secret: sometimes,string,min:16

13. create_template:
    - name: required,string,max:100
    - type: required,in:email,push,sms,in_app
    - subject: required_if:type,email,string,max:200
    - content: required,string
    - variables: sometimes,array

14. realtime_preferences:
    - auto_connect: sometimes,boolean
    - connection_timeout: sometimes,integer,min:30,max:300
    - reconnect_attempts: sometimes,integer,min:1,max:10
    - heartbeat_interval: sometimes,integer,min:10,max:60
*/
