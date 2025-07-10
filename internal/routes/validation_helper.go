package routes

import (
	"bro-network/internal/middleware"
)

// SetupNotificationValidationSchemas sets up validation schemas for notification routes
func SetupNotificationValidationSchemas(vm *middleware.ValidationMiddleware) {
	// Update notification schema
	vm.AddSchema("update_notification", middleware.ValidationSchema{
		Fields: map[string]string{
			"is_read":     "sometimes|boolean",
			"is_archived": "sometimes|boolean",
		},
	})

	// Bulk mark read schema
	vm.AddSchema("bulk_mark_read", middleware.ValidationSchema{
		Fields: map[string]string{
			"notification_ids":   "required|array|max:100",
			"notification_ids.*": "required|objectid",
		},
		Required: []string{"notification_ids"},
	})

	// Bulk delete schema
	vm.AddSchema("bulk_delete", middleware.ValidationSchema{
		Fields: map[string]string{
			"notification_ids":   "required|array|max:100",
			"notification_ids.*": "required|objectid",
		},
		Required: []string{"notification_ids"},
	})

	// Bulk archive schema
	vm.AddSchema("bulk_archive", middleware.ValidationSchema{
		Fields: map[string]string{
			"notification_ids":   "required|array|max:100",
			"notification_ids.*": "required|objectid",
		},
		Required: []string{"notification_ids"},
	})

	// Search notifications schema
	vm.AddSchema("search_notifications", middleware.ValidationSchema{
		Fields: map[string]string{
			"q":         "required|string|min:2|max:100",
			"type":      "sometimes|in:like,comment,follow,mention,message,share,system,security,promotion",
			"read":      "sometimes|boolean",
			"date_from": "sometimes|date",
			"date_to":   "sometimes|date",
			"page":      "sometimes|integer|min:1",
			"limit":     "sometimes|integer|min:1|max:100",
		},
		Required: []string{"q"},
	})

	// Filter notifications schema
	vm.AddSchema("filter_notifications", middleware.ValidationSchema{
		Fields: map[string]string{
			"type":        "sometimes|in:like,comment,follow,mention,message,share,system,security,promotion",
			"priority":    "sometimes|in:low,normal,high,critical",
			"is_read":     "sometimes|boolean",
			"is_archived": "sometimes|boolean",
			"start_date":  "sometimes|date",
			"end_date":    "sometimes|date",
			"page":        "sometimes|integer|min:1",
			"limit":       "sometimes|integer|min:1|max:100",
		},
	})

	// Notification preferences schema
	vm.AddSchema("notification_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"email_notifications":  "sometimes|boolean",
			"push_notifications":   "sometimes|boolean",
			"sms_notifications":    "sometimes|boolean",
			"in_app_notifications": "sometimes|boolean",
			"digest_frequency":     "sometimes|in:none,daily,weekly,monthly",
		},
	})

	// Channel preferences schema
	vm.AddSchema("channel_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"likes":    "sometimes|object",
			"comments": "sometimes|object",
			"follows":  "sometimes|object",
			"mentions": "sometimes|object",
			"messages": "sometimes|object",
		},
	})

	// Type preferences schema
	vm.AddSchema("type_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"types": "required|object",
		},
		Required: []string{"types"},
	})

	// Quiet hours schema
	vm.AddSchema("quiet_hours", middleware.ValidationSchema{
		Fields: map[string]string{
			"enabled":    "required|boolean",
			"start_time": "required_if:enabled,true|string|regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
			"end_time":   "required_if:enabled,true|string|regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
			"timezone":   "required_if:enabled,true|string",
		},
		Required: []string{"enabled"},
	})

	// Frequency settings schema
	vm.AddSchema("frequency_settings", middleware.ValidationSchema{
		Fields: map[string]string{
			"max_per_hour": "sometimes|integer|min:1|max:1000",
			"max_per_day":  "sometimes|integer|min:1|max:10000",
			"max_per_week": "sometimes|integer|min:1|max:50000",
		},
	})

	// Create notification rule schema
	vm.AddSchema("create_notification_rule", middleware.ValidationSchema{
		Fields: map[string]string{
			"name":       "required|string|max:100",
			"conditions": "required|array|min:1",
			"actions":    "required|array|min:1",
			"priority":   "sometimes|integer|min:1|max:100",
			"is_active":  "sometimes|boolean",
		},
		Required: []string{"name", "conditions", "actions"},
	})

	// Update notification rule schema
	vm.AddSchema("update_notification_rule", middleware.ValidationSchema{
		Fields: map[string]string{
			"name":       "sometimes|string|max:100",
			"conditions": "sometimes|array|min:1",
			"actions":    "sometimes|array|min:1",
			"priority":   "sometimes|integer|min:1|max:100",
			"is_active":  "sometimes|boolean",
		},
	})

	// Register device schema
	vm.AddSchema("register_device", middleware.ValidationSchema{
		Fields: map[string]string{
			"device_token": "required|string",
			"device_type":  "required|in:ios,android,web",
			"device_name":  "sometimes|string|max:100",
			"app_version":  "sometimes|string|max:50",
		},
		Required: []string{"device_token", "device_type"},
	})

	// Update device schema
	vm.AddSchema("update_device", middleware.ValidationSchema{
		Fields: map[string]string{
			"device_name": "sometimes|string|max:100",
			"app_version": "sometimes|string|max:50",
			"is_active":   "sometimes|boolean",
		},
	})

	// Test push schema
	vm.AddSchema("test_push", middleware.ValidationSchema{
		Fields: map[string]string{
			"message": "required|string|max:500",
			"title":   "sometimes|string|max:100",
		},
		Required: []string{"message"},
	})

	// Push preferences schema
	vm.AddSchema("push_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"enabled":     "sometimes|boolean",
			"types":       "sometimes|object",
			"quiet_hours": "sometimes|object",
		},
	})

	// Register push token schema
	vm.AddSchema("register_push_token", middleware.ValidationSchema{
		Fields: map[string]string{
			"token":       "required|string",
			"platform":    "required|in:ios,android,web,huawei",
			"environment": "sometimes|in:development,production",
		},
		Required: []string{"token", "platform"},
	})

	// Email preferences schema
	vm.AddSchema("email_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"marketing_emails": "sometimes|boolean",
			"digest_emails":    "sometimes|boolean",
			"security_alerts":  "sometimes|boolean",
			"social_updates":   "sometimes|boolean",
			"product_updates":  "sometimes|boolean",
			"digest_frequency": "sometimes|in:none,daily,weekly,monthly",
			"digest_time":      "sometimes|string|regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
		},
	})

	// Email digest schema
	vm.AddSchema("email_digest", middleware.ValidationSchema{
		Fields: map[string]string{
			"enabled":   "sometimes|boolean",
			"frequency": "sometimes|in:none,daily,weekly,monthly",
			"time":      "sometimes|string|regex:^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
			"types":     "sometimes|array",
		},
	})

	// Email unsubscribe schema
	vm.AddSchema("email_unsubscribe", middleware.ValidationSchema{
		Fields: map[string]string{
			"types": "sometimes|array",
			"all":   "sometimes|boolean",
		},
	})

	// Email resubscribe schema
	vm.AddSchema("email_resubscribe", middleware.ValidationSchema{
		Fields: map[string]string{
			"types": "sometimes|array",
		},
	})

	// SMS preferences schema
	vm.AddSchema("sms_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"security_alerts":  "sometimes|boolean",
			"critical_updates": "sometimes|boolean",
		},
	})

	// Verify phone schema
	vm.AddSchema("verify_phone", middleware.ValidationSchema{
		Fields: map[string]string{
			"phone_number": "required|string|phone",
			"country_code": "required|string|size:2",
		},
		Required: []string{"phone_number", "country_code"},
	})

	// Confirm phone schema
	vm.AddSchema("confirm_phone", middleware.ValidationSchema{
		Fields: map[string]string{
			"verification_code": "required|string|min:4|max:10",
		},
		Required: []string{"verification_code"},
	})

	// Create template schema
	vm.AddSchema("create_template", middleware.ValidationSchema{
		Fields: map[string]string{
			"name":      "required|string|max:100",
			"type":      "required|in:email,push,sms,in_app",
			"channel":   "required|in:in_app,push,email,sms",
			"subject":   "required_if:type,email|string|max:200",
			"content":   "required|string",
			"variables": "sometimes|array",
			"settings":  "sometimes|object",
		},
		Required: []string{"name", "type", "channel", "content"},
	})

	// Update template schema
	vm.AddSchema("update_template", middleware.ValidationSchema{
		Fields: map[string]string{
			"name":      "sometimes|string|max:100",
			"subject":   "sometimes|string|max:200",
			"content":   "sometimes|string",
			"variables": "sometimes|array",
			"settings":  "sometimes|object",
			"is_active": "sometimes|boolean",
		},
	})

	// Preview template schema
	vm.AddSchema("preview_template", middleware.ValidationSchema{
		Fields: map[string]string{
			"variables": "sometimes|object",
		},
	})

	// Test template schema
	vm.AddSchema("test_template", middleware.ValidationSchema{
		Fields: map[string]string{
			"user_id":   "required|objectid",
			"variables": "sometimes|object",
		},
		Required: []string{"user_id"},
	})

	// Create webhook schema
	vm.AddSchema("create_webhook", middleware.ValidationSchema{
		Fields: map[string]string{
			"url":      "required|url",
			"events":   "required|array|min:1",
			"events.*": "required|in:notification.created,notification.read,notification.deleted",
			"secret":   "sometimes|string|min:16",
			"headers":  "sometimes|object",
		},
		Required: []string{"url", "events"},
	})

	// Update webhook schema
	vm.AddSchema("update_webhook", middleware.ValidationSchema{
		Fields: map[string]string{
			"url":       "sometimes|url",
			"events":    "sometimes|array|min:1",
			"events.*":  "sometimes|in:notification.created,notification.read,notification.deleted",
			"secret":    "sometimes|string|min:16",
			"headers":   "sometimes|object",
			"is_active": "sometimes|boolean",
		},
	})

	// Webhook event schema
	vm.AddSchema("webhook_event", middleware.ValidationSchema{
		Fields: map[string]string{
			"event":   "required|in:notification.created,notification.read,notification.deleted",
			"payload": "required|object",
		},
		Required: []string{"event", "payload"},
	})

	// Real-time preferences schema
	vm.AddSchema("realtime_preferences", middleware.ValidationSchema{
		Fields: map[string]string{
			"auto_connect":       "sometimes|boolean",
			"connection_timeout": "sometimes|integer|min:30|max:300",
			"reconnect_attempts": "sometimes|integer|min:1|max:10",
			"heartbeat_interval": "sometimes|integer|min:10|max:60",
			"enabled_types":      "sometimes|array",
		},
	})

	// Mute category schema
	vm.AddSchema("mute_category", middleware.ValidationSchema{
		Fields: map[string]string{
			"duration": "sometimes|string",
		},
	})
}
