package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupMessageRoutes sets up messaging and conversation routes
func SetupMessageRoutes(api *gin.RouterGroup, messageHandler *handlers.MessageHandler, middlewares *middleware.Middlewares) {
	messages := api.Group("/messages")

	// =============================================================================
	// CONVERSATIONS MANAGEMENT
	// =============================================================================

	conversations := messages.Group("/conversations")
	{
		// List conversations
		conversations.GET("",
			messageHandler.GetConversations,
		)

		conversations.GET("/archived",
			messageHandler.GetArchivedConversations,
		)

		conversations.GET("/unread",
			messageHandler.GetUnreadConversations,
		)

		// Create conversation
		conversations.POST("",
			applyValidation("create_conversation"),
			applyRateLimit("conversation:20/hour"),
			messageHandler.CreateConversation,
		)

		// Individual conversation management
		conversations.GET("/:conversation_id",
			middlewares.ConversationAccess(),
			messageHandler.GetConversation,
		)

		conversations.PUT("/:conversation_id",
			applyValidation("update_conversation"),
			middlewares.ConversationAccess(),
			messageHandler.UpdateConversation,
		)

		conversations.DELETE("/:conversation_id",
			middlewares.ConversationAccess(),
			messageHandler.DeleteConversation,
		)

		// Conversation actions
		conversations.POST("/:conversation_id/archive",
			middlewares.ConversationAccess(),
			messageHandler.ArchiveConversation,
		)

		conversations.POST("/:conversation_id/unarchive",
			middlewares.ConversationAccess(),
			messageHandler.UnarchiveConversation,
		)

		conversations.POST("/:conversation_id/mute",
			applyValidation("mute_conversation"),
			middlewares.ConversationAccess(),
			messageHandler.MuteConversation,
		)

		conversations.POST("/:conversation_id/unmute",
			middlewares.ConversationAccess(),
			messageHandler.UnmuteConversation,
		)

		conversations.POST("/:conversation_id/mark-read",
			middlewares.ConversationAccess(),
			messageHandler.MarkConversationAsRead,
		)

		conversations.POST("/:conversation_id/mark-unread",
			middlewares.ConversationAccess(),
			messageHandler.MarkConversationAsUnread,
		)

		// Conversation participants
		conversations.GET("/:conversation_id/participants",
			middlewares.ConversationAccess(),
			messageHandler.GetConversationParticipants,
		)

		conversations.POST("/:conversation_id/participants",
			applyValidation("add_participants"),
			middlewares.ConversationAdmin(),
			messageHandler.AddParticipants,
		)

		conversations.DELETE("/:conversation_id/participants/:user_id",
			middlewares.ConversationAdmin(),
			messageHandler.RemoveParticipant,
		)

		conversations.POST("/:conversation_id/leave",
			middlewares.ConversationAccess(),
			messageHandler.LeaveConversation,
		)

		// Group conversation management
		conversations.PUT("/:conversation_id/admin/:user_id",
			middlewares.ConversationAdmin(),
			messageHandler.MakeAdmin,
		)

		conversations.DELETE("/:conversation_id/admin/:user_id",
			middlewares.ConversationAdmin(),
			messageHandler.RemoveAdmin,
		)

		conversations.POST("/:conversation_id/settings",
			applyValidation("conversation_settings"),
			middlewares.ConversationAdmin(),
			messageHandler.UpdateConversationSettings,
		)

		// Conversation media and files
		conversations.GET("/:conversation_id/media",
			middlewares.ConversationAccess(),
			messageHandler.GetConversationMedia,
		)

		conversations.GET("/:conversation_id/files",
			middlewares.ConversationAccess(),
			messageHandler.GetConversationFiles,
		)

		conversations.GET("/:conversation_id/links",
			middlewares.ConversationAccess(),
			messageHandler.GetConversationLinks,
		)

		// Conversation search
		conversations.GET("/:conversation_id/search",
			applyValidation("search_conversation"),
			middlewares.ConversationAccess(),
			messageHandler.SearchInConversation,
		)

		// Conversation export
		conversations.POST("/:conversation_id/export",
			middlewares.ConversationAccess(),
			messageHandler.ExportConversation,
		)

		conversations.GET("/:conversation_id/export/:export_id",
			middlewares.ConversationAccess(),
			messageHandler.DownloadConversationExport,
		)
	}

	// =============================================================================
	// MESSAGES MANAGEMENT
	// =============================================================================

	// Send message
	messages.POST("",
		applyValidation("send_message"),
		applyRateLimit("message:100/hour"),
		middlewares.FileUpload("attachments", 25*1024*1024), // 25MB limit
		messageHandler.SendMessage,
	)

	// Quick send to user
	messages.POST("/send/:user_id",
		applyValidation("quick_send_message"),
		applyRateLimit("message:100/hour"),
		messageHandler.QuickSendMessage,
	)

	// Get messages in conversation
	messages.GET("/conversations/:conversation_id/messages",
		middlewares.ConversationAccess(),
		messageHandler.GetMessages,
	)

	// Individual message management
	messages.GET("/:message_id",
		middlewares.MessageAccess(),
		messageHandler.GetMessage,
	)

	messages.PUT("/:message_id",
		applyValidation("update_message"),
		middlewares.MessageOwnership(),
		messageHandler.UpdateMessage,
	)

	messages.DELETE("/:message_id",
		middlewares.MessageOwnership(),
		messageHandler.DeleteMessage,
	)

	messages.POST("/:message_id/restore",
		middlewares.MessageOwnership(),
		messageHandler.RestoreMessage,
	)

	// Message reactions
	messages.POST("/:message_id/react",
		applyValidation("react_to_message"),
		applyRateLimit("reaction:200/hour"),
		middlewares.MessageAccess(),
		messageHandler.ReactToMessage,
	)

	messages.DELETE("/:message_id/react",
		middlewares.MessageAccess(),
		messageHandler.RemoveReaction,
	)

	messages.GET("/:message_id/reactions",
		middlewares.MessageAccess(),
		messageHandler.GetMessageReactions,
	)

	// Message actions
	messages.POST("/:message_id/reply",
		applyValidation("reply_to_message"),
		applyRateLimit("message:100/hour"),
		middlewares.MessageAccess(),
		messageHandler.ReplyToMessage,
	)

	messages.POST("/:message_id/forward",
		applyValidation("forward_message"),
		applyRateLimit("forward:50/hour"),
		middlewares.MessageAccess(),
		messageHandler.ForwardMessage,
	)

	messages.POST("/:message_id/star",
		middlewares.MessageAccess(),
		messageHandler.StarMessage,
	)

	messages.DELETE("/:message_id/star",
		middlewares.MessageAccess(),
		messageHandler.UnstarMessage,
	)

	messages.POST("/:message_id/report",
		applyValidation("report_message"),
		applyRateLimit("report:10/hour"),
		middlewares.MessageAccess(),
		messageHandler.ReportMessage,
	)

	// Message status
	messages.POST("/:message_id/read",
		middlewares.MessageAccess(),
		messageHandler.MarkMessageAsRead,
	)

	messages.GET("/:message_id/delivery-status",
		middlewares.MessageOwnership(),
		messageHandler.GetDeliveryStatus,
	)

	messages.GET("/:message_id/read-receipts",
		middlewares.MessageOwnership(),
		messageHandler.GetReadReceipts,
	)

	// =============================================================================
	// MESSAGE SEARCH AND DISCOVERY
	// =============================================================================

	search := messages.Group("/search")
	{
		// Global message search
		search.GET("",
			applyValidation("search_messages"),
			applyRateLimit("search:50/hour"),
			messageHandler.SearchMessages,
		)

		search.GET("/recent",
			messageHandler.GetRecentSearches,
		)

		search.DELETE("/recent",
			messageHandler.ClearRecentSearches,
		)

		// Advanced search
		search.POST("/advanced",
			applyValidation("advanced_search_messages"),
			messageHandler.AdvancedSearchMessages,
		)

		// Search by type
		search.GET("/media",
			messageHandler.SearchMessagesByMedia,
		)

		search.GET("/files",
			messageHandler.SearchMessagesByFiles,
		)

		search.GET("/links",
			messageHandler.SearchMessagesByLinks,
		)
	}

	// =============================================================================
	// MESSAGE THREADS
	// =============================================================================

	threads := messages.Group("/threads")
	{
		// Get message threads
		threads.GET("",
			messageHandler.GetMessageThreads,
		)

		threads.GET("/:thread_id",
			middlewares.ThreadAccess(),
			messageHandler.GetThread,
		)

		threads.GET("/:thread_id/messages",
			middlewares.ThreadAccess(),
			messageHandler.GetThreadMessages,
		)

		// Thread actions
		threads.POST("/:thread_id/mark-read",
			middlewares.ThreadAccess(),
			messageHandler.MarkThreadAsRead,
		)

		threads.POST("/:thread_id/follow",
			middlewares.ThreadAccess(),
			messageHandler.FollowThread,
		)

		threads.DELETE("/:thread_id/follow",
			middlewares.ThreadAccess(),
			messageHandler.UnfollowThread,
		)
	}

	// =============================================================================
	// MESSAGE DRAFTS
	// =============================================================================

	drafts := messages.Group("/drafts")
	{
		// Draft management
		drafts.GET("",
			messageHandler.GetDrafts,
		)

		drafts.POST("",
			applyValidation("create_draft"),
			messageHandler.CreateDraft,
		)

		drafts.PUT("/:draft_id",
			applyValidation("update_draft"),
			middlewares.DraftOwnership(),
			messageHandler.UpdateDraft,
		)

		drafts.DELETE("/:draft_id",
			middlewares.DraftOwnership(),
			messageHandler.DeleteDraft,
		)

		drafts.POST("/:draft_id/send",
			middlewares.DraftOwnership(),
			messageHandler.SendDraft,
		)

		// Auto-save drafts
		drafts.POST("/auto-save",
			applyValidation("auto_save_draft"),
			messageHandler.AutoSaveDraft,
		)
	}

	// =============================================================================
	// MESSAGE SCHEDULING
	// =============================================================================

	scheduled := messages.Group("/scheduled")
	{
		// Scheduled messages
		scheduled.GET("",
			messageHandler.GetScheduledMessages,
		)

		scheduled.POST("",
			applyValidation("schedule_message"),
			messageHandler.ScheduleMessage,
		)

		scheduled.PUT("/:message_id",
			applyValidation("update_scheduled_message"),
			middlewares.ScheduledMessageOwnership(),
			messageHandler.UpdateScheduledMessage,
		)

		scheduled.DELETE("/:message_id",
			middlewares.ScheduledMessageOwnership(),
			messageHandler.CancelScheduledMessage,
		)

		scheduled.POST("/:message_id/send-now",
			middlewares.ScheduledMessageOwnership(),
			messageHandler.SendScheduledMessageNow,
		)
	}

	// =============================================================================
	// MESSAGE TEMPLATES
	// =============================================================================

	templates := messages.Group("/templates")
	{
		// Template management
		templates.GET("",
			messageHandler.GetMessageTemplates,
		)

		templates.POST("",
			applyValidation("create_template"),
			messageHandler.CreateMessageTemplate,
		)

		templates.PUT("/:template_id",
			applyValidation("update_template"),
			middlewares.TemplateOwnership(),
			messageHandler.UpdateMessageTemplate,
		)

		templates.DELETE("/:template_id",
			middlewares.TemplateOwnership(),
			messageHandler.DeleteMessageTemplate,
		)

		templates.POST("/:template_id/use",
			applyValidation("use_template"),
			messageHandler.UseMessageTemplate,
		)

		// Public templates
		templates.GET("/public",
			messageHandler.GetPublicTemplates,
		)

		templates.POST("/:template_id/share",
			middlewares.TemplateOwnership(),
			messageHandler.ShareTemplate,
		)
	}

	// =============================================================================
	// MESSAGE SETTINGS AND PREFERENCES
	// =============================================================================

	settings := messages.Group("/settings")
	{
		// Message preferences
		settings.GET("",
			messageHandler.GetMessageSettings,
		)

		settings.PUT("",
			applyValidation("message_settings"),
			messageHandler.UpdateMessageSettings,
		)

		// Privacy settings
		settings.GET("/privacy",
			messageHandler.GetMessagePrivacySettings,
		)

		settings.PUT("/privacy",
			applyValidation("message_privacy"),
			messageHandler.UpdateMessagePrivacySettings,
		)

		// Notification settings
		settings.GET("/notifications",
			messageHandler.GetMessageNotificationSettings,
		)

		settings.PUT("/notifications",
			applyValidation("message_notifications"),
			messageHandler.UpdateMessageNotificationSettings,
		)

		// Auto-reply settings
		settings.GET("/auto-reply",
			messageHandler.GetAutoReplySettings,
		)

		settings.PUT("/auto-reply",
			applyValidation("auto_reply"),
			messageHandler.UpdateAutoReplySettings,
		)

		// Message filters
		settings.GET("/filters",
			messageHandler.GetMessageFilters,
		)

		settings.POST("/filters",
			applyValidation("create_filter"),
			messageHandler.CreateMessageFilter,
		)

		settings.PUT("/filters/:filter_id",
			applyValidation("update_filter"),
			messageHandler.UpdateMessageFilter,
		)

		settings.DELETE("/filters/:filter_id",
			messageHandler.DeleteMessageFilter,
		)
	}

	// =============================================================================
	// MESSAGE ANALYTICS
	// =============================================================================

	analytics := messages.Group("/analytics")
	{
		// Message statistics
		analytics.GET("/stats",
			messageHandler.GetMessageStats,
		)

		analytics.GET("/conversation/:conversation_id/stats",
			middlewares.ConversationAccess(),
			messageHandler.GetConversationStats,
		)

		// Response rates
		analytics.GET("/response-rates",
			messageHandler.GetResponseRates,
		)

		analytics.GET("/engagement",
			messageHandler.getMessageEngagement,
		)

		// Activity patterns
		analytics.GET("/activity-patterns",
			messageHandler.GetActivityPatterns,
		)

		analytics.GET("/peak-hours",
			messageHandler.GetPeakMessagingHours,
		)
	}
}

// Message validation rules that handlers will need:
/*
Required Validation Schemas:

1. create_conversation:
   - participants: required,array,min:1,max:50
   - participants.*: required,objectid
   - is_group: sometimes,boolean
   - group_name: required_if:is_group,true,string,max:100
   - group_image: sometimes,string

2. update_conversation:
   - group_name: sometimes,string,max:100
   - group_image: sometimes,string
   - settings: sometimes,object

3. send_message:
   - conversation_id: sometimes,objectid
   - recipient_id: sometimes,objectid
   - content: required,string,max:1000
   - message_type: sometimes,in:text,image,video,audio,file,location
   - attachments: sometimes,array,max:10
   - reply_to_id: sometimes,objectid
   - scheduled_at: sometimes,datetime,after:now

4. quick_send_message:
   - content: required,string,max:1000
   - message_type: sometimes,in:text,image,video,audio,file

5. update_message:
   - content: required,string,max:1000

6. react_to_message:
   - reaction: required,in:like,love,haha,wow,sad,angry,thumbs_up,thumbs_down

7. reply_to_message:
   - content: required,string,max:1000
   - attachments: sometimes,array,max:5

8. forward_message:
   - conversation_ids: required,array,max:20
   - conversation_ids.*: required,objectid
   - add_comment: sometimes,string,max:280

9. report_message:
   - reason: required,in:spam,harassment,inappropriate,violence,fake_news
   - description: sometimes,string,max:500

10. search_messages:
    - query: required,string,min:2
    - conversation_id: sometimes,objectid
    - from_user: sometimes,objectid
    - message_type: sometimes,in:text,image,video,audio,file
    - date_from: sometimes,date
    - date_to: sometimes,date

11. schedule_message:
    - conversation_id: required,objectid
    - content: required,string,max:1000
    - scheduled_at: required,datetime,after:now
    - timezone: sometimes,string

12. create_template:
    - name: required,string,max:100
    - content: required,string,max:1000
    - category: sometimes,string,max:50
    - is_public: sometimes,boolean

13. message_settings:
    - read_receipts: sometimes,boolean
    - typing_indicators: sometimes,boolean
    - auto_download_media: sometimes,boolean
    - notification_sound: sometimes,boolean
    - vibration: sometimes,boolean

14. auto_reply:
    - enabled: required,boolean
    - message: required_if:enabled,true,string,max:500
    - schedule: sometimes,object
    - exceptions: sometimes,array
*/
