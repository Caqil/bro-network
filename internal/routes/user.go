package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupPublicUserRoutes sets up public user routes (no auth required)
func SetupPublicUserRoutes(api *gin.RouterGroup, userHandler *handlers.UserHandler) {
	users := api.Group("/users")

	// Public user discovery
	users.GET("",
		applyCache("5m"),
		userHandler.GetUsers,
	)

	users.GET("/search",
		applyRateLimit("search:30/min"),
		userHandler.SearchUsers,
	)

	users.GET("/trending",
		applyCache("10m"),
		userHandler.GetTrendingUsers,
	)

	users.GET("/suggested",
		applyCache("5m"),
		userHandler.GetSuggestedUsers,
	)

	// Public profile views
	users.GET("/:username",
		applyCache("2m"),
		userHandler.GetUserProfile,
	)

	users.GET("/:username/posts",
		applyCache("1m"),
		userHandler.GetUserPosts,
	)

	users.GET("/:username/followers",
		userHandler.GetUserFollowers,
	)

	users.GET("/:username/following",
		userHandler.GetUserFollowing,
	)

	// User verification
	users.GET("/:username/verify",
		userHandler.CheckUserExists,
	)
}

// SetupUserRoutes sets up protected user routes (auth required)
func SetupUserRoutes(api *gin.RouterGroup, userHandler *handlers.UserHandler, middlewares *middleware.Middlewares) {
	users := api.Group("/users")

	// Current user profile management
	me := users.Group("/me")
	{
		// Profile information
		me.GET("",
			userHandler.GetCurrentUser,
		)

		me.PUT("",
			applyValidation("update_profile"),
			userHandler.UpdateProfile,
		)

		me.DELETE("",
			applyValidation("delete_profile"),
			userHandler.DeleteProfile,
		)

		// Profile settings
		me.GET("/settings",
			userHandler.GetUserSettings,
		)

		me.PUT("/settings",
			applyValidation("user_settings"),
			userHandler.UpdateUserSettings,
		)

		// Privacy settings
		me.GET("/privacy",
			userHandler.GetPrivacySettings,
		)

		me.PUT("/privacy",
			applyValidation("privacy_settings"),
			userHandler.UpdatePrivacySettings,
		)

		// Notification preferences
		me.GET("/notifications/preferences",
			userHandler.GetNotificationPreferences,
		)

		me.PUT("/notifications/preferences",
			applyValidation("notification_preferences"),
			userHandler.UpdateNotificationPreferences,
		)

		// Profile media
		me.POST("/avatar",
			applyValidation("avatar_upload"),
			middlewares.FileUpload("avatar", 5*1024*1024), // 5MB limit
			userHandler.UploadAvatar,
		)

		me.DELETE("/avatar",
			userHandler.RemoveAvatar,
		)

		me.POST("/cover",
			applyValidation("cover_upload"),
			middlewares.FileUpload("cover", 10*1024*1024), // 10MB limit
			userHandler.UploadCoverImage,
		)

		me.DELETE("/cover",
			userHandler.RemoveCoverImage,
		)

		// User statistics
		me.GET("/stats",
			userHandler.GetUserStats,
		)

		me.GET("/analytics",
			userHandler.GetUserAnalytics,
		)

		// Activity and history
		me.GET("/activity",
			userHandler.GetUserActivity,
		)

		me.GET("/history",
			userHandler.GetUserHistory,
		)

		// Bookmarks and saved content
		me.GET("/bookmarks",
			userHandler.GetBookmarks,
		)

		me.GET("/saved",
			userHandler.GetSavedPosts,
		)

		me.GET("/liked",
			userHandler.GetLikedPosts,
		)

		// Following management
		me.GET("/following",
			userHandler.GetMyFollowing,
		)

		me.GET("/followers",
			userHandler.GetMyFollowers,
		)

		me.GET("/follow-requests",
			userHandler.GetFollowRequests,
		)

		me.GET("/pending-requests",
			userHandler.GetPendingRequests,
		)

		// Blocked users
		me.GET("/blocked",
			userHandler.GetBlockedUsers,
		)

		me.GET("/muted",
			userHandler.GetMutedUsers,
		)

		// Account verification
		me.POST("/verify",
			applyValidation("verification_request"),
			userHandler.RequestVerification,
		)

		me.GET("/verification",
			userHandler.GetVerificationStatus,
		)

		// Data and privacy
		me.GET("/data",
			userHandler.GetUserData,
		)

		me.POST("/data/export",
			userHandler.ExportUserData,
		)

		me.GET("/data/download/:export_id",
			userHandler.DownloadUserData,
		)

		// Close friends
		me.GET("/close-friends",
			userHandler.GetCloseFriends,
		)

		me.POST("/close-friends/:user_id",
			userHandler.AddToCloseFriends,
		)

		me.DELETE("/close-friends/:user_id",
			userHandler.RemoveFromCloseFriends,
		)
	}

	// User interactions
	users.POST("/:user_id/follow",
		applyRateLimit("follow:20/min"),
		userHandler.FollowUser,
	)

	users.DELETE("/:user_id/follow",
		userHandler.UnfollowUser,
	)

	users.POST("/:user_id/block",
		userHandler.BlockUser,
	)

	users.DELETE("/:user_id/block",
		userHandler.UnblockUser,
	)

	users.POST("/:user_id/mute",
		userHandler.MuteUser,
	)

	users.DELETE("/:user_id/mute",
		userHandler.UnmuteUser,
	)

	users.POST("/:user_id/report",
		applyValidation("report_user"),
		applyRateLimit("report:5/min"),
		userHandler.ReportUser,
	)

	// Follow request management
	users.POST("/:user_id/follow-request/accept",
		userHandler.AcceptFollowRequest,
	)

	users.POST("/:user_id/follow-request/reject",
		userHandler.RejectFollowRequest,
	)

	users.DELETE("/:user_id/follow-request",
		userHandler.CancelFollowRequest,
	)

	// User lookup and search (authenticated)
	users.GET("/:user_id/relationship",
		userHandler.GetRelationship,
	)

	users.GET("/:user_id/mutual",
		userHandler.GetMutualConnections,
	)

	users.GET("/:user_id/posts",
		userHandler.GetUserPostsAuth,
	)

	users.GET("/:user_id/media",
		userHandler.GetUserMedia,
	)

	users.GET("/:user_id/likes",
		userHandler.GetUserLikes,
	)

	// User recommendations
	users.GET("/suggestions/follow",
		userHandler.GetFollowSuggestions,
	)

	users.GET("/suggestions/friends",
		userHandler.GetFriendSuggestions,
	)

	users.POST("/suggestions/:user_id/dismiss",
		userHandler.DismissSuggestion,
	)

	// User discovery
	users.GET("/nearby",
		userHandler.GetNearbyUsers,
	)

	users.GET("/online",
		userHandler.GetOnlineUsers,
	)

	// Advanced search
	users.GET("/advanced-search",
		userHandler.AdvancedUserSearch,
	)

	// User contacts
	users.POST("/contacts/sync",
		applyValidation("sync_contacts"),
		userHandler.SyncContacts,
	)

	users.GET("/contacts/find",
		userHandler.FindContactsOnPlatform,
	)

	users.POST("/contacts/invite",
		applyValidation("invite_contacts"),
		applyRateLimit("invite:10/hour"),
		userHandler.InviteContacts,
	)

	// User badges and achievements
	users.GET("/:user_id/badges",
		userHandler.GetUserBadges,
	)

	users.GET("/:user_id/achievements",
		userHandler.GetUserAchievements,
	)
}

// User validation rules that handlers will need:
/*
Required Validation Schemas:

1. update_profile:
   - first_name: sometimes,string,min:1,max:50
   - last_name: sometimes,string,min:1,max:50
   - display_name: sometimes,string,max:100
   - bio: sometimes,string,max:500
   - website: sometimes,url
   - location: sometimes,string,max:100
   - date_of_birth: sometimes,date
   - is_private: sometimes,boolean

2. user_settings:
   - theme: sometimes,in:light,dark,auto
   - language: sometimes,string,in:en,es,fr,de
   - timezone: sometimes,string
   - email_notifications: sometimes,boolean
   - push_notifications: sometimes,boolean
   - sms_notifications: sometimes,boolean

3. privacy_settings:
   - profile_visibility: sometimes,in:public,followers,private
   - show_online_status: sometimes,boolean
   - show_read_receipts: sometimes,boolean
   - allow_direct_messages: sometimes,boolean
   - show_activity_status: sometimes,boolean

4. notification_preferences:
   - email_notifications: sometimes,boolean
   - push_notifications: sometimes,boolean
   - likes: sometimes,boolean
   - comments: sometimes,boolean
   - follows: sometimes,boolean
   - messages: sometimes,boolean
   - mentions: sometimes,boolean

5. avatar_upload:
   - avatar: required,file,image,max_size:5MB

6. cover_upload:
   - cover: required,file,image,max_size:10MB

7. report_user:
   - reason: required,in:spam,harassment,fake_account,inappropriate_content
   - description: sometimes,string,max:500
   - evidence: sometimes,array

8. verification_request:
   - category: required,in:public_figure,business,brand,organization
   - documents: sometimes,array
   - website: sometimes,url
   - social_links: sometimes,array

9. sync_contacts:
   - contacts: required,array
   - contacts.*.name: required,string
   - contacts.*.email: sometimes,email
   - contacts.*.phone: sometimes,string

10. invite_contacts:
    - emails: required,array,max:50
    - message: sometimes,string,max:500
*/
