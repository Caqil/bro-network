package routes

import (
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupSocialRoutes sets up social interaction routes (likes, follows, etc.)
func SetupSocialRoutes(api *gin.RouterGroup, config *APIConfig, middlewares *middleware.Middlewares) {
	social := api.Group("/social")

	// =============================================================================
	// LIKES AND REACTIONS
	// =============================================================================

	likes := social.Group("/likes")
	{
		// Get likes for content
		likes.GET("/posts/:post_id",
			config.LikeHandler.GetPostLikes,
		)

		likes.GET("/comments/:comment_id",
			config.LikeHandler.GetCommentLikes,
		)

		// Like/Unlike content
		likes.POST("/posts/:post_id",
			applyValidation("like_content"),
			applyRateLimit("like:100/min"),
			config.LikeHandler.LikePost,
		)

		likes.DELETE("/posts/:post_id",
			config.LikeHandler.UnlikePost,
		)

		likes.POST("/comments/:comment_id",
			applyValidation("like_content"),
			applyRateLimit("like:100/min"),
			config.LikeHandler.LikeComment,
		)

		likes.DELETE("/comments/:comment_id",
			config.LikeHandler.UnlikeComment,
		)

		// Reaction management
		likes.POST("/posts/:post_id/react",
			applyValidation("react_to_content"),
			applyRateLimit("reaction:100/min"),
			config.LikeHandler.ReactToPost,
		)

		likes.POST("/comments/:comment_id/react",
			applyValidation("react_to_content"),
			applyRateLimit("reaction:100/min"),
			config.LikeHandler.ReactToComment,
		)

		// Get user's likes
		likes.GET("/user/:user_id",
			config.LikeHandler.GetUserLikes,
		)

		likes.GET("/me",
			config.LikeHandler.GetMyLikes,
		)

		// Reaction analytics
		likes.GET("/posts/:post_id/summary",
			config.LikeHandler.GetPostReactionSummary,
		)

		likes.GET("/comments/:comment_id/summary",
			config.LikeHandler.GetCommentReactionSummary,
		)
	}

	// =============================================================================
	// FOLLOWS AND RELATIONSHIPS
	// =============================================================================

	follows := social.Group("/follows")
	{
		// Follow management
		follows.POST("/users/:user_id",
			applyRateLimit("follow:50/hour"),
			config.FollowHandler.FollowUser,
		)

		follows.DELETE("/users/:user_id",
			config.FollowHandler.UnfollowUser,
		)

		// Follow requests (for private accounts)
		follows.POST("/users/:user_id/request",
			applyRateLimit("follow:30/hour"),
			config.FollowHandler.SendFollowRequest,
		)

		follows.POST("/requests/:request_id/accept",
			config.FollowHandler.AcceptFollowRequest,
		)

		follows.POST("/requests/:request_id/reject",
			config.FollowHandler.RejectFollowRequest,
		)

		follows.DELETE("/requests/:request_id",
			config.FollowHandler.CancelFollowRequest,
		)

		// Get follow requests
		follows.GET("/requests/pending",
			config.FollowHandler.GetPendingRequests,
		)

		follows.GET("/requests/received",
			config.FollowHandler.GetReceivedRequests,
		)

		// Get followers/following
		follows.GET("/users/:user_id/followers",
			config.FollowHandler.GetUserFollowers,
		)

		follows.GET("/users/:user_id/following",
			config.FollowHandler.GetUserFollowing,
		)

		follows.GET("/me/followers",
			config.FollowHandler.GetMyFollowers,
		)

		follows.GET("/me/following",
			config.FollowHandler.GetMyFollowing,
		)

		// Relationship management
		follows.POST("/users/:user_id/mute",
			config.FollowHandler.MuteUser,
		)

		follows.DELETE("/users/:user_id/mute",
			config.FollowHandler.UnmuteUser,
		)

		follows.POST("/users/:user_id/block",
			config.FollowHandler.BlockUser,
		)

		follows.DELETE("/users/:user_id/block",
			config.FollowHandler.UnblockUser,
		)

		follows.POST("/users/:user_id/restrict",
			config.FollowHandler.RestrictUser,
		)

		follows.DELETE("/users/:user_id/restrict",
			config.FollowHandler.UnrestrictUser,
		)

		// Close friends
		follows.POST("/users/:user_id/close-friends",
			config.FollowHandler.AddToCloseFriends,
		)

		follows.DELETE("/users/:user_id/close-friends",
			config.FollowHandler.RemoveFromCloseFriends,
		)

		follows.GET("/me/close-friends",
			config.FollowHandler.GetCloseFriends,
		)

		// Relationship status
		follows.GET("/users/:user_id/relationship",
			config.FollowHandler.GetRelationship,
		)

		follows.GET("/users/:user_id/mutual",
			config.FollowHandler.GetMutualFollowers,
		)

		// Blocked/muted users
		follows.GET("/me/blocked",
			config.FollowHandler.GetBlockedUsers,
		)

		follows.GET("/me/muted",
			config.FollowHandler.GetMutedUsers,
		)

		follows.GET("/me/restricted",
			config.FollowHandler.GetRestrictedUsers,
		)

		// Follow suggestions
		follows.GET("/suggestions",
			config.FollowHandler.GetFollowSuggestions,
		)

		follows.POST("/suggestions/:user_id/dismiss",
			config.FollowHandler.DismissFollowSuggestion,
		)

		follows.GET("/suggestions/mutual",
			config.FollowHandler.GetMutualFollowSuggestions,
		)

		follows.GET("/suggestions/interests",
			config.FollowHandler.getInterestBasedSuggestions,
		)

		// Bulk operations
		follows.POST("/bulk/follow",
			applyValidation("bulk_follow"),
			applyRateLimit("bulk:10/hour"),
			config.FollowHandler.BulkFollow,
		)

		follows.POST("/bulk/unfollow",
			applyValidation("bulk_unfollow"),
			config.FollowHandler.BulkUnfollow,
		)

		// Import/Export follows
		follows.POST("/import",
			applyValidation("import_follows"),
			middlewares.FileUpload("file", 5*1024*1024), // 5MB limit
			config.FollowHandler.ImportFollows,
		)

		follows.GET("/export",
			config.FollowHandler.ExportFollows,
		)
	}

	// =============================================================================
	// SOCIAL ACTIVITIES AND INTERACTIONS
	// =============================================================================

	activities := social.Group("/activities")
	{
		// Activity feed
		activities.GET("/feed",
			config.UserHandler.GetActivityFeed,
		)

		activities.GET("/feed/following",
			config.UserHandler.GetFollowingActivity,
		)

		activities.GET("/user/:user_id",
			config.UserHandler.GetUserActivity,
		)

		// Activity types
		activities.GET("/likes",
			config.UserHandler.GetLikeActivity,
		)

		activities.GET("/comments",
			config.UserHandler.GetCommentActivity,
		)

		activities.GET("/follows",
			config.UserHandler.GetFollowActivity,
		)

		activities.GET("/mentions",
			config.UserHandler.GetMentionActivity,
		)

		// Activity preferences
		activities.GET("/preferences",
			config.UserHandler.GetActivityPreferences,
		)

		activities.PUT("/preferences",
			applyValidation("activity_preferences"),
			config.UserHandler.UpdateActivityPreferences,
		)

		// Mark activities as read
		activities.POST("/mark-read",
			applyValidation("mark_read"),
			config.UserHandler.MarkActivitiesAsRead,
		)

		activities.POST("/:activity_id/read",
			config.UserHandler.MarkActivityAsRead,
		)
	}

	// =============================================================================
	// SOCIAL DISCOVERY
	// =============================================================================

	discovery := social.Group("/discovery")
	{
		// People discovery
		discovery.GET("/people",
			config.UserHandler.DiscoverPeople,
		)

		discovery.GET("/people/nearby",
			config.UserHandler.DiscoverNearbyPeople,
		)

		discovery.GET("/people/interests",
			config.UserHandler.DiscoverByInterests,
		)

		discovery.GET("/people/mutual",
			config.UserHandler.DiscoverMutualConnections,
		)

		// Content discovery
		discovery.GET("/posts",
			config.PostHandler.DiscoverPosts,
		)

		discovery.GET("/posts/trending",
			applyCache("5m"),
			config.PostHandler.DiscoverTrendingPosts,
		)

		discovery.GET("/posts/topics",
			config.PostHandler.DiscoverByTopics,
		)

		// Trending content
		discovery.GET("/trending/hashtags",
			applyCache("10m"),
			config.SearchHandler.GetTrendingHashtags,
		)

		discovery.GET("/trending/topics",
			applyCache("10m"),
			config.SearchHandler.GetTrendingTopics,
		)

		discovery.GET("/trending/people",
			applyCache("15m"),
			config.UserHandler.GetTrendingPeople,
		)

		// Discovery preferences
		discovery.GET("/preferences",
			config.UserHandler.GetDiscoveryPreferences,
		)

		discovery.PUT("/preferences",
			applyValidation("discovery_preferences"),
			config.UserHandler.UpdateDiscoveryPreferences,
		)
	}

	// =============================================================================
	// SOCIAL GRAPH AND ANALYTICS
	// =============================================================================

	graph := social.Group("/graph")
	{
		// Social graph analysis
		graph.GET("/connections",
			config.FollowHandler.GetSocialGraph,
		)

		graph.GET("/network",
			config.FollowHandler.GetNetworkAnalysis,
		)

		graph.GET("/influence",
			config.FollowHandler.GetInfluenceScore,
		)

		graph.GET("/communities",
			config.FollowHandler.GetCommunities,
		)

		// Connection strength
		graph.GET("/users/:user_id/strength",
			config.FollowHandler.GetConnectionStrength,
		)

		graph.GET("/path/:user_id",
			config.FollowHandler.GetConnectionPath,
		)

		// Social recommendations
		graph.GET("/recommendations/people",
			config.FollowHandler.GetPeopleRecommendations,
		)

		graph.GET("/recommendations/content",
			config.PostHandler.GetContentRecommendations,
		)

		graph.GET("/recommendations/groups",
			config.UserHandler.GetGroupRecommendations,
		)
	}

	// =============================================================================
	// SOCIAL ENGAGEMENT METRICS
	// =============================================================================

	engagement := social.Group("/engagement")
	{
		// User engagement metrics
		engagement.GET("/me/stats",
			config.UserHandler.GetMyEngagementStats,
		)

		engagement.GET("/users/:user_id/stats",
			config.UserHandler.GetUserEngagementStats,
		)

		// Content engagement
		engagement.GET("/posts/:post_id/metrics",
			config.PostHandler.GetPostEngagementMetrics,
		)

		engagement.GET("/me/content/performance",
			config.PostHandler.GetMyContentPerformance,
		)

		// Engagement trends
		engagement.GET("/trends/daily",
			config.UserHandler.GetDailyEngagementTrends,
		)

		engagement.GET("/trends/weekly",
			config.UserHandler.GetWeeklyEngagementTrends,
		)

		engagement.GET("/trends/monthly",
			config.UserHandler.GetMonthlyEngagementTrends,
		)

		// Audience insights
		engagement.GET("/audience",
			config.UserHandler.GetAudienceInsights,
		)

		engagement.GET("/audience/demographics",
			config.UserHandler.GetAudienceDemographics,
		)

		engagement.GET("/audience/growth",
			config.UserHandler.GetAudienceGrowth,
		)
	}
}

// Social validation rules that handlers will need:
/*
Required Validation Schemas:

1. like_content:
   - reaction_type: sometimes,in:like,love,haha,wow,sad,angry,care

2. react_to_content:
   - reaction_type: required,in:like,love,haha,wow,sad,angry,care

3. bulk_follow:
   - user_ids: required,array,max:50
   - user_ids.*: required,objectid

4. bulk_unfollow:
   - user_ids: required,array,max:100
   - user_ids.*: required,objectid

5. import_follows:
   - file: required,file,mimes:csv,json
   - source: required,in:twitter,instagram,facebook,linkedin

6. activity_preferences:
   - show_likes: sometimes,boolean
   - show_comments: sometimes,boolean
   - show_follows: sometimes,boolean
   - show_shares: sometimes,boolean
   - email_notifications: sometimes,boolean
   - push_notifications: sometimes,boolean

7. mark_read:
   - activity_ids: sometimes,array
   - activity_ids.*: required,objectid
   - mark_all: sometimes,boolean

8. discovery_preferences:
   - show_in_suggestions: sometimes,boolean
   - discover_by_interests: sometimes,boolean
   - discover_by_location: sometimes,boolean
   - discover_by_contacts: sometimes,boolean
   - allow_contact_sync: sometimes,boolean
*/
