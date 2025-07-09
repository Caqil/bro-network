package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupPublicSearchRoutes sets up public search routes (no auth required)
func SetupPublicSearchRoutes(api *gin.RouterGroup, searchHandler *handlers.SearchHandler) {
	search := api.Group("/search")

	// Basic public search
	search.GET("",
		applyValidation("basic_search"),
		applyRateLimit("search:100/hour"),
		applyCache("1m"),
		searchHandler.GlobalSearch,
	)

	// Public content search
	search.GET("/posts",
		applyValidation("search_posts"),
		applyRateLimit("search:100/hour"),
		applyCache("30s"),
		searchHandler.SearchPublicPosts,
	)

	search.GET("/users",
		applyValidation("search_users"),
		applyRateLimit("search:100/hour"),
		applyCache("1m"),
		searchHandler.SearchPublicUsers,
	)

	search.GET("/hashtags",
		applyValidation("search_hashtags"),
		applyRateLimit("search:100/hour"),
		applyCache("2m"),
		searchHandler.SearchHashtags,
	)

	// Trending content (public)
	search.GET("/trending",
		applyCache("5m"),
		searchHandler.GetTrendingContent,
	)

	search.GET("/trending/hashtags",
		applyCache("10m"),
		searchHandler.GetTrendingHashtags,
	)

	search.GET("/trending/topics",
		applyCache("10m"),
		searchHandler.GetTrendingTopics,
	)

	// Search suggestions (public)
	search.GET("/suggestions",
		applyValidation("search_suggestions"),
		applyCache("5m"),
		searchHandler.GetPublicSearchSuggestions,
	)

	// Location-based search (public)
	search.GET("/locations",
		applyValidation("search_locations"),
		applyRateLimit("search:50/hour"),
		searchHandler.SearchLocations,
	)

	search.GET("/nearby",
		applyValidation("search_nearby"),
		applyRateLimit("search:30/hour"),
		searchHandler.SearchNearbyContent,
	)
}

// SetupSearchRoutes sets up protected search routes (auth required)
func SetupSearchRoutes(api *gin.RouterGroup, searchHandler *handlers.SearchHandler, middlewares *middleware.Middlewares) {
	search := api.Group("/search")

	// =============================================================================
	// GENERAL SEARCH
	// =============================================================================

	// Global search with personalization
	search.GET("",
		applyValidation("global_search"),
		applyRateLimit("search:200/hour"),
		searchHandler.PersonalizedGlobalSearch,
	)

	// Quick search
	search.GET("/quick",
		applyValidation("quick_search"),
		applyRateLimit("search:300/hour"),
		searchHandler.QuickSearch,
	)

	// Advanced search
	search.POST("/advanced",
		applyValidation("advanced_search"),
		applyRateLimit("search:100/hour"),
		searchHandler.AdvancedSearch,
	)

	// Saved searches
	search.GET("/saved",
		searchHandler.GetSavedSearches,
	)

	search.POST("/save",
		applyValidation("save_search"),
		searchHandler.SaveSearch,
	)

	search.DELETE("/saved/:search_id",
		searchHandler.DeleteSavedSearch,
	)

	search.POST("/saved/:search_id/execute",
		searchHandler.ExecuteSavedSearch,
	)

	// Search history
	search.GET("/history",
		searchHandler.GetSearchHistory,
	)

	search.DELETE("/history",
		searchHandler.ClearSearchHistory,
	)

	search.DELETE("/history/:search_id",
		searchHandler.DeleteSearchHistoryItem,
	)

	// =============================================================================
	// CONTENT SEARCH
	// =============================================================================

	posts := search.Group("/posts")
	{
		// Post search
		posts.GET("",
			applyValidation("search_posts"),
			applyRateLimit("search:200/hour"),
			searchHandler.SearchPosts,
		)

		posts.GET("/my",
			applyValidation("search_my_posts"),
			searchHandler.SearchMyPosts,
		)

		posts.GET("/saved",
			applyValidation("search_saved_posts"),
			searchHandler.SearchSavedPosts,
		)

		posts.GET("/liked",
			applyValidation("search_liked_posts"),
			searchHandler.SearchLikedPosts,
		)

		// Advanced post search
		posts.POST("/advanced",
			applyValidation("advanced_post_search"),
			searchHandler.AdvancedPostSearch,
		)

		// Search by content type
		posts.GET("/images",
			applyValidation("search_images"),
			searchHandler.SearchImagePosts,
		)

		posts.GET("/videos",
			applyValidation("search_videos"),
			searchHandler.SearchVideoPosts,
		)

		posts.GET("/links",
			applyValidation("search_links"),
			searchHandler.SearchLinkPosts,
		)

		posts.GET("/polls",
			applyValidation("search_polls"),
			searchHandler.SearchPollPosts,
		)

		// Search by engagement
		posts.GET("/popular",
			applyValidation("search_popular_posts"),
			searchHandler.SearchPopularPosts,
		)

		posts.GET("/recent",
			applyValidation("search_recent_posts"),
			searchHandler.SearchRecentPosts,
		)

		// Search by location
		posts.GET("/nearby",
			applyValidation("search_nearby_posts"),
			searchHandler.SearchNearbyPosts,
		)

		posts.GET("/location/:location_id",
			searchHandler.SearchPostsByLocation,
		)
	}

	// =============================================================================
	// USER SEARCH
	// =============================================================================

	users := search.Group("/users")
	{
		// User search
		users.GET("",
			applyValidation("search_users"),
			applyRateLimit("search:200/hour"),
			searchHandler.SearchUsers,
		)

		users.GET("/verified",
			applyValidation("search_verified_users"),
			searchHandler.SearchVerifiedUsers,
		)

		users.GET("/influencers",
			applyValidation("search_influencers"),
			searchHandler.SearchInfluencers,
		)

		// Advanced user search
		users.POST("/advanced",
			applyValidation("advanced_user_search"),
			searchHandler.AdvancedUserSearch,
		)

		// Search by relationship
		users.GET("/following",
			applyValidation("search_following"),
			searchHandler.SearchFollowing,
		)

		users.GET("/followers",
			applyValidation("search_followers"),
			searchHandler.SearchFollowers,
		)

		users.GET("/mutual",
			applyValidation("search_mutual"),
			searchHandler.SearchMutualConnections,
		)

		// Search by attributes
		users.GET("/by-location",
			applyValidation("search_users_by_location"),
			searchHandler.SearchUsersByLocation,
		)

		users.GET("/by-interests",
			applyValidation("search_users_by_interests"),
			searchHandler.SearchUsersByInterests,
		)

		users.GET("/by-profession",
			applyValidation("search_users_by_profession"),
			searchHandler.SearchUsersByProfession,
		)

		// People discovery
		users.GET("/suggestions",
			searchHandler.GetUserSuggestions,
		)

		users.GET("/nearby",
			applyValidation("search_nearby_users"),
			searchHandler.SearchNearbyUsers,
		)

		users.GET("/online",
			searchHandler.SearchOnlineUsers,
		)
	}

	// =============================================================================
	// HASHTAG AND TOPIC SEARCH
	// =============================================================================

	hashtags := search.Group("/hashtags")
	{
		// Hashtag search
		hashtags.GET("",
			applyValidation("search_hashtags"),
			applyRateLimit("search:200/hour"),
			searchHandler.SearchHashtags,
		)

		hashtags.GET("/trending",
			applyCache("5m"),
			searchHandler.GetTrendingHashtags,
		)

		hashtags.GET("/following",
			searchHandler.GetFollowedHashtags,
		)

		hashtags.GET("/suggested",
			searchHandler.GetSuggestedHashtags,
		)

		// Hashtag details
		hashtags.GET("/:hashtag",
			searchHandler.GetHashtagDetails,
		)

		hashtags.GET("/:hashtag/posts",
			applyValidation("hashtag_posts"),
			searchHandler.GetHashtagPosts,
		)

		hashtags.GET("/:hashtag/users",
			searchHandler.GetHashtagUsers,
		)

		hashtags.GET("/:hashtag/related",
			searchHandler.GetRelatedHashtags,
		)

		// Hashtag actions
		hashtags.POST("/:hashtag/follow",
			applyRateLimit("follow:100/hour"),
			searchHandler.FollowHashtag,
		)

		hashtags.DELETE("/:hashtag/follow",
			searchHandler.UnfollowHashtag,
		)

		hashtags.POST("/:hashtag/mute",
			searchHandler.MuteHashtag,
		)

		hashtags.DELETE("/:hashtag/mute",
			searchHandler.UnmuteHashtag,
		)
	}

	// =============================================================================
	// LOCATION SEARCH
	// =============================================================================

	locations := search.Group("/locations")
	{
		// Location search
		locations.GET("",
			applyValidation("search_locations"),
			applyRateLimit("search:100/hour"),
			searchHandler.SearchLocations,
		)

		locations.GET("/nearby",
			applyValidation("search_nearby_locations"),
			searchHandler.SearchNearbyLocations,
		)

		locations.GET("/popular",
			applyCache("10m"),
			searchHandler.GetPopularLocations,
		)

		locations.GET("/recent",
			searchHandler.GetRecentLocations,
		)

		// Location details
		locations.GET("/:location_id",
			searchHandler.GetLocationDetails,
		)

		locations.GET("/:location_id/posts",
			applyValidation("location_posts"),
			searchHandler.GetLocationPosts,
		)

		locations.GET("/:location_id/users",
			searchHandler.GetLocationUsers,
		)

		// Location actions
		locations.POST("/:location_id/check-in",
			applyValidation("check_in"),
			applyRateLimit("checkin:20/hour"),
			searchHandler.CheckInLocation,
		)

		locations.GET("/check-ins",
			searchHandler.GetMyCheckIns,
		)

		locations.DELETE("/check-ins/:checkin_id",
			searchHandler.DeleteCheckIn,
		)
	}

	// =============================================================================
	// MEDIA SEARCH
	// =============================================================================

	media := search.Group("/media")
	{
		// Media search
		media.GET("/images",
			applyValidation("search_media"),
			searchHandler.SearchImages,
		)

		media.GET("/videos",
			applyValidation("search_media"),
			searchHandler.SearchVideos,
		)

		media.GET("/audio",
			applyValidation("search_media"),
			searchHandler.SearchAudio,
		)

		media.GET("/gifs",
			applyValidation("search_media"),
			searchHandler.SearchGifs,
		)

		// Visual search
		media.POST("/visual-search",
			applyValidation("visual_search"),
			middlewares.FileUpload("image", 10*1024*1024), // 10MB limit
			searchHandler.VisualSearch,
		)

		// Reverse image search
		media.POST("/reverse-image",
			applyValidation("reverse_image_search"),
			middlewares.FileUpload("image", 10*1024*1024),
			searchHandler.ReverseImageSearch,
		)

		// Media by user
		media.GET("/user/:user_id",
			applyValidation("user_media_search"),
			searchHandler.SearchUserMedia,
		)

		media.GET("/my",
			applyValidation("my_media_search"),
			searchHandler.SearchMyMedia,
		)
	}

	// =============================================================================
	// CONVERSATION AND MESSAGE SEARCH
	// =============================================================================

	messages := search.Group("/messages")
	{
		// Message search
		messages.GET("",
			applyValidation("search_messages"),
			applyRateLimit("search:100/hour"),
			searchHandler.SearchMessages,
		)

		messages.GET("/conversations",
			applyValidation("search_conversations"),
			searchHandler.SearchConversations,
		)

		// Message search by type
		messages.GET("/media",
			applyValidation("search_message_media"),
			searchHandler.SearchMessageMedia,
		)

		messages.GET("/files",
			applyValidation("search_message_files"),
			searchHandler.SearchMessageFiles,
		)

		messages.GET("/links",
			applyValidation("search_message_links"),
			searchHandler.SearchMessageLinks,
		)

		// Search within conversation
		messages.GET("/conversation/:conversation_id",
			applyValidation("search_in_conversation"),
			middlewares.ConversationAccess(),
			searchHandler.SearchInConversation,
		)
	}

	// =============================================================================
	// SEARCH ANALYTICS AND INSIGHTS
	// =============================================================================

	analytics := search.Group("/analytics")
	{
		// Search trends
		analytics.GET("/trends",
			searchHandler.GetSearchTrends,
		)

		analytics.GET("/trending-queries",
			applyCache("15m"),
			searchHandler.GetTrendingQueries,
		)

		analytics.GET("/my-trends",
			searchHandler.GetMySearchTrends,
		)

		// Search performance
		analytics.GET("/performance",
			searchHandler.GetSearchPerformance,
		)

		analytics.GET("/popular-content",
			applyCache("10m"),
			searchHandler.GetPopularContent,
		)

		// Search insights
		analytics.GET("/insights",
			searchHandler.GetSearchInsights,
		)

		analytics.GET("/user-behavior",
			middlewares.Admin(),
			searchHandler.GetSearchUserBehavior,
		)
	}

	// =============================================================================
	// SEARCH SETTINGS AND PREFERENCES
	// =============================================================================

	settings := search.Group("/settings")
	{
		// Search preferences
		settings.GET("",
			searchHandler.GetSearchSettings,
		)

		settings.PUT("",
			applyValidation("search_settings"),
			searchHandler.UpdateSearchSettings,
		)

		// Search filters
		settings.GET("/filters",
			searchHandler.GetSearchFilters,
		)

		settings.POST("/filters",
			applyValidation("create_search_filter"),
			searchHandler.CreateSearchFilter,
		)

		settings.PUT("/filters/:filter_id",
			applyValidation("update_search_filter"),
			searchHandler.UpdateSearchFilter,
		)

		settings.DELETE("/filters/:filter_id",
			searchHandler.DeleteSearchFilter,
		)

		// Blocked content
		settings.GET("/blocked",
			searchHandler.GetBlockedSearchContent,
		)

		settings.POST("/block",
			applyValidation("block_search_content"),
			searchHandler.BlockSearchContent,
		)

		settings.DELETE("/block/:item_id",
			searchHandler.UnblockSearchContent,
		)

		// Search privacy
		settings.GET("/privacy",
			searchHandler.GetSearchPrivacySettings,
		)

		settings.PUT("/privacy",
			applyValidation("search_privacy"),
			searchHandler.UpdateSearchPrivacySettings,
		)
	}
}

// Search validation rules that handlers will need:
/*
Required Validation Schemas:

1. basic_search:
   - q: required,string,min:2,max:100
   - type: sometimes,in:all,users,posts,hashtags,locations

2. global_search:
   - q: required,string,min:2,max:100
   - type: sometimes,in:all,users,posts,hashtags,locations,messages
   - page: sometimes,integer,min:1
   - limit: sometimes,integer,min:1,max:50

3. advanced_search:
   - query: required,string,min:2
   - content_type: sometimes,in:text,image,video,audio,link
   - date_from: sometimes,date
   - date_to: sometimes,date
   - location: sometimes,string
   - users: sometimes,array
   - hashtags: sometimes,array
   - min_likes: sometimes,integer,min:0
   - max_likes: sometimes,integer,min:0
   - language: sometimes,string
   - verified_only: sometimes,boolean

4. search_posts:
   - q: required,string,min:2,max:100
   - sort: sometimes,in:relevance,recent,popular,oldest
   - content_type: sometimes,in:text,image,video,audio,poll
   - has_media: sometimes,boolean
   - verified_only: sometimes,boolean

5. search_users:
   - q: required,string,min:2,max:100
   - sort: sometimes,in:relevance,followers,recent,verified
   - verified_only: sometimes,boolean
   - has_profile_image: sometimes,boolean
   - min_followers: sometimes,integer,min:0

6. search_hashtags:
   - q: required,string,min:1,max:50
   - sort: sometimes,in:relevance,popular,recent
   - min_posts: sometimes,integer,min:0

7. save_search:
   - name: required,string,max:100
   - query: required,string
   - filters: sometimes,object
   - alert_enabled: sometimes,boolean

8. search_locations:
   - q: required,string,min:2,max:100
   - lat: sometimes,numeric
   - lng: sometimes,numeric
   - radius: sometimes,integer,min:1,max:100

9. visual_search:
   - image: required,file,image,max_size:10MB
   - search_type: sometimes,in:similar,exact,objects,text

10. search_messages:
    - q: required,string,min:2,max:100
    - conversation_id: sometimes,objectid
    - from_user: sometimes,objectid
    - date_from: sometimes,date
    - date_to: sometimes,date
    - message_type: sometimes,in:text,image,video,audio,file

11. search_settings:
    - safe_search: sometimes,boolean
    - personalized_results: sometimes,boolean
    - location_based: sometimes,boolean
    - save_searches: sometimes,boolean
    - search_suggestions: sometimes,boolean
    - trending_notifications: sometimes,boolean

12. create_search_filter:
    - name: required,string,max:50
    - type: required,in:content,users,hashtags
    - criteria: required,object
    - enabled: sometimes,boolean

13. search_privacy:
    - show_in_search: sometimes,boolean
    - indexable_profile: sometimes,boolean
    - search_history_enabled: sometimes,boolean
    - personalized_ads: sometimes,boolean
*/
