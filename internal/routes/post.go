package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupPublicPostRoutes sets up public post routes (no auth required)
func SetupPublicPostRoutes(api *gin.RouterGroup, postHandler *handlers.PostHandler) {
	posts := api.Group("/posts")

	// Public post discovery
	posts.GET("",
		applyCache("2m"),
		postHandler.GetPublicPosts,
	)

	posts.GET("/trending",
		applyCache("5m"),
		postHandler.GetTrendingPosts,
	)

	posts.GET("/popular",
		applyCache("10m"),
		postHandler.GetPopularPosts,
	)

	posts.GET("/hashtag/:hashtag",
		applyCache("2m"),
		postHandler.GetPostsByHashtag,
	)

	// Individual post access
	posts.GET("/:post_id",
		applyCache("1m"),
		postHandler.GetPost,
	)

	posts.GET("/:post_id/comments",
		applyCache("30s"),
		postHandler.GetPostComments,
	)

	posts.GET("/:post_id/likes",
		postHandler.GetPostLikes,
	)

	posts.GET("/:post_id/shares",
		postHandler.GetPostShares,
	)

	// Post embeds and sharing
	posts.GET("/:post_id/embed",
		applyCache("1h"),
		postHandler.GetPostEmbed,
	)

	posts.GET("/:post_id/share-preview",
		applyCache("30m"),
		postHandler.GetSharePreview,
	)
}

// SetupPostRoutes sets up protected post routes (auth required)
func SetupPostRoutes(api *gin.RouterGroup, postHandler *handlers.PostHandler, middlewares *middleware.Middlewares) {
	posts := api.Group("/posts")

	// Post creation and management
	posts.POST("",
		applyValidation("create_post"),
		applyRateLimit("post:10/hour"),
		middlewares.FileUpload("media", 50*1024*1024), // 50MB limit
		postHandler.CreatePost,
	)

	posts.PUT("/:post_id",
		applyValidation("update_post"),
		middlewares.PostOwnership(),
		postHandler.UpdatePost,
	)

	posts.DELETE("/:post_id",
		middlewares.PostOwnership(),
		postHandler.DeletePost,
	)

	posts.POST("/:post_id/restore",
		middlewares.PostOwnership(),
		postHandler.RestorePost,
	)

	// Post interactions
	posts.POST("/:post_id/like",
		applyRateLimit("interaction:60/min"),
		postHandler.LikePost,
	)

	posts.DELETE("/:post_id/like",
		postHandler.UnlikePost,
	)

	posts.POST("/:post_id/share",
		applyValidation("share_post"),
		applyRateLimit("share:20/hour"),
		postHandler.SharePost,
	)

	posts.DELETE("/:post_id/share",
		postHandler.UnsharePost,
	)

	posts.POST("/:post_id/bookmark",
		postHandler.BookmarkPost,
	)

	posts.DELETE("/:post_id/bookmark",
		postHandler.UnbookmarkPost,
	)

	posts.POST("/:post_id/report",
		applyValidation("report_post"),
		applyRateLimit("report:5/min"),
		postHandler.ReportPost,
	)

	posts.POST("/:post_id/hide",
		postHandler.HidePost,
	)

	posts.DELETE("/:post_id/hide",
		postHandler.UnhidePost,
	)

	// Post comments
	posts.POST("/:post_id/comments",
		applyValidation("create_comment"),
		applyRateLimit("comment:30/hour"),
		postHandler.CreateComment,
	)

	posts.GET("/:post_id/comments",
		postHandler.GetPostCommentsAuth,
	)

	posts.GET("/:post_id/comments/:comment_id",
		postHandler.GetComment,
	)

	posts.PUT("/:post_id/comments/:comment_id",
		applyValidation("update_comment"),
		middlewares.CommentOwnership(),
		postHandler.UpdateComment,
	)

	posts.DELETE("/:post_id/comments/:comment_id",
		middlewares.CommentOwnership(),
		postHandler.DeleteComment,
	)

	// Comment interactions
	posts.POST("/:post_id/comments/:comment_id/like",
		applyRateLimit("interaction:60/min"),
		postHandler.LikeComment,
	)

	posts.DELETE("/:post_id/comments/:comment_id/like",
		postHandler.UnlikeComment,
	)

	posts.POST("/:post_id/comments/:comment_id/reply",
		applyValidation("create_comment"),
		applyRateLimit("comment:30/hour"),
		postHandler.ReplyToComment,
	)

	posts.POST("/:post_id/comments/:comment_id/report",
		applyValidation("report_comment"),
		applyRateLimit("report:5/min"),
		postHandler.ReportComment,
	)

	// Post scheduling
	posts.POST("/schedule",
		applyValidation("schedule_post"),
		postHandler.SchedulePost,
	)

	posts.GET("/scheduled",
		postHandler.GetScheduledPosts,
	)

	posts.PUT("/scheduled/:post_id",
		applyValidation("update_scheduled_post"),
		middlewares.PostOwnership(),
		postHandler.UpdateScheduledPost,
	)

	posts.DELETE("/scheduled/:post_id",
		middlewares.PostOwnership(),
		postHandler.CancelScheduledPost,
	)

	// Post drafts
	posts.POST("/drafts",
		applyValidation("create_draft"),
		postHandler.CreateDraft,
	)

	posts.GET("/drafts",
		postHandler.GetDrafts,
	)

	posts.PUT("/drafts/:post_id",
		applyValidation("update_draft"),
		middlewares.PostOwnership(),
		postHandler.UpdateDraft,
	)

	posts.DELETE("/drafts/:post_id",
		middlewares.PostOwnership(),
		postHandler.DeleteDraft,
	)

	posts.POST("/drafts/:post_id/publish",
		middlewares.PostOwnership(),
		postHandler.PublishDraft,
	)

	// Post analytics
	posts.GET("/:post_id/analytics",
		middlewares.PostOwnership(),
		postHandler.GetPostAnalytics,
	)

	posts.GET("/:post_id/insights",
		middlewares.PostOwnership(),
		postHandler.GetPostInsights,
	)

	posts.GET("/:post_id/reach",
		middlewares.PostOwnership(),
		postHandler.GetPostReach,
	)

	posts.GET("/:post_id/engagement",
		middlewares.PostOwnership(),
		postHandler.GetPostEngagement,
	)

	// Post threads
	posts.POST("/:post_id/thread",
		applyValidation("create_thread_post"),
		applyRateLimit("post:10/hour"),
		postHandler.AddToThread,
	)

	posts.GET("/:post_id/thread",
		postHandler.GetThread,
	)

	posts.DELETE("/:post_id/thread",
		middlewares.PostOwnership(),
		postHandler.RemoveFromThread,
	)

	// Post collections
	posts.POST("/collections",
		applyValidation("create_collection"),
		postHandler.CreateCollection,
	)

	posts.GET("/collections",
		postHandler.GetCollections,
	)

	posts.PUT("/collections/:collection_id",
		applyValidation("update_collection"),
		postHandler.UpdateCollection,
	)

	posts.DELETE("/collections/:collection_id",
		postHandler.DeleteCollection,
	)

	posts.POST("/collections/:collection_id/posts/:post_id",
		postHandler.AddPostToCollection,
	)

	posts.DELETE("/collections/:collection_id/posts/:post_id",
		postHandler.RemovePostFromCollection,
	)

	// Post mentions and tags
	posts.GET("/:post_id/mentions",
		postHandler.GetPostMentions,
	)

	posts.POST("/:post_id/tag-users",
		applyValidation("tag_users"),
		postHandler.TagUsers,
	)

	posts.DELETE("/:post_id/tag-users",
		postHandler.RemoveUserTags,
	)

	// Post versions and history
	posts.GET("/:post_id/history",
		middlewares.PostOwnership(),
		postHandler.GetPostHistory,
	)

	posts.GET("/:post_id/versions",
		middlewares.PostOwnership(),
		postHandler.GetPostVersions,
	)

	posts.POST("/:post_id/revert/:version_id",
		middlewares.PostOwnership(),
		postHandler.RevertToVersion,
	)

	// Feed endpoints
	posts.GET("/feed",
		postHandler.GetPersonalizedFeed,
	)

	posts.GET("/feed/following",
		postHandler.GetFollowingFeed,
	)

	posts.GET("/feed/explore",
		postHandler.GetExploreFeed,
	)

	posts.GET("/feed/nearby",
		postHandler.GetNearbyFeed,
	)

	posts.POST("/feed/refresh",
		postHandler.RefreshFeed,
	)

	// Post search and discovery
	posts.GET("/search",
		applyRateLimit("search:50/min"),
		postHandler.SearchPosts,
	)

	posts.GET("/suggestions",
		postHandler.GetPostSuggestions,
	)

	posts.GET("/related/:post_id",
		postHandler.GetRelatedPosts,
	)

	// Trending and topics
	posts.GET("/topics",
		applyCache("5m"),
		postHandler.GetTrendingTopics,
	)

	posts.GET("/topics/:topic",
		postHandler.GetPostsByTopic,
	)

	posts.POST("/topics/:topic/follow",
		postHandler.FollowTopic,
	)

	posts.DELETE("/topics/:topic/follow",
		postHandler.UnfollowTopic,
	)

	// Content moderation
	posts.POST("/:post_id/moderate",
		applyValidation("moderate_post"),
		middlewares.Moderator(),
		postHandler.ModeratePost,
	)

	posts.GET("/flagged",
		middlewares.Moderator(),
		postHandler.GetFlaggedPosts,
	)

	posts.POST("/:post_id/approve",
		middlewares.Moderator(),
		postHandler.ApprovePost,
	)

	posts.POST("/:post_id/reject",
		middlewares.Moderator(),
		postHandler.RejectPost,
	)

	// Post polls
	posts.POST("/:post_id/poll/vote",
		applyValidation("vote_poll"),
		postHandler.VoteOnPoll,
	)

	posts.GET("/:post_id/poll/results",
		postHandler.GetPollResults,
	)

	posts.POST("/:post_id/poll/close",
		middlewares.PostOwnership(),
		postHandler.ClosePoll,
	)
}

// Post validation rules that handlers will need:
/*
Required Validation Schemas:

1. create_post:
   - content: required,string,max:500
   - content_type: sometimes,in:text,image,video,audio,poll
   - media_files: sometimes,array,max:10
   - privacy: sometimes,in:public,followers,mentioned,private
   - allow_comments: sometimes,boolean
   - allow_reactions: sometimes,boolean
   - allow_shares: sometimes,boolean
   - location: sometimes,object
   - hashtags: sometimes,array,max:30
   - mentions: sometimes,array,max:50
   - content_warning: sometimes,string,max:100
   - sensitive_content: sometimes,boolean
   - scheduled_at: sometimes,datetime,after:now

2. update_post:
   - content: sometimes,string,max:500
   - privacy: sometimes,in:public,followers,mentioned,private
   - allow_comments: sometimes,boolean
   - allow_reactions: sometimes,boolean
   - allow_shares: sometimes,boolean
   - content_warning: sometimes,string,max:100
   - sensitive_content: sometimes,boolean

3. share_post:
   - content: sometimes,string,max:280
   - privacy: sometimes,in:public,followers,private
   - add_comment: sometimes,boolean

4. report_post:
   - reason: required,in:spam,harassment,violence,hate_speech,nudity,false_info,copyright
   - description: sometimes,string,max:500
   - evidence: sometimes,array

5. create_comment:
   - content: required,string,max:500
   - parent_id: sometimes,objectid
   - mentions: sometimes,array,max:10
   - media_files: sometimes,array,max:3

6. update_comment:
   - content: required,string,max:500

7. report_comment:
   - reason: required,in:spam,harassment,hate_speech,inappropriate
   - description: sometimes,string,max:500

8. schedule_post:
   - content: required,string,max:500
   - scheduled_at: required,datetime,after:now
   - timezone: sometimes,string
   - recurring: sometimes,boolean
   - recurring_pattern: sometimes,in:daily,weekly,monthly

9. create_draft:
   - content: sometimes,string,max:500
   - title: sometimes,string,max:100
   - auto_save: sometimes,boolean

10. create_thread_post:
    - content: required,string,max:500
    - position: sometimes,integer,min:1

11. create_collection:
    - name: required,string,max:100
    - description: sometimes,string,max:500
    - is_public: sometimes,boolean
    - cover_image: sometimes,string

12. tag_users:
    - users: required,array,max:20
    - users.*.user_id: required,objectid
    - users.*.x: required,numeric,between:0,100
    - users.*.y: required,numeric,between:0,100

13. vote_poll:
    - option_id: required,objectid
    - option_text: sometimes,string

14. moderate_post:
    - action: required,in:approve,reject,flag,hide,remove
    - reason: sometimes,string,max:500
    - notify_user: sometimes,boolean
*/
