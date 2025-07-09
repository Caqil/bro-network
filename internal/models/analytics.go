package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Analytics represents analytics data for various entities
type Analytics struct {
	ID         primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	EntityID   primitive.ObjectID     `bson:"entity_id" json:"entity_id"`
	EntityType AnalyticsEntity        `bson:"entity_type" json:"entity_type"`
	EventType  AnalyticsEvent         `bson:"event_type" json:"event_type"`
	UserID     *primitive.ObjectID    `bson:"user_id,omitempty" json:"user_id,omitempty"`
	SessionID  string                 `bson:"session_id" json:"session_id"`
	Metadata   AnalyticsMetadata      `bson:"metadata" json:"metadata"`
	Value      float64                `bson:"value" json:"value"`
	Properties map[string]interface{} `bson:"properties" json:"properties"`
	Timestamp  time.Time              `bson:"timestamp" json:"timestamp"`
	Date       string                 `bson:"date" json:"date"` // YYYY-MM-DD for aggregation
	Hour       int                    `bson:"hour" json:"hour"` // 0-23 for hourly stats
	CreatedAt  time.Time              `bson:"created_at" json:"created_at"`
}

// AnalyticsEntity represents what entity the analytics is for
type AnalyticsEntity string

const (
	AnalyticsEntityUser         AnalyticsEntity = "user"
	AnalyticsEntityPost         AnalyticsEntity = "post"
	AnalyticsEntityComment      AnalyticsEntity = "comment"
	AnalyticsEntityMessage      AnalyticsEntity = "message"
	AnalyticsEntityConversation AnalyticsEntity = "conversation"
	AnalyticsEntityPlatform     AnalyticsEntity = "platform"
	AnalyticsEntityApp          AnalyticsEntity = "app"
)

// AnalyticsEvent represents the type of event being tracked
type AnalyticsEvent string

const (
	// User events
	EventUserRegistration  AnalyticsEvent = "user_registration"
	EventUserLogin         AnalyticsEvent = "user_login"
	EventUserLogout        AnalyticsEvent = "user_logout"
	EventUserProfileView   AnalyticsEvent = "user_profile_view"
	EventUserProfileUpdate AnalyticsEvent = "user_profile_update"
	EventUserFollow        AnalyticsEvent = "user_follow"
	EventUserUnfollow      AnalyticsEvent = "user_unfollow"
	EventUserBlock         AnalyticsEvent = "user_block"
	EventUserReport        AnalyticsEvent = "user_report"

	// Post events
	EventPostCreate   AnalyticsEvent = "post_create"
	EventPostView     AnalyticsEvent = "post_view"
	EventPostLike     AnalyticsEvent = "post_like"
	EventPostUnlike   AnalyticsEvent = "post_unlike"
	EventPostComment  AnalyticsEvent = "post_comment"
	EventPostShare    AnalyticsEvent = "post_share"
	EventPostBookmark AnalyticsEvent = "post_bookmark"
	EventPostReport   AnalyticsEvent = "post_report"
	EventPostDelete   AnalyticsEvent = "post_delete"

	// Comment events
	EventCommentCreate AnalyticsEvent = "comment_create"
	EventCommentLike   AnalyticsEvent = "comment_like"
	EventCommentReply  AnalyticsEvent = "comment_reply"
	EventCommentReport AnalyticsEvent = "comment_report"
	EventCommentDelete AnalyticsEvent = "comment_delete"

	// Message events
	EventMessageSend        AnalyticsEvent = "message_send"
	EventMessageRead        AnalyticsEvent = "message_read"
	EventMessageDelete      AnalyticsEvent = "message_delete"
	EventConversationCreate AnalyticsEvent = "conversation_create"

	// Search events
	EventSearch      AnalyticsEvent = "search"
	EventSearchClick AnalyticsEvent = "search_click"

	// App events
	EventAppOpen      AnalyticsEvent = "app_open"
	EventAppClose     AnalyticsEvent = "app_close"
	EventPageView     AnalyticsEvent = "page_view"
	EventFeatureUsage AnalyticsEvent = "feature_usage"
	EventError        AnalyticsEvent = "error"
	EventCrash        AnalyticsEvent = "crash"

	// Engagement events
	EventSessionStart AnalyticsEvent = "session_start"
	EventSessionEnd   AnalyticsEvent = "session_end"
	EventTimeSpent    AnalyticsEvent = "time_spent"
	EventScrollDepth  AnalyticsEvent = "scroll_depth"

	// Business events
	EventConversion   AnalyticsEvent = "conversion"
	EventSubscription AnalyticsEvent = "subscription"
	EventPurchase     AnalyticsEvent = "purchase"
	EventAdClick      AnalyticsEvent = "ad_click"
	EventAdView       AnalyticsEvent = "ad_view"
)

// AnalyticsMetadata represents metadata for analytics events
type AnalyticsMetadata struct {
	IPAddress   string                 `bson:"ip_address" json:"ip_address"`
	UserAgent   string                 `bson:"user_agent" json:"user_agent"`
	Platform    string                 `bson:"platform" json:"platform"`       // web, ios, android
	DeviceType  string                 `bson:"device_type" json:"device_type"` // mobile, tablet, desktop
	Browser     string                 `bson:"browser" json:"browser"`
	OS          string                 `bson:"os" json:"os"`
	Country     string                 `bson:"country" json:"country"`
	City        string                 `bson:"city" json:"city"`
	Timezone    string                 `bson:"timezone" json:"timezone"`
	Language    string                 `bson:"language" json:"language"`
	Referrer    string                 `bson:"referrer" json:"referrer"`
	UTMSource   string                 `bson:"utm_source" json:"utm_source"`
	UTMMedium   string                 `bson:"utm_medium" json:"utm_medium"`
	UTMCampaign string                 `bson:"utm_campaign" json:"utm_campaign"`
	Extra       map[string]interface{} `bson:"extra" json:"extra"`
}

// UserAnalytics represents aggregated user analytics
type UserAnalytics struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID          primitive.ObjectID `bson:"user_id" json:"user_id"`
	Date            string             `bson:"date" json:"date"` // YYYY-MM-DD
	PostsCreated    int64              `bson:"posts_created" json:"posts_created"`
	PostsViewed     int64              `bson:"posts_viewed" json:"posts_viewed"`
	PostsLiked      int64              `bson:"posts_liked" json:"posts_liked"`
	CommentsCreated int64              `bson:"comments_created" json:"comments_created"`
	MessagesSeent   int64              `bson:"messages_sent" json:"messages_sent"`
	ProfileViews    int64              `bson:"profile_views" json:"profile_views"`
	FollowersGained int64              `bson:"followers_gained" json:"followers_gained"`
	FollowersLost   int64              `bson:"followers_lost" json:"followers_lost"`
	SessionCount    int64              `bson:"session_count" json:"session_count"`
	TotalTimeSpent  int64              `bson:"total_time_spent" json:"total_time_spent"` // in seconds
	PageViews       int64              `bson:"page_views" json:"page_views"`
	SearchCount     int64              `bson:"search_count" json:"search_count"`
	EngagementScore float64            `bson:"engagement_score" json:"engagement_score"`
	CreatedAt       time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time          `bson:"updated_at" json:"updated_at"`
}

// PostAnalytics represents aggregated post analytics
type PostAnalytics struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	PostID             primitive.ObjectID `bson:"post_id" json:"post_id"`
	Date               string             `bson:"date" json:"date"` // YYYY-MM-DD
	Views              int64              `bson:"views" json:"views"`
	UniqueViews        int64              `bson:"unique_views" json:"unique_views"`
	Likes              int64              `bson:"likes" json:"likes"`
	Comments           int64              `bson:"comments" json:"comments"`
	Shares             int64              `bson:"shares" json:"shares"`
	Bookmarks          int64              `bson:"bookmarks" json:"bookmarks"`
	Reports            int64              `bson:"reports" json:"reports"`
	ClickThroughRate   float64            `bson:"click_through_rate" json:"click_through_rate"`
	EngagementRate     float64            `bson:"engagement_rate" json:"engagement_rate"`
	ReachRate          float64            `bson:"reach_rate" json:"reach_rate"`
	ImpressionShare    float64            `bson:"impression_share" json:"impression_share"`
	ViewerDemographics map[string]int64   `bson:"viewer_demographics" json:"viewer_demographics"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
}

// PlatformAnalytics represents overall platform analytics
type PlatformAnalytics struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Date               string             `bson:"date" json:"date"` // YYYY-MM-DD
	ActiveUsers        int64              `bson:"active_users" json:"active_users"`
	NewUsers           int64              `bson:"new_users" json:"new_users"`
	TotalUsers         int64              `bson:"total_users" json:"total_users"`
	PostsCreated       int64              `bson:"posts_created" json:"posts_created"`
	CommentsCreated    int64              `bson:"comments_created" json:"comments_created"`
	MessagesSeent      int64              `bson:"messages_sent" json:"messages_sent"`
	TotalSessions      int64              `bson:"total_sessions" json:"total_sessions"`
	AvgSessionDuration float64            `bson:"avg_session_duration" json:"avg_session_duration"`
	PageViews          int64              `bson:"page_views" json:"page_views"`
	BounceRate         float64            `bson:"bounce_rate" json:"bounce_rate"`
	RetentionRates     map[string]float64 `bson:"retention_rates" json:"retention_rates"` // day1, day7, day30
	TopCountries       map[string]int64   `bson:"top_countries" json:"top_countries"`
	TopPlatforms       map[string]int64   `bson:"top_platforms" json:"top_platforms"`
	TopFeatures        map[string]int64   `bson:"top_features" json:"top_features"`
	RevenueMetrics     RevenueMetrics     `bson:"revenue_metrics" json:"revenue_metrics"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
}

// RevenueMetrics represents revenue-related analytics
type RevenueMetrics struct {
	TotalRevenue        float64 `bson:"total_revenue" json:"total_revenue"`
	SubscriptionRevenue float64 `bson:"subscription_revenue" json:"subscription_revenue"`
	AdRevenue           float64 `bson:"ad_revenue" json:"ad_revenue"`
	ARPU                float64 `bson:"arpu" json:"arpu"` // Average Revenue Per User
	LTV                 float64 `bson:"ltv" json:"ltv"`   // Customer Lifetime Value
	ChurnRate           float64 `bson:"churn_rate" json:"churn_rate"`
	ConversionRate      float64 `bson:"conversion_rate" json:"conversion_rate"`
}

// AnalyticsCreateRequest represents analytics event creation request
type AnalyticsCreateRequest struct {
	EntityID   primitive.ObjectID     `json:"entity_id" binding:"required"`
	EntityType AnalyticsEntity        `json:"entity_type" binding:"required"`
	EventType  AnalyticsEvent         `json:"event_type" binding:"required"`
	UserID     *primitive.ObjectID    `json:"user_id,omitempty"`
	SessionID  string                 `json:"session_id"`
	Value      float64                `json:"value"`
	Properties map[string]interface{} `json:"properties"`
	Metadata   AnalyticsMetadata      `json:"metadata"`
}

// AnalyticsFilter represents analytics filter options
type AnalyticsFilter struct {
	EntityID    *primitive.ObjectID `json:"entity_id,omitempty"`
	EntityType  *AnalyticsEntity    `json:"entity_type,omitempty"`
	EventType   *AnalyticsEvent     `json:"event_type,omitempty"`
	UserID      *primitive.ObjectID `json:"user_id,omitempty"`
	StartDate   *time.Time          `json:"start_date,omitempty"`
	EndDate     *time.Time          `json:"end_date,omitempty"`
	Country     string              `json:"country,omitempty"`
	Platform    string              `json:"platform,omitempty"`
	DeviceType  string              `json:"device_type,omitempty"`
	Granularity string              `json:"granularity"` // hour, day, week, month
	GroupBy     []string            `json:"group_by"`    // fields to group by
	Page        int                 `json:"page"`
	Limit       int                 `json:"limit"`
}

// AnalyticsResponse represents analytics query response
type AnalyticsResponse struct {
	Data       []AnalyticsDataPoint `json:"data"`
	TotalCount int64                `json:"total_count"`
	Summary    AnalyticsSummary     `json:"summary"`
	Period     AnalyticsPeriod      `json:"period"`
	Metadata   ResponseMetadata     `json:"metadata"`
}

// AnalyticsDataPoint represents a single analytics data point
type AnalyticsDataPoint struct {
	Date       string                 `json:"date"`
	Hour       *int                   `json:"hour,omitempty"`
	Value      float64                `json:"value"`
	Count      int64                  `json:"count"`
	Properties map[string]interface{} `json:"properties"`
	Breakdown  map[string]float64     `json:"breakdown,omitempty"`
}

// AnalyticsSummary represents summary statistics
type AnalyticsSummary struct {
	Total      float64 `json:"total"`
	Average    float64 `json:"average"`
	Maximum    float64 `json:"maximum"`
	Minimum    float64 `json:"minimum"`
	Growth     float64 `json:"growth"`      // percentage change
	GrowthRate float64 `json:"growth_rate"` // daily/weekly/monthly growth rate
	Trend      string  `json:"trend"`       // up, down, stable
}

// AnalyticsPeriod represents the time period for analytics
type AnalyticsPeriod struct {
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	Granularity string    `json:"granularity"`
	TotalDays   int       `json:"total_days"`
}

// ResponseMetadata represents metadata about the analytics response
type ResponseMetadata struct {
	QueryTime     time.Duration `json:"query_time"`
	CacheHit      bool          `json:"cache_hit"`
	DataSources   []string      `json:"data_sources"`
	LastUpdated   time.Time     `json:"last_updated"`
	EstimatedCost float64       `json:"estimated_cost"`
}

// DashboardMetrics represents key dashboard metrics
type DashboardMetrics struct {
	UserMetrics        UserMetrics        `json:"user_metrics"`
	ContentMetrics     ContentMetrics     `json:"content_metrics"`
	EngagementMetrics  EngagementMetrics  `json:"engagement_metrics"`
	PerformanceMetrics PerformanceMetrics `json:"performance_metrics"`
	LastUpdated        time.Time          `json:"last_updated"`
}

// UserMetrics represents user-related metrics
type UserMetrics struct {
	TotalUsers  int64   `json:"total_users"`
	ActiveUsers int64   `json:"active_users"`
	NewUsers    int64   `json:"new_users"`
	ReturnUsers int64   `json:"return_users"`
	ChurnRate   float64 `json:"churn_rate"`
	GrowthRate  float64 `json:"growth_rate"`
}

// ContentMetrics represents content-related metrics
type ContentMetrics struct {
	TotalPosts    int64   `json:"total_posts"`
	PostsToday    int64   `json:"posts_today"`
	TotalComments int64   `json:"total_comments"`
	CommentsToday int64   `json:"comments_today"`
	TotalMessages int64   `json:"total_messages"`
	MessagesToday int64   `json:"messages_today"`
	ContentGrowth float64 `json:"content_growth"`
}

// EngagementMetrics represents engagement-related metrics
type EngagementMetrics struct {
	TotalLikes          int64   `json:"total_likes"`
	TotalShares         int64   `json:"total_shares"`
	TotalViews          int64   `json:"total_views"`
	EngagementRate      float64 `json:"engagement_rate"`
	AvgSessionTime      float64 `json:"avg_session_time"`
	PageViewsPerSession float64 `json:"page_views_per_session"`
}

// PerformanceMetrics represents performance-related metrics
type PerformanceMetrics struct {
	AvgResponseTime float64 `json:"avg_response_time"`
	ErrorRate       float64 `json:"error_rate"`
	Uptime          float64 `json:"uptime"`
	ThroughputRPS   float64 `json:"throughput_rps"`
	CacheHitRate    float64 `json:"cache_hit_rate"`
}
