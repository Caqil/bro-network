package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Post represents a post in the social network
type Post struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	AuthorID         primitive.ObjectID   `bson:"author_id" json:"author_id"`
	Author           *User                `bson:"author,omitempty" json:"author,omitempty"`
	Content          string               `bson:"content" json:"content" binding:"required,max=500"`
	ContentType      PostContentType      `bson:"content_type" json:"content_type"`
	MediaFiles       []MediaFile          `bson:"media_files" json:"media_files"`
	Mentions         []primitive.ObjectID `bson:"mentions" json:"mentions"`
	Hashtags         []string             `bson:"hashtags" json:"hashtags"`
	Links            []Link               `bson:"links" json:"links"`
	ParentID         *primitive.ObjectID  `bson:"parent_id,omitempty" json:"parent_id,omitempty"` // For replies
	QuotedPostID     *primitive.ObjectID  `bson:"quoted_post_id,omitempty" json:"quoted_post_id,omitempty"`
	QuotedPost       *Post                `bson:"quoted_post,omitempty" json:"quoted_post,omitempty"`
	ThreadID         *primitive.ObjectID  `bson:"thread_id,omitempty" json:"thread_id,omitempty"`
	Privacy          PostPrivacy          `bson:"privacy" json:"privacy"`
	Status           PostStatus           `bson:"status" json:"status"`
	Stats            PostStats            `bson:"stats" json:"stats"`
	IsEdited         bool                 `bson:"is_edited" json:"is_edited"`
	IsPinned         bool                 `bson:"is_pinned" json:"is_pinned"`
	IsSponsored      bool                 `bson:"is_sponsored" json:"is_sponsored"`
	AllowComments    bool                 `bson:"allow_comments" json:"allow_comments"`
	AllowReactions   bool                 `bson:"allow_reactions" json:"allow_reactions"`
	AllowShares      bool                 `bson:"allow_shares" json:"allow_shares"`
	ContentWarning   string               `bson:"content_warning" json:"content_warning"`
	SensitiveContent bool                 `bson:"sensitive_content" json:"sensitive_content"`
	Location         *Location            `bson:"location,omitempty" json:"location,omitempty"`
	ScheduledAt      *time.Time           `bson:"scheduled_at,omitempty" json:"scheduled_at,omitempty"`
	PublishedAt      *time.Time           `bson:"published_at,omitempty" json:"published_at,omitempty"`
	EditedAt         *time.Time           `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	CreatedAt        time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time            `bson:"updated_at" json:"updated_at"`
	DeletedAt        *time.Time           `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// PostContentType represents the type of post content
type PostContentType string

const (
	ContentTypeText  PostContentType = "text"
	ContentTypeImage PostContentType = "image"
	ContentTypeVideo PostContentType = "video"
	ContentTypeAudio PostContentType = "audio"
	ContentTypePoll  PostContentType = "poll"
	ContentTypeEvent PostContentType = "event"
	ContentTypeLink  PostContentType = "link"
)

// PostPrivacy represents post privacy settings
type PostPrivacy string

const (
	PrivacyPublic    PostPrivacy = "public"
	PrivacyFollowers PostPrivacy = "followers"
	PrivacyMentioned PostPrivacy = "mentioned"
	PrivacyPrivate   PostPrivacy = "private"
)

// PostStatus represents post status
type PostStatus string

const (
	StatusDraft     PostStatus = "draft"
	StatusPublished PostStatus = "published"
	StatusScheduled PostStatus = "scheduled"
	StatusArchived  PostStatus = "archived"
	StatusDeleted   PostStatus = "deleted"
	StatusReported  PostStatus = "reported"
	StatusHidden    PostStatus = "hidden"
)

// PostStats represents post statistics
type PostStats struct {
	ViewsCount     int64   `bson:"views_count" json:"views_count"`
	LikesCount     int64   `bson:"likes_count" json:"likes_count"`
	CommentsCount  int64   `bson:"comments_count" json:"comments_count"`
	SharesCount    int64   `bson:"shares_count" json:"shares_count"`
	RepostsCount   int64   `bson:"reposts_count" json:"reposts_count"`
	QuotesCount    int64   `bson:"quotes_count" json:"quotes_count"`
	BookmarksCount int64   `bson:"bookmarks_count" json:"bookmarks_count"`
	ReportsCount   int64   `bson:"reports_count" json:"reports_count"`
	EngagementRate float64 `bson:"engagement_rate" json:"engagement_rate"`
}

// MediaFile represents media files in posts
type MediaFile struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Type         MediaType          `bson:"type" json:"type"`
	URL          string             `bson:"url" json:"url"`
	ThumbnailURL string             `bson:"thumbnail_url" json:"thumbnail_url"`
	FileName     string             `bson:"file_name" json:"file_name"`
	FileSize     int64              `bson:"file_size" json:"file_size"`
	MimeType     string             `bson:"mime_type" json:"mime_type"`
	Width        int                `bson:"width" json:"width"`
	Height       int                `bson:"height" json:"height"`
	Duration     int                `bson:"duration" json:"duration"` // For video/audio in seconds
	AltText      string             `bson:"alt_text" json:"alt_text"`
	UploadedAt   time.Time          `bson:"uploaded_at" json:"uploaded_at"`
}

// MediaType represents media file types
type MediaType string

const (
	MediaTypeImage MediaType = "image"
	MediaTypeVideo MediaType = "video"
	MediaTypeAudio MediaType = "audio"
	MediaTypeGIF   MediaType = "gif"
)

// Link represents links in posts
type Link struct {
	URL         string `bson:"url" json:"url"`
	Title       string `bson:"title" json:"title"`
	Description string `bson:"description" json:"description"`
	Image       string `bson:"image" json:"image"`
	Domain      string `bson:"domain" json:"domain"`
}

// Location represents geographical location
type Location struct {
	Name      string  `bson:"name" json:"name"`
	Address   string  `bson:"address" json:"address"`
	City      string  `bson:"city" json:"city"`
	Country   string  `bson:"country" json:"country"`
	Latitude  float64 `bson:"latitude" json:"latitude"`
	Longitude float64 `bson:"longitude" json:"longitude"`
}

// PostCreateRequest represents post creation request
type PostCreateRequest struct {
	Content          string               `json:"content" binding:"required,max=500"`
	ContentType      PostContentType      `json:"content_type"`
	MediaFiles       []MediaFile          `json:"media_files"`
	Mentions         []primitive.ObjectID `json:"mentions"`
	Hashtags         []string             `json:"hashtags"`
	ParentID         *primitive.ObjectID  `json:"parent_id,omitempty"`
	QuotedPostID     *primitive.ObjectID  `json:"quoted_post_id,omitempty"`
	Privacy          PostPrivacy          `json:"privacy"`
	AllowComments    bool                 `json:"allow_comments"`
	AllowReactions   bool                 `json:"allow_reactions"`
	AllowShares      bool                 `json:"allow_shares"`
	ContentWarning   string               `json:"content_warning"`
	SensitiveContent bool                 `json:"sensitive_content"`
	Location         *Location            `json:"location,omitempty"`
	ScheduledAt      *time.Time           `json:"scheduled_at,omitempty"`
}

// PostUpdateRequest represents post update request
type PostUpdateRequest struct {
	Content          string               `json:"content" binding:"max=500"`
	MediaFiles       []MediaFile          `json:"media_files"`
	Mentions         []primitive.ObjectID `json:"mentions"`
	Hashtags         []string             `json:"hashtags"`
	Privacy          PostPrivacy          `json:"privacy"`
	AllowComments    *bool                `json:"allow_comments"`
	AllowReactions   *bool                `json:"allow_reactions"`
	AllowShares      *bool                `json:"allow_shares"`
	ContentWarning   string               `json:"content_warning"`
	SensitiveContent *bool                `json:"sensitive_content"`
	Location         *Location            `json:"location,omitempty"`
}

// PostResponse represents post response with user interactions
type PostResponse struct {
	*Post
	IsLiked      bool `json:"is_liked"`
	IsBookmarked bool `json:"is_bookmarked"`
	IsReported   bool `json:"is_reported"`
	IsFollowing  bool `json:"is_following"`
	CanEdit      bool `json:"can_edit"`
	CanDelete    bool `json:"can_delete"`
	CanReport    bool `json:"can_report"`
}

// PostListResponse represents post list response
type PostListResponse struct {
	Posts      []PostResponse `json:"posts"`
	TotalCount int64          `json:"total_count"`
	Page       int            `json:"page"`
	Limit      int            `json:"limit"`
	HasMore    bool           `json:"has_more"`
}

// PostFeedFilter represents post feed filter options
type PostFeedFilter struct {
	UserID      *primitive.ObjectID `json:"user_id,omitempty"`
	ContentType *PostContentType    `json:"content_type,omitempty"`
	Privacy     *PostPrivacy        `json:"privacy,omitempty"`
	Status      *PostStatus         `json:"status,omitempty"`
	HasMedia    *bool               `json:"has_media,omitempty"`
	StartDate   *time.Time          `json:"start_date,omitempty"`
	EndDate     *time.Time          `json:"end_date,omitempty"`
	Hashtags    []string            `json:"hashtags,omitempty"`
	Following   bool                `json:"following"`
	Trending    bool                `json:"trending"`
	Page        int                 `json:"page"`
	Limit       int                 `json:"limit"`
	SortBy      string              `json:"sort_by"`    // created_at, likes_count, comments_count, etc.
	SortOrder   string              `json:"sort_order"` // asc, desc
}

// PostThread represents a thread of posts
type PostThread struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Posts     []Post             `bson:"posts" json:"posts"`
	AuthorID  primitive.ObjectID `bson:"author_id" json:"author_id"`
	Stats     PostStats          `bson:"stats" json:"stats"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}
