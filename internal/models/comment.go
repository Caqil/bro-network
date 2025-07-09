package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Comment represents a comment on a post
type Comment struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	PostID           primitive.ObjectID   `bson:"post_id" json:"post_id"`
	AuthorID         primitive.ObjectID   `bson:"author_id" json:"author_id"`
	Author           *User                `bson:"author,omitempty" json:"author,omitempty"`
	Content          string               `bson:"content" json:"content" binding:"required,max=500"`
	ParentID         *primitive.ObjectID  `bson:"parent_id,omitempty" json:"parent_id,omitempty"` // For replies
	Mentions         []primitive.ObjectID `bson:"mentions" json:"mentions"`
	Hashtags         []string             `bson:"hashtags" json:"hashtags"`
	MediaFiles       []MediaFile          `bson:"media_files" json:"media_files"`
	Status           CommentStatus        `bson:"status" json:"status"`
	Stats            CommentStats         `bson:"stats" json:"stats"`
	IsEdited         bool                 `bson:"is_edited" json:"is_edited"`
	SensitiveContent bool                 `bson:"sensitive_content" json:"sensitive_content"`
	CreatedAt        time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time            `bson:"updated_at" json:"updated_at"`
	DeletedAt        *time.Time           `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// CommentStatus represents comment status
type CommentStatus string

const (
	CommentStatusActive   CommentStatus = "active"
	CommentStatusEdited   CommentStatus = "edited"
	CommentStatusDeleted  CommentStatus = "deleted"
	CommentStatusReported CommentStatus = "reported"
	CommentStatusHidden   CommentStatus = "hidden"
)

// CommentStats represents comment statistics
type CommentStats struct {
	LikesCount   int64 `bson:"likes_count" json:"likes_count"`
	RepliesCount int64 `bson:"replies_count" json:"replies_count"`
	ReportsCount int64 `bson:"reports_count" json:"reports_count"`
}

// CommentCreateRequest represents comment creation request
type CommentCreateRequest struct {
	PostID     primitive.ObjectID   `json:"post_id" binding:"required"`
	Content    string               `json:"content" binding:"required,max=500"`
	ParentID   *primitive.ObjectID  `json:"parent_id,omitempty"`
	Mentions   []primitive.ObjectID `json:"mentions"`
	Hashtags   []string             `json:"hashtags"`
	MediaFiles []MediaFile          `json:"media_files"`
}

// CommentUpdateRequest represents comment update request
type CommentUpdateRequest struct {
	Content    string      `json:"content" binding:"max=500"`
	MediaFiles []MediaFile `json:"media_files"`
}

// CommentResponse represents comment response with user interactions
type CommentResponse struct {
	*Comment
	IsLiked   bool `json:"is_liked"`
	CanEdit   bool `json:"can_edit"`
	CanDelete bool `json:"can_delete"`
	CanReport bool `json:"can_report"`
}

// CommentListResponse represents comment list response
type CommentListResponse struct {
	Comments   []CommentResponse `json:"comments"`
	TotalCount int64             `json:"total_count"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	HasMore    bool              `json:"has_more"`
}
