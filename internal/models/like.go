package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Like represents a like on a post or comment
type Like struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	User         *User              `bson:"user,omitempty" json:"user,omitempty"`
	TargetID     primitive.ObjectID `bson:"target_id" json:"target_id"`
	TargetType   LikeTargetType     `bson:"target_type" json:"target_type"`
	ReactionType ReactionType       `bson:"reaction_type" json:"reaction_type"`
	IsActive     bool               `bson:"is_active" json:"is_active"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
	DeletedAt    *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// LikeTargetType represents the type of content being liked
type LikeTargetType string

const (
	LikeTargetPost    LikeTargetType = "post"
	LikeTargetComment LikeTargetType = "comment"
	LikeTargetMessage LikeTargetType = "message"
)

type ReactionType string

const (
	ReactionTypeLike       ReactionType = "like"
	ReactionTypeLove       ReactionType = "love"
	ReactionTypeHaha       ReactionType = "haha"
	ReactionTypeWow        ReactionType = "wow"
	ReactionTypeSad        ReactionType = "sad"
	ReactionTypeAngry      ReactionType = "angry"
	ReactionTypeThumbsUp   ReactionType = "thumbs_up"
	ReactionTypeThumbsDown ReactionType = "thumbs_down"
)

// LikeCreateRequest represents like creation request
type LikeCreateRequest struct {
	TargetID     primitive.ObjectID `json:"target_id" binding:"required"`
	TargetType   LikeTargetType     `json:"target_type" binding:"required"`
	ReactionType ReactionType       `json:"reaction_type" binding:"required"`
}

// LikeResponse represents like response
type LikeResponse struct {
	*Like
	CanUnlike bool `json:"can_unlike"`
}

// LikeListResponse represents like list response
type LikeListResponse struct {
	Likes      []LikeResponse `json:"likes"`
	TotalCount int64          `json:"total_count"`
	Page       int            `json:"page"`
	Limit      int            `json:"limit"`
	HasMore    bool           `json:"has_more"`
}

// ReactionSummary represents reaction summary for a target
type ReactionSummary struct {
	TargetID     primitive.ObjectID     `json:"target_id"`
	TargetType   LikeTargetType         `json:"target_type"`
	TotalCount   int64                  `json:"total_count"`
	Reactions    map[ReactionType]int64 `json:"reactions"`
	UserReaction *ReactionType          `json:"user_reaction,omitempty"`
}
