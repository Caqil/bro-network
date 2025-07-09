package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Follow represents a follow relationship between users
type Follow struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	FollowerID primitive.ObjectID `bson:"follower_id" json:"follower_id"`
	FolloweeID primitive.ObjectID `bson:"followee_id" json:"followee_id"`
	Follower   *User              `bson:"follower,omitempty" json:"follower,omitempty"`
	Followee   *User              `bson:"followee,omitempty" json:"followee,omitempty"`
	Status     FollowStatus       `bson:"status" json:"status"`
	IsClose    bool               `bson:"is_close" json:"is_close"` // Close friends
	IsMuted    bool               `bson:"is_muted" json:"is_muted"`
	IsBlocked  bool               `bson:"is_blocked" json:"is_blocked"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at" json:"updated_at"`
	DeletedAt  *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// FollowStatus represents the status of a follow relationship
type FollowStatus string

const (
	FollowStatusPending  FollowStatus = "pending"
	FollowStatusAccepted FollowStatus = "accepted"
	FollowStatusRejected FollowStatus = "rejected"
	FollowStatusBlocked  FollowStatus = "blocked"
)

// FollowRequest represents a follow request
type FollowCreateRequest struct {
	FolloweeID primitive.ObjectID `json:"followee_id" binding:"required"`
}

// FollowUpdateRequest represents follow relationship update
type FollowUpdateRequest struct {
	Status    *FollowStatus `json:"status,omitempty"`
	IsClose   *bool         `json:"is_close,omitempty"`
	IsMuted   *bool         `json:"is_muted,omitempty"`
	IsBlocked *bool         `json:"is_blocked,omitempty"`
}

// FollowResponse represents follow response with additional info
type FollowResponse struct {
	*Follow
	IsFollowingBack bool `json:"is_following_back"`
	CanUnfollow     bool `json:"can_unfollow"`
	CanBlock        bool `json:"can_block"`
	CanMute         bool `json:"can_mute"`
}

// FollowListResponse represents follow list response
type FollowListResponse struct {
	Follows    []FollowResponse `json:"follows"`
	TotalCount int64            `json:"total_count"`
	Page       int              `json:"page"`
	Limit      int              `json:"limit"`
	HasMore    bool             `json:"has_more"`
}

// FollowSuggestion represents follow suggestions
type FollowSuggestion struct {
	User        UserPublicProfile `json:"user"`
	Reason      string            `json:"reason"`
	MutualCount int64             `json:"mutual_count"`
	Score       float64           `json:"score"`
}

// FollowSuggestionsResponse represents follow suggestions response
type FollowSuggestionsResponse struct {
	Suggestions []FollowSuggestion `json:"suggestions"`
	TotalCount  int64              `json:"total_count"`
	Page        int                `json:"page"`
	Limit       int                `json:"limit"`
	HasMore     bool               `json:"has_more"`
}

// FollowFilter represents follow filter options
type FollowFilter struct {
	UserID    *primitive.ObjectID `json:"user_id,omitempty"`
	Status    *FollowStatus       `json:"status,omitempty"`
	IsClose   *bool               `json:"is_close,omitempty"`
	IsMuted   *bool               `json:"is_muted,omitempty"`
	IsBlocked *bool               `json:"is_blocked,omitempty"`
	Direction string              `json:"direction"` // followers, following
	Page      int                 `json:"page"`
	Limit     int                 `json:"limit"`
	SortBy    string              `json:"sort_by"`    // created_at, username
	SortOrder string              `json:"sort_order"` // asc, desc
}
