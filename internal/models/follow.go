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

// FollowRequest represents a follow request for private accounts
type FollowRequest struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id,omitempty"`
	RequesterID primitive.ObjectID  `bson:"requester_id" json:"requester_id"`
	TargetID    primitive.ObjectID  `bson:"target_id" json:"target_id"`
	Requester   *User               `bson:"requester,omitempty" json:"requester,omitempty"`
	Target      *User               `bson:"target,omitempty" json:"target,omitempty"`
	Status      FollowRequestStatus `bson:"status" json:"status"`
	Message     string              `bson:"message,omitempty" json:"message,omitempty"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
	ExpiresAt   *time.Time          `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// FollowRequestStatus represents the status of a follow request
type FollowRequestStatus string

const (
	FollowRequestStatusPending  FollowRequestStatus = "pending"
	FollowRequestStatusAccepted FollowRequestStatus = "accepted"
	FollowRequestStatusRejected FollowRequestStatus = "rejected"
	FollowRequestStatusExpired  FollowRequestStatus = "expired"
)

// Block represents a block relationship between users
type Block struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	BlockerID primitive.ObjectID `bson:"blocker_id" json:"blocker_id"`
	BlockedID primitive.ObjectID `bson:"blocked_id" json:"blocked_id"`
	Blocker   *User              `bson:"blocker,omitempty" json:"blocker,omitempty"`
	Blocked   *User              `bson:"blocked,omitempty" json:"blocked,omitempty"`
	Reason    string             `bson:"reason,omitempty" json:"reason,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// FollowSuggestion represents follow suggestions for users
type FollowSuggestion struct {
	ID          primitive.ObjectID       `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID       `bson:"user_id" json:"user_id"`
	SuggestedID primitive.ObjectID       `bson:"suggested_id" json:"suggested_id"`
	User        *User                    `bson:"user,omitempty" json:"user,omitempty"`
	Suggested   *User                    `bson:"suggested,omitempty" json:"suggested,omitempty"`
	Source      FollowSuggestionSource   `bson:"source" json:"source"`
	Score       float64                  `bson:"score" json:"score"`
	Reasons     []FollowSuggestionReason `bson:"reasons" json:"reasons"`
	Status      FollowSuggestionStatus   `bson:"status" json:"status"`
	CreatedAt   time.Time                `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time                `bson:"updated_at" json:"updated_at"`
	DismissedAt *time.Time               `bson:"dismissed_at,omitempty" json:"dismissed_at,omitempty"`
}

// FollowSuggestionSource represents the source of follow suggestion
type FollowSuggestionSource string

const (
	FollowSuggestionSourceMutual   FollowSuggestionSource = "mutual_followers"
	FollowSuggestionSourceContacts FollowSuggestionSource = "contacts"
	FollowSuggestionSourceLocation FollowSuggestionSource = "location"
	FollowSuggestionSourceActivity FollowSuggestionSource = "activity"
	FollowSuggestionSourceML       FollowSuggestionSource = "machine_learning"
	FollowSuggestionSourceInterest FollowSuggestionSource = "shared_interests"
)

// FollowSuggestionReason represents the reason for follow suggestion
type FollowSuggestionReason struct {
	Type        string      `bson:"type" json:"type"`
	Description string      `bson:"description" json:"description"`
	Weight      float64     `bson:"weight" json:"weight"`
	Data        interface{} `bson:"data,omitempty" json:"data,omitempty"`
}

// FollowSuggestionStatus represents the status of follow suggestion
type FollowSuggestionStatus string

const (
	FollowSuggestionStatusActive    FollowSuggestionStatus = "active"
	FollowSuggestionStatusDismissed FollowSuggestionStatus = "dismissed"
	FollowSuggestionStatusFollowed  FollowSuggestionStatus = "followed"
	FollowSuggestionStatusExpired   FollowSuggestionStatus = "expired"
)

// FollowActivity represents follow-related activities for timeline
type FollowActivity struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID       primitive.ObjectID     `bson:"user_id" json:"user_id"`
	TargetUserID primitive.ObjectID     `bson:"target_user_id" json:"target_user_id"`
	User         *User                  `bson:"user,omitempty" json:"user,omitempty"`
	TargetUser   *User                  `bson:"target_user,omitempty" json:"target_user,omitempty"`
	ActivityType FollowActivityType     `bson:"activity_type" json:"activity_type"`
	Visibility   ActivityVisibility     `bson:"visibility" json:"visibility"`
	Metadata     map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt    time.Time              `bson:"created_at" json:"created_at"`
}

// FollowActivityType represents types of follow activities
type FollowActivityType string

const (
	FollowActivityTypeFollowed        FollowActivityType = "followed"
	FollowActivityTypeUnfollowed      FollowActivityType = "unfollowed"
	FollowActivityTypeRequestSent     FollowActivityType = "follow_request_sent"
	FollowActivityTypeRequestAccepted FollowActivityType = "follow_request_accepted"
	FollowActivityTypeCloseFriend     FollowActivityType = "added_close_friend"
)

// ActivityVisibility represents visibility of activities
type ActivityVisibility string

const (
	ActivityVisibilityPublic  ActivityVisibility = "public"
	ActivityVisibilityPrivate ActivityVisibility = "private"
	ActivityVisibilityFriends ActivityVisibility = "friends"
)

// UserRelationship represents comprehensive relationship between two users
type UserRelationship struct {
	UserID          primitive.ObjectID `bson:"user_id" json:"user_id"`
	TargetUserID    primitive.ObjectID `bson:"target_user_id" json:"target_user_id"`
	IsFollowing     bool               `bson:"is_following" json:"is_following"`
	IsFollower      bool               `bson:"is_follower" json:"is_follower"`
	IsMutual        bool               `bson:"is_mutual" json:"is_mutual"`
	IsBlocked       bool               `bson:"is_blocked" json:"is_blocked"`
	IsBlockedBy     bool               `bson:"is_blocked_by" json:"is_blocked_by"`
	IsMuted         bool               `bson:"is_muted" json:"is_muted"`
	IsCloseFriend   bool               `bson:"is_close_friend" json:"is_close_friend"`
	IsRestricted    bool               `bson:"is_restricted" json:"is_restricted"`
	PendingRequest  bool               `bson:"pending_request" json:"pending_request"`
	ReceivedRequest bool               `bson:"received_request" json:"received_request"`
	FollowedAt      *time.Time         `bson:"followed_at,omitempty" json:"followed_at,omitempty"`
	MutualCount     int64              `bson:"mutual_count" json:"mutual_count"`
	UpdatedAt       time.Time          `bson:"updated_at" json:"updated_at"`
}

// FollowStats represents follow-related statistics
type FollowStats struct {
	UserID                primitive.ObjectID `bson:"user_id" json:"user_id"`
	FollowersCount        int64              `bson:"followers_count" json:"followers_count"`
	FollowingCount        int64              `bson:"following_count" json:"following_count"`
	MutualFollowsCount    int64              `bson:"mutual_follows_count" json:"mutual_follows_count"`
	CloseFriendsCount     int64              `bson:"close_friends_count" json:"close_friends_count"`
	BlockedUsersCount     int64              `bson:"blocked_users_count" json:"blocked_users_count"`
	MutedUsersCount       int64              `bson:"muted_users_count" json:"muted_users_count"`
	PendingRequestsCount  int64              `bson:"pending_requests_count" json:"pending_requests_count"`
	ReceivedRequestsCount int64              `bson:"received_requests_count" json:"received_requests_count"`
	FollowBackRatio       float64            `bson:"follow_back_ratio" json:"follow_back_ratio"`
	EngagementScore       float64            `bson:"engagement_score" json:"engagement_score"`
	UpdatedAt             time.Time          `bson:"updated_at" json:"updated_at"`
}

// FollowNotification represents follow-related notifications
type FollowNotification struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	RecipientID primitive.ObjectID     `bson:"recipient_id" json:"recipient_id"`
	ActorID     primitive.ObjectID     `bson:"actor_id" json:"actor_id"`
	Recipient   *User                  `bson:"recipient,omitempty" json:"recipient,omitempty"`
	Actor       *User                  `bson:"actor,omitempty" json:"actor,omitempty"`
	Type        FollowNotificationType `bson:"type" json:"type"`
	Title       string                 `bson:"title" json:"title"`
	Message     string                 `bson:"message" json:"message"`
	ActionURL   string                 `bson:"action_url,omitempty" json:"action_url,omitempty"`
	Data        map[string]interface{} `bson:"data,omitempty" json:"data,omitempty"`
	IsRead      bool                   `bson:"is_read" json:"is_read"`
	ReadAt      *time.Time             `bson:"read_at,omitempty" json:"read_at,omitempty"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
	ExpiresAt   *time.Time             `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// FollowNotificationType represents types of follow notifications
type FollowNotificationType string

const (
	FollowNotificationTypeFollowed        FollowNotificationType = "followed"
	FollowNotificationTypeFollowRequest   FollowNotificationType = "follow_request"
	FollowNotificationTypeRequestAccepted FollowNotificationType = "follow_request_accepted"
	FollowNotificationTypeRequestRejected FollowNotificationType = "follow_request_rejected"
	FollowNotificationTypeMilestone       FollowNotificationType = "follower_milestone"
	FollowNotificationTypeCloseFriend     FollowNotificationType = "close_friend_added"
)

// FollowBatch represents batch follow operations
type FollowBatch struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID   `bson:"user_id" json:"user_id"`
	TargetIDs   []primitive.ObjectID `bson:"target_ids" json:"target_ids"`
	Operation   FollowBatchOperation `bson:"operation" json:"operation"`
	Status      FollowBatchStatus    `bson:"status" json:"status"`
	Progress    FollowBatchProgress  `bson:"progress" json:"progress"`
	Results     []FollowBatchResult  `bson:"results,omitempty" json:"results,omitempty"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time            `bson:"updated_at" json:"updated_at"`
	CompletedAt *time.Time           `bson:"completed_at,omitempty" json:"completed_at,omitempty"`
}

// FollowBatchOperation represents batch operation types
type FollowBatchOperation string

const (
	FollowBatchOperationFollow   FollowBatchOperation = "follow"
	FollowBatchOperationUnfollow FollowBatchOperation = "unfollow"
	FollowBatchOperationBlock    FollowBatchOperation = "block"
	FollowBatchOperationUnblock  FollowBatchOperation = "unblock"
)

// FollowBatchStatus represents batch operation status
type FollowBatchStatus string

const (
	FollowBatchStatusPending    FollowBatchStatus = "pending"
	FollowBatchStatusProcessing FollowBatchStatus = "processing"
	FollowBatchStatusCompleted  FollowBatchStatus = "completed"
	FollowBatchStatusFailed     FollowBatchStatus = "failed"
	FollowBatchStatusCancelled  FollowBatchStatus = "cancelled"
)

// FollowBatchProgress represents batch operation progress
type FollowBatchProgress struct {
	Total     int `bson:"total" json:"total"`
	Processed int `bson:"processed" json:"processed"`
	Succeeded int `bson:"succeeded" json:"succeeded"`
	Failed    int `bson:"failed" json:"failed"`
	Skipped   int `bson:"skipped" json:"skipped"`
}

// FollowBatchResult represents individual batch operation result
type FollowBatchResult struct {
	TargetID primitive.ObjectID `bson:"target_id" json:"target_id"`
	Success  bool               `bson:"success" json:"success"`
	Error    string             `bson:"error,omitempty" json:"error,omitempty"`
	Skipped  bool               `bson:"skipped,omitempty" json:"skipped,omitempty"`
	Reason   string             `bson:"reason,omitempty" json:"reason,omitempty"`
}

// FollowSettings represents user's follow-related settings
type FollowSettings struct {
	UserID                       primitive.ObjectID `bson:"user_id" json:"user_id"`
	RequireApproval              bool               `bson:"require_approval" json:"require_approval"`
	AllowFollowRequests          bool               `bson:"allow_follow_requests" json:"allow_follow_requests"`
	AutoFollowBack               bool               `bson:"auto_follow_back" json:"auto_follow_back"`
	ShowFollowersToPublic        bool               `bson:"show_followers_to_public" json:"show_followers_to_public"`
	ShowFollowingToPublic        bool               `bson:"show_following_to_public" json:"show_following_to_public"`
	NotifyOnNewFollower          bool               `bson:"notify_on_new_follower" json:"notify_on_new_follower"`
	NotifyOnFollowRequest        bool               `bson:"notify_on_follow_request" json:"notify_on_follow_request"`
	NotifyOnRequestAccepted      bool               `bson:"notify_on_request_accepted" json:"notify_on_request_accepted"`
	ShowMutualConnections        bool               `bson:"show_mutual_connections" json:"show_mutual_connections"`
	AllowCloseFriendsSuggestions bool               `bson:"allow_close_friends_suggestions" json:"allow_close_friends_suggestions"`
	MaxFollowingLimit            int                `bson:"max_following_limit" json:"max_following_limit"`
	RestrictedModeEnabled        bool               `bson:"restricted_mode_enabled" json:"restricted_mode_enabled"`
	UpdatedAt                    time.Time          `bson:"updated_at" json:"updated_at"`
}
