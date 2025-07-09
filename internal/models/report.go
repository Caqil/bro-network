package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Report represents a content moderation report
type Report struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id,omitempty"`
	ReporterID  primitive.ObjectID  `bson:"reporter_id" json:"reporter_id"`
	Reporter    *User               `bson:"reporter,omitempty" json:"reporter,omitempty"`
	TargetID    primitive.ObjectID  `bson:"target_id" json:"target_id"`
	TargetType  ReportTargetType    `bson:"target_type" json:"target_type"`
	TargetUser  *User               `bson:"target_user,omitempty" json:"target_user,omitempty"`
	Category    ReportCategory      `bson:"category" json:"category"`
	Reason      ReportReason        `bson:"reason" json:"reason"`
	Description string              `bson:"description" json:"description" binding:"max=1000"`
	Evidence    []Evidence          `bson:"evidence" json:"evidence"`
	Status      ReportStatus        `bson:"status" json:"status"`
	Priority    ReportPriority      `bson:"priority" json:"priority"`
	AssignedTo  *primitive.ObjectID `bson:"assigned_to,omitempty" json:"assigned_to,omitempty"`
	Moderator   *User               `bson:"moderator,omitempty" json:"moderator,omitempty"`
	Resolution  *ReportResolution   `bson:"resolution,omitempty" json:"resolution,omitempty"`
	Actions     []ModerationAction  `bson:"actions" json:"actions"`
	Notes       []ReportNote        `bson:"notes" json:"notes"`
	Metadata    ReportMetadata      `bson:"metadata" json:"metadata"`
	ResolvedAt  *time.Time          `bson:"resolved_at,omitempty" json:"resolved_at,omitempty"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time          `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// ReportTargetType represents what is being reported
type ReportTargetType string

const (
	ReportTargetPost         ReportTargetType = "post"
	ReportTargetComment      ReportTargetType = "comment"
	ReportTargetUser         ReportTargetType = "user"
	ReportTargetMessage      ReportTargetType = "message"
	ReportTargetConversation ReportTargetType = "conversation"
)

// ReportCategory represents broad categories of reports
type ReportCategory string

const (
	ReportCategorySpam          ReportCategory = "spam"
	ReportCategoryHarassment    ReportCategory = "harassment"
	ReportCategoryHateSpeech    ReportCategory = "hate_speech"
	ReportCategoryViolence      ReportCategory = "violence"
	ReportCategorySelfHarm      ReportCategory = "self_harm"
	ReportCategoryNudity        ReportCategory = "nudity"
	ReportCategoryFakeNews      ReportCategory = "fake_news"
	ReportCategoryIntellectual  ReportCategory = "intellectual_property"
	ReportCategoryImpersonation ReportCategory = "impersonation"
	ReportCategoryMinorSafety   ReportCategory = "minor_safety"
	ReportCategoryOther         ReportCategory = "other"
)

// ReportReason represents specific reasons within categories
type ReportReason string

const (
	// Spam reasons
	ReasonRepetitiveContent  ReportReason = "repetitive_content"
	ReasonUnwantedCommercial ReportReason = "unwanted_commercial"
	ReasonMaliciousLinks     ReportReason = "malicious_links"

	// Harassment reasons
	ReasonBullying ReportReason = "bullying"
	ReasonThreats  ReportReason = "threats"
	ReasonDoxxing  ReportReason = "doxxing"
	ReasonStalking ReportReason = "stalking"

	// Hate speech reasons
	ReasonRacism               ReportReason = "racism"
	ReasonSexism               ReportReason = "sexism"
	ReasonHomophobia           ReportReason = "homophobia"
	ReasonTransphobia          ReportReason = "transphobia"
	ReasonReligiousIntolerance ReportReason = "religious_intolerance"

	// Violence reasons
	ReasonPhysicalViolence ReportReason = "physical_violence"
	ReasonTerrorism        ReportReason = "terrorism"
	ReasonGraphicContent   ReportReason = "graphic_content"

	// Other reasons
	ReasonInappropriateContent  ReportReason = "inappropriate_content"
	ReasonPrivacyViolation      ReportReason = "privacy_violation"
	ReasonCopyrightInfringement ReportReason = "copyright_infringement"
	ReasonFakeAccount           ReportReason = "fake_account"
	ReasonMinorInDanger         ReportReason = "minor_in_danger"
)

// ReportStatus represents report processing status
type ReportStatus string

const (
	ReportStatusPending       ReportStatus = "pending"
	ReportStatusInReview      ReportStatus = "in_review"
	ReportStatusInvestigating ReportStatus = "investigating"
	ReportStatusResolved      ReportStatus = "resolved"
	ReportStatusDismissed     ReportStatus = "dismissed"
	ReportStatusEscalated     ReportStatus = "escalated"
	ReportStatusClosed        ReportStatus = "closed"
)

// ReportPriority represents report priority levels
type ReportPriority string

const (
	ReportPriorityLow      ReportPriority = "low"
	ReportPriorityMedium   ReportPriority = "medium"
	ReportPriorityHigh     ReportPriority = "high"
	ReportPriorityCritical ReportPriority = "critical"
	ReportPriorityUrgent   ReportPriority = "urgent"
)

// Evidence represents evidence attached to a report
type Evidence struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Type        EvidenceType       `bson:"type" json:"type"`
	URL         string             `bson:"url" json:"url"`
	Description string             `bson:"description" json:"description"`
	Timestamp   time.Time          `bson:"timestamp" json:"timestamp"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// EvidenceType represents types of evidence
type EvidenceType string

const (
	EvidenceTypeScreenshot EvidenceType = "screenshot"
	EvidenceTypeVideo      EvidenceType = "video"
	EvidenceTypeAudio      EvidenceType = "audio"
	EvidenceTypeDocument   EvidenceType = "document"
	EvidenceTypeLink       EvidenceType = "link"
)

// ReportResolution represents the resolution of a report
type ReportResolution struct {
	Action      ResolutionAction   `bson:"action" json:"action"`
	Reason      string             `bson:"reason" json:"reason"`
	Description string             `bson:"description" json:"description"`
	ModeratorID primitive.ObjectID `bson:"moderator_id" json:"moderator_id"`
	Moderator   *User              `bson:"moderator,omitempty" json:"moderator,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// ResolutionAction represents actions taken on reports
type ResolutionAction string

const (
	ResolutionNoAction       ResolutionAction = "no_action"
	ResolutionContentRemoved ResolutionAction = "content_removed"
	ResolutionContentHidden  ResolutionAction = "content_hidden"
	ResolutionUserWarned     ResolutionAction = "user_warned"
	ResolutionUserSuspended  ResolutionAction = "user_suspended"
	ResolutionUserBanned     ResolutionAction = "user_banned"
	ResolutionAccountDeleted ResolutionAction = "account_deleted"
	ResolutionEscalated      ResolutionAction = "escalated"
	ResolutionInvalid        ResolutionAction = "invalid"
)

// ModerationAction represents actions taken by moderators
type ModerationAction struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Type        ActionType         `bson:"type" json:"type"`
	ModeratorID primitive.ObjectID `bson:"moderator_id" json:"moderator_id"`
	Moderator   *User              `bson:"moderator,omitempty" json:"moderator,omitempty"`
	Description string             `bson:"description" json:"description"`
	Duration    *time.Duration     `bson:"duration,omitempty" json:"duration,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// ActionType represents types of moderation actions
type ActionType string

const (
	ActionTypeWarning     ActionType = "warning"
	ActionTypeSuspension  ActionType = "suspension"
	ActionTypeBan         ActionType = "ban"
	ActionTypeRemoval     ActionType = "removal"
	ActionTypeRestriction ActionType = "restriction"
)

// ReportNote represents notes added by moderators
type ReportNote struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	ModeratorID primitive.ObjectID `bson:"moderator_id" json:"moderator_id"`
	Moderator   *User              `bson:"moderator,omitempty" json:"moderator,omitempty"`
	Content     string             `bson:"content" json:"content"`
	IsInternal  bool               `bson:"is_internal" json:"is_internal"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// ReportMetadata represents additional report metadata
type ReportMetadata struct {
	IPAddress      string                 `bson:"ip_address" json:"ip_address"`
	UserAgent      string                 `bson:"user_agent" json:"user_agent"`
	ReportCount    int                    `bson:"report_count" json:"report_count"`
	SimilarReports []primitive.ObjectID   `bson:"similar_reports" json:"similar_reports"`
	AutoModeration bool                   `bson:"auto_moderation" json:"auto_moderation"`
	Confidence     float64                `bson:"confidence" json:"confidence"`
	Tags           []string               `bson:"tags" json:"tags"`
	Extra          map[string]interface{} `bson:"extra" json:"extra"`
}

// ReportCreateRequest represents report creation request
type ReportCreateRequest struct {
	TargetID    primitive.ObjectID `json:"target_id" binding:"required"`
	TargetType  ReportTargetType   `json:"target_type" binding:"required"`
	Category    ReportCategory     `json:"category" binding:"required"`
	Reason      ReportReason       `json:"reason" binding:"required"`
	Description string             `json:"description" binding:"max=1000"`
	Evidence    []Evidence         `json:"evidence"`
}

// ReportUpdateRequest represents report update request
type ReportUpdateRequest struct {
	Status     *ReportStatus       `json:"status,omitempty"`
	Priority   *ReportPriority     `json:"priority,omitempty"`
	AssignedTo *primitive.ObjectID `json:"assigned_to,omitempty"`
	Notes      []ReportNote        `json:"notes,omitempty"`
}

// ReportResponse represents report response
type ReportResponse struct {
	*Report
	CanUpdate   bool `json:"can_update"`
	CanResolve  bool `json:"can_resolve"`
	CanEscalate bool `json:"can_escalate"`
	CanClose    bool `json:"can_close"`
}

// ReportListResponse represents report list response
type ReportListResponse struct {
	Reports    []ReportResponse `json:"reports"`
	TotalCount int64            `json:"total_count"`
	Page       int              `json:"page"`
	Limit      int              `json:"limit"`
	HasMore    bool             `json:"has_more"`
}

// ReportFilter represents report filter options
type ReportFilter struct {
	ReporterID *primitive.ObjectID `json:"reporter_id,omitempty"`
	TargetType *ReportTargetType   `json:"target_type,omitempty"`
	Category   *ReportCategory     `json:"category,omitempty"`
	Status     *ReportStatus       `json:"status,omitempty"`
	Priority   *ReportPriority     `json:"priority,omitempty"`
	AssignedTo *primitive.ObjectID `json:"assigned_to,omitempty"`
	StartDate  *time.Time          `json:"start_date,omitempty"`
	EndDate    *time.Time          `json:"end_date,omitempty"`
	Page       int                 `json:"page"`
	Limit      int                 `json:"limit"`
	SortBy     string              `json:"sort_by"`    // created_at, priority, status
	SortOrder  string              `json:"sort_order"` // asc, desc
}

// ReportStats represents report statistics
type ReportStats struct {
	TotalReports      int64                    `json:"total_reports"`
	PendingReports    int64                    `json:"pending_reports"`
	ResolvedReports   int64                    `json:"resolved_reports"`
	ReportsByCategory map[ReportCategory]int64 `json:"reports_by_category"`
	ReportsByStatus   map[ReportStatus]int64   `json:"reports_by_status"`
	AvgResolutionTime float64                  `json:"avg_resolution_time"`
	TopReasons        map[ReportReason]int64   `json:"top_reasons"`
}
