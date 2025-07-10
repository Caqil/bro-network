package services

import (
	"context"
	"mime/multipart"
	"time"

	"bro-network/internal/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MessageServiceInterface defines all message-related operations
type MessageServiceInterface interface {
	// =============================================================================
	// CONVERSATIONS MANAGEMENT
	// =============================================================================
	GetConversations(ctx context.Context, userID primitive.ObjectID, req *GetConversationsRequest) (*models.ConversationListResponse, error)
	CreateConversation(ctx context.Context, req *CreateConversationRequest) (*models.ConversationResponse, error)
	GetConversation(ctx context.Context, userID, conversationID primitive.ObjectID) (*models.ConversationResponse, error)
	UpdateConversation(ctx context.Context, userID, conversationID primitive.ObjectID, req *models.ConversationUpdateRequest) error
	DeleteConversation(ctx context.Context, userID, conversationID primitive.ObjectID) error
	ArchiveConversation(ctx context.Context, userID, conversationID primitive.ObjectID) error
	UnarchiveConversation(ctx context.Context, userID, conversationID primitive.ObjectID) error
	MuteConversation(ctx context.Context, userID, conversationID primitive.ObjectID, req *MuteConversationRequest) error
	UnmuteConversation(ctx context.Context, userID, conversationID primitive.ObjectID) error
	MarkConversationAsRead(ctx context.Context, userID, conversationID primitive.ObjectID) error
	MarkConversationAsUnread(ctx context.Context, userID, conversationID primitive.ObjectID) error

	// Participants management
	GetConversationParticipants(ctx context.Context, userID, conversationID primitive.ObjectID) (*ConversationParticipantsResponse, error)
	AddParticipants(ctx context.Context, userID, conversationID primitive.ObjectID, req *AddParticipantsRequest) error
	RemoveParticipant(ctx context.Context, userID, conversationID, participantID primitive.ObjectID) error
	LeaveConversation(ctx context.Context, userID, conversationID primitive.ObjectID) error
	MakeAdmin(ctx context.Context, userID, conversationID, targetUserID primitive.ObjectID) error
	RemoveAdmin(ctx context.Context, userID, conversationID, targetUserID primitive.ObjectID) error
	UpdateConversationSettings(ctx context.Context, userID, conversationID primitive.ObjectID, req *ConversationSettingsRequest) error

	// Conversation content
	GetConversationMedia(ctx context.Context, userID, conversationID primitive.ObjectID, req *GetMediaRequest) (*ConversationMediaResponse, error)
	GetConversationFiles(ctx context.Context, userID, conversationID primitive.ObjectID, req *GetFilesRequest) (*ConversationFilesResponse, error)
	GetConversationLinks(ctx context.Context, userID, conversationID primitive.ObjectID, req *GetLinksRequest) (*ConversationLinksResponse, error)
	SearchInConversation(ctx context.Context, userID, conversationID primitive.ObjectID, req *SearchConversationRequest) (*ConversationSearchResponse, error)
	ExportConversation(ctx context.Context, userID, conversationID primitive.ObjectID) (*ConversationExportResponse, error)
	DownloadConversationExport(ctx context.Context, userID, conversationID primitive.ObjectID, exportID string) (string, error)

	// =============================================================================
	// MESSAGES MANAGEMENT
	// =============================================================================
	SendMessage(ctx context.Context, req *SendMessageRequest) (*models.MessageResponse, error)
	QuickSendMessage(ctx context.Context, req *QuickSendMessageRequest) (*models.MessageResponse, error)
	GetMessages(ctx context.Context, userID, conversationID primitive.ObjectID, req *GetMessagesRequest) (*models.MessageListResponse, error)
	GetMessage(ctx context.Context, userID, messageID primitive.ObjectID) (*models.MessageResponse, error)
	UpdateMessage(ctx context.Context, userID, messageID primitive.ObjectID, req *models.MessageUpdateRequest) error
	DeleteMessage(ctx context.Context, userID, messageID primitive.ObjectID) error
	RestoreMessage(ctx context.Context, userID, messageID primitive.ObjectID) error

	// Message reactions
	ReactToMessage(ctx context.Context, userID, messageID primitive.ObjectID, req *ReactToMessageRequest) (*MessageReactionResponse, error)
	RemoveReaction(ctx context.Context, userID, messageID primitive.ObjectID) error
	GetMessageReactions(ctx context.Context, userID, messageID primitive.ObjectID) (*MessageReactionsResponse, error)

	// Message actions
	ReplyToMessage(ctx context.Context, req *ReplyToMessageRequest) (*models.MessageResponse, error)
	ForwardMessage(ctx context.Context, userID, messageID primitive.ObjectID, req *ForwardMessageRequest) (*MessageForwardResponse, error)
	StarMessage(ctx context.Context, userID, messageID primitive.ObjectID) error
	UnstarMessage(ctx context.Context, userID, messageID primitive.ObjectID) error
	ReportMessage(ctx context.Context, userID, messageID primitive.ObjectID, req *ReportMessageRequest) error

	// Message status
	MarkMessageAsRead(ctx context.Context, userID, messageID primitive.ObjectID) error
	GetDeliveryStatus(ctx context.Context, userID, messageID primitive.ObjectID) (*MessageDeliveryResponse, error)
	GetReadReceipts(ctx context.Context, userID, messageID primitive.ObjectID) (*MessageReadReceiptsResponse, error)

	// =============================================================================
	// MESSAGE SEARCH AND DISCOVERY
	// =============================================================================
	SearchMessages(ctx context.Context, userID primitive.ObjectID, req *SearchMessagesRequest) (*MessageSearchResponse, error)
	GetRecentSearches(ctx context.Context, userID primitive.ObjectID) (*MessageRecentSearchesResponse, error)
	ClearRecentSearches(ctx context.Context, userID primitive.ObjectID) error
	AdvancedSearchMessages(ctx context.Context, userID primitive.ObjectID, req *AdvancedSearchMessagesRequest) (*MessageAdvancedSearchResponse, error)
	SearchMessagesByMedia(ctx context.Context, userID primitive.ObjectID, req *SearchMessagesByMediaRequest) (*MessageMediaSearchResponse, error)
	SearchMessagesByFiles(ctx context.Context, userID primitive.ObjectID, req *SearchMessagesByFilesRequest) (*MessageFilesSearchResponse, error)
	SearchMessagesByLinks(ctx context.Context, userID primitive.ObjectID, req *SearchMessagesByLinksRequest) (*MessageLinksSearchResponse, error)

	// =============================================================================
	// MESSAGE THREADS
	// =============================================================================
	GetMessageThreads(ctx context.Context, userID primitive.ObjectID, req *GetMessageThreadsRequest) (*MessageThreadsResponse, error)
	GetThread(ctx context.Context, userID, threadID primitive.ObjectID) (*MessageThreadResponse, error)
	GetThreadMessages(ctx context.Context, userID, threadID primitive.ObjectID, req *GetThreadMessagesRequest) (*MessageThreadMessagesResponse, error)
	MarkThreadAsRead(ctx context.Context, userID, threadID primitive.ObjectID) error
	FollowThread(ctx context.Context, userID, threadID primitive.ObjectID) error
	UnfollowThread(ctx context.Context, userID, threadID primitive.ObjectID) error

	// =============================================================================
	// MESSAGE DRAFTS
	// =============================================================================
	GetMessageDrafts(ctx context.Context, userID primitive.ObjectID, req *GetMessageDraftsRequest) (*MessageDraftsResponse, error)
	CreateMessageDraft(ctx context.Context, req *CreateMessageDraftRequest) (*MessageDraftResponse, error)
	UpdateMessageDraft(ctx context.Context, userID, draftID primitive.ObjectID, req *UpdateMessageDraftRequest) error
	DeleteMessageDraft(ctx context.Context, userID, draftID primitive.ObjectID) error
	SendMessageDraft(ctx context.Context, userID, draftID primitive.ObjectID) (*models.MessageResponse, error)
	AutoSaveMessageDraft(ctx context.Context, req *AutoSaveMessageDraftRequest) (*MessageDraftResponse, error)

	// =============================================================================
	// MESSAGE SCHEDULING
	// =============================================================================
	GetScheduledMessages(ctx context.Context, userID primitive.ObjectID, req *GetScheduledMessagesRequest) (*MessageScheduledResponse, error)
	ScheduleMessage(ctx context.Context, req *ScheduleMessageRequest) (*MessageScheduleResponse, error)
	UpdateScheduledMessage(ctx context.Context, userID, messageID primitive.ObjectID, req *UpdateScheduledMessageRequest) error
	CancelScheduledMessage(ctx context.Context, userID, messageID primitive.ObjectID) error
	SendScheduledMessageNow(ctx context.Context, userID, messageID primitive.ObjectID) (*models.MessageResponse, error)

	// =============================================================================
	// MESSAGE TEMPLATES
	// =============================================================================
	GetMessageTemplates(ctx context.Context, userID primitive.ObjectID, req *GetMessageTemplatesRequest) (*MessageTemplatesResponse, error)
	CreateMessageTemplate(ctx context.Context, req *CreateMessageTemplateRequest) (*MessageTemplateResponse, error)
	UpdateMessageTemplate(ctx context.Context, userID, templateID primitive.ObjectID, req *UpdateMessageTemplateRequest) error
	DeleteMessageTemplate(ctx context.Context, userID, templateID primitive.ObjectID) error
	UseMessageTemplate(ctx context.Context, userID, templateID primitive.ObjectID, req *UseMessageTemplateRequest) (*models.MessageResponse, error)
	GetPublicMessageTemplates(ctx context.Context, req *GetPublicMessageTemplatesRequest) (*MessagePublicTemplatesResponse, error)
	ShareMessageTemplate(ctx context.Context, userID, templateID primitive.ObjectID) error

	// =============================================================================
	// MESSAGE SETTINGS AND PREFERENCES
	// =============================================================================
	GetMessageSettings(ctx context.Context, userID primitive.ObjectID) (*MessageSettingsResponse, error)
	UpdateMessageSettings(ctx context.Context, userID primitive.ObjectID, req *MessageSettingsRequest) error
	GetMessagePrivacySettings(ctx context.Context, userID primitive.ObjectID) (*MessagePrivacyResponse, error)
	UpdateMessagePrivacySettings(ctx context.Context, userID primitive.ObjectID, req *MessagePrivacyRequest) error
	GetMessageNotificationSettings(ctx context.Context, userID primitive.ObjectID) (*MessageNotificationResponse, error)
	UpdateMessageNotificationSettings(ctx context.Context, userID primitive.ObjectID, req *MessageNotificationRequest) error
	GetAutoReplySettings(ctx context.Context, userID primitive.ObjectID) (*MessageAutoReplyResponse, error)
	UpdateAutoReplySettings(ctx context.Context, userID primitive.ObjectID, req *MessageAutoReplyRequest) error

	// Message filters
	GetMessageFilters(ctx context.Context, userID primitive.ObjectID) (*MessageFiltersResponse, error)
	CreateMessageFilter(ctx context.Context, req *CreateMessageFilterRequest) (*MessageFilterResponse, error)
	UpdateMessageFilter(ctx context.Context, userID, filterID primitive.ObjectID, req *UpdateMessageFilterRequest) error
	DeleteMessageFilter(ctx context.Context, userID, filterID primitive.ObjectID) error

	// =============================================================================
	// MESSAGE ANALYTICS
	// =============================================================================
	GetMessageStats(ctx context.Context, userID primitive.ObjectID) (*MessageStatsResponse, error)
	GetConversationStats(ctx context.Context, userID, conversationID primitive.ObjectID) (*ConversationStatsResponse, error)
	GetMessageResponseRates(ctx context.Context, userID primitive.ObjectID) (*MessageResponseRatesResponse, error)
	GetMessageEngagement(ctx context.Context, userID primitive.ObjectID) (*MessageEngagementResponse, error)
	GetMessageActivityPatterns(ctx context.Context, userID primitive.ObjectID) (*MessageActivityPatternsResponse, error)
	GetPeakMessagingHours(ctx context.Context, userID primitive.ObjectID) (*MessagePeakHoursResponse, error)
}

// =============================================================================
// MESSAGE-SPECIFIC REQUEST STRUCTS (Avoiding conflicts with PostService)
// =============================================================================

// Conversation requests
type GetConversationsRequest struct {
	Page     int  `json:"page"`
	Limit    int  `json:"limit"`
	Archived bool `json:"archived,omitempty"`
	Unread   bool `json:"unread,omitempty"`
}

type CreateConversationRequest struct {
	CreatorID    primitive.ObjectID   `json:"creator_id"`
	Participants []primitive.ObjectID `json:"participants"`
	IsGroup      bool                 `json:"is_group"`
	GroupName    string               `json:"group_name,omitempty"`
	GroupImage   string               `json:"group_image,omitempty"`
}

type MuteConversationRequest struct {
	Duration  int  `json:"duration,omitempty"`
	Permanent bool `json:"permanent,omitempty"`
}

type AddParticipantsRequest struct {
	Participants []primitive.ObjectID `json:"participants"`
}

type ConversationSettingsRequest struct {
	Settings models.ConversationSettings `json:"settings"`
}

type GetMediaRequest struct {
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
	Type  string `json:"type,omitempty"`
}

type GetFilesRequest struct {
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
	Type  string `json:"type,omitempty"`
}

type GetLinksRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type SearchConversationRequest struct {
	Query string `json:"query"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

// Message requests (extending existing models.MessageCreateRequest)
type SendMessageRequest struct {
	SenderID       primitive.ObjectID      `json:"sender_id"`
	ConversationID *primitive.ObjectID     `json:"conversation_id,omitempty"`
	RecipientID    *primitive.ObjectID     `json:"recipient_id,omitempty"`
	Content        string                  `json:"content"`
	MessageType    models.MessageType      `json:"message_type,omitempty"`
	ReplyToID      *primitive.ObjectID     `json:"reply_to_id,omitempty"`
	Attachments    []*multipart.FileHeader `json:"-"`
}

type QuickSendMessageRequest struct {
	SenderID    primitive.ObjectID  `json:"sender_id"`
	RecipientID *primitive.ObjectID `json:"recipient_id"`
	Content     string              `json:"content"`
	MessageType models.MessageType  `json:"message_type,omitempty"`
}

type GetMessagesRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type ReactToMessageRequest struct {
	Reaction string `json:"reaction"`
}

type ReplyToMessageRequest struct {
	SenderID    primitive.ObjectID  `json:"sender_id"`
	ReplyToID   *primitive.ObjectID `json:"reply_to_id"`
	Content     string              `json:"content"`
	Attachments []string            `json:"attachments,omitempty"`
}

type ForwardMessageRequest struct {
	ConversationIDs []primitive.ObjectID `json:"conversation_ids"`
	AddComment      string               `json:"add_comment,omitempty"`
}

type ReportMessageRequest struct {
	Reason      string `json:"reason"`
	Description string `json:"description,omitempty"`
}

// Search requests
type SearchMessagesRequest struct {
	Query          string              `json:"query"`
	ConversationID *primitive.ObjectID `json:"conversation_id,omitempty"`
	FromUser       *primitive.ObjectID `json:"from_user,omitempty"`
	MessageType    models.MessageType  `json:"message_type,omitempty"`
	DateFrom       *time.Time          `json:"date_from,omitempty"`
	DateTo         *time.Time          `json:"date_to,omitempty"`
	Page           int                 `json:"page"`
	Limit          int                 `json:"limit"`
}

type AdvancedSearchMessagesRequest struct {
	Query   string                 `json:"query"`
	Filters map[string]interface{} `json:"filters,omitempty"`
	Page    int                    `json:"page"`
	Limit   int                    `json:"limit"`
}

type SearchMessagesByMediaRequest struct {
	Page      int              `json:"page"`
	Limit     int              `json:"limit"`
	MediaType models.MediaType `json:"media_type,omitempty"`
}

type SearchMessagesByFilesRequest struct {
	Page     int    `json:"page"`
	Limit    int    `json:"limit"`
	FileType string `json:"file_type,omitempty"`
}

type SearchMessagesByLinksRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

// Thread requests
type GetMessageThreadsRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type GetThreadMessagesRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

// Draft requests (avoiding conflicts with PostService)
type GetMessageDraftsRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type CreateMessageDraftRequest struct {
	UserID         primitive.ObjectID  `json:"user_id"`
	Content        string              `json:"content"`
	ConversationID *primitive.ObjectID `json:"conversation_id,omitempty"`
}

type UpdateMessageDraftRequest struct {
	Content *string `json:"content,omitempty"`
}

type AutoSaveMessageDraftRequest struct {
	UserID         primitive.ObjectID  `json:"user_id"`
	Content        string              `json:"content"`
	ConversationID *primitive.ObjectID `json:"conversation_id,omitempty"`
}

// Scheduling requests (avoiding conflicts with PostService)
type GetScheduledMessagesRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type ScheduleMessageRequest struct {
	SenderID       primitive.ObjectID `json:"sender_id"`
	ConversationID primitive.ObjectID `json:"conversation_id"`
	Content        string             `json:"content"`
	ScheduledAt    string             `json:"scheduled_at"`
	Timezone       string             `json:"timezone,omitempty"`
}

type UpdateScheduledMessageRequest struct {
	Content     *string `json:"content,omitempty"`
	ScheduledAt *string `json:"scheduled_at,omitempty"`
}

// Template requests (avoiding conflicts with PostService)
type GetMessageTemplatesRequest struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type CreateMessageTemplateRequest struct {
	UserID   primitive.ObjectID `json:"user_id"`
	Name     string             `json:"name"`
	Content  string             `json:"content"`
	Category string             `json:"category,omitempty"`
	IsPublic bool               `json:"is_public,omitempty"`
}

type UpdateMessageTemplateRequest struct {
	Name     *string `json:"name,omitempty"`
	Content  *string `json:"content,omitempty"`
	Category *string `json:"category,omitempty"`
	IsPublic *bool   `json:"is_public,omitempty"`
}

type UseMessageTemplateRequest struct {
	ConversationID primitive.ObjectID     `json:"conversation_id"`
	Variables      map[string]interface{} `json:"variables,omitempty"`
}

type GetPublicMessageTemplatesRequest struct {
	Page     int    `json:"page"`
	Limit    int    `json:"limit"`
	Category string `json:"category,omitempty"`
}

// Settings requests
type MessageSettingsRequest struct {
	ReadReceipts      *bool `json:"read_receipts,omitempty"`
	TypingIndicators  *bool `json:"typing_indicators,omitempty"`
	AutoDownloadMedia *bool `json:"auto_download_media,omitempty"`
	NotificationSound *bool `json:"notification_sound,omitempty"`
	Vibration         *bool `json:"vibration,omitempty"`
}

type MessagePrivacyRequest struct {
	AllowMessagesFrom string `json:"allow_messages_from,omitempty"`
	AllowGroupInvites *bool  `json:"allow_group_invites,omitempty"`
}

type MessageNotificationRequest struct {
	PushNotifications  *bool `json:"push_notifications,omitempty"`
	EmailNotifications *bool `json:"email_notifications,omitempty"`
	SMSNotifications   *bool `json:"sms_notifications,omitempty"`
}

type MessageAutoReplyRequest struct {
	Enabled    bool                   `json:"enabled"`
	Message    string                 `json:"message,omitempty"`
	Schedule   map[string]interface{} `json:"schedule,omitempty"`
	Exceptions []string               `json:"exceptions,omitempty"`
}

// Filter requests
type CreateMessageFilterRequest struct {
	UserID     primitive.ObjectID `json:"user_id"`
	Name       string             `json:"name"`
	Conditions []interface{}      `json:"conditions"`
	Actions    []interface{}      `json:"actions"`
	Enabled    bool               `json:"enabled"`
}

type UpdateMessageFilterRequest struct {
	Name       *string       `json:"name,omitempty"`
	Conditions []interface{} `json:"conditions,omitempty"`
	Actions    []interface{} `json:"actions,omitempty"`
	Enabled    *bool         `json:"enabled,omitempty"`
}

// =============================================================================
// MESSAGE-SPECIFIC RESPONSE STRUCTS (Avoiding conflicts with PostService)
// =============================================================================

// Conversation participants
type ConversationParticipant struct {
	UserID   primitive.ObjectID `json:"user_id"`
	Username string             `json:"username"`
	FullName string             `json:"full_name"`
	Avatar   string             `json:"avatar,omitempty"`
	IsAdmin  bool               `json:"is_admin"`
	JoinedAt time.Time          `json:"joined_at"`
}

type ConversationParticipantsResponse struct {
	Participants []*ConversationParticipant `json:"participants"`
	TotalCount   int64                      `json:"total_count"`
}

// Media and files for conversations
type ConversationMediaResponse struct {
	Media      []models.MediaFile `json:"media"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type ConversationFilesResponse struct {
	Files      []models.MediaFile `json:"files"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type ConversationLinksResponse struct {
	Links      []ConversationLink `json:"links"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type ConversationLink struct {
	URL         string             `json:"url"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Image       string             `json:"image,omitempty"`
	MessageID   primitive.ObjectID `json:"message_id"`
	CreatedAt   time.Time          `json:"created_at"`
}

type ConversationSearchResponse struct {
	Results    []*models.Message `json:"results"`
	TotalCount int64             `json:"total_count"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	HasMore    bool              `json:"has_more"`
}

type ConversationExportResponse struct {
	ExportID  string    `json:"export_id"`
	Status    string    `json:"status"`
	Progress  int       `json:"progress"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Message reactions
type MessageReaction struct {
	UserID    primitive.ObjectID `json:"user_id"`
	Reaction  string             `json:"reaction"`
	CreatedAt time.Time          `json:"created_at"`
}

type MessageReadStatus struct {
	UserID primitive.ObjectID `json:"user_id"`
	ReadAt time.Time          `json:"read_at"`
}

type MessageReactionResponse struct {
	Success  bool   `json:"success"`
	Reaction string `json:"reaction"`
	Count    int    `json:"count"`
}

type MessageReactionsResponse struct {
	Reactions      []MessageReaction `json:"reactions"`
	ReactionCounts map[string]int    `json:"reaction_counts"`
	UserReaction   string            `json:"user_reaction,omitempty"`
}

type MessageForwardResponse struct {
	Success          bool                 `json:"success"`
	ForwardedTo      []primitive.ObjectID `json:"forwarded_to"`
	FailedRecipients []primitive.ObjectID `json:"failed_recipients,omitempty"`
}

type MessageDeliveryResponse struct {
	MessageID   primitive.ObjectID   `json:"message_id"`
	Status      models.MessageStatus `json:"status"`
	DeliveredTo []primitive.ObjectID `json:"delivered_to"`
	FailedTo    []primitive.ObjectID `json:"failed_to,omitempty"`
	DeliveredAt time.Time            `json:"delivered_at"`
}

type MessageReadReceiptsResponse struct {
	MessageID   primitive.ObjectID   `json:"message_id"`
	ReadBy      []MessageReadStatus  `json:"read_by"`
	UnreadBy    []primitive.ObjectID `json:"unread_by"`
	ReadCount   int                  `json:"read_count"`
	UnreadCount int                  `json:"unread_count"`
}

// Search responses
type MessageSearchResponse struct {
	Messages   []*models.Message `json:"messages"`
	TotalCount int64             `json:"total_count"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	HasMore    bool              `json:"has_more"`
	SearchTime int64             `json:"search_time_ms"`
}

type MessageRecentSearchesResponse struct {
	Searches []MessageRecentSearch `json:"searches"`
}

type MessageRecentSearch struct {
	Query       string    `json:"query"`
	ResultCount int       `json:"result_count"`
	SearchedAt  time.Time `json:"searched_at"`
}

type MessageAdvancedSearchResponse struct {
	Messages   []*models.Message      `json:"messages"`
	TotalCount int64                  `json:"total_count"`
	Page       int                    `json:"page"`
	Limit      int                    `json:"limit"`
	HasMore    bool                   `json:"has_more"`
	Facets     map[string]interface{} `json:"facets,omitempty"`
}

type MessageMediaSearchResponse struct {
	Media      []models.MediaFile `json:"media"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type MessageFilesSearchResponse struct {
	Files      []models.MediaFile `json:"files"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type MessageLinksSearchResponse struct {
	Links      []ConversationLink `json:"links"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

// Thread structures
type MessageThread struct {
	ID          primitive.ObjectID `json:"id"`
	RootMessage *models.Message    `json:"root_message"`
	ReplyCount  int                `json:"reply_count"`
	LastReply   *models.Message    `json:"last_reply,omitempty"`
	IsFollowing bool               `json:"is_following"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type MessageThreadsResponse struct {
	Threads    []*MessageThread `json:"threads"`
	TotalCount int64            `json:"total_count"`
	Page       int              `json:"page"`
	Limit      int              `json:"limit"`
	HasMore    bool             `json:"has_more"`
}

type MessageThreadResponse struct {
	*MessageThread
	CanReply    bool `json:"can_reply"`
	CanFollow   bool `json:"can_follow"`
	CanUnfollow bool `json:"can_unfollow"`
}

type MessageThreadMessagesResponse struct {
	Messages   []*models.MessageResponse `json:"messages"`
	TotalCount int64                     `json:"total_count"`
	Page       int                       `json:"page"`
	Limit      int                       `json:"limit"`
	HasMore    bool                      `json:"has_more"`
}

// Draft structures (avoiding conflicts with PostService)
type MessageDraft struct {
	ID             primitive.ObjectID  `json:"id"`
	UserID         primitive.ObjectID  `json:"user_id"`
	ConversationID *primitive.ObjectID `json:"conversation_id,omitempty"`
	Content        string              `json:"content"`
	AutoSaved      bool                `json:"auto_saved"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

type MessageDraftsResponse struct {
	Drafts     []*MessageDraft `json:"drafts"`
	TotalCount int64           `json:"total_count"`
	Page       int             `json:"page"`
	Limit      int             `json:"limit"`
	HasMore    bool            `json:"has_more"`
}

type MessageDraftResponse struct {
	*MessageDraft
	CanEdit   bool `json:"can_edit"`
	CanDelete bool `json:"can_delete"`
	CanSend   bool `json:"can_send"`
}

// Scheduling structures (avoiding conflicts with PostService)
type MessageScheduled struct {
	ID             primitive.ObjectID `json:"id"`
	SenderID       primitive.ObjectID `json:"sender_id"`
	ConversationID primitive.ObjectID `json:"conversation_id"`
	Content        string             `json:"content"`
	ScheduledAt    time.Time          `json:"scheduled_at"`
	Status         string             `json:"status"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

type MessageScheduledResponse struct {
	Messages   []*MessageScheduled `json:"messages"`
	TotalCount int64               `json:"total_count"`
	Page       int                 `json:"page"`
	Limit      int                 `json:"limit"`
	HasMore    bool                `json:"has_more"`
}

type MessageScheduleResponse struct {
	*MessageScheduled
	CanEdit   bool `json:"can_edit"`
	CanCancel bool `json:"can_cancel"`
	CanSend   bool `json:"can_send"`
}

// Template structures (avoiding conflicts with PostService)
type MessageTemplate struct {
	ID        primitive.ObjectID `json:"id"`
	UserID    primitive.ObjectID `json:"user_id"`
	Name      string             `json:"name"`
	Content   string             `json:"content"`
	Category  string             `json:"category,omitempty"`
	IsPublic  bool               `json:"is_public"`
	UseCount  int                `json:"use_count"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

type MessageTemplatesResponse struct {
	Templates  []*MessageTemplate `json:"templates"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

type MessageTemplateResponse struct {
	*MessageTemplate
	CanEdit   bool `json:"can_edit"`
	CanDelete bool `json:"can_delete"`
	CanUse    bool `json:"can_use"`
	CanShare  bool `json:"can_share"`
}

type MessagePublicTemplatesResponse struct {
	Templates  []*MessageTemplate `json:"templates"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
}

// Filter structures
type MessageFilter struct {
	ID         primitive.ObjectID `json:"id"`
	UserID     primitive.ObjectID `json:"user_id"`
	Name       string             `json:"name"`
	Conditions []interface{}      `json:"conditions"`
	Actions    []interface{}      `json:"actions"`
	Enabled    bool               `json:"enabled"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

type MessageFiltersResponse struct {
	Filters    []*MessageFilter `json:"filters"`
	TotalCount int64            `json:"total_count"`
}

type MessageFilterResponse struct {
	*MessageFilter
	CanEdit   bool `json:"can_edit"`
	CanDelete bool `json:"can_delete"`
	CanToggle bool `json:"can_toggle"`
}

// Settings responses
type MessageSettingsResponse struct {
	ReadReceipts      bool `json:"read_receipts"`
	TypingIndicators  bool `json:"typing_indicators"`
	AutoDownloadMedia bool `json:"auto_download_media"`
	NotificationSound bool `json:"notification_sound"`
	Vibration         bool `json:"vibration"`
}

type MessagePrivacyResponse struct {
	AllowMessagesFrom string `json:"allow_messages_from"`
	AllowGroupInvites bool   `json:"allow_group_invites"`
}

type MessageNotificationResponse struct {
	PushNotifications  bool `json:"push_notifications"`
	EmailNotifications bool `json:"email_notifications"`
	SMSNotifications   bool `json:"sms_notifications"`
}

type MessageAutoReplyResponse struct {
	Enabled    bool                   `json:"enabled"`
	Message    string                 `json:"message,omitempty"`
	Schedule   map[string]interface{} `json:"schedule,omitempty"`
	Exceptions []string               `json:"exceptions,omitempty"`
}

// Analytics responses (avoiding conflicts with PostService)
type MessageStatsResponse struct {
	TotalMessages       int64            `json:"total_messages"`
	SentMessages        int64            `json:"sent_messages"`
	ReceivedMessages    int64            `json:"received_messages"`
	TotalConversations  int64            `json:"total_conversations"`
	ActiveConversations int64            `json:"active_conversations"`
	MessagesByType      map[string]int64 `json:"messages_by_type"`
	MessagesByPeriod    map[string]int64 `json:"messages_by_period"`
	ResponseRate        float64          `json:"response_rate"`
	AvgResponseTime     int64            `json:"avg_response_time_minutes"`
}

type ConversationStatsResponse struct {
	ConversationID   primitive.ObjectID `json:"conversation_id"`
	TotalMessages    int64              `json:"total_messages"`
	MessagesByUser   map[string]int64   `json:"messages_by_user"`
	MessagesByType   map[string]int64   `json:"messages_by_type"`
	MessagesByPeriod map[string]int64   `json:"messages_by_period"`
	FirstMessage     time.Time          `json:"first_message"`
	LastMessage      time.Time          `json:"last_message"`
	AvgResponseTime  int64              `json:"avg_response_time_minutes"`
}

type MessageResponseRatesResponse struct {
	OverallRate     float64            `json:"overall_rate"`
	RateByPeriod    map[string]float64 `json:"rate_by_period"`
	RateByUser      map[string]float64 `json:"rate_by_user"`
	AvgResponseTime int64              `json:"avg_response_time_minutes"`
	FastestResponse int64              `json:"fastest_response_seconds"`
	SlowestResponse int64              `json:"slowest_response_hours"`
}

type MessageEngagementResponse struct {
	TotalReactions     int64              `json:"total_reactions"`
	ReactionsByType    map[string]int64   `json:"reactions_by_type"`
	MostReactedMessage primitive.ObjectID `json:"most_reacted_message"`
	TotalShares        int64              `json:"total_shares"`
	TotalForwards      int64              `json:"total_forwards"`
	EngagementRate     float64            `json:"engagement_rate"`
}

type MessageActivityPatternsResponse struct {
	HourlyActivity   map[string]int64 `json:"hourly_activity"`
	DailyActivity    map[string]int64 `json:"daily_activity"`
	WeeklyActivity   map[string]int64 `json:"weekly_activity"`
	MonthlyActivity  map[string]int64 `json:"monthly_activity"`
	PeakHours        []int            `json:"peak_hours"`
	PeakDays         []string         `json:"peak_days"`
	TimezoneActivity map[string]int64 `json:"timezone_activity"`
}

type MessagePeakHoursResponse struct {
	Today     []MessagePeakHour `json:"today"`
	ThisWeek  []MessagePeakHour `json:"this_week"`
	ThisMonth []MessagePeakHour `json:"this_month"`
	Overall   []MessagePeakHour `json:"overall"`
}

type MessagePeakHour struct {
	Hour         int     `json:"hour"`
	MessageCount int64   `json:"message_count"`
	Percentage   float64 `json:"percentage"`
}
