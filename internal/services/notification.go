package services

import (
	"context"
	"time"

	"bro-network/internal/models"
	"bro-network/internal/repositories"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NotificationService handles notification business logic
type NotificationService struct {
	notificationRepo repositories.NotificationRepositoryInterface
	deviceRepo       repositories.DeviceRepositoryInterface
	webhookRepo      repositories.WebhookRepositoryInterface
	templateRepo     repositories.TemplateRepositoryInterface
	analyticsRepo    repositories.NotificationAnalyticsRepositoryInterface
	userRepo         repositories.UserRepositoryInterface
	pushService      PushServiceInterface
	emailService     EmailServiceInterface
	smsService       SMSServiceInterface
	webhookService   WebhookServiceInterface
	realtimeService  RealtimeServiceInterface
	cacheService     CacheServiceInterface
	auditService     AuditServiceInterface
	config           *NotificationConfig
}

// NotificationConfig represents notification service configuration
type NotificationConfig struct {
	MaxNotificationsPerUser int
	DefaultPageSize         int
	MaxPageSize             int
	RetryAttempts           int
	RetryDelay              time.Duration
	EnableAnalytics         bool
	EnableRealtime          bool
}

// NotificationServiceInterface defines notification service methods
type NotificationServiceInterface interface {
	// Basic notification management
	GetNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetUnreadNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetReadNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetNotificationCount(ctx context.Context, userID primitive.ObjectID) (*NotificationCountResponse, error)
	GetUnreadCount(ctx context.Context, userID primitive.ObjectID) (*UnreadCountResponse, error)
	GetNotification(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) (*models.NotificationResponse, error)
	UpdateNotification(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID, req *NotificationUpdateRequest) error
	DeleteNotification(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) error

	// Notification actions
	MarkAsRead(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) error
	MarkAsUnread(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) error
	ArchiveNotification(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) error
	UnarchiveNotification(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) error

	// Bulk operations
	MarkAllAsRead(ctx context.Context, userID primitive.ObjectID) error
	BulkMarkAsRead(ctx context.Context, userID primitive.ObjectID, notificationIDs []primitive.ObjectID) error
	ClearAllNotifications(ctx context.Context, userID primitive.ObjectID) error
	BulkDeleteNotifications(ctx context.Context, userID primitive.ObjectID, notificationIDs []primitive.ObjectID) error
	BulkArchiveNotifications(ctx context.Context, userID primitive.ObjectID, notificationIDs []primitive.ObjectID) error

	// Category management
	GetLikeNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetCommentNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetFollowNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetMentionNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetMessageNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetShareNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetSecurityNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetSystemNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)
	GetPromotionNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)

	// Category actions
	MarkCategoryAsRead(ctx context.Context, userID primitive.ObjectID, category models.NotificationType) error
	ClearCategoryNotifications(ctx context.Context, userID primitive.ObjectID, category models.NotificationType) error
	MuteCategoryNotifications(ctx context.Context, userID primitive.ObjectID, category models.NotificationType, duration time.Duration) error
	UnmuteCategoryNotifications(ctx context.Context, userID primitive.ObjectID, category models.NotificationType) error

	// Search and filtering
	SearchNotifications(ctx context.Context, userID primitive.ObjectID, req *SearchNotificationsRequest) (*NotificationListResponse, error)
	FilterNotifications(ctx context.Context, userID primitive.ObjectID, req *FilterNotificationsRequest) (*NotificationListResponse, error)
	GetArchivedNotifications(ctx context.Context, userID primitive.ObjectID, filter *NotificationFilter) (*NotificationListResponse, error)

	// Preferences management
	GetNotificationPreferences(ctx context.Context, userID primitive.ObjectID) (*NotificationPreferencesResponse, error)
	UpdateNotificationPreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateNotificationPreferencesRequest) error
	GetChannelPreferences(ctx context.Context, userID primitive.ObjectID) (*ChannelPreferencesResponse, error)
	UpdateChannelPreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateChannelPreferencesRequest) error
	GetTypePreferences(ctx context.Context, userID primitive.ObjectID) (*TypePreferencesResponse, error)
	UpdateTypePreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateTypePreferencesRequest) error
	GetQuietHours(ctx context.Context, userID primitive.ObjectID) (*QuietHoursResponse, error)
	UpdateQuietHours(ctx context.Context, userID primitive.ObjectID, req *UpdateQuietHoursRequest) error
	GetFrequencySettings(ctx context.Context, userID primitive.ObjectID) (*FrequencySettingsResponse, error)
	UpdateFrequencySettings(ctx context.Context, userID primitive.ObjectID, req *UpdateFrequencySettingsRequest) error

	// Notification rules
	GetNotificationRules(ctx context.Context, userID primitive.ObjectID) (*NotificationRulesResponse, error)
	CreateNotificationRule(ctx context.Context, userID primitive.ObjectID, req *CreateNotificationRuleRequest) (*NotificationRuleResponse, error)
	UpdateNotificationRule(ctx context.Context, userID primitive.ObjectID, ruleID primitive.ObjectID, req *UpdateNotificationRuleRequest) error
	DeleteNotificationRule(ctx context.Context, userID primitive.ObjectID, ruleID primitive.ObjectID) error

	// Push notifications
	RegisterDevice(ctx context.Context, userID primitive.ObjectID, req *RegisterDeviceRequest) (*DeviceResponse, error)
	UpdateDevice(ctx context.Context, userID primitive.ObjectID, deviceID primitive.ObjectID, req *UpdateDeviceRequest) error
	UnregisterDevice(ctx context.Context, userID primitive.ObjectID, deviceID primitive.ObjectID) error
	GetRegisteredDevices(ctx context.Context, userID primitive.ObjectID) (*RegisteredDevicesResponse, error)
	SendTestPushNotification(ctx context.Context, userID primitive.ObjectID, req *TestPushRequest) error
	GetPushPreferences(ctx context.Context, userID primitive.ObjectID) (*PushPreferencesResponse, error)
	UpdatePushPreferences(ctx context.Context, userID primitive.ObjectID, req *UpdatePushPreferencesRequest) error
	RegisterPushToken(ctx context.Context, userID primitive.ObjectID, req *RegisterPushTokenRequest) error
	UnregisterPushToken(ctx context.Context, userID primitive.ObjectID, token string) error

	// Email notifications
	GetEmailPreferences(ctx context.Context, userID primitive.ObjectID) (*EmailPreferencesResponse, error)
	UpdateEmailPreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateEmailPreferencesRequest) error
	GetEmailDigestSettings(ctx context.Context, userID primitive.ObjectID) (*EmailDigestSettingsResponse, error)
	UpdateEmailDigestSettings(ctx context.Context, userID primitive.ObjectID, req *UpdateEmailDigestSettingsRequest) error
	UnsubscribeFromEmails(ctx context.Context, userID primitive.ObjectID, req *EmailUnsubscribeRequest) error
	ResubscribeToEmails(ctx context.Context, userID primitive.ObjectID, req *EmailResubscribeRequest) error
	GetUnsubscribeStatus(ctx context.Context, userID primitive.ObjectID) (*UnsubscribeStatusResponse, error)
	GetEmailTemplates(ctx context.Context, userID primitive.ObjectID) (*EmailTemplatesResponse, error)
	PreviewEmailTemplate(ctx context.Context, userID primitive.ObjectID, templateID primitive.ObjectID) (*EmailTemplatePreviewResponse, error)
	GetEmailDeliveryStatus(ctx context.Context, userID primitive.ObjectID) (*EmailDeliveryStatusResponse, error)
	GetEmailDeliveryDetails(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) (*EmailDeliveryDetailsResponse, error)

	// SMS notifications
	GetSMSPreferences(ctx context.Context, userID primitive.ObjectID) (*SMSPreferencesResponse, error)
	UpdateSMSPreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateSMSPreferencesRequest) error
	VerifyPhoneNumber(ctx context.Context, userID primitive.ObjectID, req *VerifyPhoneRequest) error
	ConfirmPhoneNumber(ctx context.Context, userID primitive.ObjectID, req *ConfirmPhoneRequest) error
	RemovePhoneNumber(ctx context.Context, userID primitive.ObjectID) error
	GetSMSDeliveryStatus(ctx context.Context, userID primitive.ObjectID) (*SMSDeliveryStatusResponse, error)
	GetSMSDeliveryDetails(ctx context.Context, userID primitive.ObjectID, notificationID primitive.ObjectID) (*SMSDeliveryDetailsResponse, error)

	// Templates (admin only)
	GetNotificationTemplates(ctx context.Context) (*NotificationTemplatesResponse, error)
	CreateNotificationTemplate(ctx context.Context, req *CreateNotificationTemplateRequest) (*NotificationTemplateResponse, error)
	UpdateNotificationTemplate(ctx context.Context, templateID primitive.ObjectID, req *UpdateNotificationTemplateRequest) error
	DeleteNotificationTemplate(ctx context.Context, templateID primitive.ObjectID) error
	PreviewNotificationTemplate(ctx context.Context, templateID primitive.ObjectID, req *PreviewNotificationTemplateRequest) (*NotificationTemplatePreviewResponse, error)
	TestNotificationTemplate(ctx context.Context, templateID primitive.ObjectID, req *TestNotificationTemplateRequest) error

	// Analytics
	GetNotificationStats(ctx context.Context, userID primitive.ObjectID) (*NotificationStatsResponse, error)
	GetNotificationEngagement(ctx context.Context, userID primitive.ObjectID) (*NotificationEngagementResponse, error)
	GetDeliveryRates(ctx context.Context, userID primitive.ObjectID) (*DeliveryRatesResponse, error)
	GetOpenRates(ctx context.Context, userID primitive.ObjectID) (*OpenRatesResponse, error)
	GetChannelPerformance(ctx context.Context, userID primitive.ObjectID) (*ChannelPerformanceResponse, error)
	GetChannelPreferenceStats(ctx context.Context, userID primitive.ObjectID) (*ChannelPreferenceStatsResponse, error)
	GetUserNotificationBehavior(ctx context.Context, userID primitive.ObjectID) (*UserNotificationBehaviorResponse, error)
	GetInteractionPatterns(ctx context.Context, userID primitive.ObjectID) (*InteractionPatternsResponse, error)
	GetHourlyNotificationStats(ctx context.Context, userID primitive.ObjectID) (*HourlyNotificationStatsResponse, error)
	GetDailyNotificationStats(ctx context.Context, userID primitive.ObjectID) (*DailyNotificationStatsResponse, error)
	GetWeeklyNotificationStats(ctx context.Context, userID primitive.ObjectID) (*WeeklyNotificationStatsResponse, error)
	GetABTestResults(ctx context.Context) (*ABTestResultsResponse, error)

	// Webhooks
	GetWebhooks(ctx context.Context, userID primitive.ObjectID) (*WebhooksResponse, error)
	CreateWebhook(ctx context.Context, userID primitive.ObjectID, req *CreateWebhookRequest) (*WebhookResponse, error)
	UpdateWebhook(ctx context.Context, userID primitive.ObjectID, webhookID primitive.ObjectID, req *UpdateWebhookRequest) error
	DeleteWebhook(ctx context.Context, userID primitive.ObjectID, webhookID primitive.ObjectID) error
	TestWebhook(ctx context.Context, userID primitive.ObjectID, webhookID primitive.ObjectID) error
	GetWebhookLogs(ctx context.Context, userID primitive.ObjectID, webhookID primitive.ObjectID) (*WebhookLogsResponse, error)
	GetWebhookEvents(ctx context.Context, userID primitive.ObjectID) (*WebhookEventsResponse, error)
	TriggerWebhookEvent(ctx context.Context, userID primitive.ObjectID, webhookID primitive.ObjectID, req *TriggerWebhookEventRequest) error

	// Real-time notifications
	ConnectWebSocket(ctx context.Context, userID primitive.ObjectID, connectionID string) error
	StreamNotifications(ctx context.Context, userID primitive.ObjectID, connectionID string) (<-chan *models.Notification, error)
	GetRealtimePreferences(ctx context.Context, userID primitive.ObjectID) (*RealtimePreferencesResponse, error)
	UpdateRealtimePreferences(ctx context.Context, userID primitive.ObjectID, req *UpdateRealtimePreferencesRequest) error
	GetActiveConnections(ctx context.Context, userID primitive.ObjectID) (*ActiveConnectionsResponse, error)
	DisconnectConnection(ctx context.Context, userID primitive.ObjectID, connectionID string) error
	Heartbeat(ctx context.Context, userID primitive.ObjectID, connectionID string) error
	GetConnectionStatus(ctx context.Context, userID primitive.ObjectID, connectionID string) (*ConnectionStatusResponse, error)

	// Internal methods
	CreateNotification(ctx context.Context, req *models.NotificationCreateRequest) (*models.Notification, error)
	SendNotification(ctx context.Context, notification *models.Notification) error
	ProcessScheduledNotifications(ctx context.Context) error
	CleanupExpiredNotifications(ctx context.Context) error
}

// =============================================================================
// REQUEST/RESPONSE TYPES
// =============================================================================

// NotificationFilter represents notification filtering options
type NotificationFilter struct {
	Type       *models.NotificationType     `json:"type,omitempty"`
	Priority   *models.NotificationPriority `json:"priority,omitempty"`
	IsRead     *bool                        `json:"is_read,omitempty"`
	IsArchived *bool                        `json:"is_archived,omitempty"`
	StartDate  *time.Time                   `json:"start_date,omitempty"`
	EndDate    *time.Time                   `json:"end_date,omitempty"`
	Page       int                          `json:"page"`
	Limit      int                          `json:"limit"`
	SortBy     string                       `json:"sort_by"`
	SortOrder  string                       `json:"sort_order"`
}

// NotificationListResponse represents paginated notification response
type NotificationListResponse struct {
	Notifications []models.NotificationResponse `json:"notifications"`
	TotalCount    int64                         `json:"total_count"`
	UnreadCount   int64                         `json:"unread_count"`
	Page          int                           `json:"page"`
	Limit         int                           `json:"limit"`
	HasMore       bool                          `json:"has_more"`
}

// NotificationCountResponse represents notification count response
type NotificationCountResponse struct {
	Total    int64 `json:"total"`
	Unread   int64 `json:"unread"`
	Read     int64 `json:"read"`
	Archived int64 `json:"archived"`
}

// UnreadCountResponse represents unread count response
type UnreadCountResponse struct {
	Count int64 `json:"count"`
}

// NotificationUpdateRequest represents notification update request
type NotificationUpdateRequest struct {
	IsRead     *bool `json:"is_read"`
	IsArchived *bool `json:"is_archived"`
}

// SearchNotificationsRequest represents notification search request
type SearchNotificationsRequest struct {
	Query    string                   `json:"q"`
	Type     *models.NotificationType `json:"type,omitempty"`
	IsRead   *bool                    `json:"read,omitempty"`
	DateFrom *time.Time               `json:"date_from,omitempty"`
	DateTo   *time.Time               `json:"date_to,omitempty"`
	Page     int                      `json:"page"`
	Limit    int                      `json:"limit"`
}

// FilterNotificationsRequest represents notification filter request
type FilterNotificationsRequest struct {
	Type       *models.NotificationType     `json:"type,omitempty"`
	Priority   *models.NotificationPriority `json:"priority,omitempty"`
	IsRead     *bool                        `json:"is_read,omitempty"`
	IsArchived *bool                        `json:"is_archived,omitempty"`
	StartDate  *time.Time                   `json:"start_date,omitempty"`
	EndDate    *time.Time                   `json:"end_date,omitempty"`
	Page       int                          `json:"page"`
	Limit      int                          `json:"limit"`
}



// ChannelPreferencesResponse represents channel preferences
type ChannelPreferencesResponse struct {
	Likes    map[string]bool `json:"likes"`
	Comments map[string]bool `json:"comments"`
	Follows  map[string]bool `json:"follows"`
	Mentions map[string]bool `json:"mentions"`
	Messages map[string]bool `json:"messages"`
}

// UpdateChannelPreferencesRequest represents channel preferences update
type UpdateChannelPreferencesRequest struct {
	Likes    map[string]bool `json:"likes,omitempty"`
	Comments map[string]bool `json:"comments,omitempty"`
	Follows  map[string]bool `json:"follows,omitempty"`
	Mentions map[string]bool `json:"mentions,omitempty"`
	Messages map[string]bool `json:"messages,omitempty"`
}

// TypePreferencesResponse represents type preferences
type TypePreferencesResponse struct {
	Types map[models.NotificationType]bool `json:"types"`
}

// UpdateTypePreferencesRequest represents type preferences update
type UpdateTypePreferencesRequest struct {
	Types map[models.NotificationType]bool `json:"types"`
}

// QuietHoursResponse represents quiet hours settings
type QuietHoursResponse struct {
	Enabled   bool   `json:"enabled"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Timezone  string `json:"timezone"`
}

// UpdateQuietHoursRequest represents quiet hours update
type UpdateQuietHoursRequest struct {
	Enabled   bool   `json:"enabled"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
}

// FrequencySettingsResponse represents frequency settings
type FrequencySettingsResponse struct {
	MaxPerHour int `json:"max_per_hour"`
	MaxPerDay  int `json:"max_per_day"`
	MaxPerWeek int `json:"max_per_week"`
}

// UpdateFrequencySettingsRequest represents frequency settings update
type UpdateFrequencySettingsRequest struct {
	MaxPerHour *int `json:"max_per_hour,omitempty"`
	MaxPerDay  *int `json:"max_per_day,omitempty"`
	MaxPerWeek *int `json:"max_per_week,omitempty"`
}

// NotificationRulesResponse represents notification rules
type NotificationRulesResponse struct {
	Rules []models.NotificationRule `json:"rules"`
}

// CreateNotificationRuleRequest represents rule creation request
type CreateNotificationRuleRequest struct {
	Name       string                 `json:"name"`
	Conditions []models.RuleCondition `json:"conditions"`
	Actions    []models.RuleAction    `json:"actions"`
	Priority   int                    `json:"priority"`
	IsActive   bool                   `json:"is_active"`
}

// UpdateNotificationRuleRequest represents rule update request
type UpdateNotificationRuleRequest struct {
	Name       *string                `json:"name,omitempty"`
	Conditions []models.RuleCondition `json:"conditions,omitempty"`
	Actions    []models.RuleAction    `json:"actions,omitempty"`
	Priority   *int                   `json:"priority,omitempty"`
	IsActive   *bool                  `json:"is_active,omitempty"`
}

// NotificationRuleResponse represents rule response
type NotificationRuleResponse struct {
	*models.NotificationRule
}

// RegisterDeviceRequest represents device registration request
type RegisterDeviceRequest struct {
	DeviceToken string            `json:"device_token"`
	DeviceType  models.DeviceType `json:"device_type"`
	DeviceName  string            `json:"device_name,omitempty"`
	AppVersion  string            `json:"app_version,omitempty"`
}

// UpdateDeviceRequest represents device update request
type UpdateDeviceRequest struct {
	DeviceName *string `json:"device_name,omitempty"`
	AppVersion *string `json:"app_version,omitempty"`
	IsActive   *bool   `json:"is_active,omitempty"`
}

// DeviceResponse represents device response
type DeviceResponse struct {
	*models.Device
}

// RegisteredDevicesResponse represents registered devices response
type RegisteredDevicesResponse struct {
	Devices []DeviceResponse `json:"devices"`
}

// TestPushRequest represents test push notification request
type TestPushRequest struct {
	Message string `json:"message"`
	Title   string `json:"title,omitempty"`
}

// PushPreferencesResponse represents push preferences
type PushPreferencesResponse struct {
	Enabled    bool                             `json:"enabled"`
	Types      map[models.NotificationType]bool `json:"types"`
	QuietHours models.QuietHours                `json:"quiet_hours"`
}

// UpdatePushPreferencesRequest represents push preferences update
type UpdatePushPreferencesRequest struct {
	Enabled    *bool                            `json:"enabled,omitempty"`
	Types      map[models.NotificationType]bool `json:"types,omitempty"`
	QuietHours *models.QuietHours               `json:"quiet_hours,omitempty"`
}

// RegisterPushTokenRequest represents push token registration
type RegisterPushTokenRequest struct {
	Token       string              `json:"token"`
	Platform    models.PushPlatform `json:"platform"`
	Environment string              `json:"environment,omitempty"`
}

// EmailPreferencesResponse represents email preferences
type EmailPreferencesResponse struct {
	*models.EmailPreferences
}

// UpdateEmailPreferencesRequest represents email preferences update
type UpdateEmailPreferencesRequest struct {
	MarketingEmails *bool                   `json:"marketing_emails,omitempty"`
	DigestEmails    *bool                   `json:"digest_emails,omitempty"`
	SecurityAlerts  *bool                   `json:"security_alerts,omitempty"`
	SocialUpdates   *bool                   `json:"social_updates,omitempty"`
	ProductUpdates  *bool                   `json:"product_updates,omitempty"`
	DigestFrequency *models.DigestFrequency `json:"digest_frequency,omitempty"`
	DigestTime      *string                 `json:"digest_time,omitempty"`
}

// EmailDigestSettingsResponse represents email digest settings
type EmailDigestSettingsResponse struct {
	Enabled   bool                      `json:"enabled"`
	Frequency models.DigestFrequency    `json:"frequency"`
	Time      string                    `json:"time"`
	Types     []models.NotificationType `json:"types"`
}

// UpdateEmailDigestSettingsRequest represents digest settings update
type UpdateEmailDigestSettingsRequest struct {
	Enabled   *bool                     `json:"enabled,omitempty"`
	Frequency *models.DigestFrequency   `json:"frequency,omitempty"`
	Time      *string                   `json:"time,omitempty"`
	Types     []models.NotificationType `json:"types,omitempty"`
}

// EmailUnsubscribeRequest represents email unsubscribe request
type EmailUnsubscribeRequest struct {
	Types []string `json:"types,omitempty"`
	All   bool     `json:"all,omitempty"`
}

// EmailResubscribeRequest represents email resubscribe request
type EmailResubscribeRequest struct {
	Types []string `json:"types,omitempty"`
}

// UnsubscribeStatusResponse represents unsubscribe status
type UnsubscribeStatusResponse struct {
	IsUnsubscribed    bool      `json:"is_unsubscribed"`
	UnsubscribedTypes []string  `json:"unsubscribed_types"`
	UnsubscribedAt    time.Time `json:"unsubscribed_at,omitempty"`
}

// EmailTemplatesResponse represents email templates
type EmailTemplatesResponse struct {
	Templates []models.NotificationTemplate `json:"templates"`
}

// EmailTemplatePreviewResponse represents template preview
type EmailTemplatePreviewResponse struct {
	Subject string `json:"subject"`
	Content string `json:"content"`
	HTML    string `json:"html"`
}

// EmailDeliveryStatusResponse represents email delivery status
type EmailDeliveryStatusResponse struct {
	TotalSent      int64   `json:"total_sent"`
	TotalDelivered int64   `json:"total_delivered"`
	TotalFailed    int64   `json:"total_failed"`
	DeliveryRate   float64 `json:"delivery_rate"`
}

// EmailDeliveryDetailsResponse represents email delivery details
type EmailDeliveryDetailsResponse struct {
	*models.DeliveryStatus
}

// SMSPreferencesResponse represents SMS preferences
type SMSPreferencesResponse struct {
	*models.SMSPreferences
}

// UpdateSMSPreferencesRequest represents SMS preferences update
type UpdateSMSPreferencesRequest struct {
	SecurityAlerts  *bool `json:"security_alerts,omitempty"`
	CriticalUpdates *bool `json:"critical_updates,omitempty"`
}

// VerifyPhoneRequest represents phone verification request
type VerifyPhoneRequest struct {
	PhoneNumber string `json:"phone_number"`
	CountryCode string `json:"country_code"`
}

// ConfirmPhoneRequest represents phone confirmation request
type ConfirmPhoneRequest struct {
	VerificationCode string `json:"verification_code"`
}

// SMSDeliveryStatusResponse represents SMS delivery status
type SMSDeliveryStatusResponse struct {
	TotalSent      int64   `json:"total_sent"`
	TotalDelivered int64   `json:"total_delivered"`
	TotalFailed    int64   `json:"total_failed"`
	DeliveryRate   float64 `json:"delivery_rate"`
}

// SMSDeliveryDetailsResponse represents SMS delivery details
type SMSDeliveryDetailsResponse struct {
	*models.DeliveryStatus
}

// NotificationTemplatesResponse represents templates response
type NotificationTemplatesResponse struct {
	Templates []models.NotificationTemplate `json:"templates"`
}

// CreateNotificationTemplateRequest represents template creation
type CreateNotificationTemplateRequest struct {
	Name      string                     `json:"name"`
	Type      models.NotificationType    `json:"type"`
	Channel   models.NotificationChannel `json:"channel"`
	Subject   string                     `json:"subject,omitempty"`
	Content   string                     `json:"content"`
	Variables []models.TemplateVariable  `json:"variables,omitempty"`
	Settings  map[string]interface{}     `json:"settings,omitempty"`
}

// UpdateNotificationTemplateRequest represents template update
type UpdateNotificationTemplateRequest struct {
	Name      *string                   `json:"name,omitempty"`
	Subject   *string                   `json:"subject,omitempty"`
	Content   *string                   `json:"content,omitempty"`
	Variables []models.TemplateVariable `json:"variables,omitempty"`
	Settings  map[string]interface{}    `json:"settings,omitempty"`
	IsActive  *bool                     `json:"is_active,omitempty"`
}

// NotificationTemplateResponse represents template response
type NotificationTemplateResponse struct {
	*models.NotificationTemplate
}

// PreviewNotificationTemplateRequest represents template preview request
type PreviewNotificationTemplateRequest struct {
	Variables map[string]interface{} `json:"variables"`
}

// NotificationTemplatePreviewResponse represents template preview
type NotificationTemplatePreviewResponse struct {
	Subject string `json:"subject,omitempty"`
	Content string `json:"content"`
	HTML    string `json:"html,omitempty"`
}

// TestNotificationTemplateRequest represents template test request
type TestNotificationTemplateRequest struct {
	UserID    primitive.ObjectID     `json:"user_id"`
	Variables map[string]interface{} `json:"variables"`
}

// NotificationStatsResponse represents notification stats
type NotificationStatsResponse struct {
	TotalSent      int64                                 `json:"total_sent"`
	TotalDelivered int64                                 `json:"total_delivered"`
	TotalRead      int64                                 `json:"total_read"`
	TotalFailed    int64                                 `json:"total_failed"`
	DeliveryRate   float64                               `json:"delivery_rate"`
	ReadRate       float64                               `json:"read_rate"`
	FailureRate    float64                               `json:"failure_rate"`
	ByType         map[models.NotificationType]int64     `json:"by_type"`
	ByChannel      map[models.NotificationChannel]int64  `json:"by_channel"`
	ByPriority     map[models.NotificationPriority]int64 `json:"by_priority"`
}

// NotificationEngagementResponse represents engagement metrics
type NotificationEngagementResponse struct {
	EngagementRate   float64                                `json:"engagement_rate"`
	ClickThroughRate float64                                `json:"click_through_rate"`
	TimeToRead       float64                                `json:"time_to_read"`
	ByType           map[models.NotificationType]float64    `json:"by_type"`
	ByChannel        map[models.NotificationChannel]float64 `json:"by_channel"`
}

// DeliveryRatesResponse represents delivery rates
type DeliveryRatesResponse struct {
	Overall   float64                                `json:"overall"`
	ByChannel map[models.NotificationChannel]float64 `json:"by_channel"`
	ByType    map[models.NotificationType]float64    `json:"by_type"`
	Trends    []DailyRate                            `json:"trends"`
}

// OpenRatesResponse represents open rates
type OpenRatesResponse struct {
	Overall   float64                                `json:"overall"`
	ByChannel map[models.NotificationChannel]float64 `json:"by_channel"`
	ByType    map[models.NotificationType]float64    `json:"by_type"`
	Trends    []DailyRate                            `json:"trends"`
}

// DailyRate represents daily rate data
type DailyRate struct {
	Date string  `json:"date"`
	Rate float64 `json:"rate"`
}

// ChannelPerformanceResponse represents channel performance
type ChannelPerformanceResponse struct {
	Channels []ChannelPerformance `json:"channels"`
}

// ChannelPerformance represents individual channel performance
type ChannelPerformance struct {
	Channel      models.NotificationChannel `json:"channel"`
	DeliveryRate float64                    `json:"delivery_rate"`
	OpenRate     float64                    `json:"open_rate"`
	ClickRate    float64                    `json:"click_rate"`
	TotalSent    int64                      `json:"total_sent"`
}

// ChannelPreferenceStatsResponse represents channel preference stats
type ChannelPreferenceStatsResponse struct {
	Preferences map[models.NotificationChannel]int64 `json:"preferences"`
	Trends      []ChannelTrend                       `json:"trends"`
}

// ChannelTrend represents channel trend data
type ChannelTrend struct {
	Date    string                               `json:"date"`
	Enabled map[models.NotificationChannel]int64 `json:"enabled"`
}

// UserNotificationBehaviorResponse represents user behavior
type UserNotificationBehaviorResponse struct {
	AverageTimeToRead float64            `json:"average_time_to_read"`
	PreferredChannels []string           `json:"preferred_channels"`
	ActiveHours       []int              `json:"active_hours"`
	ReadPatterns      map[string]float64 `json:"read_patterns"`
	EngagementScore   float64            `json:"engagement_score"`
}

// InteractionPatternsResponse represents interaction patterns
type InteractionPatternsResponse struct {
	HourlyActivity  []HourlyActivity  `json:"hourly_activity"`
	DailyActivity   []DailyActivity   `json:"daily_activity"`
	WeeklyActivity  []WeeklyActivity  `json:"weekly_activity"`
	DeviceBreakdown []DeviceBreakdown `json:"device_breakdown"`
}

// HourlyActivity represents hourly activity data
type HourlyActivity struct {
	Hour  int   `json:"hour"`
	Count int64 `json:"count"`
}

// DailyActivity represents daily activity data
type DailyActivity struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// WeeklyActivity represents weekly activity data
type WeeklyActivity struct {
	Week  string `json:"week"`
	Count int64  `json:"count"`
}

// DeviceBreakdown represents device breakdown data
type DeviceBreakdown struct {
	DeviceType models.DeviceType `json:"device_type"`
	Count      int64             `json:"count"`
	Percentage float64           `json:"percentage"`
}

// HourlyNotificationStatsResponse represents hourly stats
type HourlyNotificationStatsResponse struct {
	Stats []HourlyStats `json:"stats"`
}

// HourlyStats represents hourly statistics
type HourlyStats struct {
	Hour      int     `json:"hour"`
	TotalSent int64   `json:"total_sent"`
	TotalRead int64   `json:"total_read"`
	ReadRate  float64 `json:"read_rate"`
}

// DailyNotificationStatsResponse represents daily stats
type DailyNotificationStatsResponse struct {
	Stats []DailyStats `json:"stats"`
}

// DailyStats represents daily statistics
type DailyStats struct {
	Date      string  `json:"date"`
	TotalSent int64   `json:"total_sent"`
	TotalRead int64   `json:"total_read"`
	ReadRate  float64 `json:"read_rate"`
}

// WeeklyNotificationStatsResponse represents weekly stats
type WeeklyNotificationStatsResponse struct {
	Stats []WeeklyStats `json:"stats"`
}

// WeeklyStats represents weekly statistics
type WeeklyStats struct {
	Week      string  `json:"week"`
	TotalSent int64   `json:"total_sent"`
	TotalRead int64   `json:"total_read"`
	ReadRate  float64 `json:"read_rate"`
}

// ABTestResultsResponse represents A/B test results
type ABTestResultsResponse struct {
	Tests []ABTestResult `json:"tests"`
}

// ABTestResult represents A/B test result
type ABTestResult struct {
	TestName        string  `json:"test_name"`
	VariantA        string  `json:"variant_a"`
	VariantB        string  `json:"variant_b"`
	ConversionRateA float64 `json:"conversion_rate_a"`
	ConversionRateB float64 `json:"conversion_rate_b"`
	Significance    float64 `json:"significance"`
	Winner          string  `json:"winner"`
}

// WebhooksResponse represents webhooks response
type WebhooksResponse struct {
	Webhooks []models.NotificationWebhook `json:"webhooks"`
}

// CreateWebhookRequest represents webhook creation request
type CreateWebhookRequest struct {
	URL     string                `json:"url"`
	Events  []models.WebhookEvent `json:"events"`
	Secret  string                `json:"secret,omitempty"`
	Headers map[string]string     `json:"headers,omitempty"`
}

// UpdateWebhookRequest represents webhook update request
type UpdateWebhookRequest struct {
	URL      *string               `json:"url,omitempty"`
	Events   []models.WebhookEvent `json:"events,omitempty"`
	Secret   *string               `json:"secret,omitempty"`
	Headers  map[string]string     `json:"headers,omitempty"`
	IsActive *bool                 `json:"is_active,omitempty"`
}

// WebhookResponse represents webhook response
type WebhookResponse struct {
	*models.NotificationWebhook
}

// WebhookLogsResponse represents webhook logs response
type WebhookLogsResponse struct {
	Logs []models.WebhookLog `json:"logs"`
}

// WebhookEventsResponse represents webhook events response
type WebhookEventsResponse struct {
	Events []models.WebhookEvent `json:"events"`
}

// TriggerWebhookEventRequest represents webhook event trigger request
type TriggerWebhookEventRequest struct {
	Event   models.WebhookEvent    `json:"event"`
	Payload map[string]interface{} `json:"payload"`
}

// RealtimePreferencesResponse represents realtime preferences
type RealtimePreferencesResponse struct {
	*models.RealtimePreferences
}

// UpdateRealtimePreferencesRequest represents realtime preferences update
type UpdateRealtimePreferencesRequest struct {
	AutoConnect       *bool                     `json:"auto_connect,omitempty"`
	ConnectionTimeout *int                      `json:"connection_timeout,omitempty"`
	ReconnectAttempts *int                      `json:"reconnect_attempts,omitempty"`
	HeartbeatInterval *int                      `json:"heartbeat_interval,omitempty"`
	EnabledTypes      []models.NotificationType `json:"enabled_types,omitempty"`
}

// ActiveConnectionsResponse represents active connections
type ActiveConnectionsResponse struct {
	Connections []models.RealtimeConnection `json:"connections"`
}

// ConnectionStatusResponse represents connection status
type ConnectionStatusResponse struct {
	IsConnected   bool       `json:"is_connected"`
	ConnectionID  string     `json:"connection_id,omitempty"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
}
