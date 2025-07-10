package handlers

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"bro-network/internal/middleware"
	"bro-network/internal/models"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NotificationHandler handles notification-related HTTP requests
type NotificationHandler struct {
	notificationService services.NotificationServiceInterface
	authMiddleware      *middleware.AuthMiddleware
	upgrader            websocket.Upgrader
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(
	notificationService services.NotificationServiceInterface,
	authMiddleware *middleware.AuthMiddleware,
) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
		authMiddleware:      authMiddleware,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// =============================================================================
// BASIC NOTIFICATION MANAGEMENT
// =============================================================================

// GetNotifications retrieves user's notifications
func (h *NotificationHandler) GetNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filter := h.buildNotificationFilter(c)
	response, err := h.notificationService.GetNotifications(c.Request.Context(), userID, filter)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notifications retrieved successfully")
}

// GetUnreadNotifications retrieves user's unread notifications
func (h *NotificationHandler) GetUnreadNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filter := h.buildNotificationFilter(c)
	response, err := h.notificationService.GetUnreadNotifications(c.Request.Context(), userID, filter)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_UNREAD_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Unread notifications retrieved successfully")
}

// GetReadNotifications retrieves user's read notifications
func (h *NotificationHandler) GetReadNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filter := h.buildNotificationFilter(c)
	response, err := h.notificationService.GetReadNotifications(c.Request.Context(), userID, filter)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_READ_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Read notifications retrieved successfully")
}

// GetNotificationCount retrieves notification counts
func (h *NotificationHandler) GetNotificationCount(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetNotificationCount(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_COUNT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification count retrieved successfully")
}

// GetUnreadCount retrieves unread notification count
func (h *NotificationHandler) GetUnreadCount(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetUnreadCount(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_UNREAD_COUNT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Unread count retrieved successfully")
}

// GetNotification retrieves a specific notification
func (h *NotificationHandler) GetNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	response, err := h.notificationService.GetNotification(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification retrieved successfully")
}

// UpdateNotification updates a notification
func (h *NotificationHandler) UpdateNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.NotificationUpdateRequest{}
	if isRead, ok := validatedData["is_read"].(bool); ok {
		req.IsRead = &isRead
	}
	if isArchived, ok := validatedData["is_archived"].(bool); ok {
		req.IsArchived = &isArchived
	}

	err = h.notificationService.UpdateNotification(c.Request.Context(), userID, notificationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_NOTIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification updated successfully")
}

// DeleteNotification deletes a notification
func (h *NotificationHandler) DeleteNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	err = h.notificationService.DeleteNotification(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_NOTIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification deleted successfully")
}

// =============================================================================
// NOTIFICATION ACTIONS
// =============================================================================

// MarkAsRead marks a notification as read
func (h *NotificationHandler) MarkAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	err = h.notificationService.MarkAsRead(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_AS_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification marked as read")
}

// MarkAsUnread marks a notification as unread
func (h *NotificationHandler) MarkAsUnread(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	err = h.notificationService.MarkAsUnread(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_AS_UNREAD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification marked as unread")
}

// ArchiveNotification archives a notification
func (h *NotificationHandler) ArchiveNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	err = h.notificationService.ArchiveNotification(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "ARCHIVE_NOTIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification archived successfully")
}

// UnarchiveNotification unarchives a notification
func (h *NotificationHandler) UnarchiveNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	err = h.notificationService.UnarchiveNotification(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNARCHIVE_NOTIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification unarchived successfully")
}

// =============================================================================
// BULK OPERATIONS
// =============================================================================

// MarkAllAsRead marks all notifications as read
func (h *NotificationHandler) MarkAllAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	err := h.notificationService.MarkAllAsRead(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_ALL_AS_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "All notifications marked as read")
}

// BulkMarkAsRead marks multiple notifications as read
func (h *NotificationHandler) BulkMarkAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	notificationIDStrings, ok := validatedData["notification_ids"].([]interface{})
	if !ok {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_IDS", "Invalid notification IDs")
		return
	}

	var notificationIDs []primitive.ObjectID
	for _, idStr := range notificationIDStrings {
		if idString, ok := idStr.(string); ok {
			if objectID, err := primitive.ObjectIDFromHex(idString); err == nil {
				notificationIDs = append(notificationIDs, objectID)
			}
		}
	}

	err := h.notificationService.BulkMarkAsRead(c.Request.Context(), userID, notificationIDs)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "BULK_MARK_AS_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notifications marked as read")
}

// ClearAllNotifications clears all notifications
func (h *NotificationHandler) ClearAllNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	err := h.notificationService.ClearAllNotifications(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CLEAR_ALL_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "All notifications cleared")
}

// BulkDeleteNotifications deletes multiple notifications
func (h *NotificationHandler) BulkDeleteNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	notificationIDs := h.extractNotificationIDs(validatedData["notification_ids"])
	if len(notificationIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_IDS", "Invalid notification IDs")
		return
	}

	err := h.notificationService.BulkDeleteNotifications(c.Request.Context(), userID, notificationIDs)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "BULK_DELETE_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notifications deleted successfully")
}

// BulkArchiveNotifications archives multiple notifications
func (h *NotificationHandler) BulkArchiveNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	notificationIDs := h.extractNotificationIDs(validatedData["notification_ids"])
	if len(notificationIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_IDS", "Invalid notification IDs")
		return
	}

	err := h.notificationService.BulkArchiveNotifications(c.Request.Context(), userID, notificationIDs)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "BULK_ARCHIVE_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notifications archived successfully")
}

// =============================================================================
// CATEGORY MANAGEMENT
// =============================================================================

// GetLikeNotifications retrieves like notifications
func (h *NotificationHandler) GetLikeNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeLike)
}

// GetCommentNotifications retrieves comment notifications
func (h *NotificationHandler) GetCommentNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeComment)
}

// GetFollowNotifications retrieves follow notifications
func (h *NotificationHandler) GetFollowNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeFollow)
}

// GetMentionNotifications retrieves mention notifications
func (h *NotificationHandler) GetMentionNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeMention)
}

// GetMessageNotifications retrieves message notifications
func (h *NotificationHandler) GetMessageNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeMessage)
}

// GetShareNotifications retrieves share notifications
func (h *NotificationHandler) GetShareNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeShare)
}

// GetSecurityNotifications retrieves security notifications
func (h *NotificationHandler) GetSecurityNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeSecurityAlert)
}

// GetSystemNotifications retrieves system notifications
func (h *NotificationHandler) GetSystemNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypeUpdate)
}

// GetPromotionNotifications retrieves promotion notifications
func (h *NotificationHandler) GetPromotionNotifications(c *gin.Context) {
	h.getCategoryNotifications(c, models.NotificationTypePromotion)
}

// MarkCategoryAsRead marks all notifications in a category as read
func (h *NotificationHandler) MarkCategoryAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	category := models.NotificationType(c.Param("category"))
	err := h.notificationService.MarkCategoryAsRead(c.Request.Context(), userID, category)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_CATEGORY_AS_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Category notifications marked as read")
}

// ClearCategoryNotifications clears all notifications in a category
func (h *NotificationHandler) ClearCategoryNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	category := models.NotificationType(c.Param("category"))
	err := h.notificationService.ClearCategoryNotifications(c.Request.Context(), userID, category)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CLEAR_CATEGORY_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Category notifications cleared")
}

// MuteCategoryNotifications mutes notifications for a category
func (h *NotificationHandler) MuteCategoryNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	category := models.NotificationType(c.Param("category"))
	duration := time.Hour * 24 // Default duration
	if durationStr, ok := validatedData["duration"].(string); ok {
		if parsedDuration, err := time.ParseDuration(durationStr); err == nil {
			duration = parsedDuration
		}
	}

	err := h.notificationService.MuteCategoryNotifications(c.Request.Context(), userID, category, duration)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MUTE_CATEGORY_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Category notifications muted")
}

// UnmuteCategoryNotifications unmutes notifications for a category
func (h *NotificationHandler) UnmuteCategoryNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	category := models.NotificationType(c.Param("category"))
	err := h.notificationService.UnmuteCategoryNotifications(c.Request.Context(), userID, category)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNMUTE_CATEGORY_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Category notifications unmuted")
}

// =============================================================================
// SEARCH AND FILTERING
// =============================================================================

// SearchNotifications searches notifications
func (h *NotificationHandler) SearchNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.SearchNotificationsRequest{
		Query: validatedData["q"].(string),
		Page:  h.getIntParam(c, "page", 1),
		Limit: h.getIntParam(c, "limit", 20),
	}

	if typeStr, ok := validatedData["type"].(string); ok {
		notifType := models.NotificationType(typeStr)
		req.Type = &notifType
	}

	if isRead, ok := validatedData["read"].(bool); ok {
		req.IsRead = &isRead
	}

	response, err := h.notificationService.SearchNotifications(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notifications searched successfully")
}

// FilterNotifications filters notifications
func (h *NotificationHandler) FilterNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.FilterNotificationsRequest{
		Page:  h.getIntParam(c, "page", 1),
		Limit: h.getIntParam(c, "limit", 20),
	}

	h.populateFilterRequest(req, validatedData)

	response, err := h.notificationService.FilterNotifications(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "FILTER_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notifications filtered successfully")
}

// GetArchivedNotifications retrieves archived notifications
func (h *NotificationHandler) GetArchivedNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filter := h.buildNotificationFilter(c)
	archived := true
	filter.IsArchived = &archived

	response, err := h.notificationService.GetArchivedNotifications(c.Request.Context(), userID, filter)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ARCHIVED_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Archived notifications retrieved successfully")
}

// =============================================================================
// PREFERENCES MANAGEMENT
// =============================================================================

// GetNotificationPreferences retrieves notification preferences
func (h *NotificationHandler) GetNotificationPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetNotificationPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification preferences retrieved successfully")
}

// UpdateNotificationPreferences updates notification preferences
func (h *NotificationHandler) UpdateNotificationPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateNotificationPreferencesRequest{}
	h.populatePreferencesRequest(req, validatedData)

	err := h.notificationService.UpdateNotificationPreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_NOTIFICATION_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification preferences updated successfully")
}

// GetChannelPreferences retrieves channel preferences
func (h *NotificationHandler) GetChannelPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetChannelPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CHANNEL_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Channel preferences retrieved successfully")
}

// UpdateChannelPreferences updates channel preferences
func (h *NotificationHandler) UpdateChannelPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateChannelPreferencesRequest{}
	h.populateChannelPreferencesRequest(req, validatedData)

	err := h.notificationService.UpdateChannelPreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_CHANNEL_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Channel preferences updated successfully")
}

// GetTypePreferences retrieves type preferences
func (h *NotificationHandler) GetTypePreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetTypePreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_TYPE_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Type preferences retrieved successfully")
}

// UpdateTypePreferences updates type preferences
func (h *NotificationHandler) UpdateTypePreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateTypePreferencesRequest{}
	if types, ok := validatedData["types"].(map[string]interface{}); ok {
		req.Types = make(map[models.NotificationType]bool)
		for typeStr, enabled := range types {
			if enabledBool, ok := enabled.(bool); ok {
				req.Types[models.NotificationType(typeStr)] = enabledBool
			}
		}
	}

	err := h.notificationService.UpdateTypePreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_TYPE_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Type preferences updated successfully")
}

// GetQuietHours retrieves quiet hours settings
func (h *NotificationHandler) GetQuietHours(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetQuietHours(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_QUIET_HOURS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Quiet hours retrieved successfully")
}

// UpdateQuietHours updates quiet hours settings
func (h *NotificationHandler) UpdateQuietHours(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateQuietHoursRequest{
		Enabled: validatedData["enabled"].(bool),
	}

	if startTime, ok := validatedData["start_time"].(string); ok {
		req.StartTime = startTime
	}
	if endTime, ok := validatedData["end_time"].(string); ok {
		req.EndTime = endTime
	}
	if timezone, ok := validatedData["timezone"].(string); ok {
		req.Timezone = timezone
	}

	err := h.notificationService.UpdateQuietHours(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_QUIET_HOURS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Quiet hours updated successfully")
}

// GetFrequencySettings retrieves frequency settings
func (h *NotificationHandler) GetFrequencySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetFrequencySettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FREQUENCY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Frequency settings retrieved successfully")
}

// UpdateFrequencySettings updates frequency settings
func (h *NotificationHandler) UpdateFrequencySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateFrequencySettingsRequest{}
	if maxPerHour, ok := validatedData["max_per_hour"].(float64); ok {
		maxPerHourInt := int(maxPerHour)
		req.MaxPerHour = &maxPerHourInt
	}
	if maxPerDay, ok := validatedData["max_per_day"].(float64); ok {
		maxPerDayInt := int(maxPerDay)
		req.MaxPerDay = &maxPerDayInt
	}
	if maxPerWeek, ok := validatedData["max_per_week"].(float64); ok {
		maxPerWeekInt := int(maxPerWeek)
		req.MaxPerWeek = &maxPerWeekInt
	}

	err := h.notificationService.UpdateFrequencySettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_FREQUENCY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Frequency settings updated successfully")
}

// =============================================================================
// NOTIFICATION RULES
// =============================================================================

// GetNotificationRules retrieves notification rules
func (h *NotificationHandler) GetNotificationRules(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetNotificationRules(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_RULES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification rules retrieved successfully")
}

// CreateNotificationRule creates a notification rule
func (h *NotificationHandler) CreateNotificationRule(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateNotificationRuleRequest{}
	h.populateCreateRuleRequest(req, validatedData)

	response, err := h.notificationService.CreateNotificationRule(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_NOTIFICATION_RULE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification rule created successfully")
}

// UpdateNotificationRule updates a notification rule
func (h *NotificationHandler) UpdateNotificationRule(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	ruleID, err := primitive.ObjectIDFromHex(c.Param("rule_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_RULE_ID", "Invalid rule ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateNotificationRuleRequest{}
	h.populateUpdateRuleRequest(req, validatedData)

	err = h.notificationService.UpdateNotificationRule(c.Request.Context(), userID, ruleID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_NOTIFICATION_RULE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification rule updated successfully")
}

// DeleteNotificationRule deletes a notification rule
func (h *NotificationHandler) DeleteNotificationRule(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	ruleID, err := primitive.ObjectIDFromHex(c.Param("rule_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_RULE_ID", "Invalid rule ID")
		return
	}

	err = h.notificationService.DeleteNotificationRule(c.Request.Context(), userID, ruleID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_NOTIFICATION_RULE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification rule deleted successfully")
}

// =============================================================================
// PUSH NOTIFICATIONS
// =============================================================================

// RegisterDevice registers a device for push notifications
func (h *NotificationHandler) RegisterDevice(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.RegisterDeviceRequest{
		DeviceToken: validatedData["device_token"].(string),
		DeviceType:  models.DeviceType(validatedData["device_type"].(string)),
	}

	if deviceName, ok := validatedData["device_name"].(string); ok {
		req.DeviceName = deviceName
	}
	if appVersion, ok := validatedData["app_version"].(string); ok {
		req.AppVersion = appVersion
	}

	response, err := h.notificationService.RegisterDevice(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REGISTER_DEVICE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Device registered successfully")
}

// UpdateDevice updates a device
func (h *NotificationHandler) UpdateDevice(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	deviceID, err := primitive.ObjectIDFromHex(c.Param("device_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DEVICE_ID", "Invalid device ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateDeviceRequest{}
	if deviceName, ok := validatedData["device_name"].(string); ok {
		req.DeviceName = &deviceName
	}
	if appVersion, ok := validatedData["app_version"].(string); ok {
		req.AppVersion = &appVersion
	}
	if isActive, ok := validatedData["is_active"].(bool); ok {
		req.IsActive = &isActive
	}

	err = h.notificationService.UpdateDevice(c.Request.Context(), userID, deviceID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_DEVICE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Device updated successfully")
}

// UnregisterDevice unregisters a device
func (h *NotificationHandler) UnregisterDevice(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	deviceID, err := primitive.ObjectIDFromHex(c.Param("device_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DEVICE_ID", "Invalid device ID")
		return
	}

	err = h.notificationService.UnregisterDevice(c.Request.Context(), userID, deviceID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNREGISTER_DEVICE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Device unregistered successfully")
}

// GetRegisteredDevices retrieves registered devices
func (h *NotificationHandler) GetRegisteredDevices(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetRegisteredDevices(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_REGISTERED_DEVICES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Registered devices retrieved successfully")
}

// SendTestPushNotification sends a test push notification
func (h *NotificationHandler) SendTestPushNotification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.TestPushRequest{
		Message: validatedData["message"].(string),
	}

	if title, ok := validatedData["title"].(string); ok {
		req.Title = title
	}

	err := h.notificationService.SendTestPushNotification(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEND_TEST_PUSH_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Test push notification sent successfully")
}

// GetPushPreferences retrieves push preferences
func (h *NotificationHandler) GetPushPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetPushPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PUSH_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Push preferences retrieved successfully")
}

// UpdatePushPreferences updates push preferences
func (h *NotificationHandler) UpdatePushPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdatePushPreferencesRequest{}
	h.populatePushPreferencesRequest(req, validatedData)

	err := h.notificationService.UpdatePushPreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_PUSH_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Push preferences updated successfully")
}

// RegisterPushToken registers a push token
func (h *NotificationHandler) RegisterPushToken(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.RegisterPushTokenRequest{
		Token:    validatedData["token"].(string),
		Platform: models.PushPlatform(validatedData["platform"].(string)),
	}

	if environment, ok := validatedData["environment"].(string); ok {
		req.Environment = environment
	}

	err := h.notificationService.RegisterPushToken(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REGISTER_PUSH_TOKEN_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Push token registered successfully")
}

// UnregisterPushToken unregisters a push token
func (h *NotificationHandler) UnregisterPushToken(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	token := c.Param("token")
	err := h.notificationService.UnregisterPushToken(c.Request.Context(), userID, token)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNREGISTER_PUSH_TOKEN_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Push token unregistered successfully")
}

// =============================================================================
// EMAIL NOTIFICATIONS
// =============================================================================

// GetEmailPreferences retrieves email preferences
func (h *NotificationHandler) GetEmailPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetEmailPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMAIL_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email preferences retrieved successfully")
}

// UpdateEmailPreferences updates email preferences
func (h *NotificationHandler) UpdateEmailPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateEmailPreferencesRequest{}
	h.populateEmailPreferencesRequest(req, validatedData)

	err := h.notificationService.UpdateEmailPreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_EMAIL_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Email preferences updated successfully")
}

// GetEmailDigestSettings retrieves email digest settings
func (h *NotificationHandler) GetEmailDigestSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetEmailDigestSettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMAIL_DIGEST_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email digest settings retrieved successfully")
}

// UpdateEmailDigestSettings updates email digest settings
func (h *NotificationHandler) UpdateEmailDigestSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateEmailDigestSettingsRequest{}
	h.populateEmailDigestRequest(req, validatedData)

	err := h.notificationService.UpdateEmailDigestSettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_EMAIL_DIGEST_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Email digest settings updated successfully")
}

// UnsubscribeFromEmails unsubscribes from emails
func (h *NotificationHandler) UnsubscribeFromEmails(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.EmailUnsubscribeRequest{}
	if types, ok := validatedData["types"].([]interface{}); ok {
		for _, t := range types {
			if typeStr, ok := t.(string); ok {
				req.Types = append(req.Types, typeStr)
			}
		}
	}
	if all, ok := validatedData["all"].(bool); ok {
		req.All = all
	}

	err := h.notificationService.UnsubscribeFromEmails(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNSUBSCRIBE_FROM_EMAILS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Successfully unsubscribed from emails")
}

// ResubscribeToEmails resubscribes to emails
func (h *NotificationHandler) ResubscribeToEmails(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.EmailResubscribeRequest{}
	if types, ok := validatedData["types"].([]interface{}); ok {
		for _, t := range types {
			if typeStr, ok := t.(string); ok {
				req.Types = append(req.Types, typeStr)
			}
		}
	}

	err := h.notificationService.ResubscribeToEmails(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "RESUBSCRIBE_TO_EMAILS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Successfully resubscribed to emails")
}

// GetUnsubscribeStatus gets unsubscribe status
func (h *NotificationHandler) GetUnsubscribeStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetUnsubscribeStatus(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_UNSUBSCRIBE_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Unsubscribe status retrieved successfully")
}

// GetEmailTemplates gets email templates
func (h *NotificationHandler) GetEmailTemplates(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetEmailTemplates(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMAIL_TEMPLATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email templates retrieved successfully")
}

// PreviewEmailTemplate previews an email template
func (h *NotificationHandler) PreviewEmailTemplate(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	templateID, err := primitive.ObjectIDFromHex(c.Param("template_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_TEMPLATE_ID", "Invalid template ID")
		return
	}

	response, err := h.notificationService.PreviewEmailTemplate(c.Request.Context(), userID, templateID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "PREVIEW_EMAIL_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email template preview generated successfully")
}

// GetEmailDeliveryStatus gets email delivery status
func (h *NotificationHandler) GetEmailDeliveryStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetEmailDeliveryStatus(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMAIL_DELIVERY_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email delivery status retrieved successfully")
}

// GetEmailDeliveryDetails gets email delivery details
func (h *NotificationHandler) GetEmailDeliveryDetails(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	response, err := h.notificationService.GetEmailDeliveryDetails(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMAIL_DELIVERY_DETAILS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Email delivery details retrieved successfully")
}

// =============================================================================
// SMS NOTIFICATIONS
// =============================================================================

// GetSMSPreferences retrieves SMS preferences
func (h *NotificationHandler) GetSMSPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetSMSPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SMS_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "SMS preferences retrieved successfully")
}

// UpdateSMSPreferences updates SMS preferences
func (h *NotificationHandler) UpdateSMSPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateSMSPreferencesRequest{}
	if securityAlerts, ok := validatedData["security_alerts"].(bool); ok {
		req.SecurityAlerts = &securityAlerts
	}
	if criticalUpdates, ok := validatedData["critical_updates"].(bool); ok {
		req.CriticalUpdates = &criticalUpdates
	}

	err := h.notificationService.UpdateSMSPreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_SMS_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "SMS preferences updated successfully")
}

// VerifyPhoneNumber verifies a phone number
func (h *NotificationHandler) VerifyPhoneNumber(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.VerifyPhoneRequest{
		PhoneNumber: validatedData["phone_number"].(string),
		CountryCode: validatedData["country_code"].(string),
	}

	err := h.notificationService.VerifyPhoneNumber(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "VERIFY_PHONE_NUMBER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Phone verification code sent successfully")
}

// ConfirmPhoneNumber confirms a phone number
func (h *NotificationHandler) ConfirmPhoneNumber(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ConfirmPhoneRequest{
		VerificationCode: validatedData["verification_code"].(string),
	}

	err := h.notificationService.ConfirmPhoneNumber(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CONFIRM_PHONE_NUMBER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Phone number confirmed successfully")
}

// RemovePhoneNumber removes a phone number
func (h *NotificationHandler) RemovePhoneNumber(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	err := h.notificationService.RemovePhoneNumber(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REMOVE_PHONE_NUMBER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Phone number removed successfully")
}

// GetSMSDeliveryStatus gets SMS delivery status
func (h *NotificationHandler) GetSMSDeliveryStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetSMSDeliveryStatus(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SMS_DELIVERY_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "SMS delivery status retrieved successfully")
}

// GetSMSDeliveryDetails gets SMS delivery details
func (h *NotificationHandler) GetSMSDeliveryDetails(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	notificationID, err := primitive.ObjectIDFromHex(c.Param("notification_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_ID", "Invalid notification ID")
		return
	}

	response, err := h.notificationService.GetSMSDeliveryDetails(c.Request.Context(), userID, notificationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SMS_DELIVERY_DETAILS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "SMS delivery details retrieved successfully")
}

// =============================================================================
// NOTIFICATION TEMPLATES (ADMIN ONLY)
// =============================================================================

// GetNotificationTemplates gets notification templates
func (h *NotificationHandler) GetNotificationTemplates(c *gin.Context) {
	response, err := h.notificationService.GetNotificationTemplates(c.Request.Context())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_TEMPLATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification templates retrieved successfully")
}

// CreateNotificationTemplate creates a notification template
func (h *NotificationHandler) CreateNotificationTemplate(c *gin.Context) {
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateNotificationTemplateRequest{}
	h.populateCreateTemplateRequest(req, validatedData)

	response, err := h.notificationService.CreateNotificationTemplate(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_NOTIFICATION_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification template created successfully")
}

// UpdateNotificationTemplate updates a notification template
func (h *NotificationHandler) UpdateNotificationTemplate(c *gin.Context) {
	templateID, err := primitive.ObjectIDFromHex(c.Param("template_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_TEMPLATE_ID", "Invalid template ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateNotificationTemplateRequest{}
	h.populateUpdateTemplateRequest(req, validatedData)

	err = h.notificationService.UpdateNotificationTemplate(c.Request.Context(), templateID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_NOTIFICATION_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification template updated successfully")
}

// DeleteNotificationTemplate deletes a notification template
func (h *NotificationHandler) DeleteNotificationTemplate(c *gin.Context) {
	templateID, err := primitive.ObjectIDFromHex(c.Param("template_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_TEMPLATE_ID", "Invalid template ID")
		return
	}

	err = h.notificationService.DeleteNotificationTemplate(c.Request.Context(), templateID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_NOTIFICATION_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification template deleted successfully")
}

// PreviewNotificationTemplate previews a notification template
func (h *NotificationHandler) PreviewNotificationTemplate(c *gin.Context) {
	templateID, err := primitive.ObjectIDFromHex(c.Param("template_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_TEMPLATE_ID", "Invalid template ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.PreviewNotificationTemplateRequest{}
	if variables, ok := validatedData["variables"].(map[string]interface{}); ok {
		req.Variables = variables
	}

	response, err := h.notificationService.PreviewNotificationTemplate(c.Request.Context(), templateID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "PREVIEW_NOTIFICATION_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification template preview generated successfully")
}

// TestNotificationTemplate tests a notification template
func (h *NotificationHandler) TestNotificationTemplate(c *gin.Context) {
	templateID, err := primitive.ObjectIDFromHex(c.Param("template_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_TEMPLATE_ID", "Invalid template ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.TestNotificationTemplateRequest{}
	if userIDStr, ok := validatedData["user_id"].(string); ok {
		if userID, err := primitive.ObjectIDFromHex(userIDStr); err == nil {
			req.UserID = userID
		}
	}
	if variables, ok := validatedData["variables"].(map[string]interface{}); ok {
		req.Variables = variables
	}

	err = h.notificationService.TestNotificationTemplate(c.Request.Context(), templateID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "TEST_NOTIFICATION_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification template test sent successfully")
}

// =============================================================================
// ANALYTICS
// =============================================================================

// GetNotificationStats gets notification statistics
func (h *NotificationHandler) GetNotificationStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetNotificationStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification stats retrieved successfully")
}

// GetNotificationEngagement gets notification engagement metrics
func (h *NotificationHandler) GetNotificationEngagement(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetNotificationEngagement(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATION_ENGAGEMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification engagement retrieved successfully")
}

// GetDeliveryRates gets delivery rates
func (h *NotificationHandler) GetDeliveryRates(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetDeliveryRates(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_DELIVERY_RATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Delivery rates retrieved successfully")
}

// GetOpenRates gets open rates
func (h *NotificationHandler) GetOpenRates(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetOpenRates(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_OPEN_RATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Open rates retrieved successfully")
}

// GetChannelPerformance gets channel performance
func (h *NotificationHandler) GetChannelPerformance(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetChannelPerformance(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CHANNEL_PERFORMANCE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Channel performance retrieved successfully")
}

// GetChannelPreferenceStats gets channel preference stats
func (h *NotificationHandler) GetChannelPreferenceStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetChannelPreferenceStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CHANNEL_PREFERENCE_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Channel preference stats retrieved successfully")
}

// GetUserNotificationBehavior gets user notification behavior
func (h *NotificationHandler) GetUserNotificationBehavior(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetUserNotificationBehavior(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_NOTIFICATION_BEHAVIOR_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User notification behavior retrieved successfully")
}

// GetInteractionPatterns gets interaction patterns
func (h *NotificationHandler) GetInteractionPatterns(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetInteractionPatterns(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_INTERACTION_PATTERNS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Interaction patterns retrieved successfully")
}

// GetHourlyNotificationStats gets hourly notification stats
func (h *NotificationHandler) GetHourlyNotificationStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetHourlyNotificationStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_HOURLY_NOTIFICATION_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Hourly notification stats retrieved successfully")
}

// GetDailyNotificationStats gets daily notification stats
func (h *NotificationHandler) GetDailyNotificationStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetDailyNotificationStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_DAILY_NOTIFICATION_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Daily notification stats retrieved successfully")
}

// GetWeeklyNotificationStats gets weekly notification stats
func (h *NotificationHandler) GetWeeklyNotificationStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetWeeklyNotificationStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_WEEKLY_NOTIFICATION_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Weekly notification stats retrieved successfully")
}

// GetABTestResults gets A/B test results
func (h *NotificationHandler) GetABTestResults(c *gin.Context) {
	response, err := h.notificationService.GetABTestResults(c.Request.Context())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_AB_TEST_RESULTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "A/B test results retrieved successfully")
}

// =============================================================================
// WEBHOOKS
// =============================================================================

// GetWebhooks gets webhooks
func (h *NotificationHandler) GetWebhooks(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetWebhooks(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_WEBHOOKS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Webhooks retrieved successfully")
}

// CreateWebhook creates a webhook
func (h *NotificationHandler) CreateWebhook(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateWebhookRequest{}
	h.populateCreateWebhookRequest(req, validatedData)

	response, err := h.notificationService.CreateWebhook(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_WEBHOOK_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Webhook created successfully")
}

// UpdateWebhook updates a webhook
func (h *NotificationHandler) UpdateWebhook(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	webhookID, err := primitive.ObjectIDFromHex(c.Param("webhook_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_WEBHOOK_ID", "Invalid webhook ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateWebhookRequest{}
	h.populateUpdateWebhookRequest(req, validatedData)

	err = h.notificationService.UpdateWebhook(c.Request.Context(), userID, webhookID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_WEBHOOK_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Webhook updated successfully")
}

// DeleteWebhook deletes a webhook
func (h *NotificationHandler) DeleteWebhook(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	webhookID, err := primitive.ObjectIDFromHex(c.Param("webhook_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_WEBHOOK_ID", "Invalid webhook ID")
		return
	}

	err = h.notificationService.DeleteWebhook(c.Request.Context(), userID, webhookID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_WEBHOOK_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Webhook deleted successfully")
}

// TestWebhook tests a webhook
func (h *NotificationHandler) TestWebhook(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	webhookID, err := primitive.ObjectIDFromHex(c.Param("webhook_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_WEBHOOK_ID", "Invalid webhook ID")
		return
	}

	err = h.notificationService.TestWebhook(c.Request.Context(), userID, webhookID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "TEST_WEBHOOK_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Webhook test triggered successfully")
}

// GetWebhookLogs gets webhook logs
func (h *NotificationHandler) GetWebhookLogs(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	webhookID, err := primitive.ObjectIDFromHex(c.Param("webhook_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_WEBHOOK_ID", "Invalid webhook ID")
		return
	}

	response, err := h.notificationService.GetWebhookLogs(c.Request.Context(), userID, webhookID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_WEBHOOK_LOGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Webhook logs retrieved successfully")
}

// GetWebhookEvents gets webhook events
func (h *NotificationHandler) GetWebhookEvents(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetWebhookEvents(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_WEBHOOK_EVENTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Webhook events retrieved successfully")
}

// TriggerWebhookEvent triggers a webhook event
func (h *NotificationHandler) TriggerWebhookEvent(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	webhookID, err := primitive.ObjectIDFromHex(c.Param("webhook_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_WEBHOOK_ID", "Invalid webhook ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.TriggerWebhookEventRequest{}
	if event, ok := validatedData["event"].(string); ok {
		req.Event = models.WebhookEvent(event)
	}
	if payload, ok := validatedData["payload"].(map[string]interface{}); ok {
		req.Payload = payload
	}

	err = h.notificationService.TriggerWebhookEvent(c.Request.Context(), userID, webhookID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "TRIGGER_WEBHOOK_EVENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Webhook event triggered successfully")
}

// =============================================================================
// REAL-TIME NOTIFICATIONS
// =============================================================================

// ConnectWebSocket connects WebSocket for real-time notifications
func (h *NotificationHandler) ConnectWebSocket(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "WEBSOCKET_UPGRADE_FAILED", err.Error())
		return
	}
	defer conn.Close()

	connectionID := c.Query("connection_id")
	if connectionID == "" {
		connectionID = primitive.NewObjectID().Hex()
	}

	err = h.notificationService.ConnectWebSocket(c.Request.Context(), userID, connectionID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "WEBSOCKET_CONNECT_FAILED", err.Error())
		return
	}

	// Handle WebSocket connection logic here
	// This would typically involve listening for messages and sending notifications
}

// StreamNotifications streams notifications via Server-Sent Events
func (h *NotificationHandler) StreamNotifications(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	connectionID := c.Query("connection_id")
	if connectionID == "" {
		connectionID = primitive.NewObjectID().Hex()
	}

	// Set headers for Server-Sent Events
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	notificationStream, err := h.notificationService.StreamNotifications(c.Request.Context(), userID, connectionID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "STREAM_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	c.Stream(func(w io.Writer) bool {
		select {
		case notification := <-notificationStream:
			if notification != nil {
				c.SSEvent("notification", notification)
				return true
			}
			return false
		case <-c.Request.Context().Done():
			return false
		}
	})
}

// GetRealtimePreferences gets real-time preferences
func (h *NotificationHandler) GetRealtimePreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetRealtimePreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_REALTIME_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Real-time preferences retrieved successfully")
}

// UpdateRealtimePreferences updates real-time preferences
func (h *NotificationHandler) UpdateRealtimePreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateRealtimePreferencesRequest{}
	h.populateRealtimePreferencesRequest(req, validatedData)

	err := h.notificationService.UpdateRealtimePreferences(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_REALTIME_PREFERENCES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Real-time preferences updated successfully")
}

// GetActiveConnections gets active connections
func (h *NotificationHandler) GetActiveConnections(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.notificationService.GetActiveConnections(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ACTIVE_CONNECTIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Active connections retrieved successfully")
}

// DisconnectConnection disconnects a connection
func (h *NotificationHandler) DisconnectConnection(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	connectionID := c.Param("connection_id")
	err := h.notificationService.DisconnectConnection(c.Request.Context(), userID, connectionID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DISCONNECT_CONNECTION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Connection disconnected successfully")
}

// Heartbeat handles heartbeat for connections
func (h *NotificationHandler) Heartbeat(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	connectionID := c.Query("connection_id")
	if connectionID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_CONNECTION_ID", "Connection ID is required")
		return
	}

	err := h.notificationService.Heartbeat(c.Request.Context(), userID, connectionID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "HEARTBEAT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Heartbeat recorded successfully")
}

// GetConnectionStatus gets connection status
func (h *NotificationHandler) GetConnectionStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	connectionID := c.Query("connection_id")
	if connectionID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_CONNECTION_ID", "Connection ID is required")
		return
	}

	response, err := h.notificationService.GetConnectionStatus(c.Request.Context(), userID, connectionID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONNECTION_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Connection status retrieved successfully")
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// buildNotificationFilter builds notification filter from query parameters
func (h *NotificationHandler) buildNotificationFilter(c *gin.Context) *services.NotificationFilter {
	filter := &services.NotificationFilter{
		Page:      h.getIntParam(c, "page", 1),
		Limit:     h.getIntParam(c, "limit", 20),
		SortBy:    c.Query("sort_by"),
		SortOrder: c.Query("sort_order"),
	}

	if typeStr := c.Query("type"); typeStr != "" {
		notifType := models.NotificationType(typeStr)
		filter.Type = &notifType
	}

	if priorityStr := c.Query("priority"); priorityStr != "" {
		priority := models.NotificationPriority(priorityStr)
		filter.Priority = &priority
	}

	if isReadStr := c.Query("is_read"); isReadStr != "" {
		if isRead, err := strconv.ParseBool(isReadStr); err == nil {
			filter.IsRead = &isRead
		}
	}

	if isArchivedStr := c.Query("is_archived"); isArchivedStr != "" {
		if isArchived, err := strconv.ParseBool(isArchivedStr); err == nil {
			filter.IsArchived = &isArchived
		}
	}

	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filter.StartDate = &startDate
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filter.EndDate = &endDate
		}
	}

	return filter
}

// getCategoryNotifications helper for category-specific notifications
func (h *NotificationHandler) getCategoryNotifications(c *gin.Context, notifType models.NotificationType) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filter := h.buildNotificationFilter(c)
	filter.Type = &notifType

	var response *services.NotificationListResponse
	var err error

	switch notifType {
	case models.NotificationTypeLike:
		response, err = h.notificationService.GetLikeNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeComment:
		response, err = h.notificationService.GetCommentNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeFollow:
		response, err = h.notificationService.GetFollowNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeMention:
		response, err = h.notificationService.GetMentionNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeMessage:
		response, err = h.notificationService.GetMessageNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeShare:
		response, err = h.notificationService.GetShareNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeSecurityAlert:
		response, err = h.notificationService.GetSecurityNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypeUpdate:
		response, err = h.notificationService.GetSystemNotifications(c.Request.Context(), userID, filter)
	case models.NotificationTypePromotion:
		response, err = h.notificationService.GetPromotionNotifications(c.Request.Context(), userID, filter)
	default:
		utils.SendError(c, http.StatusBadRequest, "INVALID_NOTIFICATION_TYPE", "Invalid notification type")
		return
	}

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CATEGORY_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Category notifications retrieved successfully")
}

// getIntParam gets integer parameter with default value
func (h *NotificationHandler) getIntParam(c *gin.Context, param string, defaultValue int) int {
	if value := c.Query(param); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// extractNotificationIDs extracts notification IDs from interface slice
func (h *NotificationHandler) extractNotificationIDs(data interface{}) []primitive.ObjectID {
	var notificationIDs []primitive.ObjectID

	if idSlice, ok := data.([]interface{}); ok {
		for _, idInterface := range idSlice {
			if idStr, ok := idInterface.(string); ok {
				if objectID, err := primitive.ObjectIDFromHex(idStr); err == nil {
					notificationIDs = append(notificationIDs, objectID)
				}
			}
		}
	}

	return notificationIDs
}

// populateFilterRequest populates filter request from validated data
func (h *NotificationHandler) populateFilterRequest(req *services.FilterNotificationsRequest, data map[string]interface{}) {
	if typeStr, ok := data["type"].(string); ok {
		notifType := models.NotificationType(typeStr)
		req.Type = &notifType
	}

	if priorityStr, ok := data["priority"].(string); ok {
		priority := models.NotificationPriority(priorityStr)
		req.Priority = &priority
	}

	if isRead, ok := data["is_read"].(bool); ok {
		req.IsRead = &isRead
	}

	if isArchived, ok := data["is_archived"].(bool); ok {
		req.IsArchived = &isArchived
	}

	if startDateStr, ok := data["start_date"].(string); ok {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			req.StartDate = &startDate
		}
	}

	if endDateStr, ok := data["end_date"].(string); ok {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			req.EndDate = &endDate
		}
	}
}

// populatePreferencesRequest populates preferences request from validated data
func (h *NotificationHandler) populatePreferencesRequest(req *services.UpdateNotificationPreferencesRequest, data map[string]interface{}) {
	if emailNotifications, ok := data["email_notifications"].(bool); ok {
		req.EmailNotifications = &emailNotifications
	}

	if pushNotifications, ok := data["push_notifications"].(bool); ok {
		req.PushNotifications = &pushNotifications
	}

	if smsNotifications, ok := data["sms_notifications"].(bool); ok {
		req.SmsNotifications = &smsNotifications
	}

	if inAppNotifications, ok := data["in_app_notifications"].(bool); ok {
		req.InAppNotifications = &inAppNotifications
	}

	if digestFrequencyStr, ok := data["digest_frequency"].(string); ok {
		digestFrequency := models.DigestFrequency(digestFrequencyStr)
		req.DigestFrequency = &digestFrequency
	}
}

// populateChannelPreferencesRequest populates channel preferences request from validated data
func (h *NotificationHandler) populateChannelPreferencesRequest(req *services.UpdateChannelPreferencesRequest, data map[string]interface{}) {
	if likes, ok := data["likes"].(map[string]interface{}); ok {
		req.Likes = make(map[string]bool)
		for key, value := range likes {
			if boolValue, ok := value.(bool); ok {
				req.Likes[key] = boolValue
			}
		}
	}

	if comments, ok := data["comments"].(map[string]interface{}); ok {
		req.Comments = make(map[string]bool)
		for key, value := range comments {
			if boolValue, ok := value.(bool); ok {
				req.Comments[key] = boolValue
			}
		}
	}

	if follows, ok := data["follows"].(map[string]interface{}); ok {
		req.Follows = make(map[string]bool)
		for key, value := range follows {
			if boolValue, ok := value.(bool); ok {
				req.Follows[key] = boolValue
			}
		}
	}

	if mentions, ok := data["mentions"].(map[string]interface{}); ok {
		req.Mentions = make(map[string]bool)
		for key, value := range mentions {
			if boolValue, ok := value.(bool); ok {
				req.Mentions[key] = boolValue
			}
		}
	}

	if messages, ok := data["messages"].(map[string]interface{}); ok {
		req.Messages = make(map[string]bool)
		for key, value := range messages {
			if boolValue, ok := value.(bool); ok {
				req.Messages[key] = boolValue
			}
		}
	}
}

// populateCreateRuleRequest populates create rule request from validated data
func (h *NotificationHandler) populateCreateRuleRequest(req *services.CreateNotificationRuleRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = name
	}

	if priority, ok := data["priority"].(float64); ok {
		req.Priority = int(priority)
	}

	if isActive, ok := data["is_active"].(bool); ok {
		req.IsActive = isActive
	}

	if conditions, ok := data["conditions"].([]interface{}); ok {
		for _, conditionInterface := range conditions {
			if conditionMap, ok := conditionInterface.(map[string]interface{}); ok {
				condition := models.RuleCondition{}
				if field, ok := conditionMap["field"].(string); ok {
					condition.Field = field
				}
				if operator, ok := conditionMap["operator"].(string); ok {
					condition.Operator = operator
				}
				if value := conditionMap["value"]; value != nil {
					condition.Value = value
				}
				req.Conditions = append(req.Conditions, condition)
			}
		}
	}

	if actions, ok := data["actions"].([]interface{}); ok {
		for _, actionInterface := range actions {
			if actionMap, ok := actionInterface.(map[string]interface{}); ok {
				action := models.RuleAction{}
				if actionType, ok := actionMap["type"].(string); ok {
					action.Type = actionType
				}
				if config, ok := actionMap["config"].(map[string]interface{}); ok {
					action.Config = config
				}
				req.Actions = append(req.Actions, action)
			}
		}
	}
}

// populateUpdateRuleRequest populates update rule request from validated data
func (h *NotificationHandler) populateUpdateRuleRequest(req *services.UpdateNotificationRuleRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = &name
	}

	if priority, ok := data["priority"].(float64); ok {
		priorityInt := int(priority)
		req.Priority = &priorityInt
	}

	if isActive, ok := data["is_active"].(bool); ok {
		req.IsActive = &isActive
	}

	if conditions, ok := data["conditions"].([]interface{}); ok {
		for _, conditionInterface := range conditions {
			if conditionMap, ok := conditionInterface.(map[string]interface{}); ok {
				condition := models.RuleCondition{}
				if field, ok := conditionMap["field"].(string); ok {
					condition.Field = field
				}
				if operator, ok := conditionMap["operator"].(string); ok {
					condition.Operator = operator
				}
				if value := conditionMap["value"]; value != nil {
					condition.Value = value
				}
				req.Conditions = append(req.Conditions, condition)
			}
		}
	}

	if actions, ok := data["actions"].([]interface{}); ok {
		for _, actionInterface := range actions {
			if actionMap, ok := actionInterface.(map[string]interface{}); ok {
				action := models.RuleAction{}
				if actionType, ok := actionMap["type"].(string); ok {
					action.Type = actionType
				}
				if config, ok := actionMap["config"].(map[string]interface{}); ok {
					action.Config = config
				}
				req.Actions = append(req.Actions, action)
			}
		}
	}
}

// populatePushPreferencesRequest populates push preferences request from validated data
func (h *NotificationHandler) populatePushPreferencesRequest(req *services.UpdatePushPreferencesRequest, data map[string]interface{}) {
	if enabled, ok := data["enabled"].(bool); ok {
		req.Enabled = &enabled
	}

	if types, ok := data["types"].(map[string]interface{}); ok {
		req.Types = make(map[models.NotificationType]bool)
		for typeStr, enabled := range types {
			if enabledBool, ok := enabled.(bool); ok {
				req.Types[models.NotificationType(typeStr)] = enabledBool
			}
		}
	}

	if quietHours, ok := data["quiet_hours"].(map[string]interface{}); ok {
		quietHoursObj := &models.QuietHours{}
		if enabled, ok := quietHours["enabled"].(bool); ok {
			quietHoursObj.Enabled = enabled
		}
		if startTime, ok := quietHours["start_time"].(string); ok {
			quietHoursObj.StartTime = startTime
		}
		if endTime, ok := quietHours["end_time"].(string); ok {
			quietHoursObj.EndTime = endTime
		}
		if timezone, ok := quietHours["timezone"].(string); ok {
			quietHoursObj.TimeZone = timezone
		}
		req.QuietHours = quietHoursObj
	}
}

// populateEmailPreferencesRequest populates email preferences request from validated data
func (h *NotificationHandler) populateEmailPreferencesRequest(req *services.UpdateEmailPreferencesRequest, data map[string]interface{}) {
	if marketingEmails, ok := data["marketing_emails"].(bool); ok {
		req.MarketingEmails = &marketingEmails
	}

	if digestEmails, ok := data["digest_emails"].(bool); ok {
		req.DigestEmails = &digestEmails
	}

	if securityAlerts, ok := data["security_alerts"].(bool); ok {
		req.SecurityAlerts = &securityAlerts
	}

	if socialUpdates, ok := data["social_updates"].(bool); ok {
		req.SocialUpdates = &socialUpdates
	}

	if productUpdates, ok := data["product_updates"].(bool); ok {
		req.ProductUpdates = &productUpdates
	}

	if digestFrequencyStr, ok := data["digest_frequency"].(string); ok {
		digestFrequency := models.DigestFrequency(digestFrequencyStr)
		req.DigestFrequency = &digestFrequency
	}

	if digestTime, ok := data["digest_time"].(string); ok {
		req.DigestTime = &digestTime
	}
}

// populateEmailDigestRequest populates email digest request from validated data
func (h *NotificationHandler) populateEmailDigestRequest(req *services.UpdateEmailDigestSettingsRequest, data map[string]interface{}) {
	if enabled, ok := data["enabled"].(bool); ok {
		req.Enabled = &enabled
	}

	if frequencyStr, ok := data["frequency"].(string); ok {
		frequency := models.DigestFrequency(frequencyStr)
		req.Frequency = &frequency
	}

	if time, ok := data["time"].(string); ok {
		req.Time = &time
	}

	if types, ok := data["types"].([]interface{}); ok {
		for _, typeInterface := range types {
			if typeStr, ok := typeInterface.(string); ok {
				req.Types = append(req.Types, models.NotificationType(typeStr))
			}
		}
	}
}

// populateCreateTemplateRequest populates create template request from validated data
func (h *NotificationHandler) populateCreateTemplateRequest(req *services.CreateNotificationTemplateRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = name
	}

	if typeStr, ok := data["type"].(string); ok {
		req.Type = models.NotificationType(typeStr)
	}

	if channelStr, ok := data["channel"].(string); ok {
		req.Channel = models.NotificationChannel(channelStr)
	}

	if subject, ok := data["subject"].(string); ok {
		req.Subject = subject
	}

	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if variables, ok := data["variables"].([]interface{}); ok {
		for _, variableInterface := range variables {
			if variableMap, ok := variableInterface.(map[string]interface{}); ok {
				variable := models.TemplateVariable{}
				if name, ok := variableMap["name"].(string); ok {
					variable.Name = name
				}
				if varType, ok := variableMap["type"].(string); ok {
					variable.Type = varType
				}
				if required, ok := variableMap["required"].(bool); ok {
					variable.Required = required
				}
				if defaultValue, ok := variableMap["default"].(string); ok {
					variable.Default = defaultValue
				}
				if description, ok := variableMap["description"].(string); ok {
					variable.Description = description
				}
				req.Variables = append(req.Variables, variable)
			}
		}
	}

	if settings, ok := data["settings"].(map[string]interface{}); ok {
		req.Settings = settings
	}
}

// populateUpdateTemplateRequest populates update template request from validated data
func (h *NotificationHandler) populateUpdateTemplateRequest(req *services.UpdateNotificationTemplateRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = &name
	}

	if subject, ok := data["subject"].(string); ok {
		req.Subject = &subject
	}

	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}

	if isActive, ok := data["is_active"].(bool); ok {
		req.IsActive = &isActive
	}

	if variables, ok := data["variables"].([]interface{}); ok {
		for _, variableInterface := range variables {
			if variableMap, ok := variableInterface.(map[string]interface{}); ok {
				variable := models.TemplateVariable{}
				if name, ok := variableMap["name"].(string); ok {
					variable.Name = name
				}
				if varType, ok := variableMap["type"].(string); ok {
					variable.Type = varType
				}
				if required, ok := variableMap["required"].(bool); ok {
					variable.Required = required
				}
				if defaultValue, ok := variableMap["default"].(string); ok {
					variable.Default = defaultValue
				}
				if description, ok := variableMap["description"].(string); ok {
					variable.Description = description
				}
				req.Variables = append(req.Variables, variable)
			}
		}
	}

	if settings, ok := data["settings"].(map[string]interface{}); ok {
		req.Settings = settings
	}
}

// populateCreateWebhookRequest populates create webhook request from validated data
func (h *NotificationHandler) populateCreateWebhookRequest(req *services.CreateWebhookRequest, data map[string]interface{}) {
	if url, ok := data["url"].(string); ok {
		req.URL = url
	}

	if secret, ok := data["secret"].(string); ok {
		req.Secret = secret
	}

	if events, ok := data["events"].([]interface{}); ok {
		for _, eventInterface := range events {
			if eventStr, ok := eventInterface.(string); ok {
				req.Events = append(req.Events, models.WebhookEvent(eventStr))
			}
		}
	}

	if headers, ok := data["headers"].(map[string]interface{}); ok {
		req.Headers = make(map[string]string)
		for key, value := range headers {
			if valueStr, ok := value.(string); ok {
				req.Headers[key] = valueStr
			}
		}
	}
}

// populateUpdateWebhookRequest populates update webhook request from validated data
func (h *NotificationHandler) populateUpdateWebhookRequest(req *services.UpdateWebhookRequest, data map[string]interface{}) {
	if url, ok := data["url"].(string); ok {
		req.URL = &url
	}

	if secret, ok := data["secret"].(string); ok {
		req.Secret = &secret
	}

	if isActive, ok := data["is_active"].(bool); ok {
		req.IsActive = &isActive
	}

	if events, ok := data["events"].([]interface{}); ok {
		for _, eventInterface := range events {
			if eventStr, ok := eventInterface.(string); ok {
				req.Events = append(req.Events, models.WebhookEvent(eventStr))
			}
		}
	}

	if headers, ok := data["headers"].(map[string]interface{}); ok {
		req.Headers = make(map[string]string)
		for key, value := range headers {
			if valueStr, ok := value.(string); ok {
				req.Headers[key] = valueStr
			}
		}
	}
}

// populateRealtimePreferencesRequest populates real-time preferences request from validated data
func (h *NotificationHandler) populateRealtimePreferencesRequest(req *services.UpdateRealtimePreferencesRequest, data map[string]interface{}) {
	if autoConnect, ok := data["auto_connect"].(bool); ok {
		req.AutoConnect = &autoConnect
	}

	if connectionTimeout, ok := data["connection_timeout"].(float64); ok {
		connectionTimeoutInt := int(connectionTimeout)
		req.ConnectionTimeout = &connectionTimeoutInt
	}

	if reconnectAttempts, ok := data["reconnect_attempts"].(float64); ok {
		reconnectAttemptsInt := int(reconnectAttempts)
		req.ReconnectAttempts = &reconnectAttemptsInt
	}

	if heartbeatInterval, ok := data["heartbeat_interval"].(float64); ok {
		heartbeatIntervalInt := int(heartbeatInterval)
		req.HeartbeatInterval = &heartbeatIntervalInt
	}

	if enabledTypes, ok := data["enabled_types"].([]interface{}); ok {
		for _, typeInterface := range enabledTypes {
			if typeStr, ok := typeInterface.(string); ok {
				req.EnabledTypes = append(req.EnabledTypes, models.NotificationType(typeStr))
			}
		}
	}
}
