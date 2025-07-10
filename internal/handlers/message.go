package handlers

import (
	"net/http"
	"strconv"

	"bro-network/internal/middleware"
	"bro-network/internal/models"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MessageHandler handles message-related HTTP requests
type MessageHandler struct {
	messageService services.MessageServiceInterface
	authMiddleware *middleware.AuthMiddleware
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(messageService services.MessageServiceInterface, authMiddleware *middleware.AuthMiddleware) *MessageHandler {
	return &MessageHandler{
		messageService: messageService,
		authMiddleware: authMiddleware,
	}
}

// =============================================================================
// CONVERSATIONS MANAGEMENT
// =============================================================================

// GetConversations retrieves user's conversations
func (h *MessageHandler) GetConversations(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetConversationsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetConversations(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversations retrieved successfully")
}

// GetArchivedConversations retrieves archived conversations
func (h *MessageHandler) GetArchivedConversations(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetConversationsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Archived: true,
	}

	response, err := h.messageService.GetConversations(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ARCHIVED_CONVERSATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Archived conversations retrieved successfully")
}

// GetUnreadConversations retrieves unread conversations
func (h *MessageHandler) GetUnreadConversations(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetConversationsRequest{
		Page:   h.getIntQuery(c, "page", 1),
		Limit:  h.getIntQuery(c, "limit", 20),
		Unread: true,
	}

	response, err := h.messageService.GetConversations(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_UNREAD_CONVERSATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Unread conversations retrieved successfully")
}

// CreateConversation creates a new conversation
func (h *MessageHandler) CreateConversation(c *gin.Context) {
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

	req := &services.CreateConversationRequest{
		CreatorID: userID,
	}
	h.populateCreateConversationRequest(req, validatedData)

	response, err := h.messageService.CreateConversation(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation created successfully")
}

// GetConversation retrieves a specific conversation
func (h *MessageHandler) GetConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	response, err := h.messageService.GetConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation retrieved successfully")
}

// UpdateConversation updates a conversation
func (h *MessageHandler) UpdateConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &models.ConversationUpdateRequest{}
	h.populateConversationUpdateRequest(req, validatedData)

	err = h.messageService.UpdateConversation(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation updated successfully")
}

// DeleteConversation deletes a conversation
func (h *MessageHandler) DeleteConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.DeleteConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation deleted successfully")
}

// ArchiveConversation archives a conversation
func (h *MessageHandler) ArchiveConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.ArchiveConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "ARCHIVE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation archived successfully")
}

// UnarchiveConversation unarchives a conversation
func (h *MessageHandler) UnarchiveConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.UnarchiveConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNARCHIVE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation unarchived successfully")
}

// MuteConversation mutes a conversation
func (h *MessageHandler) MuteConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.MuteConversationRequest{}
	h.populateMuteConversationRequest(req, validatedData)

	err = h.messageService.MuteConversation(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MUTE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation muted successfully")
}

// UnmuteConversation unmutes a conversation
func (h *MessageHandler) UnmuteConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.UnmuteConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNMUTE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation unmuted successfully")
}

// MarkConversationAsRead marks a conversation as read
func (h *MessageHandler) MarkConversationAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.MarkConversationAsRead(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_CONVERSATION_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation marked as read")
}

// MarkConversationAsUnread marks a conversation as unread
func (h *MessageHandler) MarkConversationAsUnread(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.MarkConversationAsUnread(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_CONVERSATION_UNREAD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation marked as unread")
}

// GetConversationParticipants retrieves conversation participants
func (h *MessageHandler) GetConversationParticipants(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	response, err := h.messageService.GetConversationParticipants(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_PARTICIPANTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation participants retrieved successfully")
}

// AddParticipants adds participants to a conversation
func (h *MessageHandler) AddParticipants(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.AddParticipantsRequest{}
	h.populateAddParticipantsRequest(req, validatedData)

	err = h.messageService.AddParticipants(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "ADD_PARTICIPANTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Participants added successfully")
}

// RemoveParticipant removes a participant from a conversation
func (h *MessageHandler) RemoveParticipant(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	participantID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	err = h.messageService.RemoveParticipant(c.Request.Context(), userID, conversationID, participantID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REMOVE_PARTICIPANT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Participant removed successfully")
}

// LeaveConversation allows user to leave a conversation
func (h *MessageHandler) LeaveConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	err = h.messageService.LeaveConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "LEAVE_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Left conversation successfully")
}

// MakeAdmin makes a user admin of a conversation
func (h *MessageHandler) MakeAdmin(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	err = h.messageService.MakeAdmin(c.Request.Context(), userID, conversationID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MAKE_ADMIN_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User made admin successfully")
}

// RemoveAdmin removes admin privileges from a user
func (h *MessageHandler) RemoveAdmin(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	err = h.messageService.RemoveAdmin(c.Request.Context(), userID, conversationID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REMOVE_ADMIN_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Admin privileges removed successfully")
}

// UpdateConversationSettings updates conversation settings
func (h *MessageHandler) UpdateConversationSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ConversationSettingsRequest{}
	h.populateConversationSettingsRequest(req, validatedData)

	err = h.messageService.UpdateConversationSettings(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_CONVERSATION_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Conversation settings updated successfully")
}

// GetConversationMedia retrieves media from a conversation
func (h *MessageHandler) GetConversationMedia(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	req := &services.GetMediaRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
		Type:  c.Query("type"),
	}

	response, err := h.messageService.GetConversationMedia(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_MEDIA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation media retrieved successfully")
}

// GetConversationFiles retrieves files from a conversation
func (h *MessageHandler) GetConversationFiles(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	req := &services.GetFilesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
		Type:  c.Query("type"),
	}

	response, err := h.messageService.GetConversationFiles(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_FILES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation files retrieved successfully")
}

// GetConversationLinks retrieves links from a conversation
func (h *MessageHandler) GetConversationLinks(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	req := &services.GetLinksRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetConversationLinks(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_LINKS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation links retrieved successfully")
}

// SearchInConversation searches within a conversation
func (h *MessageHandler) SearchInConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	query := c.Query("q")
	if query == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_QUERY", "Search query is required")
		return
	}

	req := &services.SearchConversationRequest{
		Query: query,
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.SearchInConversation(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_IN_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation search completed successfully")
}

// ExportConversation exports a conversation
func (h *MessageHandler) ExportConversation(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	response, err := h.messageService.ExportConversation(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "EXPORT_CONVERSATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation export initiated successfully")
}

// DownloadConversationExport downloads a conversation export
func (h *MessageHandler) DownloadConversationExport(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	exportID := c.Param("export_id")
	if exportID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_EXPORT_ID", "Export ID is required")
		return
	}

	filePath, err := h.messageService.DownloadConversationExport(c.Request.Context(), userID, conversationID, exportID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DOWNLOAD_CONVERSATION_EXPORT_FAILED", err.Error())
		return
	}

	c.File(filePath)
}

// =============================================================================
// MESSAGES MANAGEMENT
// =============================================================================

// SendMessage sends a new message
func (h *MessageHandler) SendMessage(c *gin.Context) {
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

	req := &services.SendMessageRequest{
		SenderID: userID,
	}
	h.populateSendMessageRequest(req, validatedData, c)

	response, err := h.messageService.SendMessage(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEND_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message sent successfully")
}

// QuickSendMessage sends a quick message to a user
func (h *MessageHandler) QuickSendMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	recipientID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.QuickSendMessageRequest{
		SenderID:    userID,
		RecipientID: &recipientID,
	}
	h.populateQuickSendMessageRequest(req, validatedData)

	response, err := h.messageService.QuickSendMessage(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "QUICK_SEND_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message sent successfully")
}

// GetMessages retrieves messages from a conversation
func (h *MessageHandler) GetMessages(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	req := &services.GetMessagesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 50),
	}

	response, err := h.messageService.GetMessages(c.Request.Context(), userID, conversationID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Messages retrieved successfully")
}

// GetMessage retrieves a specific message
func (h *MessageHandler) GetMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	response, err := h.messageService.GetMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message retrieved successfully")
}

// UpdateMessage updates a message
func (h *MessageHandler) UpdateMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &models.MessageUpdateRequest{}
	h.populateMessageUpdateRequest(req, validatedData)

	err = h.messageService.UpdateMessage(c.Request.Context(), userID, messageID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message updated successfully")
}

// DeleteMessage deletes a message
func (h *MessageHandler) DeleteMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.DeleteMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message deleted successfully")
}

// RestoreMessage restores a deleted message
func (h *MessageHandler) RestoreMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.RestoreMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "RESTORE_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message restored successfully")
}

// ReactToMessage adds a reaction to a message
func (h *MessageHandler) ReactToMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReactToMessageRequest{}
	h.populateReactToMessageRequest(req, validatedData)

	response, err := h.messageService.ReactToMessage(c.Request.Context(), userID, messageID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REACT_TO_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Reaction added successfully")
}

// RemoveReaction removes a reaction from a message
func (h *MessageHandler) RemoveReaction(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.RemoveReaction(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REMOVE_REACTION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Reaction removed successfully")
}

// GetMessageReactions retrieves reactions for a message
func (h *MessageHandler) GetMessageReactions(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	response, err := h.messageService.GetMessageReactions(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_REACTIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message reactions retrieved successfully")
}

// ReplyToMessage replies to a message
func (h *MessageHandler) ReplyToMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReplyToMessageRequest{
		SenderID:  userID,
		ReplyToID: &messageID,
	}
	h.populateReplyToMessageRequest(req, validatedData)

	response, err := h.messageService.ReplyToMessage(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REPLY_TO_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Reply sent successfully")
}

// ForwardMessage forwards a message
func (h *MessageHandler) ForwardMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ForwardMessageRequest{}
	h.populateForwardMessageRequest(req, validatedData)

	response, err := h.messageService.ForwardMessage(c.Request.Context(), userID, messageID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "FORWARD_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message forwarded successfully")
}

// StarMessage stars a message
func (h *MessageHandler) StarMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.StarMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "STAR_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message starred successfully")
}

// UnstarMessage unstars a message
func (h *MessageHandler) UnstarMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.UnstarMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNSTAR_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message unstarred successfully")
}

// ReportMessage reports a message
func (h *MessageHandler) ReportMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReportMessageRequest{}
	h.populateReportMessageRequest(req, validatedData)

	err = h.messageService.ReportMessage(c.Request.Context(), userID, messageID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REPORT_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message reported successfully")
}

// MarkMessageAsRead marks a message as read
func (h *MessageHandler) MarkMessageAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.MarkMessageAsRead(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_MESSAGE_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message marked as read")
}

// GetDeliveryStatus retrieves delivery status for a message
func (h *MessageHandler) GetDeliveryStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	response, err := h.messageService.GetDeliveryStatus(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_DELIVERY_STATUS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Delivery status retrieved successfully")
}

// GetReadReceipts retrieves read receipts for a message
func (h *MessageHandler) GetReadReceipts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	response, err := h.messageService.GetReadReceipts(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_READ_RECEIPTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Read receipts retrieved successfully")
}

// =============================================================================
// MESSAGE SEARCH AND DISCOVERY
// =============================================================================

// SearchMessages searches messages globally
func (h *MessageHandler) SearchMessages(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	query := c.Query("q")
	if query == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_QUERY", "Search query is required")
		return
	}

	req := &services.SearchMessagesRequest{
		Query: query,
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	// Parse optional filters
	if conversationID := c.Query("conversation_id"); conversationID != "" {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = &objID
		}
	}
	if fromUser := c.Query("from_user"); fromUser != "" {
		if objID, err := primitive.ObjectIDFromHex(fromUser); err == nil {
			req.FromUser = &objID
		}
	}

	response, err := h.messageService.SearchMessages(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_MESSAGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message search completed successfully")
}

// GetRecentSearches retrieves recent search queries
func (h *MessageHandler) GetRecentSearches(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetRecentSearches(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RECENT_SEARCHES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Recent searches retrieved successfully")
}

// ClearRecentSearches clears recent search queries
func (h *MessageHandler) ClearRecentSearches(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	err := h.messageService.ClearRecentSearches(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CLEAR_RECENT_SEARCHES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Recent searches cleared successfully")
}

// AdvancedSearchMessages performs advanced message search
func (h *MessageHandler) AdvancedSearchMessages(c *gin.Context) {
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

	req := &services.AdvancedSearchMessagesRequest{}
	h.populateAdvancedSearchMessagesRequest(req, validatedData)

	response, err := h.messageService.AdvancedSearchMessages(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "ADVANCED_SEARCH_MESSAGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Advanced search completed successfully")
}

// SearchMessagesByMedia searches messages by media type
func (h *MessageHandler) SearchMessagesByMedia(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.SearchMessagesByMediaRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.SearchMessagesByMedia(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_MESSAGES_BY_MEDIA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Media search completed successfully")
}

// SearchMessagesByFiles searches messages by file type
func (h *MessageHandler) SearchMessagesByFiles(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.SearchMessagesByFilesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.SearchMessagesByFiles(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_MESSAGES_BY_FILES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "File search completed successfully")
}

// SearchMessagesByLinks searches messages by links
func (h *MessageHandler) SearchMessagesByLinks(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.SearchMessagesByLinksRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.SearchMessagesByLinks(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_MESSAGES_BY_LINKS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Link search completed successfully")
}

// =============================================================================
// MESSAGE THREADS
// =============================================================================

// GetMessageThreads retrieves message threads
func (h *MessageHandler) GetMessageThreads(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetMessageThreadsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetMessageThreads(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_THREADS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message threads retrieved successfully")
}

// GetThread retrieves a specific thread
func (h *MessageHandler) GetThread(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	threadID, err := primitive.ObjectIDFromHex(c.Param("thread_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_THREAD_ID", "Invalid thread ID")
		return
	}

	response, err := h.messageService.GetThread(c.Request.Context(), userID, threadID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_THREAD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Thread retrieved successfully")
}

// GetThreadMessages retrieves messages in a thread
func (h *MessageHandler) GetThreadMessages(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	threadID, err := primitive.ObjectIDFromHex(c.Param("thread_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_THREAD_ID", "Invalid thread ID")
		return
	}

	req := &services.GetThreadMessagesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 50),
	}

	response, err := h.messageService.GetThreadMessages(c.Request.Context(), userID, threadID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_THREAD_MESSAGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Thread messages retrieved successfully")
}

// MarkThreadAsRead marks a thread as read
func (h *MessageHandler) MarkThreadAsRead(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	threadID, err := primitive.ObjectIDFromHex(c.Param("thread_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_THREAD_ID", "Invalid thread ID")
		return
	}

	err = h.messageService.MarkThreadAsRead(c.Request.Context(), userID, threadID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "MARK_THREAD_READ_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Thread marked as read")
}

// FollowThread follows a thread
func (h *MessageHandler) FollowThread(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	threadID, err := primitive.ObjectIDFromHex(c.Param("thread_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_THREAD_ID", "Invalid thread ID")
		return
	}

	err = h.messageService.FollowThread(c.Request.Context(), userID, threadID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "FOLLOW_THREAD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Thread followed successfully")
}

// UnfollowThread unfollows a thread
func (h *MessageHandler) UnfollowThread(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	threadID, err := primitive.ObjectIDFromHex(c.Param("thread_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_THREAD_ID", "Invalid thread ID")
		return
	}

	err = h.messageService.UnfollowThread(c.Request.Context(), userID, threadID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UNFOLLOW_THREAD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Thread unfollowed successfully")
}

// =============================================================================
// MESSAGE DRAFTS
// =============================================================================

// GetDrafts retrieves message drafts
func (h *MessageHandler) GetDrafts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetMessageDraftsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetMessageDrafts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_DRAFTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Drafts retrieved successfully")
}

// CreateDraft creates a new message draft
func (h *MessageHandler) CreateDraft(c *gin.Context) {
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

	req := &services.CreateMessageDraftRequest{
		UserID: userID,
	}
	h.populateCreateMessageDraftRequest(req, validatedData)

	response, err := h.messageService.CreateMessageDraft(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft created successfully")
}

// UpdateDraft updates a message draft
func (h *MessageHandler) UpdateDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := primitive.ObjectIDFromHex(c.Param("draft_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateMessageDraftRequest{}
	h.populateUpdateMessageDraftRequest(req, validatedData)

	err = h.messageService.UpdateMessageDraft(c.Request.Context(), userID, draftID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Draft updated successfully")
}

// DeleteDraft deletes a message draft
func (h *MessageHandler) DeleteDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := primitive.ObjectIDFromHex(c.Param("draft_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	err = h.messageService.DeleteMessageDraft(c.Request.Context(), userID, draftID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Draft deleted successfully")
}

// SendDraft sends a message draft
func (h *MessageHandler) SendDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := primitive.ObjectIDFromHex(c.Param("draft_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	response, err := h.messageService.SendMessageDraft(c.Request.Context(), userID, draftID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEND_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft sent successfully")
}

// AutoSaveDraft auto-saves a message draft
func (h *MessageHandler) AutoSaveDraft(c *gin.Context) {
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

	req := &services.AutoSaveMessageDraftRequest{
		UserID: userID,
	}
	h.populateAutoSaveMessageDraftRequest(req, validatedData)

	response, err := h.messageService.AutoSaveMessageDraft(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "AUTO_SAVE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft auto-saved successfully")
}

// =============================================================================
// MESSAGE SCHEDULING
// =============================================================================

// GetScheduledMessages retrieves scheduled messages
func (h *MessageHandler) GetScheduledMessages(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetScheduledMessagesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetScheduledMessages(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SCHEDULED_MESSAGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Scheduled messages retrieved successfully")
}

// ScheduleMessage schedules a message
func (h *MessageHandler) ScheduleMessage(c *gin.Context) {
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

	req := &services.ScheduleMessageRequest{
		SenderID: userID,
	}
	h.populateScheduleMessageRequest(req, validatedData)

	response, err := h.messageService.ScheduleMessage(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SCHEDULE_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message scheduled successfully")
}

// UpdateScheduledMessage updates a scheduled message
func (h *MessageHandler) UpdateScheduledMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateScheduledMessageRequest{}
	h.populateUpdateScheduledMessageRequest(req, validatedData)

	err = h.messageService.UpdateScheduledMessage(c.Request.Context(), userID, messageID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_SCHEDULED_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Scheduled message updated successfully")
}

// CancelScheduledMessage cancels a scheduled message
func (h *MessageHandler) CancelScheduledMessage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	err = h.messageService.CancelScheduledMessage(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CANCEL_SCHEDULED_MESSAGE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Scheduled message cancelled successfully")
}

// SendScheduledMessageNow sends a scheduled message immediately
func (h *MessageHandler) SendScheduledMessageNow(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	messageID, err := primitive.ObjectIDFromHex(c.Param("message_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_MESSAGE_ID", "Invalid message ID")
		return
	}

	response, err := h.messageService.SendScheduledMessageNow(c.Request.Context(), userID, messageID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEND_SCHEDULED_MESSAGE_NOW_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Scheduled message sent successfully")
}

// =============================================================================
// MESSAGE TEMPLATES
// =============================================================================

// GetMessageTemplates retrieves message templates
func (h *MessageHandler) GetMessageTemplates(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetMessageTemplatesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.messageService.GetMessageTemplates(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_TEMPLATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message templates retrieved successfully")
}

// CreateMessageTemplate creates a new message template
func (h *MessageHandler) CreateMessageTemplate(c *gin.Context) {
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

	req := &services.CreateMessageTemplateRequest{
		UserID: userID,
	}
	h.populateCreateMessageTemplateRequest(req, validatedData)

	response, err := h.messageService.CreateMessageTemplate(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_MESSAGE_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message template created successfully")
}

// UpdateMessageTemplate updates a message template
func (h *MessageHandler) UpdateMessageTemplate(c *gin.Context) {
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

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateMessageTemplateRequest{}
	h.populateUpdateMessageTemplateRequest(req, validatedData)

	err = h.messageService.UpdateMessageTemplate(c.Request.Context(), userID, templateID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message template updated successfully")
}

// DeleteMessageTemplate deletes a message template
func (h *MessageHandler) DeleteMessageTemplate(c *gin.Context) {
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

	err = h.messageService.DeleteMessageTemplate(c.Request.Context(), userID, templateID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_MESSAGE_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message template deleted successfully")
}

// UseMessageTemplate uses a message template
func (h *MessageHandler) UseMessageTemplate(c *gin.Context) {
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

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UseMessageTemplateRequest{}
	h.populateUseMessageTemplateRequest(req, validatedData)

	response, err := h.messageService.UseMessageTemplate(c.Request.Context(), userID, templateID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "USE_MESSAGE_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message template used successfully")
}

// GetPublicTemplates retrieves public message templates
func (h *MessageHandler) GetPublicTemplates(c *gin.Context) {
	req := &services.GetPublicMessageTemplatesRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Category: c.Query("category"),
	}

	response, err := h.messageService.GetPublicMessageTemplates(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PUBLIC_TEMPLATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Public templates retrieved successfully")
}

// ShareTemplate shares a message template
func (h *MessageHandler) ShareTemplate(c *gin.Context) {
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

	err = h.messageService.ShareMessageTemplate(c.Request.Context(), userID, templateID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SHARE_TEMPLATE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Template shared successfully")
}

// =============================================================================
// MESSAGE SETTINGS AND PREFERENCES
// =============================================================================

// GetMessageSettings retrieves message settings
func (h *MessageHandler) GetMessageSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageSettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message settings retrieved successfully")
}

// UpdateMessageSettings updates message settings
func (h *MessageHandler) UpdateMessageSettings(c *gin.Context) {
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

	req := &services.MessageSettingsRequest{}
	h.populateMessageSettingsRequest(req, validatedData)

	err := h.messageService.UpdateMessageSettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message settings updated successfully")
}

// GetMessagePrivacySettings retrieves message privacy settings
func (h *MessageHandler) GetMessagePrivacySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessagePrivacySettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_PRIVACY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message privacy settings retrieved successfully")
}

// UpdateMessagePrivacySettings updates message privacy settings
func (h *MessageHandler) UpdateMessagePrivacySettings(c *gin.Context) {
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

	req := &services.MessagePrivacyRequest{}
	h.populateMessagePrivacyRequest(req, validatedData)

	err := h.messageService.UpdateMessagePrivacySettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_PRIVACY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message privacy settings updated successfully")
}

// GetMessageNotificationSettings retrieves message notification settings
func (h *MessageHandler) GetMessageNotificationSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageNotificationSettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_NOTIFICATION_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message notification settings retrieved successfully")
}

// UpdateMessageNotificationSettings updates message notification settings
func (h *MessageHandler) UpdateMessageNotificationSettings(c *gin.Context) {
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

	req := &services.MessageNotificationRequest{}
	h.populateMessageNotificationRequest(req, validatedData)

	err := h.messageService.UpdateMessageNotificationSettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_NOTIFICATION_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message notification settings updated successfully")
}

// GetAutoReplySettings retrieves auto-reply settings
func (h *MessageHandler) GetAutoReplySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetAutoReplySettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_AUTO_REPLY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Auto-reply settings retrieved successfully")
}

// UpdateAutoReplySettings updates auto-reply settings
func (h *MessageHandler) UpdateAutoReplySettings(c *gin.Context) {
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

	req := &services.MessageAutoReplyRequest{}
	h.populateMessageAutoReplyRequest(req, validatedData)

	err := h.messageService.UpdateAutoReplySettings(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_AUTO_REPLY_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Auto-reply settings updated successfully")
}

// GetMessageFilters retrieves message filters
func (h *MessageHandler) GetMessageFilters(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageFilters(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_FILTERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message filters retrieved successfully")
}

// CreateMessageFilter creates a new message filter
func (h *MessageHandler) CreateMessageFilter(c *gin.Context) {
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

	req := &services.CreateMessageFilterRequest{
		UserID: userID,
	}
	h.populateCreateMessageFilterRequest(req, validatedData)

	response, err := h.messageService.CreateMessageFilter(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CREATE_MESSAGE_FILTER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message filter created successfully")
}

// UpdateMessageFilter updates a message filter
func (h *MessageHandler) UpdateMessageFilter(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filterID, err := primitive.ObjectIDFromHex(c.Param("filter_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_FILTER_ID", "Invalid filter ID")
		return
	}

	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateMessageFilterRequest{}
	h.populateUpdateMessageFilterRequest(req, validatedData)

	err = h.messageService.UpdateMessageFilter(c.Request.Context(), userID, filterID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "UPDATE_MESSAGE_FILTER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message filter updated successfully")
}

// DeleteMessageFilter deletes a message filter
func (h *MessageHandler) DeleteMessageFilter(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	filterID, err := primitive.ObjectIDFromHex(c.Param("filter_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_FILTER_ID", "Invalid filter ID")
		return
	}

	err = h.messageService.DeleteMessageFilter(c.Request.Context(), userID, filterID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "DELETE_MESSAGE_FILTER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Message filter deleted successfully")
}

// =============================================================================
// MESSAGE ANALYTICS
// =============================================================================

// GetMessageStats retrieves message statistics
func (h *MessageHandler) GetMessageStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message statistics retrieved successfully")
}

// GetConversationStats retrieves conversation statistics
func (h *MessageHandler) GetConversationStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	conversationID, err := primitive.ObjectIDFromHex(c.Param("conversation_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_CONVERSATION_ID", "Invalid conversation ID")
		return
	}

	response, err := h.messageService.GetConversationStats(c.Request.Context(), userID, conversationID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CONVERSATION_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Conversation statistics retrieved successfully")
}

// GetResponseRates retrieves message response rates
func (h *MessageHandler) GetResponseRates(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageResponseRates(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RESPONSE_RATES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Response rates retrieved successfully")
}

// getMessageEngagement retrieves message engagement metrics
func (h *MessageHandler) getMessageEngagement(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageEngagement(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MESSAGE_ENGAGEMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Message engagement retrieved successfully")
}

// GetActivityPatterns retrieves message activity patterns
func (h *MessageHandler) GetActivityPatterns(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetMessageActivityPatterns(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ACTIVITY_PATTERNS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Activity patterns retrieved successfully")
}

// GetPeakMessagingHours retrieves peak messaging hours
func (h *MessageHandler) GetPeakMessagingHours(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.messageService.GetPeakMessagingHours(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PEAK_MESSAGING_HOURS_FAILED", err.Error())
		return
	}
	utils.SendSuccess(c, response, "Peak messaging hours retrieved successfully")
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getIntQuery extracts integer query parameter with default value
func (h *MessageHandler) getIntQuery(c *gin.Context, key string, defaultValue int) int {
	if valueStr := c.Query(key); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// =============================================================================
// REQUEST POPULATION FUNCTIONS
// =============================================================================

// populateCreateConversationRequest populates create conversation request
func (h *MessageHandler) populateCreateConversationRequest(req *services.CreateConversationRequest, data map[string]interface{}) {
	if participants, ok := data["participants"].([]interface{}); ok {
		for _, p := range participants {
			if pStr, ok := p.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(pStr); err == nil {
					req.Participants = append(req.Participants, objID)
				}
			}
		}
	}

	if isGroup, ok := data["is_group"].(bool); ok {
		req.IsGroup = isGroup
	}

	if groupName, ok := data["group_name"].(string); ok {
		req.GroupName = groupName
	}

	if groupImage, ok := data["group_image"].(string); ok {
		req.GroupImage = groupImage
	}
}

// populateConversationUpdateRequest populates conversation update request
func (h *MessageHandler) populateConversationUpdateRequest(req *models.ConversationUpdateRequest, data map[string]interface{}) {
	if groupName, ok := data["group_name"].(string); ok {
		req.GroupName = &groupName
	}

	if groupImage, ok := data["group_image"].(string); ok {
		req.GroupImage = &groupImage
	}
}

// populateMuteConversationRequest populates mute conversation request
func (h *MessageHandler) populateMuteConversationRequest(req *services.MuteConversationRequest, data map[string]interface{}) {
	if duration, ok := data["duration"].(float64); ok {
		req.Duration = int(duration)
	}

	if permanent, ok := data["permanent"].(bool); ok {
		req.Permanent = permanent
	}
}

// populateAddParticipantsRequest populates add participants request
func (h *MessageHandler) populateAddParticipantsRequest(req *services.AddParticipantsRequest, data map[string]interface{}) {
	if participants, ok := data["participants"].([]interface{}); ok {
		for _, p := range participants {
			if pStr, ok := p.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(pStr); err == nil {
					req.Participants = append(req.Participants, objID)
				}
			}
		}
	}
}

// populateConversationSettingsRequest populates conversation settings request
func (h *MessageHandler) populateConversationSettingsRequest(req *services.ConversationSettingsRequest, data map[string]interface{}) {
	if settings, ok := data["settings"].(map[string]interface{}); ok {
		// Map the settings to models.ConversationSettings
		// This would depend on your ConversationSettings structure
		_ = settings
	}
}

// populateSendMessageRequest populates send message request
func (h *MessageHandler) populateSendMessageRequest(req *services.SendMessageRequest, data map[string]interface{}, c *gin.Context) {
	if conversationID, ok := data["conversation_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = &objID
		}
	}

	if recipientID, ok := data["recipient_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(recipientID); err == nil {
			req.RecipientID = &objID
		}
	}

	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if messageType, ok := data["message_type"].(string); ok {
		req.MessageType = models.MessageType(messageType)
	}

	if replyToID, ok := data["reply_to_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(replyToID); err == nil {
			req.ReplyToID = &objID
		}
	}

	// Handle file attachments from multipart form
	if form, err := c.MultipartForm(); err == nil && form != nil {
		if files, exists := form.File["attachments"]; exists {
			req.Attachments = files
		}
	}
}

// populateQuickSendMessageRequest populates quick send message request
func (h *MessageHandler) populateQuickSendMessageRequest(req *services.QuickSendMessageRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if messageType, ok := data["message_type"].(string); ok {
		req.MessageType = models.MessageType(messageType)
	}
}

// populateMessageUpdateRequest populates message update request
func (h *MessageHandler) populateMessageUpdateRequest(req *models.MessageUpdateRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}
}

// populateReactToMessageRequest populates react to message request
func (h *MessageHandler) populateReactToMessageRequest(req *services.ReactToMessageRequest, data map[string]interface{}) {
	if reaction, ok := data["reaction"].(string); ok {
		req.Reaction = reaction
	}
}

// populateReplyToMessageRequest populates reply to message request
func (h *MessageHandler) populateReplyToMessageRequest(req *services.ReplyToMessageRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if attachments, ok := data["attachments"].([]interface{}); ok {
		for _, a := range attachments {
			if aStr, ok := a.(string); ok {
				req.Attachments = append(req.Attachments, aStr)
			}
		}
	}
}

// populateForwardMessageRequest populates forward message request
func (h *MessageHandler) populateForwardMessageRequest(req *services.ForwardMessageRequest, data map[string]interface{}) {
	if conversationIDs, ok := data["conversation_ids"].([]interface{}); ok {
		for _, id := range conversationIDs {
			if idStr, ok := id.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(idStr); err == nil {
					req.ConversationIDs = append(req.ConversationIDs, objID)
				}
			}
		}
	}

	if addComment, ok := data["add_comment"].(string); ok {
		req.AddComment = addComment
	}
}

// populateReportMessageRequest populates report message request
func (h *MessageHandler) populateReportMessageRequest(req *services.ReportMessageRequest, data map[string]interface{}) {
	if reason, ok := data["reason"].(string); ok {
		req.Reason = reason
	}

	if description, ok := data["description"].(string); ok {
		req.Description = description
	}
}

// populateAdvancedSearchMessagesRequest populates advanced search messages request
func (h *MessageHandler) populateAdvancedSearchMessagesRequest(req *services.AdvancedSearchMessagesRequest, data map[string]interface{}) {
	if query, ok := data["query"].(string); ok {
		req.Query = query
	}

	if page, ok := data["page"].(float64); ok {
		req.Page = int(page)
	}

	if limit, ok := data["limit"].(float64); ok {
		req.Limit = int(limit)
	}

	if filters, ok := data["filters"].(map[string]interface{}); ok {
		req.Filters = filters
	}
}

// populateCreateMessageDraftRequest populates create message draft request
func (h *MessageHandler) populateCreateMessageDraftRequest(req *services.CreateMessageDraftRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if conversationID, ok := data["conversation_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = &objID
		}
	}
}

// populateUpdateMessageDraftRequest populates update message draft request
func (h *MessageHandler) populateUpdateMessageDraftRequest(req *services.UpdateMessageDraftRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}
}

// populateAutoSaveMessageDraftRequest populates auto save message draft request
func (h *MessageHandler) populateAutoSaveMessageDraftRequest(req *services.AutoSaveMessageDraftRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if conversationID, ok := data["conversation_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = &objID
		}
	}
}

// populateScheduleMessageRequest populates schedule message request
func (h *MessageHandler) populateScheduleMessageRequest(req *services.ScheduleMessageRequest, data map[string]interface{}) {
	if conversationID, ok := data["conversation_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = objID
		}
	}

	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if scheduledAt, ok := data["scheduled_at"].(string); ok {
		req.ScheduledAt = scheduledAt
	}

	if timezone, ok := data["timezone"].(string); ok {
		req.Timezone = timezone
	}
}

// populateUpdateScheduledMessageRequest populates update scheduled message request
func (h *MessageHandler) populateUpdateScheduledMessageRequest(req *services.UpdateScheduledMessageRequest, data map[string]interface{}) {
	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}

	if scheduledAt, ok := data["scheduled_at"].(string); ok {
		req.ScheduledAt = &scheduledAt
	}
}

// populateCreateMessageTemplateRequest populates create message template request
func (h *MessageHandler) populateCreateMessageTemplateRequest(req *services.CreateMessageTemplateRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = name
	}

	if content, ok := data["content"].(string); ok {
		req.Content = content
	}

	if category, ok := data["category"].(string); ok {
		req.Category = category
	}

	if isPublic, ok := data["is_public"].(bool); ok {
		req.IsPublic = isPublic
	}
}

// populateUpdateMessageTemplateRequest populates update message template request
func (h *MessageHandler) populateUpdateMessageTemplateRequest(req *services.UpdateMessageTemplateRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = &name
	}

	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}

	if category, ok := data["category"].(string); ok {
		req.Category = &category
	}

	if isPublic, ok := data["is_public"].(bool); ok {
		req.IsPublic = &isPublic
	}
}

// populateUseMessageTemplateRequest populates use message template request
func (h *MessageHandler) populateUseMessageTemplateRequest(req *services.UseMessageTemplateRequest, data map[string]interface{}) {
	if conversationID, ok := data["conversation_id"].(string); ok {
		if objID, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			req.ConversationID = objID
		}
	}

	if variables, ok := data["variables"].(map[string]interface{}); ok {
		req.Variables = variables
	}
}

// populateMessageSettingsRequest populates message settings request
func (h *MessageHandler) populateMessageSettingsRequest(req *services.MessageSettingsRequest, data map[string]interface{}) {
	if readReceipts, ok := data["read_receipts"].(bool); ok {
		req.ReadReceipts = &readReceipts
	}

	if typingIndicators, ok := data["typing_indicators"].(bool); ok {
		req.TypingIndicators = &typingIndicators
	}

	if autoDownloadMedia, ok := data["auto_download_media"].(bool); ok {
		req.AutoDownloadMedia = &autoDownloadMedia
	}

	if notificationSound, ok := data["notification_sound"].(bool); ok {
		req.NotificationSound = &notificationSound
	}

	if vibration, ok := data["vibration"].(bool); ok {
		req.Vibration = &vibration
	}
}

// populateMessagePrivacyRequest populates message privacy request
func (h *MessageHandler) populateMessagePrivacyRequest(req *services.MessagePrivacyRequest, data map[string]interface{}) {
	if allowMessagesFrom, ok := data["allow_messages_from"].(string); ok {
		req.AllowMessagesFrom = allowMessagesFrom
	}

	if allowGroupInvites, ok := data["allow_group_invites"].(bool); ok {
		req.AllowGroupInvites = &allowGroupInvites
	}
}

// populateMessageNotificationRequest populates message notification request
func (h *MessageHandler) populateMessageNotificationRequest(req *services.MessageNotificationRequest, data map[string]interface{}) {
	if pushNotifications, ok := data["push_notifications"].(bool); ok {
		req.PushNotifications = &pushNotifications
	}

	if emailNotifications, ok := data["email_notifications"].(bool); ok {
		req.EmailNotifications = &emailNotifications
	}

	if smsNotifications, ok := data["sms_notifications"].(bool); ok {
		req.SMSNotifications = &smsNotifications
	}
}

// populateMessageAutoReplyRequest populates message auto reply request
func (h *MessageHandler) populateMessageAutoReplyRequest(req *services.MessageAutoReplyRequest, data map[string]interface{}) {
	if enabled, ok := data["enabled"].(bool); ok {
		req.Enabled = enabled
	}

	if message, ok := data["message"].(string); ok {
		req.Message = message
	}

	if schedule, ok := data["schedule"].(map[string]interface{}); ok {
		req.Schedule = schedule
	}

	if exceptions, ok := data["exceptions"].([]interface{}); ok {
		for _, e := range exceptions {
			if eStr, ok := e.(string); ok {
				req.Exceptions = append(req.Exceptions, eStr)
			}
		}
	}
}

// populateCreateMessageFilterRequest populates create message filter request
func (h *MessageHandler) populateCreateMessageFilterRequest(req *services.CreateMessageFilterRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = name
	}

	if conditions, ok := data["conditions"].([]interface{}); ok {
		req.Conditions = conditions
	}

	if actions, ok := data["actions"].([]interface{}); ok {
		req.Actions = actions
	}

	if enabled, ok := data["enabled"].(bool); ok {
		req.Enabled = enabled
	}
}

// populateUpdateMessageFilterRequest populates update message filter request
func (h *MessageHandler) populateUpdateMessageFilterRequest(req *services.UpdateMessageFilterRequest, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		req.Name = &name
	}

	if conditions, ok := data["conditions"].([]interface{}); ok {
		req.Conditions = conditions
	}

	if actions, ok := data["actions"].([]interface{}); ok {
		req.Actions = actions
	}

	if enabled, ok := data["enabled"].(bool); ok {
		req.Enabled = &enabled
	}
}
