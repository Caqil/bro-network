package handlers

import (
	"net/http"
	"strconv"

	"bro-network/internal/middleware"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// FollowHandler handles follow-related HTTP requests
type FollowHandler struct {
	followService  services.FollowServiceInterface
	authMiddleware *middleware.AuthMiddleware
}

// NewFollowHandler creates a new follow handler
func NewFollowHandler(followService services.FollowServiceInterface, authMiddleware *middleware.AuthMiddleware) *FollowHandler {
	return &FollowHandler{
		followService:  followService,
		authMiddleware: authMiddleware,
	}
}

// =============================================================================
// FOLLOW MANAGEMENT
// =============================================================================

// FollowUser follows a user
func (h *FollowHandler) FollowUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_FOLLOW_SELF", "Cannot follow yourself")
		return
	}

	response, err := h.followService.FollowUser(c.Request.Context(), userID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "FOLLOW_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User followed successfully")
}

// UnfollowUser unfollows a user
func (h *FollowHandler) UnfollowUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.followService.UnfollowUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNFOLLOW_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unfollowed successfully")
}

// =============================================================================
// FOLLOW REQUESTS MANAGEMENT
// =============================================================================

// SendFollowRequest sends a follow request to a private user
func (h *FollowHandler) SendFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_FOLLOW_SELF", "Cannot send follow request to yourself")
		return
	}

	response, err := h.followService.SendFollowRequest(c.Request.Context(), userID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "SEND_FOLLOW_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Follow request sent successfully")
}

// AcceptFollowRequest accepts a follow request
func (h *FollowHandler) AcceptFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	requestID, err := primitive.ObjectIDFromHex(c.Param("request_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_REQUEST_ID", "Invalid request ID")
		return
	}

	if err := h.followService.AcceptFollowRequest(c.Request.Context(), userID, requestID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "ACCEPT_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request accepted")
}

// RejectFollowRequest rejects a follow request
func (h *FollowHandler) RejectFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	requestID, err := primitive.ObjectIDFromHex(c.Param("request_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_REQUEST_ID", "Invalid request ID")
		return
	}

	if err := h.followService.RejectFollowRequest(c.Request.Context(), userID, requestID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REJECT_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request rejected")
}

// CancelFollowRequest cancels a sent follow request
func (h *FollowHandler) CancelFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	requestID, err := primitive.ObjectIDFromHex(c.Param("request_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_REQUEST_ID", "Invalid request ID")
		return
	}

	if err := h.followService.CancelFollowRequest(c.Request.Context(), userID, requestID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "CANCEL_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request cancelled")
}

// =============================================================================
// FOLLOW REQUESTS RETRIEVAL
// =============================================================================

// GetPendingRequests retrieves pending follow requests sent by current user
func (h *FollowHandler) GetPendingRequests(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetPendingRequests(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PENDING_REQUESTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Pending requests retrieved successfully")
}

// GetReceivedRequests retrieves follow requests received by current user
func (h *FollowHandler) GetReceivedRequests(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetReceivedRequests(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RECEIVED_REQUESTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Received requests retrieved successfully")
}

// =============================================================================
// FOLLOWERS AND FOLLOWING
// =============================================================================

// GetUserFollowers retrieves followers of a specific user
func (h *FollowHandler) GetUserFollowers(c *gin.Context) {
	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	req := &services.GetFollowersRequest{
		UserID:   targetUserID,
		ViewerID: viewerID,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetUserFollowers(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_FOLLOWERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Followers retrieved successfully")
}

// GetUserFollowing retrieves users followed by a specific user
func (h *FollowHandler) GetUserFollowing(c *gin.Context) {
	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	req := &services.GetFollowingRequest{
		UserID:   targetUserID,
		ViewerID: viewerID,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetUserFollowing(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_FOLLOWING_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Following retrieved successfully")
}

// GetMyFollowers retrieves current user's followers
func (h *FollowHandler) GetMyFollowers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFollowersRequest{
		UserID:   userID,
		ViewerID: &userID,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetUserFollowers(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MY_FOLLOWERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Your followers retrieved successfully")
}

// GetMyFollowing retrieves current user's following
func (h *FollowHandler) GetMyFollowing(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFollowingRequest{
		UserID:   userID,
		ViewerID: &userID,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetUserFollowing(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MY_FOLLOWING_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Your following retrieved successfully")
}

// =============================================================================
// RELATIONSHIP MANAGEMENT
// =============================================================================

// MuteUser mutes a user
func (h *FollowHandler) MuteUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_MUTE_SELF", "Cannot mute yourself")
		return
	}

	if err := h.followService.MuteUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "MUTE_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User muted successfully")
}

// UnmuteUser unmutes a user
func (h *FollowHandler) UnmuteUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.followService.UnmuteUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNMUTE_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unmuted successfully")
}

// BlockUser blocks a user
func (h *FollowHandler) BlockUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_BLOCK_SELF", "Cannot block yourself")
		return
	}

	if err := h.followService.BlockUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "BLOCK_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User blocked successfully")
}

// UnblockUser unblocks a user
func (h *FollowHandler) UnblockUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.followService.UnblockUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNBLOCK_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unblocked successfully")
}

// RestrictUser restricts a user
func (h *FollowHandler) RestrictUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_RESTRICT_SELF", "Cannot restrict yourself")
		return
	}

	if err := h.followService.RestrictUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "RESTRICT_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User restricted successfully")
}

// UnrestrictUser unrestricts a user
func (h *FollowHandler) UnrestrictUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.followService.UnrestrictUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNRESTRICT_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unrestricted successfully")
}

// =============================================================================
// CLOSE FRIENDS MANAGEMENT
// =============================================================================

// AddToCloseFriends adds a user to close friends
func (h *FollowHandler) AddToCloseFriends(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if userID == targetUserID {
		utils.SendError(c, http.StatusBadRequest, "CANNOT_ADD_SELF", "Cannot add yourself to close friends")
		return
	}

	if err := h.followService.AddToCloseFriends(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "ADD_CLOSE_FRIEND_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User added to close friends")
}

// RemoveFromCloseFriends removes a user from close friends
func (h *FollowHandler) RemoveFromCloseFriends(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.followService.RemoveFromCloseFriends(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REMOVE_CLOSE_FRIEND_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User removed from close friends")
}

// GetCloseFriends retrieves current user's close friends
func (h *FollowHandler) GetCloseFriends(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetCloseFriends(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CLOSE_FRIENDS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Close friends retrieved successfully")
}

// =============================================================================
// RELATIONSHIP STATUS
// =============================================================================

// GetRelationship retrieves relationship status between current user and target user
func (h *FollowHandler) GetRelationship(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	relationship, err := h.followService.GetRelationship(c.Request.Context(), userID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RELATIONSHIP_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, relationship, "Relationship retrieved successfully")
}

// GetMutualFollowers retrieves mutual followers between current user and target user
func (h *FollowHandler) GetMutualFollowers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	req := &services.GetMutualFollowersRequest{
		UserID:   userID,
		TargetID: targetUserID,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetMutualFollowers(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MUTUAL_FOLLOWERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Mutual followers retrieved successfully")
}

// =============================================================================
// BLOCKED/MUTED USERS
// =============================================================================

// GetBlockedUsers retrieves current user's blocked users
func (h *FollowHandler) GetBlockedUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetBlockedUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_BLOCKED_USERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Blocked users retrieved successfully")
}

// GetMutedUsers retrieves current user's muted users
func (h *FollowHandler) GetMutedUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.followService.GetMutedUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MUTED_USERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Muted users retrieved successfully")
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// getIntQuery extracts integer query parameter with default value
func (h *FollowHandler) getIntQuery(c *gin.Context, key string, defaultValue int) int {
	if value := c.Query(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil && intValue > 0 {
			return intValue
		}
	}
	return defaultValue
}
