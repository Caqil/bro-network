package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"bro-network/internal/middleware"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	userService    services.UserServiceInterface
	authMiddleware *middleware.AuthMiddleware
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService services.UserServiceInterface, authMiddleware *middleware.AuthMiddleware) *UserHandler {
	return &UserHandler{
		userService:    userService,
		authMiddleware: authMiddleware,
	}
}

// =============================================================================
// PUBLIC USER ROUTES (NO AUTH REQUIRED)
// =============================================================================

// GetUsers retrieves a list of users with pagination and filtering
func (h *UserHandler) GetUsers(c *gin.Context) {
	// Parse query parameters
	req := &services.GetUsersRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Sort:     c.Query("sort"),
		Filter:   c.Query("filter"),
		Location: c.Query("location"),
	}

	// Call service
	response, err := h.userService.GetUsers(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Users retrieved successfully")
}

// SearchUsers searches for users based on query
func (h *UserHandler) SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_QUERY", "Search query is required")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	req := &services.SearchUsersRequest{
		Query:    query,
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Filters:  make(map[string]interface{}),
		ViewerID: viewerID,
	}

	// Parse additional filters
	if location := c.Query("location"); location != "" {
		req.Filters["location"] = location
	}
	if verified := c.Query("verified"); verified == "true" {
		req.Filters["is_verified"] = true
	}

	// Call service
	response, err := h.userService.SearchUsers(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_USERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Search completed successfully")
}

// GetTrendingUsers retrieves trending users
func (h *UserHandler) GetTrendingUsers(c *gin.Context) {
	limit := h.getIntQuery(c, "limit", 20)

	users, err := h.userService.GetTrendingUsers(c.Request.Context(), limit)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_TRENDING_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, gin.H{"users": users}, "Trending users retrieved successfully")
}

// GetSuggestedUsers retrieves suggested users
func (h *UserHandler) GetSuggestedUsers(c *gin.Context) {
	limit := h.getIntQuery(c, "limit", 20)

	users, err := h.userService.GetSuggestedUsers(c.Request.Context(), limit)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SUGGESTED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, gin.H{"users": users}, "Suggested users retrieved successfully")
}

// GetUserProfile retrieves a user's public profile
func (h *UserHandler) GetUserProfile(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_USERNAME", "Username is required")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	profile, err := h.userService.GetUserProfile(c.Request.Context(), username, viewerID)
	if err != nil {
		utils.SendError(c, http.StatusNotFound, "USER_NOT_FOUND", err.Error())
		return
	}

	utils.SendSuccess(c, profile, "Profile retrieved successfully")
}

// GetUserPosts retrieves a user's posts
func (h *UserHandler) GetUserPosts(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_USERNAME", "Username is required")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	req := &services.GetUserPostsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Type:     c.Query("type"),
		Sort:     c.Query("sort"),
		ViewerID: viewerID,
	}

	response, err := h.userService.GetUserPosts(c.Request.Context(), username, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Posts retrieved successfully")
}

// GetUserFollowers retrieves a user's followers
func (h *UserHandler) GetUserFollowers(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_USERNAME", "Username is required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetUserFollowers(c.Request.Context(), username, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FOLLOWERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Followers retrieved successfully")
}

// GetUserFollowing retrieves users that a user is following
func (h *UserHandler) GetUserFollowing(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_USERNAME", "Username is required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetUserFollowing(c.Request.Context(), username, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FOLLOWING_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Following retrieved successfully")
}

// CheckUserExists checks if a user exists
func (h *UserHandler) CheckUserExists(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_USERNAME", "Username is required")
		return
	}

	response, err := h.userService.CheckUserExists(c.Request.Context(), username)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "CHECK_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User existence checked")
}

// =============================================================================
// CURRENT USER OPERATIONS (/me endpoints)
// =============================================================================

// GetCurrentUser retrieves the current user's full profile
func (h *UserHandler) GetCurrentUser(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, err := h.userService.GetCurrentUser(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CURRENT_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, user, "Current user retrieved successfully")
}

// UpdateProfile updates user's profile information
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &services.UpdateProfileRequest{}

	if firstName, ok := validatedData["first_name"].(string); ok {
		req.FirstName = &firstName
	}
	if lastName, ok := validatedData["last_name"].(string); ok {
		req.LastName = &lastName
	}
	if displayName, ok := validatedData["display_name"].(string); ok {
		req.DisplayName = &displayName
	}
	if bio, ok := validatedData["bio"].(string); ok {
		req.Bio = &bio
	}
	if website, ok := validatedData["website"].(string); ok {
		req.Website = &website
	}
	if location, ok := validatedData["location"].(string); ok {
		req.Location = &location
	}
	if isPrivate, ok := validatedData["is_private"].(bool); ok {
		req.IsPrivate = &isPrivate
	}

	// Call service
	if err := h.userService.UpdateProfile(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_PROFILE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Profile updated successfully")
}

// DeleteProfile soft deletes user profile
func (h *UserHandler) DeleteProfile(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.DeleteProfileRequest{
		Password:     validatedData["password"].(string),
		Confirmation: validatedData["confirmation"].(string),
	}

	if reason, ok := validatedData["reason"].(string); ok {
		req.Reason = reason
	}

	// Call service
	if err := h.userService.DeleteProfile(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DELETE_PROFILE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Profile deleted successfully")
}

// GetUserSettings retrieves user's settings
func (h *UserHandler) GetUserSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetUserSettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Settings retrieved successfully")
}

// UpdateUserSettings updates user's settings
func (h *UserHandler) UpdateUserSettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &services.UpdateUserSettingsRequest{}

	if theme, ok := validatedData["theme"].(string); ok {
		req.Theme = &theme
	}
	if language, ok := validatedData["language"].(string); ok {
		req.Language = &language
	}
	if timezone, ok := validatedData["timezone"].(string); ok {
		req.TimeZone = &timezone
	}
	if emailNotifications, ok := validatedData["email_notifications"].(bool); ok {
		req.EmailNotifications = &emailNotifications
	}
	if pushNotifications, ok := validatedData["push_notifications"].(bool); ok {
		req.PushNotifications = &pushNotifications
	}
	if smsNotifications, ok := validatedData["sms_notifications"].(bool); ok {
		req.SMSNotifications = &smsNotifications
	}

	// Call service
	if err := h.userService.UpdateUserSettings(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_SETTINGS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Settings updated successfully")
}

// GetPrivacySettings retrieves user's privacy settings
func (h *UserHandler) GetPrivacySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetPrivacySettings(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PRIVACY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Privacy settings retrieved successfully")
}

// UpdatePrivacySettings updates user's privacy settings
func (h *UserHandler) UpdatePrivacySettings(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &services.UpdatePrivacySettingsRequest{}

	if profileVisibility, ok := validatedData["profile_visibility"].(string); ok {
		req.ProfileVisibility = &profileVisibility
	}
	if showOnlineStatus, ok := validatedData["show_online_status"].(bool); ok {
		req.ShowOnlineStatus = &showOnlineStatus
	}
	if showReadReceipts, ok := validatedData["show_read_receipts"].(bool); ok {
		req.ShowReadReceipts = &showReadReceipts
	}
	if allowDirectMessages, ok := validatedData["allow_direct_messages"].(bool); ok {
		req.AllowDirectMessages = &allowDirectMessages
	}
	if showActivityStatus, ok := validatedData["show_activity_status"].(bool); ok {
		req.ShowActivityStatus = &showActivityStatus
	}

	// Call service
	if err := h.userService.UpdatePrivacySettings(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_PRIVACY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Privacy settings updated successfully")
}

// GetNotificationPreferences retrieves user's notification preferences
func (h *UserHandler) GetNotificationPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetNotificationPreferences(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Notification preferences retrieved successfully")
}

// UpdateNotificationPreferences updates user's notification preferences
func (h *UserHandler) UpdateNotificationPreferences(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := &services.UpdateNotificationPreferencesRequest{}

	if emailNotifications, ok := validatedData["email_notifications"].(bool); ok {
		req.EmailNotifications = &emailNotifications
	}
	if pushNotifications, ok := validatedData["push_notifications"].(bool); ok {
		req.PushNotifications = &pushNotifications
	}
	if likes, ok := validatedData["likes"].(bool); ok {
		req.Likes = &likes
	}
	if comments, ok := validatedData["comments"].(bool); ok {
		req.Comments = &comments
	}
	if follows, ok := validatedData["follows"].(bool); ok {
		req.Follows = &follows
	}
	if messages, ok := validatedData["messages"].(bool); ok {
		req.Messages = &messages
	}
	if mentions, ok := validatedData["mentions"].(bool); ok {
		req.Mentions = &mentions
	}

	// Call service
	if err := h.userService.UpdateNotificationPreferences(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_NOTIFICATIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Notification preferences updated successfully")
}

// UploadAvatar uploads user's avatar image
func (h *UserHandler) UploadAvatar(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get uploaded file from context (set by file upload middleware)
	file, exists := c.Get("uploaded_file")
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "NO_FILE", "No file uploaded")
		return
	}

	uploadedFile, ok := file.(*services.UploadedFile)
	if !ok {
		utils.SendError(c, http.StatusBadRequest, "INVALID_FILE", "Invalid file format")
		return
	}

	// Call service
	response, err := h.userService.UploadAvatar(c.Request.Context(), userID, uploadedFile)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPLOAD_AVATAR_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Avatar uploaded successfully")
}

// RemoveAvatar removes user's avatar image
func (h *UserHandler) RemoveAvatar(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	if err := h.userService.RemoveAvatar(c.Request.Context(), userID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REMOVE_AVATAR_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Avatar removed successfully")
}

// UploadCoverImage uploads user's cover image
func (h *UserHandler) UploadCoverImage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get uploaded file from context
	file, exists := c.Get("uploaded_file")
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "NO_FILE", "No file uploaded")
		return
	}

	uploadedFile, ok := file.(*services.UploadedFile)
	if !ok {
		utils.SendError(c, http.StatusBadRequest, "INVALID_FILE", "Invalid file format")
		return
	}

	// Call service
	response, err := h.userService.UploadCoverImage(c.Request.Context(), userID, uploadedFile)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPLOAD_COVER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Cover image uploaded successfully")
}

// RemoveCoverImage removes user's cover image
func (h *UserHandler) RemoveCoverImage(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Call service
	if err := h.userService.RemoveCoverImage(c.Request.Context(), userID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REMOVE_COVER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Cover image removed successfully")
}

// GetUserStats retrieves user's statistics
func (h *UserHandler) GetUserStats(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetUserStats(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_STATS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User stats retrieved successfully")
}

// GetUserAnalytics retrieves user's analytics
func (h *UserHandler) GetUserAnalytics(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Parse analytics request parameters
	req := &services.AnalyticsRequest{
		Period:  c.Query("period"),
		Metrics: strings.Split(c.Query("metrics"), ","),
	}

	// Parse date parameters if provided
	if startDate := c.Query("start_date"); startDate != "" {
		// Parse start date
	}
	if endDate := c.Query("end_date"); endDate != "" {
		// Parse end date
	}

	response, err := h.userService.GetUserAnalytics(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ANALYTICS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Analytics retrieved successfully")
}

// GetUserActivity retrieves user's activity log
func (h *UserHandler) GetUserActivity(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.ActivityRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
		Types: strings.Split(c.Query("types"), ","),
	}

	response, err := h.userService.GetUserActivity(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ACTIVITY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Activity retrieved successfully")
}

// GetUserHistory retrieves user's action history
func (h *UserHandler) GetUserHistory(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.HistoryRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
		Type:  c.Query("type"),
	}

	response, err := h.userService.GetUserHistory(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_HISTORY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "History retrieved successfully")
}

// GetBookmarks retrieves user's bookmarks
func (h *UserHandler) GetBookmarks(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetBookmarks(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_BOOKMARKS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Bookmarks retrieved successfully")
}

// GetSavedPosts retrieves user's saved posts
func (h *UserHandler) GetSavedPosts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetSavedPosts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SAVED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Saved posts retrieved successfully")
}

// GetLikedPosts retrieves user's liked posts
func (h *UserHandler) GetLikedPosts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetLikedPosts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_LIKED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Liked posts retrieved successfully")
}

// GetMyFollowing retrieves current user's following list
func (h *UserHandler) GetMyFollowing(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetMyFollowing(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MY_FOLLOWING_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Following list retrieved successfully")
}

// GetMyFollowers retrieves current user's followers list
func (h *UserHandler) GetMyFollowers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetMyFollowers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MY_FOLLOWERS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Followers list retrieved successfully")
}

// GetFollowRequests retrieves pending follow requests for current user
func (h *UserHandler) GetFollowRequests(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetFollowRequests(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FOLLOW_REQUESTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Follow requests retrieved successfully")
}

// GetPendingRequests retrieves current user's pending follow requests
func (h *UserHandler) GetPendingRequests(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetPendingRequests(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PENDING_REQUESTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Pending requests retrieved successfully")
}

// GetBlockedUsers retrieves current user's blocked users list
func (h *UserHandler) GetBlockedUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetBlockedUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_BLOCKED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Blocked users retrieved successfully")
}

// GetMutedUsers retrieves current user's muted users list
func (h *UserHandler) GetMutedUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetMutedUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MUTED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Muted users retrieved successfully")
}

// RequestVerification requests account verification
func (h *UserHandler) RequestVerification(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.VerificationRequest{
		Category:    validatedData["category"].(string),
		Website:     validatedData["website"].(string),
		Description: validatedData["description"].(string),
	}

	if documents, ok := validatedData["documents"].([]interface{}); ok {
		for _, doc := range documents {
			if docStr, ok := doc.(string); ok {
				req.Documents = append(req.Documents, docStr)
			}
		}
	}

	if socialLinks, ok := validatedData["social_links"].([]interface{}); ok {
		for _, link := range socialLinks {
			if linkStr, ok := link.(string); ok {
				req.SocialLinks = append(req.SocialLinks, linkStr)
			}
		}
	}

	// Call service
	if err := h.userService.RequestVerification(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REQUEST_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, "Verification request submitted")
}

// GetVerificationStatus retrieves current user's verification status
func (h *UserHandler) GetVerificationStatus(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetVerificationStatus(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_VERIFICATION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Verification status retrieved successfully")
}

// GetUserData retrieves current user's data summary
func (h *UserHandler) GetUserData(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.GetUserData(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_DATA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User data retrieved")
}

// ExportUserData initiates user data export
func (h *UserHandler) ExportUserData(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.userService.ExportUserData(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "EXPORT_DATA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Data export initiated")
}

// DownloadUserData provides download link for exported data
func (h *UserHandler) DownloadUserData(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	exportID := c.Param("export_id")
	if exportID == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_EXPORT_ID", "Export ID is required")
		return
	}

	response, err := h.userService.DownloadUserData(c.Request.Context(), userID, exportID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "DOWNLOAD_DATA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Download link generated successfully")
}

// GetCloseFriends retrieves current user's close friends list
func (h *UserHandler) GetCloseFriends(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetCloseFriends(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_CLOSE_FRIENDS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Close friends retrieved successfully")
}

// AddToCloseFriends adds a user to close friends list
func (h *UserHandler) AddToCloseFriends(c *gin.Context) {
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

	if err := h.userService.AddToCloseFriends(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "ADD_CLOSE_FRIEND_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Added to close friends")
}

// RemoveFromCloseFriends removes a user from close friends list
func (h *UserHandler) RemoveFromCloseFriends(c *gin.Context) {
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

	if err := h.userService.RemoveFromCloseFriends(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REMOVE_CLOSE_FRIEND_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Removed from close friends")
}

// =============================================================================
// USER INTERACTIONS
// =============================================================================

// FollowUser follows a user
func (h *UserHandler) FollowUser(c *gin.Context) {
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

	response, err := h.userService.FollowUser(c.Request.Context(), userID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "FOLLOW_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Follow action completed successfully")
}

// UnfollowUser unfollows a user
func (h *UserHandler) UnfollowUser(c *gin.Context) {
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

	if err := h.userService.UnfollowUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNFOLLOW_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unfollowed successfully")
}

// BlockUser blocks a user
func (h *UserHandler) BlockUser(c *gin.Context) {
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

	if err := h.userService.BlockUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "BLOCK_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User blocked successfully")
}

// UnblockUser unblocks a user
func (h *UserHandler) UnblockUser(c *gin.Context) {
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

	if err := h.userService.UnblockUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNBLOCK_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unblocked successfully")
}

// MuteUser mutes a user
func (h *UserHandler) MuteUser(c *gin.Context) {
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

	if err := h.userService.MuteUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "MUTE_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User muted successfully")
}

// UnmuteUser unmutes a user
func (h *UserHandler) UnmuteUser(c *gin.Context) {
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

	if err := h.userService.UnmuteUser(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNMUTE_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User unmuted successfully")
}

// ReportUser reports a user
func (h *UserHandler) ReportUser(c *gin.Context) {
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

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReportUserRequest{
		Reason:      validatedData["reason"].(string),
		Description: validatedData["description"].(string),
	}

	if evidence, ok := validatedData["evidence"].([]interface{}); ok {
		for _, item := range evidence {
			if str, ok := item.(string); ok {
				req.Evidence = append(req.Evidence, str)
			}
		}
	}

	if err := h.userService.ReportUser(c.Request.Context(), userID, targetUserID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REPORT_USER_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "User reported successfully")
}

// AcceptFollowRequest accepts a follow request
func (h *UserHandler) AcceptFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	requesterID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.userService.AcceptFollowRequest(c.Request.Context(), userID, requesterID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "ACCEPT_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request accepted")
}

// RejectFollowRequest rejects a follow request
func (h *UserHandler) RejectFollowRequest(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	requesterID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.userService.RejectFollowRequest(c.Request.Context(), userID, requesterID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REJECT_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request rejected")
}

// CancelFollowRequest cancels a sent follow request
func (h *UserHandler) CancelFollowRequest(c *gin.Context) {
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

	if err := h.userService.CancelFollowRequest(c.Request.Context(), userID, targetUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "CANCEL_REQUEST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Follow request cancelled")
}

// GetRelationship gets relationship status between users
func (h *UserHandler) GetRelationship(c *gin.Context) {
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

	response, err := h.userService.GetRelationship(c.Request.Context(), userID, targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RELATIONSHIP_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Relationship retrieved")
}

// GetMutualConnections gets mutual connections between users
func (h *UserHandler) GetMutualConnections(c *gin.Context) {
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

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetMutualConnections(c.Request.Context(), userID, targetUserID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_MUTUAL_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Mutual connections retrieved")
}

// GetUserPostsAuth gets a user's posts (authenticated version)
func (h *UserHandler) GetUserPostsAuth(c *gin.Context) {
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

	req := &services.GetUserPostsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Type:     c.Query("type"),
		Sort:     c.Query("sort"),
		ViewerID: &userID,
	}

	response, err := h.userService.GetUserPostsAuth(c.Request.Context(), userID, targetUserID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User posts retrieved")
}

// GetUserMedia gets a user's media
func (h *UserHandler) GetUserMedia(c *gin.Context) {
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

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetUserMedia(c.Request.Context(), userID, targetUserID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_MEDIA_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User media retrieved")
}

// GetUserLikes gets a user's liked posts
func (h *UserHandler) GetUserLikes(c *gin.Context) {
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

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetUserLikes(c.Request.Context(), userID, targetUserID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_USER_LIKES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User likes retrieved")
}

// =============================================================================
// RECOMMENDATIONS AND DISCOVERY
// =============================================================================

// GetFollowSuggestions gets follow suggestions for user
func (h *UserHandler) GetFollowSuggestions(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.SuggestionsRequest{
		Page:    h.getIntQuery(c, "page", 1),
		Limit:   h.getIntQuery(c, "limit", 20),
		Filters: strings.Split(c.Query("filters"), ","),
	}

	response, err := h.userService.GetFollowSuggestions(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SUGGESTIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Follow suggestions retrieved")
}

// GetFriendSuggestions gets friend suggestions for user
func (h *UserHandler) GetFriendSuggestions(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.SuggestionsRequest{
		Page:    h.getIntQuery(c, "page", 1),
		Limit:   h.getIntQuery(c, "limit", 20),
		Filters: strings.Split(c.Query("filters"), ","),
	}

	response, err := h.userService.GetFriendSuggestions(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FRIEND_SUGGESTIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Friend suggestions retrieved")
}

// DismissSuggestion dismisses a user suggestion
func (h *UserHandler) DismissSuggestion(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	suggestedUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	if err := h.userService.DismissSuggestion(c.Request.Context(), userID, suggestedUserID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DISMISS_SUGGESTION_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Suggestion dismissed")
}

// GetNearbyUsers gets nearby users
func (h *UserHandler) GetNearbyUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	lat, _ := strconv.ParseFloat(c.Query("lat"), 64)
	lng, _ := strconv.ParseFloat(c.Query("lng"), 64)
	radius, _ := strconv.Atoi(c.Query("radius"))

	if lat == 0 || lng == 0 {
		utils.SendError(c, http.StatusBadRequest, "MISSING_LOCATION", "Latitude and longitude are required")
		return
	}

	req := &services.NearbyUsersRequest{
		Latitude:  lat,
		Longitude: lng,
		Radius:    radius,
		Page:      h.getIntQuery(c, "page", 1),
		Limit:     h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetNearbyUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NEARBY_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Nearby users retrieved")
}

// GetOnlineUsers gets currently online users
func (h *UserHandler) GetOnlineUsers(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.PaginationRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.userService.GetOnlineUsers(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ONLINE_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Online users retrieved")
}

// AdvancedUserSearch performs advanced user search
func (h *UserHandler) AdvancedUserSearch(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.AdvancedSearchRequest{
		Query:   c.Query("q"),
		Sort:    c.Query("sort"),
		Page:    h.getIntQuery(c, "page", 1),
		Limit:   h.getIntQuery(c, "limit", 20),
		Filters: make(map[string]interface{}),
	}

	// Parse filters from query parameters
	if location := c.Query("location"); location != "" {
		req.Filters["location"] = location
	}
	if verified := c.Query("verified"); verified != "" {
		req.Verified = &[]bool{verified == "true"}[0]
	}

	response, err := h.userService.AdvancedUserSearch(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "ADVANCED_SEARCH_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Advanced search completed")
}

// =============================================================================
// CONTACTS
// =============================================================================

// SyncContacts syncs user's contacts
func (h *UserHandler) SyncContacts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.SyncContactsRequest{}

	if contacts, ok := validatedData["contacts"].([]interface{}); ok {
		for _, contact := range contacts {
			if contactMap, ok := contact.(map[string]interface{}); ok {
				syncContact := &services.Contact{
					Name:  contactMap["name"].(string),
					Email: contactMap["email"].(string),
					Phone: contactMap["phone"].(string),
				}
				req.Contacts = append(req.Contacts, syncContact)
			}
		}
	}

	response, err := h.userService.SyncContacts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "SYNC_CONTACTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Contacts synced successfully")
}

// FindContactsOnPlatform finds contacts on the platform
func (h *UserHandler) FindContactsOnPlatform(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.FindContactsRequest{
		Email: c.Query("email"),
		Phone: c.Query("phone"),
	}

	response, err := h.userService.FindContactsOnPlatform(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "FIND_CONTACTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Contacts found")
}

// InviteContacts invites contacts to join the platform
func (h *UserHandler) InviteContacts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.InviteContactsRequest{
		Message: validatedData["message"].(string),
	}

	if emails, ok := validatedData["emails"].([]interface{}); ok {
		for _, email := range emails {
			if emailStr, ok := email.(string); ok {
				req.Emails = append(req.Emails, emailStr)
			}
		}
	}

	if err := h.userService.InviteContacts(c.Request.Context(), userID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVITE_CONTACTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Invitations sent successfully")
}

// =============================================================================
// BADGES AND ACHIEVEMENTS
// =============================================================================

// GetUserBadges gets a user's badges
func (h *UserHandler) GetUserBadges(c *gin.Context) {
	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	response, err := h.userService.GetUserBadges(c.Request.Context(), targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_BADGES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User badges retrieved")
}

// GetUserAchievements gets a user's achievements
func (h *UserHandler) GetUserAchievements(c *gin.Context) {
	targetUserID, err := primitive.ObjectIDFromHex(c.Param("user_id"))
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_USER_ID", "Invalid user ID")
		return
	}

	response, err := h.userService.GetUserAchievements(c.Request.Context(), targetUserID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_ACHIEVEMENTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "User achievements retrieved")
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// getIntQuery gets integer value from query parameter with default
func (h *UserHandler) getIntQuery(c *gin.Context, param string, defaultValue int) int {
	if value := c.Query(param); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getObjectIDParam gets ObjectID from URL parameter
func (h *UserHandler) getObjectIDParam(c *gin.Context, param string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Param(param))
}
