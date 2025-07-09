package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"bro-network/internal/middleware"
	"bro-network/internal/models"
	"bro-network/internal/services"
	"bro-network/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// PostHandler handles post-related HTTP requests
type PostHandler struct {
	postService    services.PostServiceInterface
	authMiddleware *middleware.AuthMiddleware
}

// NewPostHandler creates a new post handler
func NewPostHandler(postService services.PostServiceInterface, authMiddleware *middleware.AuthMiddleware) *PostHandler {
	return &PostHandler{
		postService:    postService,
		authMiddleware: authMiddleware,
	}
}

// =============================================================================
// PUBLIC POST ROUTES (NO AUTH REQUIRED)
// =============================================================================

// GetPublicPosts retrieves public posts with filtering and pagination
func (h *PostHandler) GetPublicPosts(c *gin.Context) {
	req := &services.GetPublicPostsRequest{
		Page:      h.getIntQuery(c, "page", 1),
		Limit:     h.getIntQuery(c, "limit", 20),
		SortBy:    c.Query("sort_by"),
		SortOrder: c.Query("sort_order"),
		Filter:    h.buildPostFilter(c),
	}

	response, err := h.postService.GetPublicPosts(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_PUBLIC_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Public posts retrieved successfully")
}

// GetTrendingPosts retrieves trending posts
func (h *PostHandler) GetTrendingPosts(c *gin.Context) {
	req := &services.GetTrendingPostsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Period:   c.DefaultQuery("period", "day"),
		Category: c.Query("category"),
	}

	response, err := h.postService.GetTrendingPosts(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_TRENDING_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Trending posts retrieved successfully")
}

// GetPopularPosts retrieves popular posts
func (h *PostHandler) GetPopularPosts(c *gin.Context) {
	req := &services.GetPopularPostsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Period:   c.DefaultQuery("period", "week"),
		MinLikes: h.getIntQuery(c, "min_likes", 0),
	}

	response, err := h.postService.GetPopularPosts(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_POPULAR_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Popular posts retrieved successfully")
}

// GetPostsByHashtag retrieves posts by hashtag
func (h *PostHandler) GetPostsByHashtag(c *gin.Context) {
	hashtag := c.Param("hashtag")
	if hashtag == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_HASHTAG", "Hashtag is required")
		return
	}

	req := &services.GetPostsByHashtagRequest{
		Page:   h.getIntQuery(c, "page", 1),
		Limit:  h.getIntQuery(c, "limit", 20),
		SortBy: c.DefaultQuery("sort_by", "created_at"),
	}

	response, err := h.postService.GetPostsByHashtag(c.Request.Context(), hashtag, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_POSTS_BY_HASHTAG_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Posts retrieved successfully")
}

// GetPost retrieves a single post
func (h *PostHandler) GetPost(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	response, err := h.postService.GetPost(c.Request.Context(), postID, viewerID)
	if err != nil {
		utils.SendError(c, http.StatusNotFound, "POST_NOT_FOUND", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post retrieved successfully")
}

// GetPostComments retrieves comments for a post
func (h *PostHandler) GetPostComments(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetCommentsRequest{
		Page:         h.getIntQuery(c, "page", 1),
		Limit:        h.getIntQuery(c, "limit", 20),
		SortBy:       c.DefaultQuery("sort_by", "created_at"),
		IncludeReply: c.Query("include_reply") == "true",
	}

	response, err := h.postService.GetPostComments(c.Request.Context(), postID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_COMMENTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Comments retrieved successfully")
}

// GetPostLikes retrieves likes for a post
func (h *PostHandler) GetPostLikes(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetLikesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	// Parse reaction type filter if provided
	if reactionType := c.Query("reaction_type"); reactionType != "" {
		reaction := models.ReactionType(reactionType)
		req.ReactionType = &reaction
	}

	response, err := h.postService.GetPostLikes(c.Request.Context(), postID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_LIKES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Likes retrieved successfully")
}

// GetPostShares retrieves shares for a post
func (h *PostHandler) GetPostShares(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetSharesRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.postService.GetPostShares(c.Request.Context(), postID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SHARES_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Shares retrieved successfully")
}

// GetPostEmbed retrieves embed HTML for a post
func (h *PostHandler) GetPostEmbed(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	response, err := h.postService.GetPostEmbed(c.Request.Context(), postID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EMBED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Embed generated successfully")
}

// GetSharePreview retrieves share preview for a post
func (h *PostHandler) GetSharePreview(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	response, err := h.postService.GetSharePreview(c.Request.Context(), postID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SHARE_PREVIEW_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Share preview generated successfully")
}

// =============================================================================
// POST CREATION AND MANAGEMENT (AUTH REQUIRED)
// =============================================================================

// CreatePost creates a new post
func (h *PostHandler) CreatePost(c *gin.Context) {
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
	req := h.mapCreatePostRequest(validatedData)

	// Handle uploaded media files if any
	if mediaFiles, exists := c.Get("uploaded_media"); exists {
		if files, ok := mediaFiles.([]models.MediaFile); ok {
			req.MediaFiles = files
		}
	}

	response, err := h.postService.CreatePost(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "CREATE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post created successfully")
}

// UpdatePost updates an existing post
func (h *PostHandler) UpdatePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	// Map validated data to request struct
	req := h.mapUpdatePostRequest(validatedData)

	response, err := h.postService.UpdatePost(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post updated successfully")
}

// DeletePost deletes a post
func (h *PostHandler) DeletePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.DeletePost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DELETE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post deleted successfully")
}

// RestorePost restores a deleted post
func (h *PostHandler) RestorePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	response, err := h.postService.RestorePost(c.Request.Context(), userID, postID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "RESTORE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post restored successfully")
}

// =============================================================================
// POST INTERACTIONS
// =============================================================================

// LikePost likes a post
func (h *PostHandler) LikePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get reaction type from body or default to like
	reactionType := models.ReactionLike
	if body := c.Query("reaction_type"); body != "" {
		reactionType = models.ReactionType(body)
	}

	response, err := h.postService.LikePost(c.Request.Context(), userID, postID, reactionType)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "LIKE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post reaction updated")
}

// UnlikePost unlikes a post
func (h *PostHandler) UnlikePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.UnlikePost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNLIKE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post unliked successfully")
}

// SharePost shares a post
func (h *PostHandler) SharePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.SharePostRequest{
		Content:    validatedData["content"].(string),
		AddComment: validatedData["add_comment"].(bool),
	}

	if privacy, ok := validatedData["privacy"].(string); ok {
		privacyEnum := models.PostPrivacy(privacy)
		req.Privacy = &privacyEnum
	}

	response, err := h.postService.SharePost(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "SHARE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post shared successfully")
}

// UnsharePost unshares a post
func (h *PostHandler) UnsharePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.UnsharePost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNSHARE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post unshared successfully")
}

// BookmarkPost bookmarks a post
func (h *PostHandler) BookmarkPost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	response, err := h.postService.BookmarkPost(c.Request.Context(), userID, postID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "BOOKMARK_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post bookmarked successfully")
}

// UnbookmarkPost removes bookmark from a post
func (h *PostHandler) UnbookmarkPost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.UnbookmarkPost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNBOOKMARK_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post unbookmarked successfully")
}

// ReportPost reports a post
func (h *PostHandler) ReportPost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReportPostRequest{
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

	if err := h.postService.ReportPost(c.Request.Context(), userID, postID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REPORT_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post reported successfully")
}

// HidePost hides a post from user's feed
func (h *PostHandler) HidePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.HidePost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "HIDE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post hidden successfully")
}

// UnhidePost unhides a post
func (h *PostHandler) UnhidePost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.UnhidePost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNHIDE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post unhidden successfully")
}

// =============================================================================
// COMMENT OPERATIONS
// =============================================================================

// CreateComment creates a new comment on a post
func (h *PostHandler) CreateComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateCommentRequest{
		Content: validatedData["content"].(string),
	}

	// Handle optional fields
	if parentID, ok := validatedData["parent_id"].(string); ok && parentID != "" {
		if objID, err := primitive.ObjectIDFromHex(parentID); err == nil {
			req.ParentID = &objID
		}
	}

	if mentions, ok := validatedData["mentions"].([]interface{}); ok {
		for _, mention := range mentions {
			if mentionStr, ok := mention.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(mentionStr); err == nil {
					req.Mentions = append(req.Mentions, objID)
				}
			}
		}
	}

	// Handle uploaded media files if any
	if mediaFiles, exists := c.Get("uploaded_media"); exists {
		if files, ok := mediaFiles.([]models.MediaFile); ok {
			req.MediaFiles = files
		}
	}

	response, err := h.postService.CreateComment(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "CREATE_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Comment created successfully")
}

// GetPostCommentsAuth retrieves comments for a post (authenticated version)
func (h *PostHandler) GetPostCommentsAuth(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetCommentsRequest{
		Page:         h.getIntQuery(c, "page", 1),
		Limit:        h.getIntQuery(c, "limit", 20),
		SortBy:       c.DefaultQuery("sort_by", "created_at"),
		IncludeReply: c.Query("include_reply") == "true",
	}

	response, err := h.postService.GetPostCommentsAuth(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_COMMENTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c,response, "Comments retrieved successfully")
}

// GetComment retrieves a single comment
func (h *PostHandler) GetComment(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	// Get viewer ID if authenticated
	var viewerID *primitive.ObjectID
	if user := h.authMiddleware.GetCurrentUser(c); user != nil {
		viewerID = &user.ID
	}

	response, err := h.postService.GetComment(c.Request.Context(), postID, commentID, viewerID)
	if err != nil {
		utils.SendError(c, http.StatusNotFound, "COMMENT_NOT_FOUND", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Comment retrieved successfully")
}

// UpdateComment updates a comment
func (h *PostHandler) UpdateComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateCommentRequest{
		Content: validatedData["content"].(string),
	}

	response, err := h.postService.UpdateComment(c.Request.Context(), userID, postID, commentID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Comment updated successfully")
}

// DeleteComment deletes a comment
func (h *PostHandler) DeleteComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	if err := h.postService.DeleteComment(c.Request.Context(), userID, postID, commentID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DELETE_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Comment deleted successfully")
}

// LikeComment likes a comment
func (h *PostHandler) LikeComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	// Get reaction type from body or default to like
	reactionType := models.ReactionLike
	if body := c.Query("reaction_type"); body != "" {
		reactionType = models.ReactionType(body)
	}

	response, err := h.postService.LikeComment(c.Request.Context(), userID, postID, commentID, reactionType)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "LIKE_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Comment reaction updated")
}

// UnlikeComment unlikes a comment
func (h *PostHandler) UnlikeComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	if err := h.postService.UnlikeComment(c.Request.Context(), userID, postID, commentID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNLIKE_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Comment unliked successfully")
}

// ReplyToComment creates a reply to a comment
func (h *PostHandler) ReplyToComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.CreateCommentRequest{
		Content:  validatedData["content"].(string),
		ParentID: &commentID, // Set the comment being replied to as parent
	}

	if mentions, ok := validatedData["mentions"].([]interface{}); ok {
		for _, mention := range mentions {
			if mentionStr, ok := mention.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(mentionStr); err == nil {
					req.Mentions = append(req.Mentions, objID)
				}
			}
		}
	}

	response, err := h.postService.ReplyToComment(c.Request.Context(), userID, postID, commentID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "REPLY_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Reply created successfully")
}

// ReportComment reports a comment
func (h *PostHandler) ReportComment(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	commentID, err := h.getObjectIDParam(c, "comment_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_COMMENT_ID", "Invalid comment ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ReportCommentRequest{
		Reason:      validatedData["reason"].(string),
		Description: validatedData["description"].(string),
	}

	if err := h.postService.ReportComment(c.Request.Context(), userID, postID, commentID, req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REPORT_COMMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Comment reported successfully")
}

// =============================================================================
// POST SCHEDULING AND DRAFTS
// =============================================================================

// SchedulePost schedules a post for later publishing
func (h *PostHandler) SchedulePost(c *gin.Context) {
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

	// Parse scheduled time
	scheduledAtStr := validatedData["scheduled_at"].(string)
	scheduledAt, err := time.Parse(time.RFC3339, scheduledAtStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_SCHEDULED_TIME", "Invalid scheduled time format")
		return
	}

	req := &services.SchedulePostRequest{
		Content:          validatedData["content"].(string),
		ScheduledAt:      scheduledAt,
		Timezone:         validatedData["timezone"].(string),
		Recurring:        validatedData["recurring"].(bool),
		RecurringPattern: validatedData["recurring_pattern"].(string),
	}

	// Handle optional fields
	if contentType, ok := validatedData["content_type"].(string); ok {
		ct := models.PostContentType(contentType)
		req.ContentType = &ct
	}

	if privacy, ok := validatedData["privacy"].(string); ok {
		p := models.PostPrivacy(privacy)
		req.Privacy = &p
	}

	response, err := h.postService.SchedulePost(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "SCHEDULE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post scheduled successfully")
}

// GetScheduledPosts retrieves user's scheduled posts
func (h *PostHandler) GetScheduledPosts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetScheduledPostsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.postService.GetScheduledPosts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SCHEDULED_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Scheduled posts retrieved")
}

// UpdateScheduledPost updates a scheduled post
func (h *PostHandler) UpdateScheduledPost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateScheduledPostRequest{}

	if content, ok := validatedData["content"].(string); ok {
		req.Content = &content
	}

	if scheduledAtStr, ok := validatedData["scheduled_at"].(string); ok {
		if scheduledAt, err := time.Parse(time.RFC3339, scheduledAtStr); err == nil {
			req.ScheduledAt = &scheduledAt
		}
	}

	if recurring, ok := validatedData["recurring"].(bool); ok {
		req.Recurring = &recurring
	}

	if pattern, ok := validatedData["recurring_pattern"].(string); ok {
		req.RecurringPattern = &pattern
	}

	response, err := h.postService.UpdateScheduledPost(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_SCHEDULED_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Scheduled post updated")
}

// CancelScheduledPost cancels a scheduled post
func (h *PostHandler) CancelScheduledPost(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.CancelScheduledPost(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "CANCEL_SCHEDULED_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Scheduled post cancelled")
}

// CreateDraft creates a draft post
func (h *PostHandler) CreateDraft(c *gin.Context) {
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

	req := &services.CreateDraftRequest{
		Content:  validatedData["content"].(string),
		Title:    validatedData["title"].(string),
		AutoSave: validatedData["auto_save"].(bool),
	}

	response, err := h.postService.CreateDraft(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "CREATE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft created successfully")
}

// GetDrafts retrieves user's draft posts
func (h *PostHandler) GetDrafts(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetDraftsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	response, err := h.postService.GetDrafts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_DRAFTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Drafts retrieved successfully")
}

// UpdateDraft updates a draft post
func (h *PostHandler) UpdateDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.UpdateDraftRequest{}

	if content, ok := validatedData["content"].(string); ok {
		req.Content = &content
	}

	if title, ok := validatedData["title"].(string); ok {
		req.Title = &title
	}

	if autoSave, ok := validatedData["auto_save"].(bool); ok {
		req.AutoSave = &autoSave
	}

	response, err := h.postService.UpdateDraft(c.Request.Context(), userID, draftID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "UPDATE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft updated successfully")
}

// DeleteDraft deletes a draft post
func (h *PostHandler) DeleteDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	if err := h.postService.DeleteDraft(c.Request.Context(), userID, draftID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "DELETE_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Draft deleted successfully")
}

// PublishDraft publishes a draft as a post
func (h *PostHandler) PublishDraft(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	draftID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_DRAFT_ID", "Invalid draft ID")
		return
	}

	response, err := h.postService.PublishDraft(c.Request.Context(), userID, draftID)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "PUBLISH_DRAFT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Draft published successfully")
}

// =============================================================================
// ANALYTICS AND INSIGHTS
// =============================================================================

// GetPostAnalytics retrieves analytics for a post
func (h *PostHandler) GetPostAnalytics(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetAnalyticsRequest{
		Period:  c.DefaultQuery("period", "week"),
		Metrics: strings.Split(c.Query("metrics"), ","),
	}

	// Parse date parameters if provided
	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse("2006-01-02", startDate); err == nil {
			req.StartDate = parsed
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse("2006-01-02", endDate); err == nil {
			req.EndDate = parsed
		}
	}

	response, err := h.postService.GetPostAnalytics(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "GET_ANALYTICS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Analytics retrieved successfully")
}

// GetPostInsights retrieves insights for a post
func (h *PostHandler) GetPostInsights(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetInsightsRequest{
		Period: c.DefaultQuery("period", "week"),
	}

	response, err := h.postService.GetPostInsights(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "GET_INSIGHTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Insights retrieved successfully")
}

// GetPostReach retrieves reach analytics for a post
func (h *PostHandler) GetPostReach(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetReachRequest{
		Period: c.DefaultQuery("period", "week"),
	}

	response, err := h.postService.GetPostReach(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "GET_REACH_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Reach data retrieved successfully")
}

// GetPostEngagement retrieves engagement analytics for a post
func (h *PostHandler) GetPostEngagement(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetEngagementRequest{
		Period: c.DefaultQuery("period", "week"),
	}

	response, err := h.postService.GetPostEngagement(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "GET_ENGAGEMENT_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Engagement data retrieved successfully")
}

// =============================================================================
// FEED OPERATIONS
// =============================================================================

// GetPersonalizedFeed retrieves user's personalized feed
func (h *PostHandler) GetPersonalizedFeed(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFeedRequest{
		Page:      h.getIntQuery(c, "page", 1),
		Limit:     h.getIntQuery(c, "limit", 20),
		Algorithm: c.DefaultQuery("algorithm", "personalized"),
		Filter:    h.buildPostFilter(c),
	}

	response, err := h.postService.GetPersonalizedFeed(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FEED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Feed retrieved successfully")
}

// GetFollowingFeed retrieves feed from followed users
func (h *PostHandler) GetFollowingFeed(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFeedRequest{
		Page:   h.getIntQuery(c, "page", 1),
		Limit:  h.getIntQuery(c, "limit", 20),
		Filter: h.buildPostFilter(c),
	}

	response, err := h.postService.GetFollowingFeed(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FOLLOWING_FEED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Following feed retrieved successfully")
}

// GetExploreFeed retrieves explore feed
func (h *PostHandler) GetExploreFeed(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFeedRequest{
		Page:   h.getIntQuery(c, "page", 1),
		Limit:  h.getIntQuery(c, "limit", 20),
		Filter: h.buildPostFilter(c),
	}

	response, err := h.postService.GetExploreFeed(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_EXPLORE_FEED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Explore feed retrieved successfully")
}

// GetNearbyFeed retrieves nearby posts
func (h *PostHandler) GetNearbyFeed(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	lat, _ := strconv.ParseFloat(c.Query("lat"), 64)
	lng, _ := strconv.ParseFloat(c.Query("lng"), 64)
	radius, _ := strconv.Atoi(c.DefaultQuery("radius", "10"))

	if lat == 0 || lng == 0 {
		utils.SendError(c, http.StatusBadRequest, "MISSING_LOCATION", "Latitude and longitude are required")
		return
	}

	req := &services.GetNearbyFeedRequest{
		Page:      h.getIntQuery(c, "page", 1),
		Limit:     h.getIntQuery(c, "limit", 20),
		Latitude:  lat,
		Longitude: lng,
		Radius:    radius,
	}

	response, err := h.postService.GetNearbyFeed(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_NEARBY_FEED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Nearby feed retrieved successfully")
}

// RefreshFeed refreshes user's feed
func (h *PostHandler) RefreshFeed(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	response, err := h.postService.RefreshFeed(c.Request.Context(), userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "REFRESH_FEED_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Feed refreshed successfully")
}

// =============================================================================
// SEARCH AND DISCOVERY
// =============================================================================

// SearchPosts searches for posts
func (h *PostHandler) SearchPosts(c *gin.Context) {
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

	req := &services.SearchPostsRequest{
		Query:     query,
		Page:      h.getIntQuery(c, "page", 1),
		Limit:     h.getIntQuery(c, "limit", 20),
		Filters:   make(map[string]interface{}),
		SortBy:    c.DefaultQuery("sort_by", "relevance"),
		SortOrder: c.DefaultQuery("sort_order", "desc"),
	}

	// Parse additional filters
	if contentType := c.Query("content_type"); contentType != "" {
		req.Filters["content_type"] = contentType
	}
	if hasMedia := c.Query("has_media"); hasMedia == "true" {
		req.Filters["has_media"] = true
	}

	response, err := h.postService.SearchPosts(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "SEARCH_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Search completed successfully")
}

// GetPostSuggestions retrieves post suggestions for user
func (h *PostHandler) GetPostSuggestions(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetSuggestionsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
		Types: strings.Split(c.Query("types"), ","),
	}

	response, err := h.postService.GetPostSuggestions(c.Request.Context(), userID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_SUGGESTIONS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Suggestions retrieved successfully")
}

// GetRelatedPosts retrieves posts related to a specific post
func (h *PostHandler) GetRelatedPosts(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	req := &services.GetRelatedPostsRequest{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 10),
	}

	response, err := h.postService.GetRelatedPosts(c.Request.Context(), postID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_RELATED_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Related posts retrieved successfully")
}

// GetTrendingTopics retrieves trending topics/hashtags
func (h *PostHandler) GetTrendingTopics(c *gin.Context) {
	req := &services.GetTrendingTopicsRequest{
		Period: c.DefaultQuery("period", "day"),
		Limit:  h.getIntQuery(c, "limit", 20),
	}

	response, err := h.postService.GetTrendingTopics(c.Request.Context(), req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_TRENDING_TOPICS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Trending topics retrieved successfully")
}

// GetPostsByTopic retrieves posts by topic/hashtag
func (h *PostHandler) GetPostsByTopic(c *gin.Context) {
	topic := c.Param("topic")
	if topic == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_TOPIC", "Topic is required")
		return
	}

	req := &services.GetPostsByTopicRequest{
		Page:   h.getIntQuery(c, "page", 1),
		Limit:  h.getIntQuery(c, "limit", 20),
		SortBy: c.DefaultQuery("sort_by", "created_at"),
	}

	response, err := h.postService.GetPostsByTopic(c.Request.Context(), topic, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_POSTS_BY_TOPIC_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Posts retrieved successfully")
}

// FollowTopic follows a topic/hashtag
func (h *PostHandler) FollowTopic(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	topic := c.Param("topic")
	if topic == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_TOPIC", "Topic is required")
		return
	}

	if err := h.postService.FollowTopic(c.Request.Context(), userID, topic); err != nil {
		utils.SendError(c, http.StatusBadRequest, "FOLLOW_TOPIC_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Topic followed successfully")
}

// UnfollowTopic unfollows a topic/hashtag
func (h *PostHandler) UnfollowTopic(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	topic := c.Param("topic")
	if topic == "" {
		utils.SendError(c, http.StatusBadRequest, "MISSING_TOPIC", "Topic is required")
		return
	}

	if err := h.postService.UnfollowTopic(c.Request.Context(), userID, topic); err != nil {
		utils.SendError(c, http.StatusBadRequest, "UNFOLLOW_TOPIC_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Topic unfollowed successfully")
}

// =============================================================================
// MODERATION (MODERATOR ONLY)
// =============================================================================

// ModeratePost moderates a post
func (h *PostHandler) ModeratePost(c *gin.Context) {
	moderatorID := h.authMiddleware.GetCurrentUserID(c)
	if moderatorID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	req := &services.ModeratePostRequest{
		Action:     validatedData["action"].(string),
		Reason:     validatedData["reason"].(string),
		NotifyUser: validatedData["notify_user"].(bool),
	}

	response, err := h.postService.ModeratePost(c.Request.Context(), moderatorID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "MODERATE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Post moderated successfully")
}

// GetFlaggedPosts retrieves flagged posts for moderation
func (h *PostHandler) GetFlaggedPosts(c *gin.Context) {
	moderatorID := h.authMiddleware.GetCurrentUserID(c)
	if moderatorID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	req := &services.GetFlaggedPostsRequest{
		Page:     h.getIntQuery(c, "page", 1),
		Limit:    h.getIntQuery(c, "limit", 20),
		Status:   c.Query("status"),
		Category: c.Query("category"),
	}

	response, err := h.postService.GetFlaggedPosts(c.Request.Context(), moderatorID, req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_FLAGGED_POSTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Flagged posts retrieved successfully")
}

// ApprovePost approves a flagged post
func (h *PostHandler) ApprovePost(c *gin.Context) {
	moderatorID := h.authMiddleware.GetCurrentUserID(c)
	if moderatorID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.ApprovePost(c.Request.Context(), moderatorID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "APPROVE_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post approved successfully")
}

// RejectPost rejects a flagged post
func (h *PostHandler) RejectPost(c *gin.Context) {
	moderatorID := h.authMiddleware.GetCurrentUserID(c)
	if moderatorID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	reason := c.PostForm("reason")

	if err := h.postService.RejectPost(c.Request.Context(), moderatorID, postID, reason); err != nil {
		utils.SendError(c, http.StatusBadRequest, "REJECT_POST_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Post rejected successfully")
}

// =============================================================================
// POLL OPERATIONS
// =============================================================================

// VoteOnPoll votes on a poll in a post
func (h *PostHandler) VoteOnPoll(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	// Get validated data from middleware
	validatedData, exists := middleware.GetValidatedData(c)
	if !exists {
		utils.SendError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request data")
		return
	}

	optionIDStr := validatedData["option_id"].(string)
	optionID, err := primitive.ObjectIDFromHex(optionIDStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_OPTION_ID", "Invalid option ID")
		return
	}

	req := &services.VotePollRequest{
		OptionID:   optionID,
		OptionText: validatedData["option_text"].(string),
	}

	response, err := h.postService.VoteOnPoll(c.Request.Context(), userID, postID, req)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "VOTE_POLL_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Vote recorded successfully")
}

// GetPollResults gets poll results
func (h *PostHandler) GetPollResults(c *gin.Context) {
	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	response, err := h.postService.GetPollResults(c.Request.Context(), postID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "GET_POLL_RESULTS_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, response, "Poll results retrieved successfully")
}

// ClosePoll closes a poll
func (h *PostHandler) ClosePoll(c *gin.Context) {
	userID := h.authMiddleware.GetCurrentUserID(c)
	if userID == primitive.NilObjectID {
		utils.SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	postID, err := h.getObjectIDParam(c, "post_id")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "INVALID_POST_ID", "Invalid post ID")
		return
	}

	if err := h.postService.ClosePoll(c.Request.Context(), userID, postID); err != nil {
		utils.SendError(c, http.StatusBadRequest, "CLOSE_POLL_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, nil, "Poll closed successfully")
}

// =============================================================================
// HELPER METHODS (ADDITIONAL METHODS TO BE IMPLEMENTED)
// =============================================================================

// Additional methods like:
// - AddToThread, GetThread, RemoveFromThread
// - CreateCollection, GetCollections, UpdateCollection, DeleteCollection
// - AddPostToCollection, RemovePostFromCollection
// - GetPostMentions, TagUsers, RemoveUserTags
// - GetPostHistory, GetPostVersions, RevertToVersion
// would be implemented here following the same patterns...

// =============================================================================
// HELPER METHODS
// =============================================================================

// getIntQuery gets integer value from query parameter with default
func (h *PostHandler) getIntQuery(c *gin.Context, param string, defaultValue int) int {
	if value := c.Query(param); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getObjectIDParam gets ObjectID from URL parameter
func (h *PostHandler) getObjectIDParam(c *gin.Context, param string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Param(param))
}

// buildPostFilter builds post filter from query parameters
func (h *PostHandler) buildPostFilter(c *gin.Context) *models.PostFeedFilter {
	filter := &models.PostFeedFilter{
		Page:  h.getIntQuery(c, "page", 1),
		Limit: h.getIntQuery(c, "limit", 20),
	}

	if contentType := c.Query("content_type"); contentType != "" {
		ct := models.PostContentType(contentType)
		filter.ContentType = &ct
	}

	if privacy := c.Query("privacy"); privacy != "" {
		p := models.PostPrivacy(privacy)
		filter.Privacy = &p
	}

	if hasMedia := c.Query("has_media"); hasMedia == "true" {
		filter.HasMedia = &[]bool{true}[0]
	}

	if hashtags := c.Query("hashtags"); hashtags != "" {
		filter.Hashtags = strings.Split(hashtags, ",")
	}

	filter.SortBy = c.DefaultQuery("sort_by", "created_at")
	filter.SortOrder = c.DefaultQuery("sort_order", "desc")

	return filter
}

// mapCreatePostRequest maps validated data to CreatePostRequest
func (h *PostHandler) mapCreatePostRequest(data map[string]interface{}) *services.CreatePostRequest {
	req := &services.CreatePostRequest{
		Content: data["content"].(string),
	}

	if contentType, ok := data["content_type"].(string); ok {
		ct := models.PostContentType(contentType)
		req.ContentType = &ct
	}

	if privacy, ok := data["privacy"].(string); ok {
		p := models.PostPrivacy(privacy)
		req.Privacy = &p
	}

	if allowComments, ok := data["allow_comments"].(bool); ok {
		req.AllowComments = &allowComments
	}

	if allowReactions, ok := data["allow_reactions"].(bool); ok {
		req.AllowReactions = &allowReactions
	}

	if allowShares, ok := data["allow_shares"].(bool); ok {
		req.AllowShares = &allowShares
	}

	if contentWarning, ok := data["content_warning"].(string); ok {
		req.ContentWarning = contentWarning
	}

	if sensitiveContent, ok := data["sensitive_content"].(bool); ok {
		req.SensitiveContent = &sensitiveContent
	}

	if hashtags, ok := data["hashtags"].([]interface{}); ok {
		for _, tag := range hashtags {
			if tagStr, ok := tag.(string); ok {
				req.Hashtags = append(req.Hashtags, tagStr)
			}
		}
	}

	if mentions, ok := data["mentions"].([]interface{}); ok {
		for _, mention := range mentions {
			if mentionStr, ok := mention.(string); ok {
				if objID, err := primitive.ObjectIDFromHex(mentionStr); err == nil {
					req.Mentions = append(req.Mentions, objID)
				}
			}
		}
	}

	if scheduledAt, ok := data["scheduled_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, scheduledAt); err == nil {
			req.ScheduledAt = &parsed
		}
	}

	return req
}

// mapUpdatePostRequest maps validated data to UpdatePostRequest
func (h *PostHandler) mapUpdatePostRequest(data map[string]interface{}) *services.UpdatePostRequest {
	req := &services.UpdatePostRequest{}

	if content, ok := data["content"].(string); ok {
		req.Content = &content
	}

	if privacy, ok := data["privacy"].(string); ok {
		p := models.PostPrivacy(privacy)
		req.Privacy = &p
	}

	if allowComments, ok := data["allow_comments"].(bool); ok {
		req.AllowComments = &allowComments
	}

	if allowReactions, ok := data["allow_reactions"].(bool); ok {
		req.AllowReactions = &allowReactions
	}

	if allowShares, ok := data["allow_shares"].(bool); ok {
		req.AllowShares = &allowShares
	}

	if contentWarning, ok := data["content_warning"].(string); ok {
		req.ContentWarning = &contentWarning
	}

	if sensitiveContent, ok := data["sensitive_content"].(bool); ok {
		req.SensitiveContent = &sensitiveContent
	}

	return req
}
