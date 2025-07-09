package routes

import (
	"bro-network/internal/handlers"
	"bro-network/internal/middleware"

	"github.com/gin-gonic/gin"
)

// SetupUploadRoutes sets up file upload and media management routes
func SetupUploadRoutes(api *gin.RouterGroup, uploadHandler *handlers.UploadHandler, middlewares *middleware.Middlewares) {
	uploads := api.Group("/uploads")

	// =============================================================================
	// FILE UPLOAD
	// =============================================================================

	// Single file upload
	uploads.POST("/file",
		applyValidation("upload_file"),
		applyRateLimit("upload:50/hour"),
		middlewares.FileUpload("file", 100*1024*1024), // 100MB limit
		uploadHandler.UploadFile,
	)

	// Multiple file upload
	uploads.POST("/files",
		applyValidation("upload_files"),
		applyRateLimit("upload:30/hour"),
		middlewares.MultiFileUpload("files", 10, 50*1024*1024), // 10 files, 50MB each
		uploadHandler.UploadMultipleFiles,
	)

	// Chunked upload for large files
	uploads.POST("/chunked/init",
		applyValidation("init_chunked_upload"),
		uploadHandler.InitiateChunkedUpload,
	)

	uploads.POST("/chunked/:upload_id/chunk",
		applyValidation("upload_chunk"),
		middlewares.ChunkedUpload(),
		uploadHandler.UploadChunk,
	)

	uploads.POST("/chunked/:upload_id/complete",
		uploadHandler.CompleteChunkedUpload,
	)

	uploads.DELETE("/chunked/:upload_id",
		uploadHandler.AbortChunkedUpload,
	)

	uploads.GET("/chunked/:upload_id/status",
		uploadHandler.GetChunkedUploadStatus,
	)

	// =============================================================================
	// IMAGE UPLOADS
	// =============================================================================

	images := uploads.Group("/images")
	{
		// Image upload with processing
		images.POST("",
			applyValidation("upload_image"),
			applyRateLimit("upload:100/hour"),
			middlewares.ImageUpload("image", 20*1024*1024), // 20MB limit
			uploadHandler.UploadImage,
		)

		// Multiple image upload
		images.POST("/multiple",
			applyValidation("upload_images"),
			applyRateLimit("upload:50/hour"),
			middlewares.MultiImageUpload("images", 20, 10*1024*1024), // 20 images, 10MB each
			uploadHandler.UploadMultipleImages,
		)

		// Profile/avatar upload
		images.POST("/avatar",
			applyValidation("upload_avatar"),
			middlewares.ImageUpload("avatar", 5*1024*1024), // 5MB limit
			uploadHandler.UploadAvatar,
		)

		// Cover image upload
		images.POST("/cover",
			applyValidation("upload_cover"),
			middlewares.ImageUpload("cover", 10*1024*1024), // 10MB limit
			uploadHandler.UploadCoverImage,
		)

		// Image editing and processing
		images.POST("/:file_id/resize",
			applyValidation("resize_image"),
			middlewares.FileOwnership(),
			uploadHandler.ResizeImage,
		)

		images.POST("/:file_id/crop",
			applyValidation("crop_image"),
			middlewares.FileOwnership(),
			uploadHandler.CropImage,
		)

		images.POST("/:file_id/rotate",
			applyValidation("rotate_image"),
			middlewares.FileOwnership(),
			uploadHandler.RotateImage,
		)

		images.POST("/:file_id/filter",
			applyValidation("apply_filter"),
			middlewares.FileOwnership(),
			uploadHandler.ApplyImageFilter,
		)

		// Image optimization
		images.POST("/:file_id/optimize",
			middlewares.FileOwnership(),
			uploadHandler.OptimizeImage,
		)

		images.POST("/:file_id/compress",
			applyValidation("compress_image"),
			middlewares.FileOwnership(),
			uploadHandler.CompressImage,
		)

		// Generate thumbnails
		images.POST("/:file_id/thumbnails",
			applyValidation("generate_thumbnails"),
			middlewares.FileOwnership(),
			uploadHandler.GenerateThumbnails,
		)
	}

	// =============================================================================
	// VIDEO UPLOADS
	// =============================================================================

	videos := uploads.Group("/videos")
	{
		// Video upload
		videos.POST("",
			applyValidation("upload_video"),
			applyRateLimit("upload:20/hour"),
			middlewares.VideoUpload("video", 500*1024*1024), // 500MB limit
			uploadHandler.UploadVideo,
		)

		// Video thumbnail generation
		videos.POST("/:file_id/thumbnail",
			applyValidation("generate_video_thumbnail"),
			middlewares.FileOwnership(),
			uploadHandler.GenerateVideoThumbnail,
		)

		// Video processing
		videos.POST("/:file_id/transcode",
			applyValidation("transcode_video"),
			middlewares.FileOwnership(),
			uploadHandler.TranscodeVideo,
		)

		videos.POST("/:file_id/trim",
			applyValidation("trim_video"),
			middlewares.FileOwnership(),
			uploadHandler.TrimVideo,
		)

		videos.POST("/:file_id/compress",
			applyValidation("compress_video"),
			middlewares.FileOwnership(),
			uploadHandler.CompressVideo,
		)

		// Video metadata
		videos.GET("/:file_id/metadata",
			middlewares.FileAccess(),
			uploadHandler.GetVideoMetadata,
		)

		videos.POST("/:file_id/extract-frames",
			applyValidation("extract_frames"),
			middlewares.FileOwnership(),
			uploadHandler.ExtractVideoFrames,
		)

		// Video streaming
		videos.GET("/:file_id/stream",
			middlewares.FileAccess(),
			uploadHandler.StreamVideo,
		)

		videos.GET("/:file_id/hls",
			middlewares.FileAccess(),
			uploadHandler.GetHLSPlaylist,
		)
	}

	// =============================================================================
	// AUDIO UPLOADS
	// =============================================================================

	audio := uploads.Group("/audio")
	{
		// Audio upload
		audio.POST("",
			applyValidation("upload_audio"),
			applyRateLimit("upload:30/hour"),
			middlewares.AudioUpload("audio", 100*1024*1024), // 100MB limit
			uploadHandler.UploadAudio,
		)

		// Audio processing
		audio.POST("/:file_id/transcode",
			applyValidation("transcode_audio"),
			middlewares.FileOwnership(),
			uploadHandler.TranscodeAudio,
		)

		audio.POST("/:file_id/trim",
			applyValidation("trim_audio"),
			middlewares.FileOwnership(),
			uploadHandler.TrimAudio,
		)

		audio.POST("/:file_id/normalize",
			middlewares.FileOwnership(),
			uploadHandler.NormalizeAudio,
		)

		// Audio metadata
		audio.GET("/:file_id/metadata",
			middlewares.FileAccess(),
			uploadHandler.GetAudioMetadata,
		)

		audio.GET("/:file_id/waveform",
			middlewares.FileAccess(),
			uploadHandler.GenerateWaveform,
		)

		// Audio streaming
		audio.GET("/:file_id/stream",
			middlewares.FileAccess(),
			uploadHandler.StreamAudio,
		)
	}

	// =============================================================================
	// DOCUMENT UPLOADS
	// =============================================================================

	documents := uploads.Group("/documents")
	{
		// Document upload
		documents.POST("",
			applyValidation("upload_document"),
			applyRateLimit("upload:40/hour"),
			middlewares.DocumentUpload("document", 50*1024*1024), // 50MB limit
			uploadHandler.UploadDocument,
		)

		// Document processing
		documents.POST("/:file_id/convert",
			applyValidation("convert_document"),
			middlewares.FileOwnership(),
			uploadHandler.ConvertDocument,
		)

		documents.POST("/:file_id/extract-text",
			middlewares.FileOwnership(),
			uploadHandler.ExtractDocumentText,
		)

		documents.POST("/:file_id/generate-preview",
			middlewares.FileOwnership(),
			uploadHandler.GenerateDocumentPreview,
		)

		// Document metadata
		documents.GET("/:file_id/metadata",
			middlewares.FileAccess(),
			uploadHandler.GetDocumentMetadata,
		)

		documents.GET("/:file_id/pages",
			middlewares.FileAccess(),
			uploadHandler.GetDocumentPages,
		)

		// Document viewer
		documents.GET("/:file_id/view",
			middlewares.FileAccess(),
			uploadHandler.ViewDocument,
		)

		documents.GET("/:file_id/download",
			middlewares.FileAccess(),
			uploadHandler.DownloadDocument,
		)
	}

	// =============================================================================
	// FILE MANAGEMENT
	// =============================================================================

	files := uploads.Group("/files")
	{
		// List user files
		files.GET("",
			uploadHandler.GetUserFiles,
		)

		files.GET("/recent",
			uploadHandler.GetRecentFiles,
		)

		files.GET("/by-type/:type",
			uploadHandler.GetFilesByType,
		)

		// Individual file management
		files.GET("/:file_id",
			middlewares.FileAccess(),
			uploadHandler.GetFile,
		)

		files.PUT("/:file_id",
			applyValidation("update_file"),
			middlewares.FileOwnership(),
			uploadHandler.UpdateFile,
		)

		files.DELETE("/:file_id",
			middlewares.FileOwnership(),
			uploadHandler.DeleteFile,
		)

		files.POST("/:file_id/restore",
			middlewares.FileOwnership(),
			uploadHandler.RestoreFile,
		)

		// File actions
		files.POST("/:file_id/copy",
			middlewares.FileAccess(),
			uploadHandler.CopyFile,
		)

		files.POST("/:file_id/move",
			applyValidation("move_file"),
			middlewares.FileOwnership(),
			uploadHandler.MoveFile,
		)

		files.POST("/:file_id/rename",
			applyValidation("rename_file"),
			middlewares.FileOwnership(),
			uploadHandler.RenameFile,
		)

		// File sharing
		files.POST("/:file_id/share",
			applyValidation("share_file"),
			middlewares.FileOwnership(),
			uploadHandler.ShareFile,
		)

		files.GET("/:file_id/share-link",
			middlewares.FileOwnership(),
			uploadHandler.GetShareLink,
		)

		files.DELETE("/:file_id/share-link",
			middlewares.FileOwnership(),
			uploadHandler.RevokeShareLink,
		)

		// File versions
		files.GET("/:file_id/versions",
			middlewares.FileOwnership(),
			uploadHandler.GetFileVersions,
		)

		files.POST("/:file_id/versions",
			middlewares.FileUpload("file", 100*1024*1024),
			middlewares.FileOwnership(),
			uploadHandler.CreateFileVersion,
		)

		files.POST("/:file_id/versions/:version_id/restore",
			middlewares.FileOwnership(),
			uploadHandler.RestoreFileVersion,
		)

		// File download and access
		files.GET("/:file_id/download",
			middlewares.FileAccess(),
			uploadHandler.DownloadFile,
		)

		files.GET("/:file_id/view",
			middlewares.FileAccess(),
			uploadHandler.ViewFile,
		)

		files.GET("/:file_id/thumbnail",
			middlewares.FileAccess(),
			uploadHandler.GetFileThumbnail,
		)
	}

	// =============================================================================
	// FOLDER MANAGEMENT
	// =============================================================================

	folders := uploads.Group("/folders")
	{
		// Folder operations
		folders.GET("",
			uploadHandler.GetUserFolders,
		)

		folders.POST("",
			applyValidation("create_folder"),
			uploadHandler.CreateFolder,
		)

		folders.GET("/:folder_id",
			middlewares.FolderAccess(),
			uploadHandler.GetFolder,
		)

		folders.PUT("/:folder_id",
			applyValidation("update_folder"),
			middlewares.FolderOwnership(),
			uploadHandler.UpdateFolder,
		)

		folders.DELETE("/:folder_id",
			middlewares.FolderOwnership(),
			uploadHandler.DeleteFolder,
		)

		// Folder contents
		folders.GET("/:folder_id/files",
			middlewares.FolderAccess(),
			uploadHandler.GetFolderFiles,
		)

		folders.POST("/:folder_id/files",
			middlewares.FileUpload("files", 100*1024*1024),
			middlewares.FolderAccess(),
			uploadHandler.UploadToFolder,
		)

		// Folder sharing
		folders.POST("/:folder_id/share",
			applyValidation("share_folder"),
			middlewares.FolderOwnership(),
			uploadHandler.ShareFolder,
		)

		folders.GET("/:folder_id/permissions",
			middlewares.FolderAccess(),
			uploadHandler.GetFolderPermissions,
		)

		folders.PUT("/:folder_id/permissions",
			applyValidation("update_folder_permissions"),
			middlewares.FolderOwnership(),
			uploadHandler.UpdateFolderPermissions,
		)
	}

	// =============================================================================
	// MEDIA LIBRARY
	// =============================================================================

	library := uploads.Group("/library")
	{
		// Media library overview
		library.GET("",
			uploadHandler.GetMediaLibrary,
		)

		library.GET("/stats",
			uploadHandler.GetLibraryStats,
		)

		library.GET("/usage",
			uploadHandler.GetStorageUsage,
		)

		// Media collections
		library.GET("/albums",
			uploadHandler.GetAlbums,
		)

		library.POST("/albums",
			applyValidation("create_album"),
			uploadHandler.CreateAlbum,
		)

		library.PUT("/albums/:album_id",
			applyValidation("update_album"),
			uploadHandler.UpdateAlbum,
		)

		library.DELETE("/albums/:album_id",
			uploadHandler.DeleteAlbum,
		)

		library.POST("/albums/:album_id/files/:file_id",
			uploadHandler.AddFileToAlbum,
		)

		library.DELETE("/albums/:album_id/files/:file_id",
			uploadHandler.RemoveFileFromAlbum,
		)

		// Search and filter
		library.GET("/search",
			applyValidation("search_media"),
			uploadHandler.SearchMedia,
		)

		library.GET("/filter",
			applyValidation("filter_media"),
			uploadHandler.FilterMedia,
		)

		// Bulk operations
		library.POST("/bulk/delete",
			applyValidation("bulk_delete_files"),
			uploadHandler.BulkDeleteFiles,
		)

		library.POST("/bulk/move",
			applyValidation("bulk_move_files"),
			uploadHandler.BulkMoveFiles,
		)

		library.POST("/bulk/tag",
			applyValidation("bulk_tag_files"),
			uploadHandler.BulkTagFiles,
		)
	}

	// =============================================================================
	// UPLOAD SETTINGS AND PREFERENCES
	// =============================================================================

	settings := uploads.Group("/settings")
	{
		// Upload preferences
		settings.GET("",
			uploadHandler.GetUploadSettings,
		)

		settings.PUT("",
			applyValidation("upload_settings"),
			uploadHandler.UpdateUploadSettings,
		)

		// Storage settings
		settings.GET("/storage",
			uploadHandler.GetStorageSettings,
		)

		settings.PUT("/storage",
			applyValidation("storage_settings"),
			uploadHandler.UpdateStorageSettings,
		)

		// Auto-processing settings
		settings.GET("/auto-processing",
			uploadHandler.GetAutoProcessingSettings,
		)

		settings.PUT("/auto-processing",
			applyValidation("auto_processing"),
			uploadHandler.UpdateAutoProcessingSettings,
		)

		// File organization
		settings.GET("/organization",
			uploadHandler.GetOrganizationSettings,
		)

		settings.PUT("/organization",
			applyValidation("organization_settings"),
			uploadHandler.UpdateOrganizationSettings,
		)
	}

	// =============================================================================
	// UPLOAD ANALYTICS
	// =============================================================================

	analytics := uploads.Group("/analytics")
	{
		// Upload statistics
		analytics.GET("/stats",
			uploadHandler.GetUploadStats,
		)

		analytics.GET("/usage-trends",
			uploadHandler.GetUsageTrends,
		)

		analytics.GET("/file-types",
			uploadHandler.GetFileTypeDistribution,
		)

		analytics.GET("/storage-breakdown",
			uploadHandler.GetStorageBreakdown,
		)

		// Performance metrics
		analytics.GET("/performance",
			uploadHandler.GetUploadPerformance,
		)

		analytics.GET("/bandwidth",
			uploadHandler.getBandwidthUsage,
		)

		analytics.GET("/popular-files",
			uploadHandler.GetPopularFiles,
		)
	}
}

// Upload validation rules that handlers will need:
/*
Required Validation Schemas:

1. upload_file:
   - file: required,file,max_size:100MB
   - folder_id: sometimes,objectid
   - description: sometimes,string,max:500
   - tags: sometimes,array,max:20
   - is_public: sometimes,boolean

2. upload_image:
   - image: required,file,image,max_size:20MB
   - quality: sometimes,integer,min:1,max:100
   - auto_optimize: sometimes,boolean
   - generate_thumbnails: sometimes,boolean

3. resize_image:
   - width: required,integer,min:1,max:4000
   - height: required,integer,min:1,max:4000
   - maintain_aspect: sometimes,boolean
   - upscale: sometimes,boolean

4. crop_image:
   - x: required,integer,min:0
   - y: required,integer,min:0
   - width: required,integer,min:1
   - height: required,integer,min:1

5. upload_video:
   - video: required,file,video,max_size:500MB
   - generate_thumbnail: sometimes,boolean
   - auto_transcode: sometimes,boolean
   - quality: sometimes,in:low,medium,high,ultra

6. transcode_video:
   - format: required,in:mp4,webm,avi,mov
   - quality: sometimes,in:240p,360p,480p,720p,1080p,4k
   - bitrate: sometimes,integer,min:100,max:50000

7. trim_video:
   - start_time: required,integer,min:0
   - end_time: required,integer,min:1
   - format: sometimes,in:mp4,webm

8. upload_audio:
   - audio: required,file,audio,max_size:100MB
   - auto_normalize: sometimes,boolean
   - generate_waveform: sometimes,boolean

9. upload_document:
   - document: required,file,document,max_size:50MB
   - extract_text: sometimes,boolean
   - generate_preview: sometimes,boolean

10. share_file:
    - permissions: required,in:view,download,edit
    - expires_at: sometimes,datetime,after:now
    - password: sometimes,string,min:6
    - allow_public: sometimes,boolean

11. create_folder:
    - name: required,string,max:100
    - parent_id: sometimes,objectid
    - description: sometimes,string,max:500
    - is_public: sometimes,boolean

12. create_album:
    - name: required,string,max:100
    - description: sometimes,string,max:500
    - cover_image: sometimes,objectid
    - is_public: sometimes,boolean

13. upload_settings:
    - auto_organize: sometimes,boolean
    - auto_optimize: sometimes,boolean
    - default_privacy: sometimes,in:public,private,followers
    - max_file_size: sometimes,integer,min:1,max:1000
    - allowed_types: sometimes,array

14. bulk_delete_files:
    - file_ids: required,array,min:1,max:100
    - file_ids.*: required,objectid
    - permanent: sometimes,boolean
*/
