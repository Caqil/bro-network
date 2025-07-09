package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/disintegration/imaging"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UploadConfig represents upload configuration
type UploadConfig struct {
	MaxFileSize        int64                `json:"max_file_size"`
	AllowedMimeTypes   []string             `json:"allowed_mime_types"`
	AllowedExtensions  []string             `json:"allowed_extensions"`
	ImageSizes         map[string]ImageSize `json:"image_sizes"`
	S3Config           *S3Config            `json:"s3_config"`
	LocalPath          string               `json:"local_path"`
	CDNBaseURL         string               `json:"cdn_base_url"`
	GenerateThumbnails bool                 `json:"generate_thumbnails"`
	OptimizeImages     bool                 `json:"optimize_images"`
	VirusScanEnabled   bool                 `json:"virus_scan_enabled"`
}

// S3Config represents AWS S3 configuration
type S3Config struct {
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	UseSSL          bool   `json:"use_ssl"`
	ForcePathStyle  bool   `json:"force_path_style"`
}

// ImageSize represents image size configuration
type ImageSize struct {
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Quality int    `json:"quality"`
	Format  string `json:"format"` // jpeg, png, webp
	Crop    bool   `json:"crop"`
}

// UploadResult represents upload result
type UploadResult struct {
	ID           primitive.ObjectID     `json:"id"`
	OriginalName string                 `json:"original_name"`
	FileName     string                 `json:"file_name"`
	URL          string                 `json:"url"`
	CDNUrl       string                 `json:"cdn_url,omitempty"`
	Size         int64                  `json:"size"`
	MimeType     string                 `json:"mime_type"`
	Extension    string                 `json:"extension"`
	Hash         string                 `json:"hash"`
	Width        int                    `json:"width,omitempty"`
	Height       int                    `json:"height,omitempty"`
	Duration     int                    `json:"duration,omitempty"`
	Thumbnails   map[string]string      `json:"thumbnails,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	UploadedAt   time.Time              `json:"uploaded_at"`
}

// FileValidator represents file validation interface
type FileValidator interface {
	Validate(file multipart.File, header *multipart.FileHeader) error
}

// UploadService provides file upload functionality
type UploadService struct {
	config     *UploadConfig
	s3Client   *s3.S3
	s3Uploader *s3manager.Uploader
	validators []FileValidator
}

// FileType represents supported file types
type FileType string

const (
	FileTypeImage    FileType = "image"
	FileTypeVideo    FileType = "video"
	FileTypeAudio    FileType = "audio"
	FileTypeDocument FileType = "document"
	FileTypeArchive  FileType = "archive"
	FileTypeOther    FileType = "other"
)

// Common MIME types
var MimeTypeMap = map[string]FileType{
	// Images
	"image/jpeg":    FileTypeImage,
	"image/jpg":     FileTypeImage,
	"image/png":     FileTypeImage,
	"image/gif":     FileTypeImage,
	"image/webp":    FileTypeImage,
	"image/svg+xml": FileTypeImage,

	// Videos
	"video/mp4":       FileTypeVideo,
	"video/mpeg":      FileTypeVideo,
	"video/quicktime": FileTypeVideo,
	"video/webm":      FileTypeVideo,
	"video/avi":       FileTypeVideo,

	// Audio
	"audio/mpeg": FileTypeAudio,
	"audio/mp3":  FileTypeAudio,
	"audio/wav":  FileTypeAudio,
	"audio/ogg":  FileTypeAudio,
	"audio/aac":  FileTypeAudio,

	// Documents
	"application/pdf":    FileTypeDocument,
	"application/msword": FileTypeDocument,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": FileTypeDocument,
	"application/vnd.ms-excel": FileTypeDocument,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": FileTypeDocument,
	"text/plain": FileTypeDocument,
	"text/csv":   FileTypeDocument,

	// Archives
	"application/zip":             FileTypeArchive,
	"application/x-rar":           FileTypeArchive,
	"application/x-tar":           FileTypeArchive,
	"application/gzip":            FileTypeArchive,
	"application/x-7z-compressed": FileTypeArchive,
}

// Default configurations
var DefaultImageSizes = map[string]ImageSize{
	"thumbnail": {Width: 150, Height: 150, Quality: 80, Format: "jpeg", Crop: true},
	"small":     {Width: 300, Height: 300, Quality: 85, Format: "jpeg", Crop: false},
	"medium":    {Width: 600, Height: 600, Quality: 90, Format: "jpeg", Crop: false},
	"large":     {Width: 1200, Height: 1200, Quality: 95, Format: "jpeg", Crop: false},
}

var DefaultAllowedMimeTypes = []string{
	"image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp",
	"video/mp4", "video/mpeg", "video/quicktime", "video/webm",
	"audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg",
	"application/pdf", "text/plain",
}

var DefaultAllowedExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".webp",
	".mp4", ".mpeg", ".mov", ".webm",
	".mp3", ".wav", ".ogg",
	".pdf", ".txt",
}

// NewUploadService creates a new upload service
func NewUploadService(config *UploadConfig) (*UploadService, error) {
	service := &UploadService{
		config:     config,
		validators: []FileValidator{},
	}

	// Initialize S3 client if configured
	if config.S3Config != nil {
		sess, err := session.NewSession(&aws.Config{
			Region:           aws.String(config.S3Config.Region),
			Endpoint:         aws.String(config.S3Config.Endpoint),
			DisableSSL:       aws.Bool(!config.S3Config.UseSSL),
			S3ForcePathStyle: aws.Bool(config.S3Config.ForcePathStyle),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS session: %w", err)
		}

		service.s3Client = s3.New(sess)
		service.s3Uploader = s3manager.NewUploader(sess)
	}

	// Add default validators
	service.AddValidator(&FileSizeValidator{MaxSize: config.MaxFileSize})
	service.AddValidator(&MimeTypeValidator{AllowedTypes: config.AllowedMimeTypes})
	service.AddValidator(&ExtensionValidator{AllowedExtensions: config.AllowedExtensions})

	return service, nil
}

// AddValidator adds a file validator
func (us *UploadService) AddValidator(validator FileValidator) {
	us.validators = append(us.validators, validator)
}

// UploadFile uploads a file
func (us *UploadService) UploadFile(file multipart.File, header *multipart.FileHeader, userID primitive.ObjectID) (*UploadResult, error) {
	// Validate file
	if err := us.validateFile(file, header); err != nil {
		return nil, fmt.Errorf("file validation failed: %w", err)
	}

	// Reset file pointer
	file.Seek(0, 0)

	// Read file content
	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Generate file hash
	hash := us.generateFileHash(fileContent)

	// Check for duplicate
	if existing := us.checkDuplicate(hash); existing != nil {
		return existing, nil
	}

	// Generate unique filename
	fileName := us.generateFileName(header.Filename, userID)

	// Detect MIME type
	mimeType := us.detectMimeType(fileContent, header.Filename)

	// Get file type
	fileType := us.getFileType(mimeType)

	// Create upload result
	result := &UploadResult{
		ID:           primitive.NewObjectID(),
		OriginalName: header.Filename,
		FileName:     fileName,
		Size:         header.Size,
		MimeType:     mimeType,
		Extension:    filepath.Ext(header.Filename),
		Hash:         hash,
		Metadata:     make(map[string]interface{}),
		UploadedAt:   time.Now(),
	}

	// Extract metadata for images
	if fileType == FileTypeImage {
		if err := us.extractImageMetadata(bytes.NewReader(fileContent), result); err != nil {
			return nil, fmt.Errorf("failed to extract image metadata: %w", err)
		}
	}

	// Upload to storage
	if us.config.S3Config != nil {
		if err := us.uploadToS3(fileContent, fileName, mimeType, result); err != nil {
			return nil, fmt.Errorf("failed to upload to S3: %w", err)
		}
	} else {
		if err := us.uploadToLocal(fileContent, fileName, result); err != nil {
			return nil, fmt.Errorf("failed to upload to local storage: %w", err)
		}
	}

	// Generate thumbnails for images
	if fileType == FileTypeImage && us.config.GenerateThumbnails {
		if err := us.generateThumbnails(fileContent, fileName, result); err != nil {
			// Log error but don't fail upload
			fmt.Printf("Failed to generate thumbnails: %v\n", err)
		}
	}

	return result, nil
}

// UploadMultipleFiles uploads multiple files
func (us *UploadService) UploadMultipleFiles(files []*multipart.FileHeader, userID primitive.ObjectID) ([]*UploadResult, error) {
	var results []*UploadResult
	var errors []error

	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to open file %s: %w", header.Filename, err))
			continue
		}

		result, err := us.UploadFile(file, header, userID)
		file.Close()

		if err != nil {
			errors = append(errors, fmt.Errorf("failed to upload file %s: %w", header.Filename, err))
			continue
		}

		results = append(results, result)
	}

	if len(errors) > 0 {
		return results, fmt.Errorf("some files failed to upload: %v", errors)
	}

	return results, nil
}

// DeleteFile deletes a file from storage
func (us *UploadService) DeleteFile(fileName string) error {
	if us.config.S3Config != nil {
		return us.deleteFromS3(fileName)
	}
	return us.deleteFromLocal(fileName)
}

// validateFile validates file against all validators
func (us *UploadService) validateFile(file multipart.File, header *multipart.FileHeader) error {
	for _, validator := range us.validators {
		if err := validator.Validate(file, header); err != nil {
			return err
		}
		// Reset file pointer after each validation
		file.Seek(0, 0)
	}
	return nil
}

// generateFileHash generates MD5 hash of file content
func (us *UploadService) generateFileHash(content []byte) string {
	hash := md5.Sum(content)
	return hex.EncodeToString(hash[:])
}

// checkDuplicate checks if file already exists (implement based on your storage)
func (us *UploadService) checkDuplicate(hash string) *UploadResult {
	// Implement duplicate check based on your database
	return nil
}

// generateFileName generates unique filename
func (us *UploadService) generateFileName(originalName string, userID primitive.ObjectID) string {
	ext := filepath.Ext(originalName)
	timestamp := time.Now().Unix()
	randomID := primitive.NewObjectID().Hex()
	return fmt.Sprintf("%s_%d_%s%s", userID.Hex(), timestamp, randomID, ext)
}

// detectMimeType detects MIME type from content and filename
func (us *UploadService) detectMimeType(content []byte, filename string) string {
	// Detect from content
	mimeType := http.DetectContentType(content)

	// Fallback to extension-based detection
	if mimeType == "application/octet-stream" {
		mimeType = mime.TypeByExtension(filepath.Ext(filename))
	}

	return mimeType
}

// getFileType determines file type from MIME type
func (us *UploadService) getFileType(mimeType string) FileType {
	if fileType, exists := MimeTypeMap[mimeType]; exists {
		return fileType
	}
	return FileTypeOther
}

// extractImageMetadata extracts metadata from images
func (us *UploadService) extractImageMetadata(reader io.Reader, result *UploadResult) error {
	img, _, err := image.DecodeConfig(reader)
	if err != nil {
		return err
	}

	result.Width = img.Width
	result.Height = img.Height
	result.Metadata["width"] = img.Width
	result.Metadata["height"] = img.Height
	result.Metadata["aspect_ratio"] = float64(img.Width) / float64(img.Height)

	return nil
}

// uploadToS3 uploads file to AWS S3
func (us *UploadService) uploadToS3(content []byte, fileName, mimeType string, result *UploadResult) error {
	input := &s3manager.UploadInput{
		Bucket:      aws.String(us.config.S3Config.Bucket),
		Key:         aws.String(fileName),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(mimeType),
		ACL:         aws.String("public-read"),
	}

	uploadResult, err := us.s3Uploader.Upload(input)
	if err != nil {
		return err
	}

	result.URL = uploadResult.Location
	if us.config.CDNBaseURL != "" {
		result.CDNUrl = fmt.Sprintf("%s/%s", us.config.CDNBaseURL, fileName)
	}

	return nil
}

// uploadToLocal uploads file to local storage
func (us *UploadService) uploadToLocal(content []byte, fileName string, result *UploadResult) error {
	// Implement local file storage
	// This is a placeholder implementation
	filePath := filepath.Join(us.config.LocalPath, fileName)
	result.URL = fmt.Sprintf("/uploads/%s", fileName)

	// In real implementation, write content to filePath
	_ = filePath
	_ = content

	return nil
}

// deleteFromS3 deletes file from AWS S3
func (us *UploadService) deleteFromS3(fileName string) error {
	_, err := us.s3Client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(us.config.S3Config.Bucket),
		Key:    aws.String(fileName),
	})
	return err
}

// deleteFromLocal deletes file from local storage
func (us *UploadService) deleteFromLocal(fileName string) error {
	// Implement local file deletion
	return nil
}

// generateThumbnails generates image thumbnails
func (us *UploadService) generateThumbnails(content []byte, fileName string, result *UploadResult) error {
	// Decode original image
	img, format, err := image.Decode(bytes.NewReader(content))
	if err != nil {
		return err
	}

	result.Thumbnails = make(map[string]string)

	// Generate thumbnails for each configured size
	for sizeName, sizeConfig := range us.config.ImageSizes {
		thumbnail, err := us.resizeImage(img, sizeConfig)
		if err != nil {
			continue
		}

		// Generate thumbnail filename
		ext := filepath.Ext(fileName)
		nameWithoutExt := strings.TrimSuffix(fileName, ext)
		thumbnailFileName := fmt.Sprintf("%s_%s%s", nameWithoutExt, sizeName, ext)

		// Encode thumbnail
		var buf bytes.Buffer
		if err := us.encodeImage(&buf, thumbnail, format, sizeConfig.Quality); err != nil {
			continue
		}

		// Upload thumbnail
		if us.config.S3Config != nil {
			if err := us.uploadThumbnailToS3(buf.Bytes(), thumbnailFileName, result.MimeType); err != nil {
				continue
			}
			result.Thumbnails[sizeName] = fmt.Sprintf("%s/%s", us.config.CDNBaseURL, thumbnailFileName)
		} else {
			if err := us.uploadThumbnailToLocal(buf.Bytes(), thumbnailFileName); err != nil {
				continue
			}
			result.Thumbnails[sizeName] = fmt.Sprintf("/uploads/%s", thumbnailFileName)
		}
	}

	return nil
}

// resizeImage resizes image according to size configuration
func (us *UploadService) resizeImage(img image.Image, sizeConfig ImageSize) (image.Image, error) {
	if sizeConfig.Crop {
		return imaging.Fill(img, sizeConfig.Width, sizeConfig.Height, imaging.Center, imaging.Lanczos), nil
	}
	return imaging.Fit(img, sizeConfig.Width, sizeConfig.Height, imaging.Lanczos), nil
}

// encodeImage encodes image with specified format and quality
func (us *UploadService) encodeImage(w io.Writer, img image.Image, format string, quality int) error {
	switch format {
	case "jpeg", "jpg":
		return jpeg.Encode(w, img, &jpeg.Options{Quality: quality})
	case "png":
		return png.Encode(w, img)
	case "gif":
		return gif.Encode(w, img, nil)
	default:
		return jpeg.Encode(w, img, &jpeg.Options{Quality: quality})
	}
}

// uploadThumbnailToS3 uploads thumbnail to S3
func (us *UploadService) uploadThumbnailToS3(content []byte, fileName, mimeType string) error {
	input := &s3manager.UploadInput{
		Bucket:      aws.String(us.config.S3Config.Bucket),
		Key:         aws.String(fileName),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(mimeType),
		ACL:         aws.String("public-read"),
	}

	_, err := us.s3Uploader.Upload(input)
	return err
}

// uploadThumbnailToLocal uploads thumbnail to local storage
func (us *UploadService) uploadThumbnailToLocal(content []byte, fileName string) error {
	// Implement local thumbnail storage
	return nil
}

// File Validators

// FileSizeValidator validates file size
type FileSizeValidator struct {
	MaxSize int64
}

func (v *FileSizeValidator) Validate(file multipart.File, header *multipart.FileHeader) error {
	if header.Size > v.MaxSize {
		return fmt.Errorf("file size %d exceeds maximum allowed size %d", header.Size, v.MaxSize)
	}
	return nil
}

// MimeTypeValidator validates MIME type
type MimeTypeValidator struct {
	AllowedTypes []string
}

func (v *MimeTypeValidator) Validate(file multipart.File, header *multipart.FileHeader) error {
	// Read first 512 bytes to detect MIME type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}

	mimeType := http.DetectContentType(buffer[:n])

	for _, allowedType := range v.AllowedTypes {
		if mimeType == allowedType {
			return nil
		}
	}

	return fmt.Errorf("MIME type %s is not allowed", mimeType)
}

// ExtensionValidator validates file extension
type ExtensionValidator struct {
	AllowedExtensions []string
}

func (v *ExtensionValidator) Validate(file multipart.File, header *multipart.FileHeader) error {
	ext := strings.ToLower(filepath.Ext(header.Filename))

	for _, allowedExt := range v.AllowedExtensions {
		if ext == strings.ToLower(allowedExt) {
			return nil
		}
	}

	return fmt.Errorf("file extension %s is not allowed", ext)
}

// ImageValidator validates image files
type ImageValidator struct {
	MaxWidth  int
	MaxHeight int
	MinWidth  int
	MinHeight int
}

func (v *ImageValidator) Validate(file multipart.File, header *multipart.FileHeader) error {
	// Check if it's an image
	config, _, err := image.DecodeConfig(file)
	if err != nil {
		return fmt.Errorf("invalid image file: %w", err)
	}

	if v.MaxWidth > 0 && config.Width > v.MaxWidth {
		return fmt.Errorf("image width %d exceeds maximum %d", config.Width, v.MaxWidth)
	}

	if v.MaxHeight > 0 && config.Height > v.MaxHeight {
		return fmt.Errorf("image height %d exceeds maximum %d", config.Height, v.MaxHeight)
	}

	if v.MinWidth > 0 && config.Width < v.MinWidth {
		return fmt.Errorf("image width %d below minimum %d", config.Width, v.MinWidth)
	}

	if v.MinHeight > 0 && config.Height < v.MinHeight {
		return fmt.Errorf("image height %d below minimum %d", config.Height, v.MinHeight)
	}

	return nil
}

// Utility functions

// GetFileSizeString converts file size to human-readable string
func GetFileSizeString(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case size >= TB:
		return fmt.Sprintf("%.2f TB", float64(size)/TB)
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/GB)
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/MB)
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/KB)
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// ParseFileSize parses file size string to bytes
func ParseFileSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	var multiplier int64 = 1
	var numStr string

	if strings.HasSuffix(sizeStr, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "TB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "GB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "B") {
		numStr = strings.TrimSuffix(sizeStr, "B")
	} else {
		numStr = sizeStr
	}

	num, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64)
	if err != nil {
		return 0, err
	}

	return int64(num * float64(multiplier)), nil
}

// IsImageFile checks if file is an image
func IsImageFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "image/")
}

// IsVideoFile checks if file is a video
func IsVideoFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "video/")
}

// IsAudioFile checks if file is an audio file
func IsAudioFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "audio/")
}

// GenerateSecureFileName generates a secure filename
func GenerateSecureFileName(originalName string, userID string) string {
	ext := filepath.Ext(originalName)
	timestamp := time.Now().Unix()
	randomID := primitive.NewObjectID().Hex()
	return fmt.Sprintf("%s_%d_%s%s", userID, timestamp, randomID, ext)
}

// SanitizeFileName sanitizes filename for safe storage
func SanitizeFileName(filename string) string {
	// Remove or replace dangerous characters
	filename = strings.ReplaceAll(filename, "..", "")
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, " ", "_")
	return filename
}

// ValidateUploadRequest validates upload request parameters
func ValidateUploadRequest(maxFiles int, totalSize int64) error {
	if maxFiles > 0 && maxFiles > 10 {
		return errors.New("too many files in single request")
	}

	if totalSize > 100*1024*1024 { // 100MB
		return errors.New("total upload size too large")
	}

	return nil
}
