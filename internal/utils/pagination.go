package utils

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PaginationConfig represents pagination configuration
type PaginationConfig struct {
	DefaultLimit int64
	MaxLimit     int64
	MinLimit     int64
}

// PaginationParams represents pagination parameters from request
type PaginationParams struct {
	Page   int64  `json:"page" form:"page" query:"page"`
	Limit  int64  `json:"limit" form:"limit" query:"limit"`
	Sort   string `json:"sort" form:"sort" query:"sort"`
	Order  string `json:"order" form:"order" query:"order"`
	Search string `json:"search" form:"search" query:"search"`
	Filter string `json:"filter" form:"filter" query:"filter"`
	Cursor string `json:"cursor" form:"cursor" query:"cursor"`
}

// PaginationResult represents pagination result
type PaginationResult struct {
	Page         int64           `json:"page"`
	Limit        int64           `json:"limit"`
	TotalCount   int64           `json:"total_count"`
	TotalPages   int64           `json:"total_pages"`
	HasPrevious  bool            `json:"has_previous"`
	HasNext      bool            `json:"has_next"`
	PreviousPage *int64          `json:"previous_page"`
	NextPage     *int64          `json:"next_page"`
	Data         interface{}     `json:"data"`
	Meta         *PaginationMeta `json:"meta,omitempty"`
}

// PaginationMeta represents additional pagination metadata
type PaginationMeta struct {
	Sort        string                 `json:"sort,omitempty"`
	Order       string                 `json:"order,omitempty"`
	Search      string                 `json:"search,omitempty"`
	Filters     map[string]interface{} `json:"filters,omitempty"`
	Links       *PaginationLinks       `json:"links,omitempty"`
	Aggregation *AggregationData       `json:"aggregation,omitempty"`
}

// PaginationLinks represents pagination navigation links
type PaginationLinks struct {
	First    string `json:"first,omitempty"`
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current"`
	Next     string `json:"next,omitempty"`
	Last     string `json:"last,omitempty"`
}

// AggregationData represents aggregation data for pagination
type AggregationData struct {
	Counts    map[string]int64       `json:"counts,omitempty"`
	Sums      map[string]float64     `json:"sums,omitempty"`
	Averages  map[string]float64     `json:"averages,omitempty"`
	MinValues map[string]interface{} `json:"min_values,omitempty"`
	MaxValues map[string]interface{} `json:"max_values,omitempty"`
}

// CursorPaginationParams represents cursor-based pagination parameters
type CursorPaginationParams struct {
	Limit     int64  `json:"limit"`
	Cursor    string `json:"cursor"`
	Direction string `json:"direction"` // forward, backward
	Sort      string `json:"sort"`
	Order     string `json:"order"`
}

// CursorPaginationResult represents cursor-based pagination result
type CursorPaginationResult struct {
	Data       interface{} `json:"data"`
	HasMore    bool        `json:"has_more"`
	NextCursor string      `json:"next_cursor,omitempty"`
	PrevCursor string      `json:"prev_cursor,omitempty"`
	Count      int64       `json:"count"`
	Limit      int64       `json:"limit"`
}

// SortOrder represents sort order
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// DefaultPaginationConfig provides default pagination settings
var DefaultPaginationConfig = &PaginationConfig{
	DefaultLimit: 20,
	MaxLimit:     100,
	MinLimit:     1,
}

// NewPaginationParams creates pagination parameters with validation
func NewPaginationParams(page, limit int64, sort, order string) *PaginationParams {
	params := &PaginationParams{
		Page:  page,
		Limit: limit,
		Sort:  sort,
		Order: order,
	}

	return ValidatePaginationParams(params, DefaultPaginationConfig)
}

// ValidatePaginationParams validates and normalizes pagination parameters
func ValidatePaginationParams(params *PaginationParams, config *PaginationConfig) *PaginationParams {
	if params == nil {
		params = &PaginationParams{}
	}

	// Validate and set page
	if params.Page < 1 {
		params.Page = 1
	}

	// Validate and set limit
	if params.Limit < config.MinLimit {
		params.Limit = config.DefaultLimit
	}
	if params.Limit > config.MaxLimit {
		params.Limit = config.MaxLimit
	}
	if params.Limit == 0 {
		params.Limit = config.DefaultLimit
	}

	// Normalize sort order
	params.Order = strings.ToLower(params.Order)
	if params.Order != "asc" && params.Order != "desc" {
		params.Order = "desc"
	}

	// Sanitize sort field
	params.Sort = strings.TrimSpace(params.Sort)
	if params.Sort == "" {
		params.Sort = "created_at"
	}

	return params
}

// CalculateOffset calculates offset for database query
func CalculateOffset(page, limit int64) int64 {
	if page < 1 {
		page = 1
	}
	return (page - 1) * limit
}

// CalculateTotalPages calculates total number of pages
func CalculateTotalPages(totalCount, limit int64) int64 {
	if limit == 0 {
		return 0
	}
	return int64(math.Ceil(float64(totalCount) / float64(limit)))
}

// CreatePaginationResult creates a complete pagination result
func CreatePaginationResult(params *PaginationParams, totalCount int64, data interface{}) *PaginationResult {
	totalPages := CalculateTotalPages(totalCount, params.Limit)

	result := &PaginationResult{
		Page:       params.Page,
		Limit:      params.Limit,
		TotalCount: totalCount,
		TotalPages: totalPages,
		Data:       data,
	}

	// Set navigation flags
	result.HasPrevious = params.Page > 1
	result.HasNext = params.Page < totalPages

	// Set previous/next page numbers
	if result.HasPrevious {
		prev := params.Page - 1
		result.PreviousPage = &prev
	}
	if result.HasNext {
		next := params.Page + 1
		result.NextPage = &next
	}

	// Add metadata if available
	if params.Sort != "" || params.Order != "" || params.Search != "" {
		result.Meta = &PaginationMeta{
			Sort:   params.Sort,
			Order:  params.Order,
			Search: params.Search,
		}
	}

	return result
}

// CreatePaginationResultWithMeta creates pagination result with additional metadata
func CreatePaginationResultWithMeta(params *PaginationParams, totalCount int64, data interface{}, meta *PaginationMeta) *PaginationResult {
	result := CreatePaginationResult(params, totalCount, data)

	if meta != nil {
		if result.Meta == nil {
			result.Meta = &PaginationMeta{}
		}

		// Merge metadata
		if meta.Filters != nil {
			result.Meta.Filters = meta.Filters
		}
		if meta.Links != nil {
			result.Meta.Links = meta.Links
		}
		if meta.Aggregation != nil {
			result.Meta.Aggregation = meta.Aggregation
		}
	}

	return result
}

// GeneratePaginationLinks generates pagination navigation links
func GeneratePaginationLinks(baseURL string, params *PaginationParams, totalPages int64) *PaginationLinks {
	links := &PaginationLinks{}

	// Parse base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	values := u.Query()

	// Add non-pagination parameters
	if params.Sort != "" {
		values.Set("sort", params.Sort)
	}
	if params.Order != "" {
		values.Set("order", params.Order)
	}
	if params.Search != "" {
		values.Set("search", params.Search)
	}
	if params.Filter != "" {
		values.Set("filter", params.Filter)
	}
	values.Set("limit", strconv.FormatInt(params.Limit, 10))

	// Generate links
	if totalPages > 0 {
		// First page
		values.Set("page", "1")
		u.RawQuery = values.Encode()
		links.First = u.String()

		// Last page
		values.Set("page", strconv.FormatInt(totalPages, 10))
		u.RawQuery = values.Encode()
		links.Last = u.String()
	}

	// Current page
	values.Set("page", strconv.FormatInt(params.Page, 10))
	u.RawQuery = values.Encode()
	links.Current = u.String()

	// Previous page
	if params.Page > 1 {
		values.Set("page", strconv.FormatInt(params.Page-1, 10))
		u.RawQuery = values.Encode()
		links.Previous = u.String()
	}

	// Next page
	if params.Page < totalPages {
		values.Set("page", strconv.FormatInt(params.Page+1, 10))
		u.RawQuery = values.Encode()
		links.Next = u.String()
	}

	return links
}

// GetMongoFindOptions converts pagination params to MongoDB find options
func GetMongoFindOptions(params *PaginationParams) *options.FindOptions {
	opts := options.Find()

	// Set limit and skip
	opts.SetLimit(params.Limit)
	opts.SetSkip(CalculateOffset(params.Page, params.Limit))

	// Set sort
	if params.Sort != "" {
		sortOrder := 1
		if params.Order == "desc" {
			sortOrder = -1
		}
		opts.SetSort(bson.D{{Key: params.Sort, Value: sortOrder}})
	}

	return opts
}

// GetMongoAggregationPipeline creates aggregation pipeline with pagination
func GetMongoAggregationPipeline(params *PaginationParams, matchStage bson.D) []bson.D {
	pipeline := []bson.D{}

	// Add match stage if provided
	if len(matchStage) > 0 {
		pipeline = append(pipeline, bson.D{{"$match", matchStage}})
	}

	// Add sort stage
	if params.Sort != "" {
		sortOrder := 1
		if params.Order == "desc" {
			sortOrder = -1
		}
		pipeline = append(pipeline, bson.D{{"$sort", bson.D{{Key: params.Sort, Value: sortOrder}}}})
	}

	// Add skip stage
	offset := CalculateOffset(params.Page, params.Limit)
	if offset > 0 {
		pipeline = append(pipeline, bson.D{{"$skip", offset}})
	}

	// Add limit stage
	pipeline = append(pipeline, bson.D{{"$limit", params.Limit}})

	return pipeline
}

// CreateCursorPaginationResult creates cursor-based pagination result
func CreateCursorPaginationResult(params *CursorPaginationParams, data interface{}, count int64, hasMore bool, nextCursor, prevCursor string) *CursorPaginationResult {
	return &CursorPaginationResult{
		Data:       data,
		HasMore:    hasMore,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
		Count:      count,
		Limit:      params.Limit,
	}
}

// ParseSortFields parses sort fields from string (e.g., "name:asc,created_at:desc")
func ParseSortFields(sortString string) map[string]SortOrder {
	result := make(map[string]SortOrder)

	if sortString == "" {
		return result
	}

	fields := strings.Split(sortString, ",")
	for _, field := range fields {
		parts := strings.Split(strings.TrimSpace(field), ":")
		if len(parts) == 1 {
			result[parts[0]] = SortOrderDesc
		} else if len(parts) == 2 {
			order := SortOrderDesc
			if strings.ToLower(parts[1]) == "asc" {
				order = SortOrderAsc
			}
			result[parts[0]] = order
		}
	}

	return result
}

// BuildSortBson builds BSON sort document from sort fields
func BuildSortBson(sortFields map[string]SortOrder) bson.D {
	var sort bson.D

	for field, order := range sortFields {
		value := -1
		if order == SortOrderAsc {
			value = 1
		}
		sort = append(sort, bson.E{Key: field, Value: value})
	}

	return sort
}

// ValidateSortField validates if sort field is allowed
func ValidateSortField(field string, allowedFields []string) bool {
	if len(allowedFields) == 0 {
		return true // No restrictions
	}

	for _, allowed := range allowedFields {
		if field == allowed {
			return true
		}
	}

	return false
}

// SanitizeSortFields removes invalid sort fields
func SanitizeSortFields(sortFields map[string]SortOrder, allowedFields []string) map[string]SortOrder {
	if len(allowedFields) == 0 {
		return sortFields
	}

	sanitized := make(map[string]SortOrder)
	for field, order := range sortFields {
		if ValidateSortField(field, allowedFields) {
			sanitized[field] = order
		}
	}

	return sanitized
}

// GetPaginationSummary returns a text summary of pagination
func GetPaginationSummary(result *PaginationResult) string {
	if result.TotalCount == 0 {
		return "No items found"
	}

	start := (result.Page-1)*result.Limit + 1
	end := start + int64(len(result.Data.([]interface{}))) - 1

	if end > result.TotalCount {
		end = result.TotalCount
	}

	return fmt.Sprintf("Showing %d-%d of %d items", start, end, result.TotalCount)
}

// CalculatePageRange calculates page range for pagination UI
func CalculatePageRange(currentPage, totalPages, rangeSize int64) (int64, int64) {
	if rangeSize < 1 {
		rangeSize = 5
	}

	halfRange := rangeSize / 2

	start := currentPage - halfRange
	if start < 1 {
		start = 1
	}

	end := start + rangeSize - 1
	if end > totalPages {
		end = totalPages
		start = end - rangeSize + 1
		if start < 1 {
			start = 1
		}
	}

	return start, end
}

// GeneratePageNumbers generates array of page numbers for pagination UI
func GeneratePageNumbers(currentPage, totalPages, rangeSize int64) []int64 {
	start, end := CalculatePageRange(currentPage, totalPages, rangeSize)

	pages := make([]int64, 0, end-start+1)
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	return pages
}

// EstimateQueryPerformance estimates query performance impact
func EstimateQueryPerformance(params *PaginationParams, totalCount int64) map[string]interface{} {
	performance := make(map[string]interface{})

	// Calculate skip efficiency
	offset := CalculateOffset(params.Page, params.Limit)
	skipRatio := float64(offset) / float64(totalCount)

	performance["skip_ratio"] = skipRatio
	performance["skip_count"] = offset
	performance["efficiency"] = "high"

	if skipRatio > 0.1 {
		performance["efficiency"] = "medium"
	}
	if skipRatio > 0.5 {
		performance["efficiency"] = "low"
		performance["recommendation"] = "Consider using cursor-based pagination for better performance"
	}

	return performance
}

// OptimizePaginationParams optimizes pagination parameters for performance
func OptimizePaginationParams(params *PaginationParams, totalCount int64) *PaginationParams {
	optimized := *params

	// Suggest cursor pagination for large datasets
	offset := CalculateOffset(params.Page, params.Limit)
	if float64(offset)/float64(totalCount) > 0.1 && totalCount > 10000 {
		// Large offset detected, suggest cursor pagination
		optimized.Cursor = "suggested"
	}

	// Optimize limit for performance
	if params.Limit > 100 && totalCount > 50000 {
		optimized.Limit = 50 // Reduce limit for large datasets
	}

	return &optimized
}
