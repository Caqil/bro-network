package database

import (
	"context"
	"fmt"
	"time"

	"bro-network/internal/database"
	"bro-network/internal/models"
	"bro-network/pkg/constants"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AnalyticsService handles analytics data operations
type AnalyticsService struct {
	db     *database.Database
	logger database.Logger
}

// NewAnalyticsService creates a new analytics service
func NewAnalyticsService(logger database.Logger) *AnalyticsService {
	return &AnalyticsService{
		db:     database.GetAnalyticsDB(), // Use analytics-specific DB if available
		logger: logger,
	}
}

// TrackEvent tracks an analytics event
func (as *AnalyticsService) TrackEvent(ctx context.Context, event *models.Analytics) error {
	collection := as.db.Collection(constants.CollectionAnalytics)

	// Set timestamp and date fields if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if event.Date == "" {
		event.Date = event.Timestamp.Format("2006-01-02")
	}

	if event.Hour == 0 {
		event.Hour = event.Timestamp.Hour()
	}

	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	// Generate ID if not provided
	if event.ID.IsZero() {
		event.ID = primitive.NewObjectID()
	}

	_, err := collection.InsertOne(ctx, event)
	if err != nil {
		if as.logger != nil {
			as.logger.Error("Failed to track analytics event", "error", err, "event", event.EventType)
		}
		return fmt.Errorf("failed to track analytics event: %w", err)
	}

	if as.logger != nil {
		as.logger.Debug("Analytics event tracked",
			"entity_type", event.EntityType,
			"event_type", event.EventType,
			"entity_id", event.EntityID,
		)
	}

	return nil
}

// TrackUserEvent tracks a user-related event
func (as *AnalyticsService) TrackUserEvent(ctx context.Context, userID *primitive.ObjectID, entityID primitive.ObjectID, entityType models.AnalyticsEntity, eventType models.AnalyticsEvent, sessionID string, metadata models.AnalyticsMetadata) error {
	event := &models.Analytics{
		EntityID:   entityID,
		EntityType: entityType,
		EventType:  eventType,
		UserID:     userID,
		SessionID:  sessionID,
		Metadata:   metadata,
		Value:      1, // Default value for count-based events
	}

	return as.TrackEvent(ctx, event)
}

// TrackPostView tracks a post view event
func (as *AnalyticsService) TrackPostView(ctx context.Context, postID primitive.ObjectID, userID *primitive.ObjectID, sessionID string, metadata models.AnalyticsMetadata) error {
	return as.TrackUserEvent(ctx, userID, postID, models.AnalyticsEntityPost, models.EventPostView, sessionID, metadata)
}

// TrackPostLike tracks a post like event
func (as *AnalyticsService) TrackPostLike(ctx context.Context, postID primitive.ObjectID, userID primitive.ObjectID, sessionID string) error {
	metadata := models.AnalyticsMetadata{
		Platform:  "web",
		UserAgent: "",
		IPAddress: "",
	}
	return as.TrackUserEvent(ctx, &userID, postID, models.AnalyticsEntityPost, models.EventPostLike, sessionID, metadata)
}

// TrackUserRegistration tracks a user registration event
func (as *AnalyticsService) TrackUserRegistration(ctx context.Context, userID primitive.ObjectID, sessionID string, metadata models.AnalyticsMetadata) error {
	return as.TrackUserEvent(ctx, &userID, userID, models.AnalyticsEntityUser, models.EventUserRegistration, sessionID, metadata)
}

// TrackUserLogin tracks a user login event
func (as *AnalyticsService) TrackUserLogin(ctx context.Context, userID primitive.ObjectID, sessionID string, metadata models.AnalyticsMetadata) error {
	return as.TrackUserEvent(ctx, &userID, userID, models.AnalyticsEntityUser, models.EventUserLogin, sessionID, metadata)
}

// GetEntityAnalytics gets analytics data for a specific entity
func (as *AnalyticsService) GetEntityAnalytics(ctx context.Context, entityID primitive.ObjectID, entityType models.AnalyticsEntity, startDate, endDate time.Time) ([]models.Analytics, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	filter := bson.M{
		"entity_id":   entityID,
		"entity_type": entityType,
		"timestamp": bson.M{
			"$gte": startDate,
			"$lte": endDate,
		},
	}

	cursor, err := collection.Find(ctx, filter, options.Find().SetSort(bson.D{{"timestamp", -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var analytics []models.Analytics
	if err := cursor.All(ctx, &analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

// GetEventCounts gets event counts by type for an entity
func (as *AnalyticsService) GetEventCounts(ctx context.Context, entityID primitive.ObjectID, entityType models.AnalyticsEntity, startDate, endDate time.Time) (map[string]int64, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_id":   entityID,
				"entity_type": entityType,
				"timestamp": bson.M{
					"$gte": startDate,
					"$lte": endDate,
				},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$event_type",
				"count": bson.M{"$sum": 1},
			},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, result := range results {
		eventType := result["_id"].(string)
		count := result["count"].(int64)
		counts[eventType] = count
	}

	return counts, nil
}

// GetDailyEventCounts gets daily event counts for an entity
func (as *AnalyticsService) GetDailyEventCounts(ctx context.Context, entityID primitive.ObjectID, entityType models.AnalyticsEntity, eventType models.AnalyticsEvent, days int) ([]bson.M, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	startDate := time.Now().AddDate(0, 0, -days)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_id":   entityID,
				"entity_type": entityType,
				"event_type":  eventType,
				"timestamp":   bson.M{"$gte": startDate},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$date",
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// GetHourlyEventCounts gets hourly event counts for an entity
func (as *AnalyticsService) GetHourlyEventCounts(ctx context.Context, entityID primitive.ObjectID, entityType models.AnalyticsEntity, eventType models.AnalyticsEvent, date string) ([]bson.M, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_id":   entityID,
				"entity_type": entityType,
				"event_type":  eventType,
				"date":        date,
			},
		},
		{
			"$group": bson.M{
				"_id":   "$hour",
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// GetUserActivityAnalytics gets user activity analytics
func (as *AnalyticsService) GetUserActivityAnalytics(ctx context.Context, userID primitive.ObjectID, startDate, endDate time.Time) (map[string]interface{}, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"user_id": userID,
				"timestamp": bson.M{
					"$gte": startDate,
					"$lte": endDate,
				},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$event_type",
				"count": bson.M{"$sum": 1},
				"unique_entities": bson.M{
					"$addToSet": "$entity_id",
				},
			},
		},
		{
			"$addFields": bson.M{
				"unique_entities_count": bson.M{
					"$size": "$unique_entities",
				},
			},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	analytics := make(map[string]interface{})
	for _, result := range results {
		eventType := result["_id"].(string)
		analytics[eventType] = map[string]interface{}{
			"count":                 result["count"],
			"unique_entities_count": result["unique_entities_count"],
		}
	}

	return analytics, nil
}

// GetTopContent gets top content by analytics metrics
func (as *AnalyticsService) GetTopContent(ctx context.Context, entityType models.AnalyticsEntity, eventType models.AnalyticsEvent, startDate, endDate time.Time, limit int64) ([]bson.M, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_type": entityType,
				"event_type":  eventType,
				"timestamp": bson.M{
					"$gte": startDate,
					"$lte": endDate,
				},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$entity_id",
				"count": bson.M{"$sum": 1},
				"unique_users": bson.M{
					"$addToSet": "$user_id",
				},
			},
		},
		{
			"$addFields": bson.M{
				"unique_users_count": bson.M{
					"$size": "$unique_users",
				},
			},
		},
		{
			"$sort": bson.M{
				"count":              -1,
				"unique_users_count": -1,
			},
		},
		{
			"$limit": limit,
		},
	}

	// Add lookup based on entity type
	var lookupCollection string
	switch entityType {
	case models.AnalyticsEntityPost:
		lookupCollection = constants.CollectionPosts
	case models.AnalyticsEntityUser:
		lookupCollection = constants.CollectionUsers
	case models.AnalyticsEntityComment:
		lookupCollection = constants.CollectionComments
	default:
		return nil, fmt.Errorf("unsupported entity type: %s", entityType)
	}

	pipeline = append(pipeline, bson.M{
		"$lookup": bson.M{
			"from":         lookupCollection,
			"localField":   "_id",
			"foreignField": "_id",
			"as":           "entity",
		},
	})

	pipeline = append(pipeline, bson.M{
		"$unwind": "$entity",
	})

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// GetEngagementTrends gets engagement trends over time
func (as *AnalyticsService) GetEngagementTrends(ctx context.Context, entityType models.AnalyticsEntity, days int) ([]bson.M, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	startDate := time.Now().AddDate(0, 0, -days)

	// Define engagement events
	engagementEvents := []models.AnalyticsEvent{
		models.EventPostLike,
		models.EventPostComment,
		models.EventPostShare,
		models.EventUserFollow,
	}

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_type": entityType,
				"event_type":  bson.M{"$in": engagementEvents},
				"timestamp":   bson.M{"$gte": startDate},
			},
		},
		{
			"$group": bson.M{
				"_id": bson.M{
					"date":       "$date",
					"event_type": "$event_type",
				},
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$group": bson.M{
				"_id": "$_id.date",
				"events": bson.M{
					"$push": bson.M{
						"event_type": "$_id.event_type",
						"count":      "$count",
					},
				},
				"total_engagement": bson.M{"$sum": "$count"},
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// GetUserBehaviorPatterns analyzes user behavior patterns
func (as *AnalyticsService) GetUserBehaviorPatterns(ctx context.Context, userID primitive.ObjectID, days int) (map[string]interface{}, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	startDate := time.Now().AddDate(0, 0, -days)

	// Get activity by hour of day
	hourlyPattern := []bson.M{
		{
			"$match": bson.M{
				"user_id":   userID,
				"timestamp": bson.M{"$gte": startDate},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$hour",
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor, err := collection.Aggregate(ctx, hourlyPattern)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var hourlyResults []bson.M
	if err := cursor.All(ctx, &hourlyResults); err != nil {
		return nil, err
	}

	// Get activity by day of week
	dailyPattern := []bson.M{
		{
			"$match": bson.M{
				"user_id":   userID,
				"timestamp": bson.M{"$gte": startDate},
			},
		},
		{
			"$group": bson.M{
				"_id": bson.M{
					"$dayOfWeek": "$timestamp",
				},
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor2, err := collection.Aggregate(ctx, dailyPattern)
	if err != nil {
		return nil, err
	}
	defer cursor2.Close(ctx)

	var dailyResults []bson.M
	if err := cursor2.All(ctx, &dailyResults); err != nil {
		return nil, err
	}

	// Get event type distribution
	eventPattern := []bson.M{
		{
			"$match": bson.M{
				"user_id":   userID,
				"timestamp": bson.M{"$gte": startDate},
			},
		},
		{
			"$group": bson.M{
				"_id":   "$event_type",
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{"count": -1},
		},
	}

	cursor3, err := collection.Aggregate(ctx, eventPattern)
	if err != nil {
		return nil, err
	}
	defer cursor3.Close(ctx)

	var eventResults []bson.M
	if err := cursor3.All(ctx, &eventResults); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hourly_activity":    hourlyResults,
		"daily_activity":     dailyResults,
		"event_distribution": eventResults,
	}, nil
}

// GetRealTimeAnalytics gets real-time analytics data
func (as *AnalyticsService) GetRealTimeAnalytics(ctx context.Context, minutes int) (map[string]interface{}, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	startTime := time.Now().Add(-time.Duration(minutes) * time.Minute)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"timestamp": bson.M{"$gte": startTime},
			},
		},
		{
			"$group": bson.M{
				"_id": bson.M{
					"entity_type": "$entity_type",
					"event_type":  "$event_type",
				},
				"count": bson.M{"$sum": 1},
				"unique_users": bson.M{
					"$addToSet": "$user_id",
				},
				"unique_entities": bson.M{
					"$addToSet": "$entity_id",
				},
			},
		},
		{
			"$addFields": bson.M{
				"unique_users_count": bson.M{
					"$size": "$unique_users",
				},
				"unique_entities_count": bson.M{
					"$size": "$unique_entities",
				},
			},
		},
		{
			"$sort": bson.M{"count": -1},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	// Get total active users
	activeUsersPipeline := []bson.M{
		{
			"$match": bson.M{
				"timestamp": bson.M{"$gte": startTime},
				"user_id":   bson.M{"$ne": nil},
			},
		},
		{
			"$group": bson.M{
				"_id": nil,
				"active_users": bson.M{
					"$addToSet": "$user_id",
				},
			},
		},
		{
			"$addFields": bson.M{
				"active_users_count": bson.M{
					"$size": "$active_users",
				},
			},
		},
	}

	cursor2, err := collection.Aggregate(ctx, activeUsersPipeline)
	if err != nil {
		return nil, err
	}
	defer cursor2.Close(ctx)

	var activeUsersResults []bson.M
	if err := cursor2.All(ctx, &activeUsersResults); err != nil {
		return nil, err
	}

	activeUsersCount := int64(0)
	if len(activeUsersResults) > 0 {
		if count, ok := activeUsersResults[0]["active_users_count"].(int32); ok {
			activeUsersCount = int64(count)
		}
	}

	return map[string]interface{}{
		"events":             results,
		"active_users_count": activeUsersCount,
		"time_range_minutes": minutes,
		"timestamp":          time.Now(),
	}, nil
}

// CleanupOldAnalytics removes old analytics data based on retention policy
func (as *AnalyticsService) CleanupOldAnalytics(ctx context.Context, retentionDays int) (int64, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	result, err := collection.DeleteMany(ctx, bson.M{
		"timestamp": bson.M{"$lt": cutoffDate},
	})
	if err != nil {
		return 0, err
	}

	if as.logger != nil {
		as.logger.Info("Cleaned up old analytics data",
			"deleted_count", result.DeletedCount,
			"cutoff_date", cutoffDate,
		)
	}

	return result.DeletedCount, nil
}

// GetAnalyticsSummary gets a comprehensive analytics summary
func (as *AnalyticsService) GetAnalyticsSummary(ctx context.Context, entityID primitive.ObjectID, entityType models.AnalyticsEntity, days int) (map[string]interface{}, error) {
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)

	// Get event counts
	eventCounts, err := as.GetEventCounts(ctx, entityID, entityType, startDate, endDate)
	if err != nil {
		return nil, err
	}

	// Get daily trends
	dailyData, err := as.GetDailyEventCounts(ctx, entityID, entityType, models.EventPostView, days)
	if err != nil {
		return nil, err
	}

	// Calculate growth rate
	var growthRate float64
	if len(dailyData) >= 2 {
		firstDay := dailyData[0]["count"].(int64)
		lastDay := dailyData[len(dailyData)-1]["count"].(int64)
		if firstDay > 0 {
			growthRate = float64(lastDay-firstDay) / float64(firstDay) * 100
		}
	}

	return map[string]interface{}{
		"entity_id":    entityID,
		"entity_type":  entityType,
		"date_range":   map[string]time.Time{"start": startDate, "end": endDate},
		"event_counts": eventCounts,
		"daily_data":   dailyData,
		"growth_rate":  growthRate,
		"total_events": sumEventCounts(eventCounts),
	}, nil
}

// Helper function to sum event counts
func sumEventCounts(eventCounts map[string]int64) int64 {
	var total int64
	for _, count := range eventCounts {
		total += count
	}
	return total
}

// BatchTrackEvents tracks multiple events in a single operation
func (as *AnalyticsService) BatchTrackEvents(ctx context.Context, events []models.Analytics) error {
	if len(events) == 0 {
		return nil
	}

	collection := as.db.Collection(constants.CollectionAnalytics)

	// Prepare documents for batch insertion
	var docs []interface{}
	now := time.Now()

	for _, event := range events {
		// Set default values if not provided
		if event.Timestamp.IsZero() {
			event.Timestamp = now
		}
		if event.Date == "" {
			event.Date = event.Timestamp.Format("2006-01-02")
		}
		if event.Hour == 0 {
			event.Hour = event.Timestamp.Hour()
		}
		if event.CreatedAt.IsZero() {
			event.CreatedAt = now
		}
		if event.ID.IsZero() {
			event.ID = primitive.NewObjectID()
		}

		docs = append(docs, event)
	}

	_, err := collection.InsertMany(ctx, docs)
	if err != nil {
		if as.logger != nil {
			as.logger.Error("Failed to batch track analytics events", "error", err, "count", len(events))
		}
		return fmt.Errorf("failed to batch track analytics events: %w", err)
	}

	if as.logger != nil {
		as.logger.Debug("Batch analytics events tracked", "count", len(events))
	}

	return nil
}

// GetEventTypesByEntity gets all event types for a specific entity type
func (as *AnalyticsService) GetEventTypesByEntity(ctx context.Context, entityType models.AnalyticsEntity) ([]string, error) {
	collection := as.db.Collection(constants.CollectionAnalytics)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"entity_type": entityType,
			},
		},
		{
			"$group": bson.M{
				"_id": "$event_type",
			},
		},
		{
			"$sort": bson.M{"_id": 1},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	var eventTypes []string
	for _, result := range results {
		eventTypes = append(eventTypes, result["_id"].(string))
	}

	return eventTypes, nil
}
