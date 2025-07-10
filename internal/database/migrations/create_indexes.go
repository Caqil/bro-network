package database

import (
	"context"
	"fmt"

	"bro-network/internal/database"
	"bro-network/pkg/constants"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// IndexDefinition represents a MongoDB index definition
type IndexDefinition struct {
	Collection string
	Keys       bson.D
	Options    *options.IndexOptions
}

// CreateAllIndexes creates all indexes for the social network application
func CreateAllIndexes(ctx context.Context) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	indexes := getAllIndexDefinitions()

	for _, indexDef := range indexes {
		if err := createIndex(ctx, db, indexDef); err != nil {
			return fmt.Errorf("failed to create index on %s: %w", indexDef.Collection, err)
		}
	}

	return nil
}

// createIndex creates a single index
func createIndex(ctx context.Context, db *database.Database, indexDef IndexDefinition) error {
	collection := db.Collection(indexDef.Collection)

	indexModel := mongo.IndexModel{
		Keys:    indexDef.Keys,
		Options: indexDef.Options,
	}

	_, err := collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		if db.Logger != nil {
			db.Logger.Error("Failed to create index",
				"collection", indexDef.Collection,
				"keys", indexDef.Keys,
				"error", err,
			)
		}
		return err
	}

	if db.Logger != nil {
		db.Logger.Info("Created index",
			"collection", indexDef.Collection,
			"keys", indexDef.Keys,
		)
	}

	return nil
}

// getAllIndexDefinitions returns all index definitions for the application
func getAllIndexDefinitions() []IndexDefinition {
	return []IndexDefinition{
		// User indexes
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"email", 1}},
			Options:    options.Index().SetUnique(true).SetName(constants.IndexUserEmail),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"username", 1}},
			Options:    options.Index().SetUnique(true).SetName(constants.IndexUserUsername),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"created_at", -1}},
			Options:    options.Index().SetName("user_created_at_desc"),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"last_seen", -1}},
			Options:    options.Index().SetName("user_last_seen_desc"),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"role", 1}, {"is_active", 1}},
			Options:    options.Index().SetName("user_role_active"),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"is_verified", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("user_verified_created"),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"location.coordinates", "2dsphere"}},
			Options:    options.Index().SetName("user_location_geo"),
		},

		// Post indexes
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"author_id", 1}},
			Options:    options.Index().SetName(constants.IndexPostAuthor),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"created_at", -1}},
			Options:    options.Index().SetName(constants.IndexPostCreatedAt),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"author_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_author_created_desc"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"status", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_status_created"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"hashtags", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_hashtags_created"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"mentions", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_mentions_created"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"location.coordinates", "2dsphere"}},
			Options:    options.Index().SetName("post_location_geo"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"engagement.likes_count", -1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_likes_created"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"engagement.score", -1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_engagement_score"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"parent_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_parent_created"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"thread_id", 1}, {"thread_order", 1}},
			Options:    options.Index().SetName("post_thread_order"),
		},

		// Comment indexes
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"post_id", 1}},
			Options:    options.Index().SetName(constants.IndexCommentPost),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"post_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("comment_post_created"),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"author_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("comment_author_created"),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"parent_id", 1}, {"created_at", 1}},
			Options:    options.Index().SetName("comment_parent_created"),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"mentions", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("comment_mentions_created"),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"likes_count", -1}, {"created_at", -1}},
			Options:    options.Index().SetName("comment_likes_created"),
		},

		// Like indexes
		{
			Collection: constants.CollectionLikes,
			Keys:       bson.D{{"target_id", 1}, {"user_id", 1}},
			Options:    options.Index().SetUnique(true).SetName(constants.IndexLikeTarget),
		},
		{
			Collection: constants.CollectionLikes,
			Keys:       bson.D{{"user_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("like_user_created"),
		},
		{
			Collection: constants.CollectionLikes,
			Keys:       bson.D{{"target_id", 1}, {"target_type", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("like_target_type_created"),
		},

		// Follow indexes
		{
			Collection: constants.CollectionFollows,
			Keys:       bson.D{{"follower_id", 1}, {"followee_id", 1}},
			Options:    options.Index().SetUnique(true).SetName(constants.IndexFollowUsers),
		},
		{
			Collection: constants.CollectionFollows,
			Keys:       bson.D{{"follower_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("follow_follower_created"),
		},
		{
			Collection: constants.CollectionFollows,
			Keys:       bson.D{{"followee_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("follow_followee_created"),
		},
		{
			Collection: constants.CollectionFollows,
			Keys:       bson.D{{"status", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("follow_status_created"),
		},

		// Message indexes
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"conversation_id", 1}},
			Options:    options.Index().SetName(constants.IndexMessageConv),
		},
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"conversation_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("message_conversation_created"),
		},
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"sender_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("message_sender_created"),
		},
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"recipient_id", 1}, {"status", 1}},
			Options:    options.Index().SetName("message_recipient_status"),
		},
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"conversation_id", 1}, {"message_type", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("message_conversation_type_created"),
		},

		// Conversation indexes
		{
			Collection: constants.CollectionConversations,
			Keys:       bson.D{{"participants", 1}},
			Options:    options.Index().SetName("conversation_participants"),
		},
		{
			Collection: constants.CollectionConversations,
			Keys:       bson.D{{"last_message_at", -1}},
			Options:    options.Index().SetName("conversation_last_message"),
		},
		{
			Collection: constants.CollectionConversations,
			Keys:       bson.D{{"created_by", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("conversation_creator_created"),
		},
		{
			Collection: constants.CollectionConversations,
			Keys:       bson.D{{"type", 1}, {"updated_at", -1}},
			Options:    options.Index().SetName("conversation_type_updated"),
		},

		// Notification indexes
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"user_id", 1}},
			Options:    options.Index().SetName(constants.IndexNotifUser),
		},
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"user_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("notification_user_created"),
		},
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"user_id", 1}, {"is_read", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("notification_user_read_created"),
		},
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"type", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("notification_type_created"),
		},
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"entity_id", 1}, {"entity_type", 1}},
			Options:    options.Index().SetName("notification_entity"),
		},
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"scheduled_for", 1}},
			Options:    options.Index().SetName("notification_scheduled_for"),
		},

		// Report indexes
		{
			Collection: constants.CollectionReports,
			Keys:       bson.D{{"target_id", 1}},
			Options:    options.Index().SetName(constants.IndexReportTarget),
		},
		{
			Collection: constants.CollectionReports,
			Keys:       bson.D{{"reporter_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("report_reporter_created"),
		},
		{
			Collection: constants.CollectionReports,
			Keys:       bson.D{{"status", 1}, {"priority", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("report_status_priority_created"),
		},
		{
			Collection: constants.CollectionReports,
			Keys:       bson.D{{"category", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("report_category_created"),
		},
		{
			Collection: constants.CollectionReports,
			Keys:       bson.D{{"assigned_to", 1}, {"status", 1}},
			Options:    options.Index().SetName("report_assigned_status"),
		},

		// Analytics indexes
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"entity_id", 1}, {"date", 1}},
			Options:    options.Index().SetName(constants.IndexAnalyticsEntity),
		},
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"entity_type", 1}, {"event_type", 1}, {"date", 1}},
			Options:    options.Index().SetName("analytics_entity_event_date"),
		},
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"user_id", 1}, {"timestamp", -1}},
			Options:    options.Index().SetName("analytics_user_timestamp"),
		},
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"date", 1}, {"hour", 1}},
			Options:    options.Index().SetName("analytics_date_hour"),
		},
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"session_id", 1}, {"timestamp", 1}},
			Options:    options.Index().SetName("analytics_session_timestamp"),
		},

		// Audit log indexes
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"user_id", 1}, {"action", 1}},
			Options:    options.Index().SetName(constants.IndexAuditUser),
		},
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"created_at", -1}},
			Options:    options.Index().SetName("audit_created_desc"),
		},
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"resource", 1}, {"resource_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("audit_resource_created"),
		},
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"ip_address", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("audit_ip_created"),
		},
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"severity", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("audit_severity_created"),
		},

		// Session indexes
		{
			Collection: constants.CollectionSessions,
			Keys:       bson.D{{"user_id", 1}},
			Options:    options.Index().SetName("session_user"),
		},
		{
			Collection: constants.CollectionSessions,
			Keys:       bson.D{{"expires_at", 1}},
			Options:    options.Index().SetExpireAfterSeconds(0).SetName("session_expires"),
		},
		{
			Collection: constants.CollectionSessions,
			Keys:       bson.D{{"session_id", 1}},
			Options:    options.Index().SetUnique(true).SetName("session_id_unique"),
		},
		{
			Collection: constants.CollectionSessions,
			Keys:       bson.D{{"device_id", 1}, {"user_id", 1}},
			Options:    options.Index().SetName("session_device_user"),
		},

		// File indexes
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"user_id", 1}},
			Options:    options.Index().SetName(constants.IndexFileUser),
		},
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"user_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("file_user_created"),
		},
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"folder_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("file_folder_created"),
		},
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"mime_type", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("file_mime_created"),
		},
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"tags", 1}},
			Options:    options.Index().SetName("file_tags"),
		},
		{
			Collection: constants.CollectionFiles,
			Keys:       bson.D{{"checksum", 1}},
			Options:    options.Index().SetName("file_checksum"),
		},

		// Folder indexes
		{
			Collection: constants.CollectionFolders,
			Keys:       bson.D{{"user_id", 1}, {"name", 1}},
			Options:    options.Index().SetName("folder_user_name"),
		},
		{
			Collection: constants.CollectionFolders,
			Keys:       bson.D{{"parent_id", 1}},
			Options:    options.Index().SetName("folder_parent"),
		},
		{
			Collection: constants.CollectionFolders,
			Keys:       bson.D{{"path", 1}},
			Options:    options.Index().SetName("folder_path"),
		},

		// Album indexes
		{
			Collection: constants.CollectionAlbums,
			Keys:       bson.D{{"user_id", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("album_user_created"),
		},
		{
			Collection: constants.CollectionAlbums,
			Keys:       bson.D{{"files", 1}},
			Options:    options.Index().SetName("album_files"),
		},
		{
			Collection: constants.CollectionAlbums,
			Keys:       bson.D{{"tags", 1}},
			Options:    options.Index().SetName("album_tags"),
		},

		// Hashtag indexes
		{
			Collection: constants.CollectionHashtags,
			Keys:       bson.D{{"name", 1}},
			Options:    options.Index().SetUnique(true).SetName(constants.IndexHashtagName),
		},
		{
			Collection: constants.CollectionHashtags,
			Keys:       bson.D{{"usage_count", -1}},
			Options:    options.Index().SetName("hashtag_usage_count"),
		},
		{
			Collection: constants.CollectionHashtags,
			Keys:       bson.D{{"trending_score", -1}, {"updated_at", -1}},
			Options:    options.Index().SetName("hashtag_trending_score"),
		},
		{
			Collection: constants.CollectionHashtags,
			Keys:       bson.D{{"category", 1}, {"usage_count", -1}},
			Options:    options.Index().SetName("hashtag_category_usage"),
		},

		// Location indexes
		{
			Collection: constants.CollectionLocations,
			Keys:       bson.D{{"coordinates", "2dsphere"}},
			Options:    options.Index().SetName("location_coordinates_geo"),
		},
		{
			Collection: constants.CollectionLocations,
			Keys:       bson.D{{"name", "text"}, {"address", "text"}, {"city", "text"}},
			Options:    options.Index().SetName("location_text_search"),
		},
		{
			Collection: constants.CollectionLocations,
			Keys:       bson.D{{"place_id", 1}},
			Options:    options.Index().SetUnique(true).SetName("location_place_id"),
		},

		// Topic indexes
		{
			Collection: constants.CollectionTopics,
			Keys:       bson.D{{"name", 1}},
			Options:    options.Index().SetUnique(true).SetName("topic_name_unique"),
		},
		{
			Collection: constants.CollectionTopics,
			Keys:       bson.D{{"category", 1}, {"popularity_score", -1}},
			Options:    options.Index().SetName("topic_category_popularity"),
		},
		{
			Collection: constants.CollectionTopics,
			Keys:       bson.D{{"followers_count", -1}},
			Options:    options.Index().SetName("topic_followers_count"),
		},

		// Additional compound indexes for complex queries
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"author_id", 1}, {"status", 1}, {"visibility", 1}, {"created_at", -1}},
			Options:    options.Index().SetName("post_author_status_visibility_created"),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{Key: "username", Value: "text"}, {Key: "first_name", Value: "text"}, {"last_name", "text"}, {"display_name", "text"}},
			Options:    options.Index().SetName("user_text_search"),
		},
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"content", "text"}, {"hashtags", "text"}},
			Options:    options.Index().SetName("post_text_search"),
		},
		{
			Collection: constants.CollectionComments,
			Keys:       bson.D{{"content", "text"}},
			Options:    options.Index().SetName("comment_text_search"),
		},

		// Performance optimization indexes
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"user_id", 1}, {"type", 1}, {"is_read", 1}},
			Options:    options.Index().SetName("notification_user_type_read"),
		},
		{
			Collection: constants.CollectionMessages,
			Keys:       bson.D{{"participants", 1}, {"last_message_at", -1}},
			Options:    options.Index().SetName("message_participants_last"),
		},
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"entity_type", 1}, {"date", 1}, {"hour", 1}},
			Options:    options.Index().SetName("analytics_entity_date_hour"),
		},

		// TTL indexes for cleanup
		{
			Collection: constants.CollectionAnalytics,
			Keys:       bson.D{{"created_at", 1}},
			Options:    options.Index().SetExpireAfterSeconds(365 * 24 * 3600).SetName("analytics_ttl"), // 1 year
		},
		{
			Collection: constants.CollectionAuditLogs,
			Keys:       bson.D{{"created_at", 1}},
			Options:    options.Index().SetExpireAfterSeconds(2 * 365 * 24 * 3600).SetName("audit_ttl"), // 2 years
		},
	}
}

// DropAllIndexes drops all custom indexes (useful for development/testing)
func DropAllIndexes(ctx context.Context) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	collections := []string{
		constants.CollectionUsers,
		constants.CollectionPosts,
		constants.CollectionComments,
		constants.CollectionLikes,
		constants.CollectionFollows,
		constants.CollectionMessages,
		constants.CollectionConversations,
		constants.CollectionNotifications,
		constants.CollectionReports,
		constants.CollectionAnalytics,
		constants.CollectionAuditLogs,
		constants.CollectionSessions,
		constants.CollectionFiles,
		constants.CollectionFolders,
		constants.CollectionAlbums,
		constants.CollectionHashtags,
		constants.CollectionLocations,
		constants.CollectionTopics,
	}

	for _, collectionName := range collections {
		collection := db.Collection(collectionName)
		if _, err := collection.Indexes().DropAll(ctx); err != nil {
			if db.Logger != nil {
				db.Logger.Error("Failed to drop indexes", "collection", collectionName, "error", err)
			}
			return fmt.Errorf("failed to drop indexes for %s: %w", collectionName, err)
		}
	}

	return nil
}

// ListIndexes lists all indexes for a specific collection
func ListIndexes(ctx context.Context, collectionName string) ([]bson.M, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	collection := db.Collection(collectionName)
	cursor, err := collection.Indexes().List(ctx)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var indexes []bson.M
	if err := cursor.All(ctx, &indexes); err != nil {
		return nil, err
	}

	return indexes, nil
}

// CheckIndexes verifies that all required indexes exist
func CheckIndexes(ctx context.Context) (map[string]bool, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	indexDefs := getAllIndexDefinitions()
	results := make(map[string]bool)

	for _, indexDef := range indexDefs {
		collection := db.Collection(indexDef.Collection)
		indexes, err := collection.Indexes().List(ctx)
		if err != nil {
			return nil, err
		}

		indexName := indexDef.Options.Name
		if indexName == nil {
			continue
		}

		found := false
		for indexes.Next(ctx) {
			var index bson.M
			if err := indexes.Decode(&index); err != nil {
				continue
			}
			if name, ok := index["name"].(string); ok && name == *indexName {
				found = true
				break
			}
		}

		results[fmt.Sprintf("%s.%s", indexDef.Collection, *indexName)] = found
	}

	return results, nil
}

// CreateIndexIfNotExists creates an index only if it doesn't already exist
func CreateIndexIfNotExists(ctx context.Context, collectionName string, indexDef IndexDefinition) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	collection := db.Collection(collectionName)

	// Check if index already exists
	if indexDef.Options.Name != nil {
		indexes, err := collection.Indexes().List(ctx)
		if err != nil {
			return err
		}

		for indexes.Next(ctx) {
			var index bson.M
			if err := indexes.Decode(&index); err != nil {
				continue
			}
			if name, ok := index["name"].(string); ok && name == *indexDef.Options.Name {
				// Index already exists
				return nil
			}
		}
	}

	// Create the index
	return createIndex(ctx, db, indexDef)
}

// GetIndexUsageStats returns index usage statistics
func GetIndexUsageStats(ctx context.Context, collectionName string) ([]bson.M, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	collection := db.Collection(collectionName)

	// Run $indexStats aggregation
	pipeline := []bson.M{
		{"$indexStats": bson.M{}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var stats []bson.M
	if err := cursor.All(ctx, &stats); err != nil {
		return nil, err
	}

	return stats, nil
}

// CreatePartialIndexes creates partial indexes for soft-deleted documents
func CreatePartialIndexes(ctx context.Context) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	partialIndexes := []IndexDefinition{
		// Active users only
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"email", 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("user_email_active").
				SetPartialFilterExpression(bson.D{{"deleted_at", bson.D{{"$exists", false}}}}),
		},
		{
			Collection: constants.CollectionUsers,
			Keys:       bson.D{{"username", 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("user_username_active").
				SetPartialFilterExpression(bson.D{{"deleted_at", bson.D{{"$exists", false}}}}),
		},
		// Active posts only
		{
			Collection: constants.CollectionPosts,
			Keys:       bson.D{{"created_at", -1}},
			Options: options.Index().
				SetName("post_created_active").
				SetPartialFilterExpression(bson.D{{"deleted_at", bson.D{{"$exists", false}}}}),
		},
		// Unread notifications only
		{
			Collection: constants.CollectionNotifications,
			Keys:       bson.D{{"user_id", 1}, {"created_at", -1}},
			Options: options.Index().
				SetName("notification_user_unread").
				SetPartialFilterExpression(bson.D{{"is_read", false}}),
		},
	}

	for _, indexDef := range partialIndexes {
		if err := createIndex(ctx, db, indexDef); err != nil {
			return fmt.Errorf("failed to create partial index on %s: %w", indexDef.Collection, err)
		}
	}

	return nil
}
