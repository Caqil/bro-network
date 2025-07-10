package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"bro-network/internal/config"
	"bro-network/pkg/constants"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

// Database represents the database connection manager
type Database struct {
	Client      *mongo.Client
	DB          *mongo.Database
	Config      *config.DatabaseConfig
	Logger      Logger
	Stats       *ConnectionStats
	mu          sync.RWMutex
	isConnected bool
}

// Logger interface for database logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
}

// ConnectionStats tracks database connection statistics
type ConnectionStats struct {
	TotalConnections    int64         `json:"total_connections"`
	ActiveConnections   int64         `json:"active_connections"`
	IdleConnections     int64         `json:"idle_connections"`
	QueriesExecuted     int64         `json:"queries_executed"`
	SlowQueries         int64         `json:"slow_queries"`
	FailedConnections   int64         `json:"failed_connections"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	LastConnectedAt     time.Time     `json:"last_connected_at"`
	LastError           string        `json:"last_error,omitempty"`
	mu                  sync.RWMutex
}

// DatabaseManager manages multiple database connections
type DatabaseManager struct {
	Primary   *Database
	ReadOnly  *Database
	Analytics *Database
	Cache     *Database
	mu        sync.RWMutex
}

var (
	dbManager *DatabaseManager
	once      sync.Once
)

// Initialize initializes the database connections
func Initialize(cfg *config.Config) error {
	var err error
	once.Do(func() {
		dbManager, err = initializeDatabases(cfg)
	})
	return err
}

// GetDB returns the primary database instance
func GetDB() *Database {
	if dbManager == nil {
		panic("Database not initialized. Call Initialize() first.")
	}
	return dbManager.Primary
}

// GetReadOnlyDB returns the read-only database instance
func GetReadOnlyDB() *Database {
	if dbManager == nil || dbManager.ReadOnly == nil {
		return GetDB() // Fallback to primary
	}
	return dbManager.ReadOnly
}

// GetAnalyticsDB returns the analytics database instance
func GetAnalyticsDB() *Database {
	if dbManager == nil || dbManager.Analytics == nil {
		return GetDB() // Fallback to primary
	}
	return dbManager.Analytics
}

// GetManager returns the database manager instance
func GetManager() *DatabaseManager {
	return dbManager
}

// initializeDatabases initializes all database connections
func initializeDatabases(cfg *config.Config) (*DatabaseManager, error) {
	manager := &DatabaseManager{}

	// Initialize primary database
	primary, err := NewDatabase(cfg.Database, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize primary database: %w", err)
	}
	manager.Primary = primary

	// Initialize read-only database (if configured)
	if cfg.Database.ReadOnly {
		readOnly, err := NewDatabase(cfg.Database, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize read-only database: %w", err)
		}
		manager.ReadOnly = readOnly
	}

	// Initialize analytics database (if configured separately)
	if cfg.App.Features.EnableAnalytics {
		analytics, err := NewDatabase(cfg.Database, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize analytics database: %w", err)
		}
		manager.Analytics = analytics
	}

	return manager, nil
}

// NewDatabase creates a new database connection
func NewDatabase(cfg *config.DatabaseConfig, logger Logger) (*Database, error) {
	db := &Database{
		Config: cfg,
		Logger: logger,
		Stats:  &ConnectionStats{},
	}

	if err := db.Connect(); err != nil {
		return nil, err
	}

	return db, nil
}

// Connect establishes a connection to MongoDB
func (db *Database) Connect() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.isConnected {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), db.Config.ConnectTimeout)
	defer cancel()

	// Create client options
	opts := db.buildClientOptions()

	// Create MongoDB client
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		db.Stats.incrementFailedConnections()
		if db.Logger != nil {
			db.Logger.Error("Failed to connect to MongoDB", "error", err)
		}
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Test the connection
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		db.Stats.incrementFailedConnections()
		if db.Logger != nil {
			db.Logger.Error("Failed to ping MongoDB", "error", err)
		}
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	db.Client = client
	db.DB = client.Database(db.Config.Name)
	db.isConnected = true
	db.Stats.LastConnectedAt = time.Now()

	if db.Logger != nil {
		db.Logger.Info("Successfully connected to MongoDB",
			"database", db.Config.Name,
			"host", db.Config.Host,
			"port", db.Config.Port,
		)
	}

	return nil
}

// buildClientOptions builds MongoDB client options
func (db *Database) buildClientOptions() *options.ClientOptions {
	opts := options.Client()

	// Set URI
	uri := db.Config.GetMongoURI()
	opts.ApplyURI(uri)

	// Connection pool settings
	opts.SetMaxPoolSize(uint64(db.Config.MaxPoolSize))
	opts.SetMinPoolSize(uint64(db.Config.MinPoolSize))
	opts.SetMaxConnIdleTime(db.Config.MaxConnIdleTime)
	opts.SetConnectTimeout(db.Config.ConnectTimeout)
	opts.SetSocketTimeout(db.Config.SocketTimeout)
	opts.SetServerSelectionTimeout(db.Config.ServerSelectionTimeout)

	// Read preferences
	readPref := db.getReadPreference()
	opts.SetReadPreference(readPref)

	// Read concern
	if db.Config.ReadConcern != "" {
		readConcern := db.getReadConcern()
		opts.SetReadConcern(readConcern)
	}

	// Write concern
	if db.Config.WriteConcern != "" {
		writeConcern := db.getWriteConcern()
		opts.SetWriteConcern(writeConcern)
	}

	// Retry settings
	opts.SetRetryWrites(db.Config.RetryWrites)
	opts.SetRetryReads(db.Config.RetryReads)

	// Compression
	if len(db.Config.Compressors) > 0 {
		opts.SetCompressors(db.Config.Compressors)
	}

	// App name
	if db.Config.AppName != "" {
		opts.SetAppName(db.Config.AppName)
	}

	// Direct connection
	opts.SetDirect(db.Config.DirectConnection)

	// Local threshold
	opts.SetLocalThreshold(db.Config.LocalThreshold)

	// Command monitoring (for logging and stats)
	if db.Config.EnableMonitoring || db.Config.EnableSlowQueries {
		opts.SetMonitor(db.createCommandMonitor())
	}

	return opts
}

// getReadPreference returns read preference based on configuration
func (db *Database) getReadPreference() *readpref.ReadPref {
	switch db.Config.ReadPreference {
	case "primary":
		return readpref.Primary()
	case "primaryPreferred":
		return readpref.PrimaryPreferred()
	case "secondary":
		return readpref.Secondary()
	case "secondaryPreferred":
		return readpref.SecondaryPreferred()
	case "nearest":
		return readpref.Nearest()
	default:
		return readpref.Primary()
	}
}

// getReadConcern returns read concern based on configuration
func (db *Database) getReadConcern() *readconcern.ReadConcern {
	switch db.Config.ReadConcern {
	case "local":
		return readconcern.Local()
	case "available":
		return readconcern.Available()
	case "majority":
		return readconcern.Majority()
	case "linearizable":
		return readconcern.Linearizable()
	case "snapshot":
		return readconcern.Snapshot()
	default:
		return readconcern.Majority()
	}
}

// getWriteConcern returns write concern based on configuration
func (db *Database) getWriteConcern() *writeconcern.WriteConcern {
	switch db.Config.WriteConcern {
	case "majority":
		return writeconcern.New(writeconcern.WMajority())
	case "acknowledged":
		return writeconcern.New(writeconcern.W(1))
	case "unacknowledged":
		return writeconcern.New(writeconcern.W(0))
	default:
		return writeconcern.New(writeconcern.WMajority())
	}
}

// createCommandMonitor creates a command monitor for logging and statistics
func (db *Database) createCommandMonitor() *event.CommandMonitor {
	return &event.CommandMonitor{
		Started: func(ctx context.Context, evt *event.CommandStartedEvent) {
			db.Stats.incrementQueriesExecuted()
			if db.Logger != nil && db.Config.LogLevel == "debug" {
				db.Logger.Debug("MongoDB command started",
					"command", evt.CommandName,
					"database", evt.DatabaseName,
					"collection", getCollectionFromCommand(evt.Command),
				)
			}
		},
		Succeeded: func(ctx context.Context, evt *event.CommandSucceededEvent) {
			duration := time.Duration(evt.DurationNanos)
			db.Stats.updateResponseTime(duration)

			if db.Config.EnableSlowQueries && duration > db.Config.SlowQueryThreshold {
				db.Stats.incrementSlowQueries()
				if db.Logger != nil {
					db.Logger.Warn("Slow query detected",
						"command", evt.CommandName,
						"duration", duration,
						"threshold", db.Config.SlowQueryThreshold,
					)
				}
			}
		},
		Failed: func(ctx context.Context, evt *event.CommandFailedEvent) {
			if db.Logger != nil {
				db.Logger.Error("MongoDB command failed",
					"command", evt.CommandName,
					"error", evt.Failure,
					"duration", time.Duration(evt.DurationNanos),
				)
			}
		},
	}
}

// getCollectionFromCommand extracts collection name from BSON command
func getCollectionFromCommand(command bson.Raw) string {
	// Try to extract collection name from common command fields
	if val, err := command.LookupErr("find"); err == nil {
		if str, ok := val.StringValueOK(); ok {
			return str
		}
	}
	if val, err := command.LookupErr("insert"); err == nil {
		if str, ok := val.StringValueOK(); ok {
			return str
		}
	}
	if val, err := command.LookupErr("update"); err == nil {
		if str, ok := val.StringValueOK(); ok {
			return str
		}
	}
	if val, err := command.LookupErr("delete"); err == nil {
		if str, ok := val.StringValueOK(); ok {
			return str
		}
	}
	if val, err := command.LookupErr("aggregate"); err == nil {
		if str, ok := val.StringValueOK(); ok {
			return str
		}
	}
	return "unknown"
}

// Disconnect closes the database connection
func (db *Database) Disconnect() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.isConnected || db.Client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.Client.Disconnect(ctx); err != nil {
		if db.Logger != nil {
			db.Logger.Error("Failed to disconnect from MongoDB", "error", err)
		}
		return err
	}

	db.isConnected = false
	if db.Logger != nil {
		db.Logger.Info("Disconnected from MongoDB")
	}

	return nil
}

// IsConnected returns whether the database is connected
func (db *Database) IsConnected() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.isConnected
}

// Ping pings the database to check connectivity
func (db *Database) Ping(ctx context.Context) error {
	if !db.isConnected {
		return fmt.Errorf("database not connected")
	}

	return db.Client.Ping(ctx, readpref.Primary())
}

// Collection returns a collection by name
func (db *Database) Collection(name string) *mongo.Collection {
	return db.DB.Collection(name)
}

// RunTransaction runs a function within a transaction
func (db *Database) RunTransaction(ctx context.Context, fn func(sessCtx mongo.SessionContext) (interface{}, error)) (interface{}, error) {
	session, err := db.Client.StartSession()
	if err != nil {
		return nil, err
	}
	defer session.EndSession(ctx)

	result, err := session.WithTransaction(ctx, fn)
	return result, err
}

// GetStats returns connection statistics
func (db *Database) GetStats() *ConnectionStats {
	db.Stats.mu.RLock()
	defer db.Stats.mu.RUnlock()

	// Create a copy to avoid race conditions
	stats := *db.Stats
	return &stats
}

// Health returns database health information
func (db *Database) Health(ctx context.Context) map[string]interface{} {
	health := map[string]interface{}{
		"connected": db.isConnected,
		"stats":     db.GetStats(),
	}

	if db.isConnected {
		// Get server status
		var result bson.M
		err := db.DB.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&result)
		if err == nil {
			health["server_status"] = map[string]interface{}{
				"uptime":      result["uptime"],
				"connections": result["connections"],
				"memory":      result["mem"],
				"version":     result["version"],
			}
		}

		// Test ping
		if pingErr := db.Ping(ctx); pingErr != nil {
			health["ping_error"] = pingErr.Error()
		} else {
			health["ping"] = "ok"
		}
	}

	return health
}

// ConnectionStats methods

func (cs *ConnectionStats) incrementQueriesExecuted() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.QueriesExecuted++
}

func (cs *ConnectionStats) incrementSlowQueries() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.SlowQueries++
}

func (cs *ConnectionStats) incrementFailedConnections() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.FailedConnections++
}

func (cs *ConnectionStats) updateResponseTime(duration time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Simple moving average calculation
	if cs.AverageResponseTime == 0 {
		cs.AverageResponseTime = duration
	} else {
		cs.AverageResponseTime = (cs.AverageResponseTime + duration) / 2
	}
}

// Cleanup closes all database connections
func Cleanup() error {
	if dbManager == nil {
		return nil
	}

	var errors []error

	if dbManager.Primary != nil {
		if err := dbManager.Primary.Disconnect(); err != nil {
			errors = append(errors, fmt.Errorf("primary database: %w", err))
		}
	}

	if dbManager.ReadOnly != nil {
		if err := dbManager.ReadOnly.Disconnect(); err != nil {
			errors = append(errors, fmt.Errorf("read-only database: %w", err))
		}
	}

	if dbManager.Analytics != nil {
		if err := dbManager.Analytics.Disconnect(); err != nil {
			errors = append(errors, fmt.Errorf("analytics database: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("database cleanup errors: %v", errors)
	}

	return nil
}

// GetCollections returns all collection names for the specified collections
func GetCollections() map[string]*mongo.Collection {
	db := GetDB()
	return map[string]*mongo.Collection{
		constants.CollectionUsers:         db.Collection(constants.CollectionUsers),
		constants.CollectionPosts:         db.Collection(constants.CollectionPosts),
		constants.CollectionComments:      db.Collection(constants.CollectionComments),
		constants.CollectionLikes:         db.Collection(constants.CollectionLikes),
		constants.CollectionFollows:       db.Collection(constants.CollectionFollows),
		constants.CollectionMessages:      db.Collection(constants.CollectionMessages),
		constants.CollectionConversations: db.Collection(constants.CollectionConversations),
		constants.CollectionNotifications: db.Collection(constants.CollectionNotifications),
		constants.CollectionReports:       db.Collection(constants.CollectionReports),
		constants.CollectionAnalytics:     db.Collection(constants.CollectionAnalytics),
		constants.CollectionAuditLogs:     db.Collection(constants.CollectionAuditLogs),
		constants.CollectionSessions:      db.Collection(constants.CollectionSessions),
		constants.CollectionFiles:         db.Collection(constants.CollectionFiles),
		constants.CollectionFolders:       db.Collection(constants.CollectionFolders),
		constants.CollectionAlbums:        db.Collection(constants.CollectionAlbums),
		constants.CollectionHashtags:      db.Collection(constants.CollectionHashtags),
		constants.CollectionLocations:     db.Collection(constants.CollectionLocations),
		constants.CollectionTopics:        db.Collection(constants.CollectionTopics),
	}
}

// GetCollection returns a specific collection
func GetCollection(name string) *mongo.Collection {
	return GetDB().Collection(name)
}
