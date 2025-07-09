package routes

import (
	"bro-network/internal/handlers"

	"github.com/gin-gonic/gin"
)

// SetupHealthRoutes sets up health check and monitoring routes
func SetupHealthRoutes(router *gin.Engine, healthHandler *handlers.HealthHandler) {
	// =============================================================================
	// BASIC HEALTH CHECKS (No authentication required)
	// =============================================================================

	// Simple health check
	router.GET("/health", healthHandler.HealthCheck)
	router.HEAD("/health", healthHandler.HealthCheck)

	// Readiness check
	router.GET("/ready", healthHandler.ReadinessCheck)
	router.HEAD("/ready", healthHandler.ReadinessCheck)

	// Liveness check
	router.GET("/live", healthHandler.LivenessCheck)
	router.HEAD("/live", healthHandler.LivenessCheck)

	// Application status
	router.GET("/status", healthHandler.GetStatus)

	// =============================================================================
	// DETAILED HEALTH INFORMATION
	// =============================================================================

	health := router.Group("/health")
	{
		// Comprehensive health check
		health.GET("/detailed", healthHandler.DetailedHealthCheck)

		// Individual service health checks
		health.GET("/database", healthHandler.DatabaseHealth)
		health.GET("/redis", healthHandler.RedisHealth)
		health.GET("/storage", healthHandler.StorageHealth)
		health.GET("/email", healthHandler.EmailServiceHealth)
		health.GET("/external-apis", healthHandler.ExternalAPIHealth)

		// Infrastructure health
		health.GET("/infrastructure", healthHandler.InfrastructureHealth)
		health.GET("/dependencies", healthHandler.DependenciesHealth)

		// Performance metrics
		health.GET("/metrics", healthHandler.GetMetrics)
		health.GET("/performance", healthHandler.GetPerformanceMetrics)

		// System information
		health.GET("/system", healthHandler.GetSystemInfo)
		health.GET("/version", healthHandler.GetVersionInfo)
		health.GET("/config", healthHandler.GetConfigInfo)
	}

	// =============================================================================
	// MONITORING AND OBSERVABILITY
	// =============================================================================

	monitoring := router.Group("/monitoring")
	{
		// Application metrics (Prometheus format)
		monitoring.GET("/metrics", healthHandler.PrometheusMetrics)

		// Custom metrics
		monitoring.GET("/custom-metrics", healthHandler.CustomMetrics)
		monitoring.GET("/business-metrics", healthHandler.BusinessMetrics)

		// Real-time stats
		monitoring.GET("/realtime", healthHandler.RealtimeStats)
		monitoring.GET("/stats", healthHandler.GetStats)

		// Performance monitoring
		monitoring.GET("/performance/cpu", healthHandler.CPUMetrics)
		monitoring.GET("/performance/memory", healthHandler.MemoryMetrics)
		monitoring.GET("/performance/disk", healthHandler.DiskMetrics)
		monitoring.GET("/performance/network", healthHandler.NetworkMetrics)

		// Application performance
		monitoring.GET("/performance/requests", healthHandler.RequestMetrics)
		monitoring.GET("/performance/database", healthHandler.DatabaseMetrics)
		monitoring.GET("/performance/cache", healthHandler.CacheMetrics)

		// Error tracking
		monitoring.GET("/errors", healthHandler.ErrorMetrics)
		monitoring.GET("/errors/rate", healthHandler.ErrorRate)
		monitoring.GET("/errors/recent", healthHandler.RecentErrors)

		// Uptime and availability
		monitoring.GET("/uptime", healthHandler.UptimeMetrics)
		monitoring.GET("/availability", healthHandler.AvailabilityMetrics)

		// Load and capacity
		monitoring.GET("/load", healthHandler.LoadMetrics)
		monitoring.GET("/capacity", healthHandler.CapacityMetrics)
		monitoring.GET("/throughput", healthHandler.ThroughputMetrics)
	}

	// =============================================================================
	// DIAGNOSTICS (Admin access required)
	// =============================================================================

	diagnostics := router.Group("/diagnostics")
	// Note: These should have admin authentication in production
	{
		// System diagnostics
		diagnostics.GET("/system", healthHandler.SystemDiagnostics)
		diagnostics.GET("/threads", healthHandler.ThreadDump)
		diagnostics.GET("/goroutines", healthHandler.GoroutineDump)
		diagnostics.GET("/memory", healthHandler.MemoryDump)

		// Application diagnostics
		diagnostics.GET("/runtime", healthHandler.RuntimeDiagnostics)
		diagnostics.GET("/gc", healthHandler.GCStats)
		diagnostics.GET("/heap", healthHandler.HeapProfile)
		diagnostics.GET("/profile", healthHandler.CPUProfile)

		// Database diagnostics
		diagnostics.GET("/database/connections", healthHandler.DatabaseConnections)
		diagnostics.GET("/database/queries", healthHandler.SlowQueries)
		diagnostics.GET("/database/locks", healthHandler.DatabaseLocks)

		// Cache diagnostics
		diagnostics.GET("/cache/stats", healthHandler.CacheStats)
		diagnostics.GET("/cache/keys", healthHandler.CacheKeys)
		diagnostics.GET("/cache/memory", healthHandler.CacheMemoryUsage)

		// Configuration diagnostics
		diagnostics.GET("/config/all", healthHandler.AllConfigurations)
		diagnostics.GET("/config/env", healthHandler.EnvironmentVariables)
		diagnostics.GET("/config/flags", healthHandler.FeatureFlags)

		// Network diagnostics
		diagnostics.GET("/network/connections", healthHandler.NetworkConnections)
		diagnostics.GET("/network/sockets", healthHandler.OpenSockets)

		// Trace and debug
		diagnostics.GET("/trace", healthHandler.ExecutionTrace)
		diagnostics.POST("/trace/start", healthHandler.StartTrace)
		diagnostics.POST("/trace/stop", healthHandler.StopTrace)

		// Emergency controls
		diagnostics.POST("/gc/force", healthHandler.ForceGC)
		diagnostics.POST("/cache/clear", healthHandler.ClearAllCaches)
		diagnostics.POST("/connections/close", healthHandler.CloseIdleConnections)
	}

	// =============================================================================
	// SERVICE DISCOVERY AND REGISTRY
	// =============================================================================

	discovery := router.Group("/discovery")
	{
		// Service registration
		discovery.POST("/register", healthHandler.RegisterService)
		discovery.DELETE("/deregister", healthHandler.DeregisterService)

		// Service discovery
		discovery.GET("/services", healthHandler.DiscoverServices)
		discovery.GET("/services/:service_name", healthHandler.GetServiceInstances)

		// Health check callbacks
		discovery.POST("/health-check", healthHandler.HealthCheckCallback)
		discovery.GET("/service-health/:service_id", healthHandler.GetServiceHealth)

		// Load balancing info
		discovery.GET("/load-balancer", healthHandler.LoadBalancerInfo)
		discovery.GET("/routing", healthHandler.RoutingInfo)
	}

	// =============================================================================
	// ALERTS AND NOTIFICATIONS
	// =============================================================================

	alerts := router.Group("/alerts")
	{
		// Health alerts
		alerts.GET("/health", healthHandler.GetHealthAlerts)
		alerts.POST("/health", healthHandler.CreateHealthAlert)
		alerts.PUT("/health/:alert_id", healthHandler.UpdateHealthAlert)
		alerts.DELETE("/health/:alert_id", healthHandler.DeleteHealthAlert)

		// Performance alerts
		alerts.GET("/performance", healthHandler.GetPerformanceAlerts)
		alerts.POST("/performance/cpu", healthHandler.CreateCPUAlert)
		alerts.POST("/performance/memory", healthHandler.CreateMemoryAlert)
		alerts.POST("/performance/disk", healthHandler.CreateDiskAlert)

		// Error rate alerts
		alerts.GET("/errors", healthHandler.GetErrorAlerts)
		alerts.POST("/errors/rate", healthHandler.CreateErrorRateAlert)
		alerts.POST("/errors/threshold", healthHandler.CreateErrorThresholdAlert)

		// Custom alerts
		alerts.GET("/custom", healthHandler.GetCustomAlerts)
		alerts.POST("/custom", healthHandler.CreateCustomAlert)

		// Alert history
		alerts.GET("/history", healthHandler.GetAlertHistory)
		alerts.GET("/history/:alert_id", healthHandler.GetAlertDetails)

		// Alert configuration
		alerts.GET("/config", healthHandler.GetAlertConfig)
		alerts.PUT("/config", healthHandler.UpdateAlertConfig)

		// Webhook configuration for alerts
		alerts.GET("/webhooks", healthHandler.GetAlertWebhooks)
		alerts.POST("/webhooks", healthHandler.CreateAlertWebhook)
		alerts.PUT("/webhooks/:webhook_id", healthHandler.UpdateAlertWebhook)
		alerts.DELETE("/webhooks/:webhook_id", healthHandler.DeleteAlertWebhook)
	}

	// =============================================================================
	// CIRCUIT BREAKER STATUS
	// =============================================================================

	circuitbreaker := router.Group("/circuit-breaker")
	{
		// Circuit breaker status
		circuitbreaker.GET("/status", healthHandler.CircuitBreakerStatus)
		circuitbreaker.GET("/status/:service", healthHandler.ServiceCircuitBreakerStatus)

		// Circuit breaker controls
		circuitbreaker.POST("/reset/:service", healthHandler.ResetCircuitBreaker)
		circuitbreaker.POST("/open/:service", healthHandler.OpenCircuitBreaker)
		circuitbreaker.POST("/close/:service", healthHandler.CloseCircuitBreaker)

		// Circuit breaker configuration
		circuitbreaker.GET("/config", healthHandler.GetCircuitBreakerConfig)
		circuitbreaker.PUT("/config/:service", healthHandler.UpdateCircuitBreakerConfig)

		// Circuit breaker metrics
		circuitbreaker.GET("/metrics", healthHandler.CircuitBreakerMetrics)
		circuitbreaker.GET("/metrics/:service", healthHandler.ServiceCircuitBreakerMetrics)
	}

	// =============================================================================
	// MAINTENANCE MODE
	// =============================================================================

	maintenance := router.Group("/maintenance")
	{
		// Maintenance mode status
		maintenance.GET("/status", healthHandler.MaintenanceStatus)

		// Maintenance mode controls (Admin only in production)
		maintenance.POST("/enable", healthHandler.EnableMaintenance)
		maintenance.POST("/disable", healthHandler.DisableMaintenance)

		// Maintenance schedule
		maintenance.GET("/schedule", healthHandler.GetMaintenanceSchedule)
		maintenance.POST("/schedule", healthHandler.ScheduleMaintenance)
		maintenance.PUT("/schedule/:schedule_id", healthHandler.UpdateMaintenanceSchedule)
		maintenance.DELETE("/schedule/:schedule_id", healthHandler.CancelMaintenanceSchedule)

		// Maintenance notifications
		maintenance.GET("/notifications", healthHandler.GetMaintenanceNotifications)
		maintenance.POST("/notifications", healthHandler.CreateMaintenanceNotification)

		// Graceful shutdown
		maintenance.POST("/graceful-shutdown", healthHandler.InitiateGracefulShutdown)
		maintenance.GET("/shutdown-status", healthHandler.GetShutdownStatus)
	}

	// =============================================================================
	// BACKUP AND RECOVERY STATUS
	// =============================================================================

	backup := router.Group("/backup")
	{
		// Backup status
		backup.GET("/status", healthHandler.BackupStatus)
		backup.GET("/last-backup", healthHandler.LastBackupInfo)
		backup.GET("/schedule", healthHandler.BackupSchedule)

		// Recovery status
		backup.GET("/recovery/status", healthHandler.RecoveryStatus)
		backup.GET("/recovery/point", healthHandler.RecoveryPointObjective)
		backup.GET("/recovery/time", healthHandler.RecoveryTimeObjective)

		// Backup validation
		backup.POST("/validate", healthHandler.ValidateBackup)
		backup.GET("/validation-results", healthHandler.GetBackupValidationResults)
	}

	// =============================================================================
	// SECURITY HEALTH
	// =============================================================================

	security := router.Group("/security")
	{
		// Security health checks
		security.GET("/status", healthHandler.SecurityStatus)
		security.GET("/certificates", healthHandler.CertificateStatus)
		security.GET("/ssl", healthHandler.SSLStatus)

		// Authentication health
		security.GET("/auth", healthHandler.AuthenticationHealth)
		security.GET("/tokens", healthHandler.TokenHealth)
		security.GET("/sessions", healthHandler.SessionHealth)

		// Security metrics
		security.GET("/metrics", healthHandler.SecurityMetrics)
		security.GET("/threats", healthHandler.ThreatMetrics)
		security.GET("/intrusions", healthHandler.IntrusionAttempts)

		// Vulnerability status
		security.GET("/vulnerabilities", healthHandler.VulnerabilityStatus)
		security.GET("/security-updates", healthHandler.SecurityUpdates)
	}
}

// Health check response structures that handlers will need:
/*
Expected Response Structures:

1. Basic Health Response:
{
  "status": "healthy|unhealthy|degraded",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "uptime": "72h30m15s"
}

2. Detailed Health Response:
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "uptime": "72h30m15s",
  "services": {
    "database": {"status": "healthy", "response_time": "5ms"},
    "redis": {"status": "healthy", "response_time": "2ms"},
    "storage": {"status": "healthy", "response_time": "10ms"}
  },
  "system": {
    "cpu_usage": 45.2,
    "memory_usage": 67.8,
    "disk_usage": 23.4
  }
}

3. Metrics Response:
{
  "timestamp": "2024-01-01T00:00:00Z",
  "requests_per_second": 150.5,
  "response_time_avg": "25ms",
  "error_rate": 0.02,
  "active_connections": 245,
  "memory_usage": 512000000,
  "cpu_usage": 45.2
}

4. System Info Response:
{
  "hostname": "api-server-01",
  "os": "linux",
  "arch": "amd64",
  "go_version": "1.21.0",
  "num_cpu": 8,
  "num_goroutines": 42,
  "build_info": {
    "version": "1.0.0",
    "commit": "abc123",
    "build_time": "2024-01-01T00:00:00Z"
  }
}
*/
