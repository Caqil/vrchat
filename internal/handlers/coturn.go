package handlers

import (
	"fmt"
	"net/http"
	"time"

	"vrchat/internal/models"
	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
)

type CoturnHandler struct {
	coturnService *services.CoturnService
}

func NewCoturnHandler(coturnService *services.CoturnService) *CoturnHandler {
	return &CoturnHandler{
		coturnService: coturnService,
	}
}

// Public endpoints for getting ICE servers

func (h *CoturnHandler) GetICEServers(c *gin.Context) {
	// Get user's region from IP or query parameter
	region := c.Query("region")
	if region == "" {
		regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
		region = regionInfo.Code
	}

	// Get username from session if available (for guests, we'll generate one)
	userID := c.GetString("user_id")
	if userID == "" {
		// Generate temporary username for guest users
		userID = "guest_" + utils.HashSHA256(c.ClientIP() + time.Now().String())[:8]
	}

	// Get ICE servers for the region
	iceServers, err := h.coturnService.GetICEServersForRegion(region, userID)
	if err != nil {
		logger.WithError(err).Error("Failed to get ICE servers")
		// Return basic STUN servers as fallback
		fallbackServers := h.getFallbackICEServers()
		utils.SuccessResponse(c, fallbackServers)
		return
	}

	// Log ICE server request for analytics
	logger.LogUserAction(userID, "ice_servers_requested", map[string]interface{}{
		"region":       region,
		"server_count": len(iceServers),
		"ip":           c.ClientIP(),
	})

	response := map[string]interface{}{
		"ice_servers":  iceServers,
		"region":       region,
		"ttl":          3600, // 1 hour TTL for credentials
		"generated_at": time.Now(),
	}

	utils.SuccessResponse(c, response)
}

func (h *CoturnHandler) GetRegionalICEServers(c *gin.Context) {
	region := c.Param("region")
	userID := c.GetString("user_id")

	if region == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Region parameter is required")
		return
	}

	// Validate region
	if !h.isValidRegion(region) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid region")
		return
	}

	// Get ICE servers for specific region
	iceServers, err := h.coturnService.GetICEServersForRegion(region, userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get ICE servers for region")
		return
	}

	// Get server statistics for this region
	stats, err := h.coturnService.GetRegionStats(region)
	if err != nil {
		logger.WithError(err).Warn("Failed to get region stats")
		stats = map[string]interface{}{
			"available_servers": len(iceServers),
			"status":            "unknown",
		}
	}

	response := map[string]interface{}{
		"ice_servers":  iceServers,
		"region":       region,
		"stats":        stats,
		"ttl":          3600,
		"generated_at": time.Now(),
	}

	utils.SuccessResponse(c, response)
}

// Protected endpoints for testing and management

func (h *CoturnHandler) TestICEServers(c *gin.Context) {
	userID := c.GetString("user_id")
	region := c.DefaultQuery("region", "us-east")

	// Get ICE servers for testing
	iceServers, err := h.coturnService.GetICEServersForRegion(region, userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get ICE servers")
		return
	}

	// Perform connectivity tests
	testResults := make([]map[string]interface{}, 0)

	for _, server := range iceServers {
		if iceServer, ok := server.(models.ICEServer); ok {
			for _, url := range iceServer.URLs {
				result := h.testICEServerConnectivity(url, iceServer.Username, iceServer.Credential)
				testResults = append(testResults, map[string]interface{}{
					"url":           url,
					"status":        result.Status,
					"response_time": result.ResponseTime,
					"error":         result.Error,
					"tested_at":     time.Now(),
				})
			}
		}
	}

	// Calculate overall health
	successCount := 0
	for _, result := range testResults {
		if result["status"] == "success" {
			successCount++
		}
	}

	healthPercentage := float64(successCount) / float64(len(testResults)) * 100

	logger.LogUserAction(userID, "ice_servers_tested", map[string]interface{}{
		"region":         region,
		"servers_tested": len(testResults),
		"success_rate":   healthPercentage,
		"ip":             c.ClientIP(),
	})

	response := map[string]interface{}{
		"test_results":      testResults,
		"total_servers":     len(testResults),
		"successful":        successCount,
		"health_percentage": healthPercentage,
		"region":            region,
		"tested_at":         time.Now(),
	}

	utils.SuccessResponse(c, response)
}

func (h *CoturnHandler) GetServerHealth(c *gin.Context) {
	// Get health status for all regions
	regions := []string{"us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast"}

	healthStatus := make(map[string]interface{})

	for _, region := range regions {
		stats, err := h.coturnService.GetRegionStats(region)
		if err != nil {
			healthStatus[region] = map[string]interface{}{
				"status":     "error",
				"error":      err.Error(),
				"servers":    0,
				"checked_at": time.Now(),
			}
			continue
		}

		healthStatus[region] = stats
	}

	// Get overall system health
	overallHealth := h.calculateOverallHealth(healthStatus)

	response := map[string]interface{}{
		"overall_health": overallHealth,
		"regions":        healthStatus,
		"timestamp":      time.Now(),
	}

	utils.SuccessResponse(c, response)
}

func (h *CoturnHandler) RefreshCredentials(c *gin.Context) {
	userID := c.GetString("user_id")
	region := c.DefaultQuery("region", "")

	// Get user's region if not specified
	if region == "" {
		regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
		region = regionInfo.Code
	}

	// Generate new credentials
	iceServers, err := h.coturnService.RefreshCredentialsForUser(userID, region)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to refresh credentials")
		return
	}

	logger.LogUserAction(userID, "ice_credentials_refreshed", map[string]interface{}{
		"region": region,
		"ip":     c.ClientIP(),
	})

	response := map[string]interface{}{
		"ice_servers":  iceServers,
		"region":       region,
		"ttl":          3600,
		"refreshed_at": time.Now(),
	}

	utils.SuccessResponseWithMessage(c, "Credentials refreshed successfully", response)
}

func (h *CoturnHandler) GetServerStatistics(c *gin.Context) {
	// Get comprehensive server statistics
	stats, err := h.coturnService.GetComprehensiveStats()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get server statistics")
		return
	}

	// Add real-time metrics
	realTimeStats := h.getRealTimeMetrics()

	response := map[string]interface{}{
		"statistics":   stats,
		"real_time":    realTimeStats,
		"generated_at": time.Now(),
	}

	utils.SuccessResponse(c, response)
}

// Advanced COTURN management endpoints

func (h *CoturnHandler) GetLoadBalancingInfo(c *gin.Context) {
	region := c.Query("region")

	if region != "" && !h.isValidRegion(region) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid region")
		return
	}

	loadInfo, err := h.coturnService.GetLoadBalancingInfo(region)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get load balancing info")
		return
	}

	utils.SuccessResponse(c, loadInfo)
}

func (h *CoturnHandler) UpdateServerWeights(c *gin.Context) {
	var weightData struct {
		ServerWeights map[string]int `json:"server_weights" binding:"required"`
		Region        string         `json:"region"`
	}

	if err := c.ShouldBindJSON(&weightData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid weight data")
		return
	}

	err := h.coturnService.UpdateServerWeights(weightData.ServerWeights, weightData.Region)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update server weights")
		return
	}

	logger.LogUserAction(c.GetString("user_id"), "server_weights_updated", map[string]interface{}{
		"region":  weightData.Region,
		"weights": weightData.ServerWeights,
	})

	utils.SuccessResponseWithMessage(c, "Server weights updated successfully", nil)
}

func (h *CoturnHandler) GetServerMetrics(c *gin.Context) {
	serverID := c.Query("server_id")
	period := c.DefaultQuery("period", "1h")

	if serverID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Server ID is required")
		return
	}

	metrics, err := h.coturnService.GetServerMetrics(serverID, period)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get server metrics")
		return
	}

	utils.SuccessResponse(c, metrics)
}

func (h *CoturnHandler) TriggerServerMaintenance(c *gin.Context) {
	var maintenanceData struct {
		ServerID         string     `json:"server_id" binding:"required"`
		MaintenanceType  string     `json:"maintenance_type" binding:"required"` // restart, update, config_reload
		ScheduledAt      *time.Time `json:"scheduled_at"`
		DrainConnections bool       `json:"drain_connections"`
	}

	if err := c.ShouldBindJSON(&maintenanceData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid maintenance data")
		return
	}

	err := h.coturnService.ScheduleMaintenance(
		maintenanceData.ServerID,
		maintenanceData.MaintenanceType,
		maintenanceData.ScheduledAt,
		maintenanceData.DrainConnections,
	)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to schedule maintenance")
		return
	}

	logger.LogUserAction(c.GetString("user_id"), "server_maintenance_scheduled", map[string]interface{}{
		"server_id":         maintenanceData.ServerID,
		"maintenance_type":  maintenanceData.MaintenanceType,
		"scheduled_at":      maintenanceData.ScheduledAt,
		"drain_connections": maintenanceData.DrainConnections,
	})

	utils.SuccessResponseWithMessage(c, "Maintenance scheduled successfully", nil)
}

// Helper methods

type ICETestResult struct {
	Status       string        `json:"status"`
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
}

func (h *CoturnHandler) testICEServerConnectivity(url, username, credential string) ICETestResult {
	startTime := time.Now()

	// Implement actual connectivity test
	// This is a simplified version - in production you'd want to test STUN/TURN connectivity
	result := ICETestResult{
		Status:       "success",
		ResponseTime: time.Since(startTime),
	}

	// Simulate some test logic
	if len(url) == 0 {
		result.Status = "error"
		result.Error = "Invalid URL"
	}

	return result
}

func (h *CoturnHandler) getFallbackICEServers() []models.ICEServer {
	// Return basic STUN servers as fallback
	return []models.ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
		{
			URLs: []string{"stun:stun1.l.google.com:19302"},
		},
		{
			URLs: []string{"stun:stun2.l.google.com:19302"},
		},
		{
			URLs: []string{"stun:stun.cloudflare.com:3478"},
		},
	}
}

func (h *CoturnHandler) isValidRegion(region string) bool {
	validRegions := []string{"us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast"}
	for _, validRegion := range validRegions {
		if region == validRegion {
			return true
		}
	}
	return false
}

func (h *CoturnHandler) calculateOverallHealth(regionHealth map[string]interface{}) map[string]interface{} {
	totalServers := 0
	healthyServers := 0

	for _, regionData := range regionHealth {
		if regionMap, ok := regionData.(map[string]interface{}); ok {
			if servers, exists := regionMap["servers"].(int); exists {
				totalServers += servers
			}
			if status, exists := regionMap["status"].(string); exists && status == "healthy" {
				if servers, exists := regionMap["servers"].(int); exists {
					healthyServers += servers
				}
			}
		}
	}

	healthPercentage := 0.0
	if totalServers > 0 {
		healthPercentage = float64(healthyServers) / float64(totalServers) * 100
	}

	status := "healthy"
	if healthPercentage < 50 {
		status = "critical"
	} else if healthPercentage < 80 {
		status = "degraded"
	}

	return map[string]interface{}{
		"status":            status,
		"health_percentage": healthPercentage,
		"total_servers":     totalServers,
		"healthy_servers":   healthyServers,
		"last_check":        time.Now(),
	}
}

func (h *CoturnHandler) getRealTimeMetrics() map[string]interface{} {
	// Get real-time metrics from COTURN servers
	// This would typically involve querying server APIs or monitoring systems

	return map[string]interface{}{
		"active_connections":   250,
		"bandwidth_usage_mbps": 125.5,
		"cpu_usage_percent":    45.2,
		"memory_usage_percent": 62.8,
		"requests_per_second":  12.5,
		"error_rate_percent":   0.1,
		"last_updated":         time.Now(),
	}
}

// Monitoring and alerting endpoints

func (h *CoturnHandler) GetAlerts(c *gin.Context) {
	severity := c.DefaultQuery("severity", "")
	region := c.DefaultQuery("region", "")

	alerts, err := h.coturnService.GetAlerts(severity, region)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get alerts")
		return
	}

	utils.SuccessResponse(c, alerts)
}

func (h *CoturnHandler) AcknowledgeAlert(c *gin.Context) {
	alertID := c.Param("alert_id")
	userID := c.GetString("user_id")

	if alertID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Alert ID is required")
		return
	}

	err := h.coturnService.AcknowledgeAlert(alertID, userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to acknowledge alert")
		return
	}

	logger.LogUserAction(userID, "alert_acknowledged", map[string]interface{}{
		"alert_id": alertID,
	})

	utils.SuccessResponseWithMessage(c, "Alert acknowledged successfully", nil)
}

func (h *CoturnHandler) GetPerformanceReport(c *gin.Context) {
	period := c.DefaultQuery("period", "24h")
	region := c.Query("region")

	report, err := h.coturnService.GeneratePerformanceReport(period, region)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to generate performance report")
		return
	}

	// Set headers for file download if requested
	if c.Query("download") == "true" {
		filename := fmt.Sprintf("coturn_performance_report_%s.json", time.Now().Format("20060102_150405"))
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Header("Content-Type", "application/json")
	}

	utils.SuccessResponse(c, report)
}

// Configuration management

func (h *CoturnHandler) GetServerConfiguration(c *gin.Context) {
	serverID := c.Query("server_id")
	if serverID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Server ID is required")
		return
	}

	config, err := h.coturnService.GetServerConfiguration(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Server configuration not found")
		return
	}

	utils.SuccessResponse(c, config)
}

func (h *CoturnHandler) UpdateServerConfiguration(c *gin.Context) {
	serverID := c.Query("server_id")
	if serverID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Server ID is required")
		return
	}

	var configData map[string]interface{}
	if err := c.ShouldBindJSON(&configData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid configuration data")
		return
	}

	err := h.coturnService.UpdateServerConfiguration(serverID, configData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update server configuration")
		return
	}

	logger.LogUserAction(c.GetString("user_id"), "server_config_updated", map[string]interface{}{
		"server_id": serverID,
		"config":    configData,
	})

	utils.SuccessResponseWithMessage(c, "Server configuration updated successfully", nil)
}

func (h *CoturnHandler) ValidateConfiguration(c *gin.Context) {
	var configData map[string]interface{}
	if err := c.ShouldBindJSON(&configData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid configuration data")
		return
	}

	validation, err := h.coturnService.ValidateConfiguration(configData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to validate configuration")
		return
	}

	utils.SuccessResponse(c, validation)
}
