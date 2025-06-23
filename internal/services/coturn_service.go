package services

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"vrchat/internal/models"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type CoturnService struct {
	db                *mongo.Database
	serversCollection *mongo.Collection
	alertsCollection  *mongo.Collection
	metricsCollection *mongo.Collection
	configCollection  *mongo.Collection
}

type ServerAlert struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	ServerID  string                 `bson:"server_id" json:"server_id"`
	Type      string                 `bson:"type" json:"type"`         // connection, performance, configuration
	Severity  string                 `bson:"severity" json:"severity"` // low, medium, high, critical
	Message   string                 `bson:"message" json:"message"`
	Data      map[string]interface{} `bson:"data,omitempty" json:"data,omitempty"`
	Status    string                 `bson:"status" json:"status"` // active, acknowledged, resolved
	AckedBy   string                 `bson:"acked_by,omitempty" json:"acked_by,omitempty"`
	AckedAt   *time.Time             `bson:"acked_at,omitempty" json:"acked_at,omitempty"`
	CreatedAt time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time              `bson:"updated_at" json:"updated_at"`
}

type ServerMetrics struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServerID          string             `bson:"server_id" json:"server_id"`
	Timestamp         time.Time          `bson:"timestamp" json:"timestamp"`
	ActiveConnections int                `bson:"active_connections" json:"active_connections"`
	TotalConnections  int                `bson:"total_connections" json:"total_connections"`
	BytesTransferred  int64              `bson:"bytes_transferred" json:"bytes_transferred"`
	CPUUsage          float64            `bson:"cpu_usage" json:"cpu_usage"`
	MemoryUsage       float64            `bson:"memory_usage" json:"memory_usage"`
	ResponseTimeMs    float64            `bson:"response_time_ms" json:"response_time_ms"`
	ErrorRate         float64            `bson:"error_rate" json:"error_rate"`
	Region            string             `bson:"region" json:"region"`
}

type ServerConfiguration struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	ServerID    string                 `bson:"server_id" json:"server_id"`
	Config      map[string]interface{} `bson:"config" json:"config"`
	Version     string                 `bson:"version" json:"version"`
	LastApplied time.Time              `bson:"last_applied" json:"last_applied"`
	CreatedBy   string                 `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
}

func NewCoturnService(db *mongo.Database) *CoturnService {
	return &CoturnService{
		db:                db,
		serversCollection: db.Collection("coturn_servers"),
		alertsCollection:  db.Collection("coturn_alerts"),
		metricsCollection: db.Collection("coturn_metrics"),
		configCollection:  db.Collection("coturn_configs"),
	}
}

// ICE Server Management

func (s *CoturnService) GetICEServersForRegion(region, userID string) ([]models.ICEServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get active servers for the region
	filter := bson.M{
		"region":    region,
		"is_active": true,
		"status":    "online",
	}

	// Sort by priority and current load
	opts := options.Find().SetSort(bson.D{
		{Key: "priority", Value: 1},
		{Key: "current_users", Value: 1},
	})

	cursor, err := s.serversCollection.Find(ctx, filter, opts)
	if err != nil {
		logger.LogError(err, "Failed to get COTURN servers", map[string]interface{}{
			"region":  region,
			"user_id": userID,
		})
		return nil, fmt.Errorf("failed to get COTURN servers: %w", err)
	}
	defer cursor.Close(ctx)

	var servers []models.CoturnServer
	if err = cursor.All(ctx, &servers); err != nil {
		return nil, fmt.Errorf("failed to decode servers: %w", err)
	}

	// If no servers in region, get fallback servers
	if len(servers) == 0 {
		return s.getFallbackServers(region, userID)
	}

	// Convert to ICE servers with credentials
	iceServers := make([]models.ICEServer, 0)

	for _, server := range servers {
		// Generate TURN credentials
		turnUsername, turnPassword := utils.GenerateTurnCredentials(userID, server.Password)

		// Add STUN server
		stunURL := fmt.Sprintf("stun:%s", server.URL)
		iceServers = append(iceServers, models.ICEServer{
			URLs: []string{stunURL},
		})

		// Add TURN server with UDP
		turnUDPURL := fmt.Sprintf("turn:%s?transport=udp", server.URL)
		iceServers = append(iceServers, models.ICEServer{
			URLs:       []string{turnUDPURL},
			Username:   turnUsername,
			Credential: turnPassword,
		})

		// Add TURN server with TCP
		turnTCPURL := fmt.Sprintf("turn:%s?transport=tcp", server.URL)
		iceServers = append(iceServers, models.ICEServer{
			URLs:       []string{turnTCPURL},
			Username:   turnUsername,
			Credential: turnPassword,
		})

		// Add TURNS server (if supported)
		turnsURL := fmt.Sprintf("turns:%s?transport=tcp", server.URL)
		iceServers = append(iceServers, models.ICEServer{
			URLs:       []string{turnsURL},
			Username:   turnUsername,
			Credential: turnPassword,
		})

		// Update server usage count
		s.incrementServerUsage(server.ID)
	}

	// Log ICE server request
	logger.LogUserAction(userID, "ice_servers_requested", map[string]interface{}{
		"region":       region,
		"server_count": len(servers),
		"ice_count":    len(iceServers),
	})

	return iceServers, nil
}

func (s *CoturnService) getFallbackServers(region, userID string) ([]models.ICEServer, error) {
	// Return basic public STUN servers as fallback
	fallbackServers := []models.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{URLs: []string{"stun:stun1.l.google.com:19302"}},
		{URLs: []string{"stun:stun2.l.google.com:19302"}},
		{URLs: []string{"stun:stun.cloudflare.com:3478"}},
	}

	logger.LogUserAction(userID, "ice_servers_fallback", map[string]interface{}{
		"region":       region,
		"server_count": len(fallbackServers),
		"reason":       "no_regional_servers",
	})

	return fallbackServers, nil
}

func (s *CoturnService) incrementServerUsage(serverID primitive.ObjectID) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$inc": bson.M{"current_users": 1},
		"$set": bson.M{"last_checked": time.Now()},
	}

	s.serversCollection.UpdateOne(ctx, bson.M{"_id": serverID}, update)
}

func (s *CoturnService) RefreshCredentialsForUser(userID, region string) ([]models.ICEServer, error) {
	// Simply call GetICEServersForRegion as it generates fresh credentials each time
	return s.GetICEServersForRegion(region, userID)
}

// Server Management

func (s *CoturnService) GetAllServers() ([]models.CoturnServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{
		{Key: "region", Value: 1},
		{Key: "priority", Value: 1},
	})

	cursor, err := s.serversCollection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get servers: %w", err)
	}
	defer cursor.Close(ctx)

	var servers []models.CoturnServer
	if err = cursor.All(ctx, &servers); err != nil {
		return nil, fmt.Errorf("failed to decode servers: %w", err)
	}

	return servers, nil
}

func (s *CoturnService) CreateServer(server *models.CoturnServer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.CreatedAt = time.Now()
	server.UpdatedAt = time.Now()
	server.LastChecked = time.Now()
	server.Status = "offline" // Will be updated by health check
	server.CurrentUsers = 0

	result, err := s.serversCollection.InsertOne(ctx, server)
	if err != nil {
		logger.LogError(err, "Failed to create COTURN server", map[string]interface{}{
			"name":   server.Name,
			"region": server.Region,
			"url":    server.URL,
		})
		return fmt.Errorf("failed to create server: %w", err)
	}

	server.ID = result.InsertedID.(primitive.ObjectID)

	// Test the server immediately
	go s.testServerHealth(server.ID)

	return nil
}

func (s *CoturnService) GetServerByID(serverID primitive.ObjectID) (*models.CoturnServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var server models.CoturnServer
	err := s.serversCollection.FindOne(ctx, bson.M{"_id": serverID}).Decode(&server)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("server not found")
		}
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	return &server, nil
}

func (s *CoturnService) UpdateServer(serverID primitive.ObjectID, updateData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	updateData["updated_at"] = time.Now()

	update := bson.M{"$set": updateData}

	_, err := s.serversCollection.UpdateOne(ctx, bson.M{"_id": serverID}, update)
	if err != nil {
		logger.LogError(err, "Failed to update COTURN server", map[string]interface{}{
			"server_id":   serverID.Hex(),
			"update_data": updateData,
		})
		return fmt.Errorf("failed to update server: %w", err)
	}

	// If URL or credentials changed, test the server
	if _, urlChanged := updateData["url"]; urlChanged {
		go s.testServerHealth(serverID)
	}

	return nil
}

func (s *CoturnService) DeleteServer(serverID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete server
	_, err := s.serversCollection.DeleteOne(ctx, bson.M{"_id": serverID})
	if err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}

	// Clean up related data
	go s.cleanupServerData(serverID)

	return nil
}

func (s *CoturnService) ToggleServerStatus(serverID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get current status
	server, err := s.GetServerByID(serverID)
	if err != nil {
		return err
	}

	newStatus := !server.IsActive

	update := bson.M{
		"$set": bson.M{
			"is_active":  newStatus,
			"updated_at": time.Now(),
		},
	}

	_, err = s.serversCollection.UpdateOne(ctx, bson.M{"_id": serverID}, update)
	if err != nil {
		return fmt.Errorf("failed to toggle server status: %w", err)
	}

	return nil
}

// Server Testing and Health

func (s *CoturnService) TestServer(serverID primitive.ObjectID) (map[string]interface{}, error) {
	server, err := s.GetServerByID(serverID)
	if err != nil {
		return nil, err
	}

	result := s.performServerTest(server)

	// Update server status based on test result
	s.updateServerStatus(serverID, result)

	return result, nil
}

func (s *CoturnService) BulkTestServers() (map[string]interface{}, error) {
	servers, err := s.GetAllServers()
	if err != nil {
		return nil, err
	}

	results := make(map[string]interface{})
	successCount := 0
	totalCount := len(servers)

	for _, server := range servers {
		result := s.performServerTest(&server)
		results[server.ID.Hex()] = result

		if result["status"] == "success" {
			successCount++
		}

		// Update server status
		s.updateServerStatus(server.ID, result)

		// Small delay to avoid overwhelming servers
		time.Sleep(100 * time.Millisecond)
	}

	summary := map[string]interface{}{
		"total_servers":      totalCount,
		"successful_tests":   successCount,
		"failed_tests":       totalCount - successCount,
		"success_rate":       float64(successCount) / float64(totalCount) * 100,
		"individual_results": results,
		"tested_at":          time.Now(),
	}

	return summary, nil
}

func (s *CoturnService) performServerTest(server *models.CoturnServer) map[string]interface{} {
	startTime := time.Now()

	result := map[string]interface{}{
		"server_id":   server.ID.Hex(),
		"server_name": server.Name,
		"server_url":  server.URL,
		"region":      server.Region,
		"tested_at":   startTime,
	}

	// Test STUN connectivity
	stunSuccess, stunLatency := s.testSTUNConnectivity(server.URL)
	result["stun_success"] = stunSuccess
	result["stun_latency_ms"] = stunLatency

	// Test TURN connectivity
	turnSuccess, turnLatency := s.testTURNConnectivity(server.URL, server.Username, server.Password)
	result["turn_success"] = turnSuccess
	result["turn_latency_ms"] = turnLatency

	// Overall test result
	if stunSuccess && turnSuccess {
		result["status"] = "success"
		result["health"] = "healthy"
	} else if stunSuccess || turnSuccess {
		result["status"] = "partial"
		result["health"] = "degraded"
	} else {
		result["status"] = "failed"
		result["health"] = "unhealthy"
	}

	result["total_test_time_ms"] = time.Since(startTime).Milliseconds()

	return result
}

func (s *CoturnService) testSTUNConnectivity(serverURL string) (bool, float64) {
	startTime := time.Now()

	// Parse server URL and test connectivity
	conn, err := net.DialTimeout("udp", serverURL, 5*time.Second)
	if err != nil {
		return false, 0
	}
	defer conn.Close()

	latency := float64(time.Since(startTime).Milliseconds())
	return true, latency
}

func (s *CoturnService) testTURNConnectivity(serverURL, username, password string) (bool, float64) {
	startTime := time.Now()

	// This would involve actual TURN protocol testing
	// For now, we'll simulate a basic TCP connection test
	conn, err := net.DialTimeout("tcp", serverURL, 5*time.Second)
	if err != nil {
		return false, 0
	}
	defer conn.Close()

	latency := float64(time.Since(startTime).Milliseconds())
	return true, latency
}

func (s *CoturnService) updateServerStatus(serverID primitive.ObjectID, testResult map[string]interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status := "offline"
	if testResult["status"] == "success" {
		status = "online"
	} else if testResult["status"] == "partial" {
		status = "degraded"
	}

	update := bson.M{
		"$set": bson.M{
			"status":           status,
			"last_checked":     time.Now(),
			"last_test_result": testResult,
		},
	}

	s.serversCollection.UpdateOne(ctx, bson.M{"_id": serverID}, update)
}

func (s *CoturnService) testServerHealth(serverID primitive.ObjectID) {
	server, err := s.GetServerByID(serverID)
	if err != nil {
		return
	}

	result := s.performServerTest(server)
	s.updateServerStatus(serverID, result)

	// Create alert if server is unhealthy
	if result["status"] != "success" {
		s.createServerAlert(serverID, "health_check_failed", "high", fmt.Sprintf("Server %s health check failed", server.Name), result)
	}
}

// Statistics and Metrics

func (s *CoturnService) GetRegionStats(region string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$match": bson.M{"region": region}},
		{"$group": bson.M{
			"_id":            region,
			"total_servers":  bson.M{"$sum": 1},
			"active_servers": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$is_active", true}}, 1, 0}}},
			"online_servers": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "online"}}, 1, 0}}},
			"total_users":    bson.M{"$sum": "$current_users"},
			"total_capacity": bson.M{"$sum": "$max_users"},
		}},
	}

	cursor, err := s.serversCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get region stats: %w", err)
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode region stats: %w", err)
	}

	if len(results) == 0 {
		return map[string]interface{}{
			"region":         region,
			"total_servers":  0,
			"active_servers": 0,
			"online_servers": 0,
			"total_users":    0,
			"total_capacity": 0,
			"status":         "no_servers",
			"load_percent":   0,
		}, nil
	}

	stats := results[0]
	totalUsers := int(stats["total_users"].(int32))
	totalCapacity := int(stats["total_capacity"].(int32))

	loadPercent := 0.0
	if totalCapacity > 0 {
		loadPercent = float64(totalUsers) / float64(totalCapacity) * 100
	}

	// Determine overall region health
	onlineServers := int(stats["online_servers"].(int32))
	totalServers := int(stats["total_servers"].(int32))

	status := "healthy"
	if onlineServers == 0 {
		status = "offline"
	} else if float64(onlineServers)/float64(totalServers) < 0.5 {
		status = "degraded"
	} else if loadPercent > 90 {
		status = "overloaded"
	}

	stats["status"] = status
	stats["load_percent"] = loadPercent
	stats["checked_at"] = time.Now()

	return stats, nil
}

func (s *CoturnService) GetServersCount() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.serversCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		logger.LogError(err, "Failed to count servers", nil)
		return 0
	}

	return count
}

func (s *CoturnService) GetComprehensiveStats() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Get overall server statistics
	pipeline := []bson.M{
		{"$group": bson.M{
			"_id":              nil,
			"total_servers":    bson.M{"$sum": 1},
			"active_servers":   bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$is_active", true}}, 1, 0}}},
			"online_servers":   bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "online"}}, 1, 0}}},
			"degraded_servers": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "degraded"}}, 1, 0}}},
			"offline_servers":  bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "offline"}}, 1, 0}}},
			"total_users":      bson.M{"$sum": "$current_users"},
			"total_capacity":   bson.M{"$sum": "$max_users"},
			"avg_priority":     bson.M{"$avg": "$priority"},
		}},
	}

	cursor, err := s.serversCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get comprehensive stats: %w", err)
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode comprehensive stats: %w", err)
	}

	var stats map[string]interface{}
	if len(results) > 0 {
		stats = results[0]
	} else {
		stats = map[string]interface{}{
			"total_servers":    0,
			"active_servers":   0,
			"online_servers":   0,
			"degraded_servers": 0,
			"offline_servers":  0,
			"total_users":      0,
			"total_capacity":   0,
			"avg_priority":     0,
		}
	}

	// Get regional breakdown
	regionalStats, err := s.getRegionalBreakdown()
	if err != nil {
		logger.LogError(err, "Failed to get regional breakdown", nil)
		regionalStats = map[string]interface{}{}
	}

	// Get recent alerts
	recentAlerts, err := s.getRecentAlerts(10)
	if err != nil {
		logger.LogError(err, "Failed to get recent alerts", nil)
		recentAlerts = []interface{}{}
	}

	// Calculate health metrics
	totalServers := int(stats["total_servers"].(int32))
	onlineServers := int(stats["online_servers"].(int32))
	totalUsers := int(stats["total_users"].(int32))
	totalCapacity := int(stats["total_capacity"].(int32))

	healthPercentage := 0.0
	if totalServers > 0 {
		healthPercentage = float64(onlineServers) / float64(totalServers) * 100
	}

	loadPercentage := 0.0
	if totalCapacity > 0 {
		loadPercentage = float64(totalUsers) / float64(totalCapacity) * 100
	}

	overallHealth := "healthy"
	if healthPercentage < 50 {
		overallHealth = "critical"
	} else if healthPercentage < 80 {
		overallHealth = "degraded"
	} else if loadPercentage > 90 {
		overallHealth = "overloaded"
	}

	comprehensiveStats := map[string]interface{}{
		"overview":          stats,
		"regional_stats":    regionalStats,
		"recent_alerts":     recentAlerts,
		"health_percentage": healthPercentage,
		"load_percentage":   loadPercentage,
		"overall_health":    overallHealth,
		"generated_at":      time.Now(),
	}

	return comprehensiveStats, nil
}

func (s *CoturnService) getRegionalBreakdown() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$group": bson.M{
			"_id":            "$region",
			"total_servers":  bson.M{"$sum": 1},
			"online_servers": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "online"}}, 1, 0}}},
			"total_users":    bson.M{"$sum": "$current_users"},
			"total_capacity": bson.M{"$sum": "$max_users"},
		}},
		{"$sort": bson.M{"_id": 1}},
	}

	cursor, err := s.serversCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	breakdown := make(map[string]interface{})
	for _, result := range results {
		region := result["_id"].(string)
		breakdown[region] = result
	}

	return breakdown, nil
}

func (s *CoturnService) getRecentAlerts(limit int) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := s.alertsCollection.Find(ctx, bson.M{"status": "active"}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var alerts []interface{}
	if err = cursor.All(ctx, &alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

// Server Configuration and Maintenance

func (s *CoturnService) GetServerConfiguration(serverID string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var config ServerConfiguration
	err := s.configCollection.FindOne(ctx, bson.M{"server_id": serverID}).Decode(&config)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return s.getDefaultConfiguration(), nil
		}
		return nil, fmt.Errorf("failed to get server configuration: %w", err)
	}

	return map[string]interface{}{
		"server_id":    config.ServerID,
		"config":       config.Config,
		"version":      config.Version,
		"last_applied": config.LastApplied,
		"created_by":   config.CreatedBy,
		"created_at":   config.CreatedAt,
	}, nil
}

func (s *CoturnService) UpdateServerConfiguration(serverID string, configData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := ServerConfiguration{
		ServerID:    serverID,
		Config:      configData,
		Version:     fmt.Sprintf("v%d", time.Now().Unix()),
		LastApplied: time.Now(),
		CreatedAt:   time.Now(),
	}

	opts := options.Replace().SetUpsert(true)
	_, err := s.configCollection.ReplaceOne(ctx, bson.M{"server_id": serverID}, config, opts)
	if err != nil {
		return fmt.Errorf("failed to update server configuration: %w", err)
	}

	return nil
}

func (s *CoturnService) ValidateConfiguration(configData map[string]interface{}) (map[string]interface{}, error) {
	validation := map[string]interface{}{
		"valid":    true,
		"errors":   []string{},
		"warnings": []string{},
	}

	errors := []string{}
	warnings := []string{}

	// Validate required fields
	requiredFields := []string{"realm", "listening-port", "external-ip"}
	for _, field := range requiredFields {
		if _, exists := configData[field]; !exists {
			errors = append(errors, fmt.Sprintf("Missing required field: %s", field))
		}
	}

	// Validate port ranges
	if port, exists := configData["listening-port"]; exists {
		if portNum, ok := port.(float64); ok {
			if portNum < 1024 || portNum > 65535 {
				errors = append(errors, "listening-port must be between 1024 and 65535")
			}
		}
	}

	// Validate external IP
	if ip, exists := configData["external-ip"]; exists {
		if ipStr, ok := ip.(string); ok {
			if net.ParseIP(ipStr) == nil {
				errors = append(errors, "external-ip is not a valid IP address")
			}
		}
	}

	// Add warnings for performance settings
	if maxBps, exists := configData["max-bps"]; exists {
		if bps, ok := maxBps.(float64); ok && bps > 1000000 {
			warnings = append(warnings, "max-bps is set very high, may impact server performance")
		}
	}

	validation["errors"] = errors
	validation["warnings"] = warnings
	validation["valid"] = len(errors) == 0

	return validation, nil
}

func (s *CoturnService) getDefaultConfiguration() map[string]interface{} {
	return map[string]interface{}{
		"realm":              "coturn.local",
		"listening-port":     3478,
		"external-ip":        "auto-detect",
		"relay-ip":           "auto-detect",
		"min-port":           49152,
		"max-port":           65535,
		"verbose":            false,
		"fingerprint":        true,
		"lt-cred-mech":       true,
		"use-auth-secret":    true,
		"static-auth-secret": "generated-secret",
		"total-quota":        100,
		"user-quota":         50,
		"max-bps":            64000,
		"log-file":           "/var/log/coturn/coturn.log",
		"simple-log":         true,
	}
}

// Load Balancing

func (s *CoturnService) GetLoadBalancingInfo(region string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"is_active": true}
	if region != "" {
		filter["region"] = region
	}

	cursor, err := s.serversCollection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get load balancing info: %w", err)
	}
	defer cursor.Close(ctx)

	var servers []models.CoturnServer
	if err = cursor.All(ctx, &servers); err != nil {
		return nil, fmt.Errorf("failed to decode servers: %w", err)
	}

	// Calculate load distribution
	loadInfo := map[string]interface{}{
		"total_servers":   len(servers),
		"servers":         []map[string]interface{}{},
		"recommendations": []string{},
	}

	serverInfo := make([]map[string]interface{}, 0)
	totalCapacity := 0
	totalUsers := 0

	for _, server := range servers {
		loadPercent := 0.0
		if server.MaxUsers > 0 {
			loadPercent = float64(server.CurrentUsers) / float64(server.MaxUsers) * 100
		}

		info := map[string]interface{}{
			"id":            server.ID.Hex(),
			"name":          server.Name,
			"region":        server.Region,
			"priority":      server.Priority,
			"current_users": server.CurrentUsers,
			"max_users":     server.MaxUsers,
			"load_percent":  loadPercent,
			"status":        server.Status,
			"weight":        s.calculateServerWeight(&server),
		}

		serverInfo = append(serverInfo, info)
		totalCapacity += server.MaxUsers
		totalUsers += server.CurrentUsers
	}

	// Sort by weight (higher weight = better choice)
	sort.Slice(serverInfo, func(i, j int) bool {
		return serverInfo[i]["weight"].(float64) > serverInfo[j]["weight"].(float64)
	})

	loadInfo["servers"] = serverInfo

	// Generate recommendations
	recommendations := []string{}
	if len(servers) == 0 {
		recommendations = append(recommendations, "No active servers available")
	} else {
		overallLoad := 0.0
		if totalCapacity > 0 {
			overallLoad = float64(totalUsers) / float64(totalCapacity) * 100
		}

		if overallLoad > 90 {
			recommendations = append(recommendations, "System is near capacity - consider adding more servers")
		} else if overallLoad > 75 {
			recommendations = append(recommendations, "System load is high - monitor closely")
		}

		// Check for unbalanced load
		if len(serverInfo) > 1 {
			minLoad := serverInfo[len(serverInfo)-1]["load_percent"].(float64)
			maxLoad := serverInfo[0]["load_percent"].(float64)
			if maxLoad-minLoad > 30 {
				recommendations = append(recommendations, "Load is unbalanced between servers - consider adjusting weights")
			}
		}
	}

	loadInfo["recommendations"] = recommendations
	loadInfo["overall_load_percent"] = float64(totalUsers) / float64(totalCapacity) * 100
	loadInfo["generated_at"] = time.Now()

	return loadInfo, nil
}

func (s *CoturnService) calculateServerWeight(server *models.CoturnServer) float64 {
	weight := float64(server.Priority)

	// Adjust weight based on current load
	if server.MaxUsers > 0 {
		loadPercent := float64(server.CurrentUsers) / float64(server.MaxUsers) * 100
		loadFactor := 1.0 - (loadPercent / 100.0)
		weight *= loadFactor
	}

	// Adjust weight based on status
	switch server.Status {
	case "online":
		weight *= 1.0
	case "degraded":
		weight *= 0.5
	case "offline":
		weight *= 0.0
	}

	return weight
}

func (s *CoturnService) UpdateServerWeights(weights map[string]int, region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for serverIDStr, weight := range weights {
		serverID, err := primitive.ObjectIDFromHex(serverIDStr)
		if err != nil {
			continue
		}

		update := bson.M{
			"$set": bson.M{
				"priority":   weight,
				"updated_at": time.Now(),
			},
		}

		_, err = s.serversCollection.UpdateOne(ctx, bson.M{"_id": serverID}, update)
		if err != nil {
			logger.LogError(err, "Failed to update server weight", map[string]interface{}{
				"server_id": serverIDStr,
				"weight":    weight,
			})
		}
	}

	return nil
}

// Metrics and Monitoring

func (s *CoturnService) GetServerStats(serverID primitive.ObjectID) (map[string]interface{}, error) {
	server, err := s.GetServerByID(serverID)
	if err != nil {
		return nil, err
	}

	// Get recent metrics
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	filter := bson.M{
		"server_id": serverID.Hex(),
		"timestamp": bson.M{"$gte": oneHourAgo},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(60)

	cursor, err := s.metricsCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get server metrics: %w", err)
	}
	defer cursor.Close(ctx)

	var metrics []ServerMetrics
	if err = cursor.All(ctx, &metrics); err != nil {
		return nil, fmt.Errorf("failed to decode metrics: %w", err)
	}

	// Calculate statistics
	stats := map[string]interface{}{
		"server_id":    serverID.Hex(),
		"server_name":  server.Name,
		"region":       server.Region,
		"status":       server.Status,
		"is_active":    server.IsActive,
		"metrics":      metrics,
		"generated_at": time.Now(),
	}

	if len(metrics) > 0 {
		// Calculate averages
		totalConnections := 0
		totalCPU := 0.0
		totalMemory := 0.0
		totalResponseTime := 0.0

		for _, metric := range metrics {
			totalConnections += metric.ActiveConnections
			totalCPU += metric.CPUUsage
			totalMemory += metric.MemoryUsage
			totalResponseTime += metric.ResponseTimeMs
		}

		count := float64(len(metrics))
		stats["avg_connections"] = float64(totalConnections) / count
		stats["avg_cpu_usage"] = totalCPU / count
		stats["avg_memory_usage"] = totalMemory / count
		stats["avg_response_time"] = totalResponseTime / count
		stats["latest_metric"] = metrics[0]
	}

	return stats, nil
}

func (s *CoturnService) GetServerMetrics(serverID, period string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var timeFilter time.Time
	switch period {
	case "1h":
		timeFilter = time.Now().Add(-1 * time.Hour)
	case "24h":
		timeFilter = time.Now().Add(-24 * time.Hour)
	case "7d":
		timeFilter = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		timeFilter = time.Now().Add(-30 * 24 * time.Hour)
	default:
		timeFilter = time.Now().Add(-24 * time.Hour)
	}

	filter := bson.M{
		"server_id": serverID,
		"timestamp": bson.M{"$gte": timeFilter},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := s.metricsCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get server metrics: %w", err)
	}
	defer cursor.Close(ctx)

	var metrics []ServerMetrics
	if err = cursor.All(ctx, &metrics); err != nil {
		return nil, fmt.Errorf("failed to decode metrics: %w", err)
	}

	// Process metrics into chart data
	labels := make([]string, len(metrics))
	connectionData := make([]int, len(metrics))
	cpuData := make([]float64, len(metrics))
	memoryData := make([]float64, len(metrics))
	responseTimeData := make([]float64, len(metrics))

	for i, metric := range metrics {
		labels[i] = metric.Timestamp.Format("15:04")
		connectionData[i] = metric.ActiveConnections
		cpuData[i] = metric.CPUUsage
		memoryData[i] = metric.MemoryUsage
		responseTimeData[i] = metric.ResponseTimeMs
	}

	return map[string]interface{}{
		"server_id": serverID,
		"period":    period,
		"labels":    labels,
		"datasets": map[string]interface{}{
			"connections":   connectionData,
			"cpu_usage":     cpuData,
			"memory_usage":  memoryData,
			"response_time": responseTimeData,
		},
		"generated_at": time.Now(),
	}, nil
}

// Maintenance and Operations

func (s *CoturnService) ScheduleMaintenance(serverID, maintenanceType string, scheduledAt *time.Time, drainConnections bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	maintenance := map[string]interface{}{
		"server_id":         serverID,
		"maintenance_type":  maintenanceType,
		"scheduled_at":      scheduledAt,
		"drain_connections": drainConnections,
		"status":            "scheduled",
		"created_at":        time.Now(),
	}

	_, err := s.db.Collection("coturn_maintenance").InsertOne(ctx, maintenance)
	if err != nil {
		return fmt.Errorf("failed to schedule maintenance: %w", err)
	}

	// Create alert for scheduled maintenance
	serverObjID, _ := primitive.ObjectIDFromHex(serverID)
	s.createServerAlert(serverObjID, "maintenance_scheduled", "medium",
		fmt.Sprintf("Maintenance scheduled for server %s", serverID), maintenance)

	return nil
}

// Alert Management

func (s *CoturnService) GetAlerts(severity, region string) ([]ServerAlert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"status": bson.M{"$in": []string{"active", "acknowledged"}}}

	if severity != "" {
		filter["severity"] = severity
	}

	// If region specified, get server IDs for that region first
	if region != "" {
		serverIDs, err := s.getServerIDsForRegion(region)
		if err != nil {
			return nil, err
		}
		filter["server_id"] = bson.M{"$in": serverIDs}
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(100)

	cursor, err := s.alertsCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts: %w", err)
	}
	defer cursor.Close(ctx)

	var alerts []ServerAlert
	if err = cursor.All(ctx, &alerts); err != nil {
		return nil, fmt.Errorf("failed to decode alerts: %w", err)
	}

	return alerts, nil
}

func (s *CoturnService) AcknowledgeAlert(alertID, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alertObjID, err := primitive.ObjectIDFromHex(alertID)
	if err != nil {
		return fmt.Errorf("invalid alert ID: %w", err)
	}

	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":     "acknowledged",
			"acked_by":   userID,
			"acked_at":   &now,
			"updated_at": now,
		},
	}

	_, err = s.alertsCollection.UpdateOne(ctx, bson.M{"_id": alertObjID}, update)
	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	return nil
}

func (s *CoturnService) createServerAlert(serverID primitive.ObjectID, alertType, severity, message string, data map[string]interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alert := ServerAlert{
		ServerID:  serverID.Hex(),
		Type:      alertType,
		Severity:  severity,
		Message:   message,
		Data:      data,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := s.alertsCollection.InsertOne(ctx, alert)
	if err != nil {
		logger.LogError(err, "Failed to create server alert", map[string]interface{}{
			"server_id": serverID.Hex(),
			"type":      alertType,
			"severity":  severity,
		})
	}
}

// Reporting

func (s *CoturnService) GeneratePerformanceReport(period, region string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var timeFilter time.Time
	switch period {
	case "24h":
		timeFilter = time.Now().Add(-24 * time.Hour)
	case "7d":
		timeFilter = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		timeFilter = time.Now().Add(-30 * 24 * time.Hour)
	default:
		timeFilter = time.Now().Add(-24 * time.Hour)
	}

	// Build aggregation pipeline
	matchStage := bson.M{"timestamp": bson.M{"$gte": timeFilter}}
	if region != "" {
		matchStage["region"] = region
	}

	pipeline := []bson.M{
		{"$match": matchStage},
		{"$group": bson.M{
			"_id":                    nil,
			"avg_active_connections": bson.M{"$avg": "$active_connections"},
			"max_active_connections": bson.M{"$max": "$active_connections"},
			"avg_cpu_usage":          bson.M{"$avg": "$cpu_usage"},
			"max_cpu_usage":          bson.M{"$max": "$cpu_usage"},
			"avg_memory_usage":       bson.M{"$avg": "$memory_usage"},
			"max_memory_usage":       bson.M{"$max": "$memory_usage"},
			"avg_response_time":      bson.M{"$avg": "$response_time_ms"},
			"max_response_time":      bson.M{"$max": "$response_time_ms"},
			"avg_error_rate":         bson.M{"$avg": "$error_rate"},
			"max_error_rate":         bson.M{"$max": "$error_rate"},
			"total_bytes":            bson.M{"$sum": "$bytes_transferred"},
			"sample_count":           bson.M{"$sum": 1},
		}},
	}

	cursor, err := s.metricsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to generate performance report: %w", err)
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode performance report: %w", err)
	}

	report := map[string]interface{}{
		"period":       period,
		"region":       region,
		"generated_at": time.Now(),
		"time_range": map[string]interface{}{
			"start": timeFilter,
			"end":   time.Now(),
		},
	}

	if len(results) > 0 {
		report["metrics"] = results[0]
	} else {
		report["metrics"] = map[string]interface{}{
			"avg_active_connections": 0,
			"max_active_connections": 0,
			"avg_cpu_usage":          0,
			"max_cpu_usage":          0,
			"avg_memory_usage":       0,
			"max_memory_usage":       0,
			"avg_response_time":      0,
			"max_response_time":      0,
			"avg_error_rate":         0,
			"max_error_rate":         0,
			"total_bytes":            0,
			"sample_count":           0,
		}
	}

	// Get server count and status
	serverStats, _ := s.getServerStatusSummary(region)
	report["server_stats"] = serverStats

	// Get alert summary
	alertSummary, _ := s.getAlertSummary(region, timeFilter)
	report["alert_summary"] = alertSummary

	return report, nil
}

// Utility Methods

func (s *CoturnService) GetAvailableRegions() []string {
	return []string{"us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast"}
}

func (s *CoturnService) getServerIDsForRegion(region string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := s.serversCollection.Find(ctx, bson.M{"region": region}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var serverIDs []string
	for cursor.Next(ctx) {
		var server struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&server); err == nil {
			serverIDs = append(serverIDs, server.ID.Hex())
		}
	}

	return serverIDs, nil
}

func (s *CoturnService) getServerStatusSummary(region string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{}
	if region != "" {
		filter["region"] = region
	}

	pipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id":              nil,
			"total_servers":    bson.M{"$sum": 1},
			"online_servers":   bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "online"}}, 1, 0}}},
			"offline_servers":  bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "offline"}}, 1, 0}}},
			"degraded_servers": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "degraded"}}, 1, 0}}},
		}},
	}

	cursor, err := s.serversCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[0], nil
	}

	return map[string]interface{}{
		"total_servers":    0,
		"online_servers":   0,
		"offline_servers":  0,
		"degraded_servers": 0,
	}, nil
}

func (s *CoturnService) getAlertSummary(region string, since time.Time) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"created_at": bson.M{"$gte": since}}

	if region != "" {
		serverIDs, err := s.getServerIDsForRegion(region)
		if err != nil {
			return nil, err
		}
		filter["server_id"] = bson.M{"$in": serverIDs}
	}

	pipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id":                 nil,
			"total_alerts":        bson.M{"$sum": 1},
			"critical_alerts":     bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$severity", "critical"}}, 1, 0}}},
			"high_alerts":         bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$severity", "high"}}, 1, 0}}},
			"medium_alerts":       bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$severity", "medium"}}, 1, 0}}},
			"low_alerts":          bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$severity", "low"}}, 1, 0}}},
			"acknowledged_alerts": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "acknowledged"}}, 1, 0}}},
		}},
	}

	cursor, err := s.alertsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[0], nil
	}

	return map[string]interface{}{
		"total_alerts":        0,
		"critical_alerts":     0,
		"high_alerts":         0,
		"medium_alerts":       0,
		"low_alerts":          0,
		"acknowledged_alerts": 0,
	}, nil
}

func (s *CoturnService) cleanupServerData(serverID primitive.ObjectID) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverIDStr := serverID.Hex()

	// Delete metrics
	s.metricsCollection.DeleteMany(ctx, bson.M{"server_id": serverIDStr})

	// Delete alerts
	s.alertsCollection.DeleteMany(ctx, bson.M{"server_id": serverIDStr})

	// Delete configurations
	s.configCollection.DeleteMany(ctx, bson.M{"server_id": serverIDStr})

	logger.Info("Cleaned up server data", map[string]interface{}{
		"server_id": serverIDStr,
	})
}
