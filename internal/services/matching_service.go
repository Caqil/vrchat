package services

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"vrchat/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MatchingService struct {
	db                 *mongo.Database
	queueCollection    *mongo.Collection
	preferencesCollection *mongo.Collection
	statsCollection    *mongo.Collection
	mutex              sync.RWMutex
	memoryQueue        map[string]*QueueEntry
	matchingInProgress map[string]bool
}

type MatchingPreferences struct {
	UserID             string   `bson:"user_id" json:"user_id"`
	ChatType           string   `bson:"chat_type" json:"chat_type"` // text, video, audio
	Language           string   `bson:"language" json:"language"`
	Region             string   `bson:"region" json:"region"`
	Interests          []string `bson:"interests" json:"interests"`
	AgeRange           AgeRange `bson:"age_range" json:"age_range"`
	MaxWaitTime        int      `bson:"max_wait_time" json:"max_wait_time"` // seconds
	AllowCrossRegion   bool     `bson:"allow_cross_region" json:"allow_cross_region"`
	AllowCrossLanguage bool     `bson:"allow_cross_language" json:"allow_cross_language"`
	RequireInterests   bool     `bson:"require_interests" json:"require_interests"`
	CreatedAt          time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time `bson:"updated_at" json:"updated_at"`
}

type AgeRange struct {
	Min int `bson:"min" json:"min"`
	Max int `bson:"max" json:"max"`
}

type QueueEntry struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	UserID        string               `bson:"user_id" json:"user_id"`
	Preferences   MatchingPreferences  `bson:"preferences" json:"preferences"`
	QueuedAt      time.Time           `bson:"queued_at" json:"queued_at"`
	Priority      int                 `bson:"priority" json:"priority"`
	Region        string              `bson:"region" json:"region"`
	Language      string              `bson:"language" json:"language"`
	ChatType      string              `bson:"chat_type" json:"chat_type"`
	Interests     []string            `bson:"interests" json:"interests"`
	Status        string              `bson:"status" json:"status"` // waiting, matching, matched, expired
	AttemptCount  int                 `bson:"attempt_count" json:"attempt_count"`
	LastAttemptAt *time.Time          `bson:"last_attempt_at,omitempty" json:"last_attempt_at,omitempty"`
	ExpiresAt     time.Time           `bson:"expires_at" json:"expires_at"`
}

type MatchResult struct {
	PartnerID string      `json:"partner_id"`
	Partner   UserInfo    `json:"partner"`
	QueueTime int64       `json:"queue_time_ms"`
	MatchScore float64    `json:"match_score"`
	MatchedOn  []string   `json:"matched_on"` // criteria that matched
}

type UserInfo struct {
	ID        string   `json:"id"`
	Region    string   `json:"region"`
	Language  string   `json:"language"`
	Interests []string `json:"interests,omitempty"`
	IsGuest   bool     `json:"is_guest"`
}

type QueueStatus struct {
	Position      int    `json:"position"`
	EstimatedWait int    `json:"estimated_wait_seconds"`
	QueueSize     int    `json:"queue_size"`
	ChatType      string `json:"chat_type"`
	QueuedAt      time.Time `json:"queued_at"`
}

type MatchingStats struct {
	ID                  primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Date                time.Time          `bson:"date" json:"date"`
	TotalMatches        int                `bson:"total_matches" json:"total_matches"`
	SuccessfulMatches   int                `bson:"successful_matches" json:"successful_matches"`
	AverageWaitTime     float64            `bson:"average_wait_time" json:"average_wait_time"`
	ChatTypeBreakdown   map[string]int     `bson:"chat_type_breakdown" json:"chat_type_breakdown"`
	RegionBreakdown     map[string]int     `bson:"region_breakdown" json:"region_breakdown"`
	LanguageBreakdown   map[string]int     `bson:"language_breakdown" json:"language_breakdown"`
	QueueSizes          map[string]int     `bson:"queue_sizes" json:"queue_sizes"`
}

func NewMatchingService(db *mongo.Database) *MatchingService {
	service := &MatchingService{
		db:                 db,
		queueCollection:    db.Collection("matching_queue"),
		preferencesCollection: db.Collection("matching_preferences"),
		statsCollection:    db.Collection("matching_stats"),
		memoryQueue:        make(map[string]*QueueEntry),
		matchingInProgress: make(map[string]bool),
	}

	// Start background tasks
	go service.startMatchingEngine()
	go service.startQueueCleanup()
	go service.startStatsAggregation()

	return service
}

// Core Matching Logic

func (s *MatchingService) FindMatch(preferences *MatchingPreferences) (*MatchResult, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if user is already in queue or being matched
	if s.matchingInProgress[preferences.UserID] {
		return nil, fmt.Errorf("user is already being matched")
	}

	// Mark user as being matched
	s.matchingInProgress[preferences.UserID] = true
	defer func() {
		delete(s.matchingInProgress, preferences.UserID)
	}()

	// Store/update user preferences
	s.storeUserPreferences(preferences)

	// Try to find immediate match
	match, err := s.findImmediateMatch(preferences)
	if err != nil {
		return nil, err
	}

	if match != nil {
		// Remove matched user from queue
		s.removeFromMemoryQueue(match.PartnerID)
		
		// Log successful match
		logger.LogUserAction(preferences.UserID, "match_found", map[string]interface{}{
			"partner_id":   match.PartnerID,
			"match_score":  match.MatchScore,
			"queue_time":   match.QueueTime,
			"matched_on":   match.MatchedOn,
			"chat_type":    preferences.ChatType,
		})

		// Update matching stats
		s.updateMatchingStats(preferences, match)

		return match, nil
	}

	// No immediate match found
	return nil, fmt.Errorf("no match found")
}

func (s *MatchingService) findImmediateMatch(preferences *MatchingPreferences) (*MatchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build match filter
	filter := s.buildMatchFilter(preferences)

	// Find potential matches from queue
	opts := options.Find().
		SetSort(bson.D{{Key: "queued_at", Value: 1}}). // FIFO
		SetLimit(20) // Limit candidates for performance

	cursor, err := s.queueCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to find potential matches: %w", err)
	}
	defer cursor.Close(ctx)

	var candidates []QueueEntry
	if err = cursor.All(ctx, &candidates); err != nil {
		return nil, fmt.Errorf("failed to decode candidates: %w", err)
	}

	// Score and rank candidates
	bestMatch := s.findBestMatch(preferences, candidates)
	if bestMatch == nil {
		return nil, nil
	}

	// Create match result
	queueTime := time.Since(bestMatch.QueuedAt).Milliseconds()
	
	match := &MatchResult{
		PartnerID:  bestMatch.UserID,
		QueueTime:  queueTime,
		MatchScore: s.calculateMatchScore(preferences, &bestMatch.Preferences),
		MatchedOn:  s.getMatchCriteria(preferences, &bestMatch.Preferences),
		Partner: UserInfo{
			ID:        bestMatch.UserID,
			Region:    bestMatch.Region,
			Language:  bestMatch.Language,
			Interests: bestMatch.Interests,
			IsGuest:   true, // Assume guest for now
		},
	}

	return match, nil
}

func (s *MatchingService) buildMatchFilter(preferences *MatchingPreferences) bson.M {
	filter := bson.M{
		"status":    "waiting",
		"chat_type": preferences.ChatType,
		"user_id":   bson.M{"$ne": preferences.UserID}, // Don't match with self
		"expires_at": bson.M{"$gt": time.Now()},        // Not expired
	}

	// Language matching
	if !preferences.AllowCrossLanguage {
		filter["language"] = preferences.Language
	}

	// Region matching
	if !preferences.AllowCrossRegion {
		filter["region"] = preferences.Region
	}

	return filter
}

func (s *MatchingService) findBestMatch(preferences *MatchingPreferences, candidates []QueueEntry) *QueueEntry {
	if len(candidates) == 0 {
		return nil
	}

	type scoredCandidate struct {
		entry *QueueEntry
		score float64
	}

	scored := make([]scoredCandidate, 0, len(candidates))

	for i := range candidates {
		candidate := &candidates[i]
		score := s.calculateMatchScore(preferences, &candidate.Preferences)
		
		// Apply wait time bonus (longer wait = higher priority)
		waitTimeBonus := math.Min(float64(time.Since(candidate.QueuedAt).Minutes()), 30) * 0.1
		score += waitTimeBonus

		scored = append(scored, scoredCandidate{
			entry: candidate,
			score: score,
		})
	}

	// Sort by score (highest first)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	// Return best match if score is above threshold
	if scored[0].score >= 0.3 { // Minimum match threshold
		return scored[0].entry
	}

	return nil
}

func (s *MatchingService) calculateMatchScore(prefs1, prefs2 *MatchingPreferences) float64 {
	score := 0.0
	maxScore := 0.0

	// Chat type (must match)
	maxScore += 1.0
	if prefs1.ChatType == prefs2.ChatType {
		score += 1.0
	} else {
		return 0.0 // Chat type must match
	}

	// Language match
	maxScore += 0.8
	if prefs1.Language == prefs2.Language {
		score += 0.8
	}

	// Region match
	maxScore += 0.6
	if prefs1.Region == prefs2.Region {
		score += 0.6
	}

	// Interest overlap
	maxScore += 0.7
	if len(prefs1.Interests) > 0 && len(prefs2.Interests) > 0 {
		overlap := s.calculateInterestOverlap(prefs1.Interests, prefs2.Interests)
		score += overlap * 0.7
	}

	// Age range compatibility (if both specified)
	if (prefs1.AgeRange.Min > 0 || prefs1.AgeRange.Max > 0) && 
	   (prefs2.AgeRange.Min > 0 || prefs2.AgeRange.Max > 0) {
		maxScore += 0.4
		if s.ageRangesOverlap(prefs1.AgeRange, prefs2.AgeRange) {
			score += 0.4
		}
	}

	if maxScore == 0 {
		return 0
	}

	return score / maxScore
}

func (s *MatchingService) calculateInterestOverlap(interests1, interests2 []string) float64 {
	if len(interests1) == 0 || len(interests2) == 0 {
		return 0.0
	}

	interestSet := make(map[string]bool)
	for _, interest := range interests1 {
		interestSet[interest] = true
	}

	common := 0
	for _, interest := range interests2 {
		if interestSet[interest] {
			common++
		}
	}

	// Jaccard similarity
	union := len(interests1) + len(interests2) - common
	if union == 0 {
		return 0.0
	}

	return float64(common) / float64(union)
}

func (s *MatchingService) ageRangesOverlap(range1, range2 AgeRange) bool {
	// If either range is not specified, consider as compatible
	if (range1.Min == 0 && range1.Max == 0) || (range2.Min == 0 && range2.Max == 0) {
		return true
	}

	// Set defaults if not specified
	if range1.Min == 0 {
		range1.Min = 18
	}
	if range1.Max == 0 {
		range1.Max = 100
	}
	if range2.Min == 0 {
		range2.Min = 18
	}
	if range2.Max == 0 {
		range2.Max = 100
	}

	return range1.Min <= range2.Max && range2.Min <= range1.Max
}

func (s *MatchingService) getMatchCriteria(prefs1, prefs2 *MatchingPreferences) []string {
	criteria := []string{}

	if prefs1.ChatType == prefs2.ChatType {
		criteria = append(criteria, "chat_type")
	}

	if prefs1.Language == prefs2.Language {
		criteria = append(criteria, "language")
	}

	if prefs1.Region == prefs2.Region {
		criteria = append(criteria, "region")
	}

	if len(prefs1.Interests) > 0 && len(prefs2.Interests) > 0 {
		overlap := s.calculateInterestOverlap(prefs1.Interests, prefs2.Interests)
		if overlap > 0.1 {
			criteria = append(criteria, "interests")
		}
	}

	if s.ageRangesOverlap(prefs1.AgeRange, prefs2.AgeRange) {
		criteria = append(criteria, "age_range")
	}

	return criteria
}

// Queue Management

func (s *MatchingService) AddToQueue(preferences *MatchingPreferences) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if user is already in queue
	if _, exists := s.memoryQueue[preferences.UserID]; exists {
		return s.getQueuePosition(preferences.UserID), nil
	}

	// Create queue entry
	queueEntry := &QueueEntry{
		UserID:      preferences.UserID,
		Preferences: *preferences,
		QueuedAt:    time.Now(),
		Priority:    s.calculateQueuePriority(preferences),
		Region:      preferences.Region,
		Language:    preferences.Language,
		ChatType:    preferences.ChatType,
		Interests:   preferences.Interests,
		Status:      "waiting",
		ExpiresAt:   time.Now().Add(time.Duration(preferences.MaxWaitTime) * time.Second),
	}

	// Set default expiry if not specified
	if preferences.MaxWaitTime == 0 {
		queueEntry.ExpiresAt = time.Now().Add(10 * time.Minute)
	}

	// Store in database
	result, err := s.queueCollection.InsertOne(ctx, queueEntry)
	if err != nil {
		return 0, fmt.Errorf("failed to add to queue: %w", err)
	}

	queueEntry.ID = result.InsertedID.(primitive.ObjectID)

	// Store in memory for faster access
	s.memoryQueue[preferences.UserID] = queueEntry

	// Store user preferences
	s.storeUserPreferences(preferences)

	position := s.getQueuePosition(preferences.UserID)

	logger.LogUserAction(preferences.UserID, "added_to_queue", map[string]interface{}{
		"chat_type": preferences.ChatType,
		"region":    preferences.Region,
		"language":  preferences.Language,
		"position":  position,
		"priority":  queueEntry.Priority,
	})

	return position, nil
}

func (s *MatchingService) calculateQueuePriority(preferences *MatchingPreferences) int {
	priority := 100 // Base priority

	// Higher priority for video/audio chats (typically harder to match)
	switch preferences.ChatType {
	case "video":
		priority += 20
	case "audio":
		priority += 10
	}

	// Lower priority for users with very specific requirements
	if !preferences.AllowCrossLanguage {
		priority -= 5
	}
	if !preferences.AllowCrossRegion {
		priority -= 5
	}
	if preferences.RequireInterests && len(preferences.Interests) > 5 {
		priority -= 10
	}

	// Randomize slightly to prevent starvation
	priority += rand.Intn(10) - 5

	return priority
}

func (s *MatchingService) getQueuePosition(userID string) int {
	// Get all waiting entries for the same chat type
	userEntry, exists := s.memoryQueue[userID]
	if !exists {
		return 0
	}

	position := 1
	for _, entry := range s.memoryQueue {
		if entry.UserID != userID && 
		   entry.ChatType == userEntry.ChatType && 
		   entry.Status == "waiting" &&
		   (entry.QueuedAt.Before(userEntry.QueuedAt) || 
		    (entry.QueuedAt.Equal(userEntry.QueuedAt) && entry.Priority > userEntry.Priority)) {
			position++
		}
	}

	return position
}

func (s *MatchingService) RemoveFromQueue(userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Remove from memory
	delete(s.memoryQueue, userID)
	delete(s.matchingInProgress, userID)

	// Remove from database
	_, err := s.queueCollection.DeleteOne(ctx, bson.M{"user_id": userID})
	if err != nil {
		logger.LogError(err, "Failed to remove user from queue", map[string]interface{}{
			"user_id": userID,
		})
		return fmt.Errorf("failed to remove from queue: %w", err)
	}

	logger.LogUserAction(userID, "removed_from_queue", nil)

	return nil
}

func (s *MatchingService) removeFromMemoryQueue(userID string) {
	delete(s.memoryQueue, userID)
}

func (s *MatchingService) GetQueueStatus(userID string) (*QueueStatus, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.memoryQueue[userID]
	if !exists {
		return nil, fmt.Errorf("user not in queue")
	}

	position := s.getQueuePosition(userID)
	estimatedWait := s.GetEstimatedWaitTime(entry.ChatType)
	queueSize := s.getQueueSizeForChatType(entry.ChatType)

	status := &QueueStatus{
		Position:      position,
		EstimatedWait: estimatedWait,
		QueueSize:     queueSize,
		ChatType:      entry.ChatType,
		QueuedAt:      entry.QueuedAt,
	}

	return status, nil
}

func (s *MatchingService) getQueueSizeForChatType(chatType string) int {
	size := 0
	for _, entry := range s.memoryQueue {
		if entry.ChatType == chatType && entry.Status == "waiting" {
			size++
		}
	}
	return size
}

func (s *MatchingService) GetEstimatedWaitTime(chatType string) int {
	// Base wait times by chat type (in seconds)
	baseWaitTimes := map[string]int{
		"text":  30,  // 30 seconds
		"audio": 60,  // 1 minute
		"video": 120, // 2 minutes
	}

	baseWait, exists := baseWaitTimes[chatType]
	if !exists {
		baseWait = 60
	}

	// Adjust based on current queue size
	queueSize := s.getQueueSizeForChatType(chatType)
	
	// More people in queue = longer wait
	queueMultiplier := 1.0 + (float64(queueSize) * 0.1)
	
	// Cap the multiplier
	if queueMultiplier > 3.0 {
		queueMultiplier = 3.0
	}

	estimatedWait := int(float64(baseWait) * queueMultiplier)

	// Add some randomness to avoid everyone expecting the same wait time
	randomFactor := rand.Float64()*0.4 + 0.8 // 0.8 to 1.2
	estimatedWait = int(float64(estimatedWait) * randomFactor)

	return estimatedWait
}

// Preferences Management

func (s *MatchingService) GetLastPreferences(userID string) (*MatchingPreferences, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var preferences MatchingPreferences
	err := s.preferencesCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&preferences)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no previous preferences found")
		}
		return nil, fmt.Errorf("failed to get preferences: %w", err)
	}

	return &preferences, nil
}

func (s *MatchingService) UpdatePreferences(preferences *MatchingPreferences) error {
	preferences.UpdatedAt = time.Now()
	return s.storeUserPreferences(preferences)
}

func (s *MatchingService) storeUserPreferences(preferences *MatchingPreferences) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if preferences.CreatedAt.IsZero() {
		preferences.CreatedAt = time.Now()
	}
	preferences.UpdatedAt = time.Now()

	// Set defaults
	if preferences.MaxWaitTime == 0 {
		preferences.MaxWaitTime = 600 // 10 minutes
	}

	opts := options.Replace().SetUpsert(true)
	_, err := s.preferencesCollection.ReplaceOne(
		ctx, 
		bson.M{"user_id": preferences.UserID}, 
		preferences, 
		opts,
	)

	if err != nil {
		logger.LogError(err, "Failed to store user preferences", map[string]interface{}{
			"user_id": preferences.UserID,
		})
		return fmt.Errorf("failed to store preferences: %w", err)
	}

	return nil
}

// Background Tasks

func (s *MatchingService) startMatchingEngine() {
	ticker := time.NewTicker(5 * time.Second) // Run every 5 seconds
	defer ticker.Stop()

	for range ticker.C {
		s.runMatchingCycle()
	}
}

func (s *MatchingService) runMatchingCycle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get users waiting to be matched
	waitingUsers := make([]*QueueEntry, 0)
	for _, entry := range s.memoryQueue {
		if entry.Status == "waiting" && !s.matchingInProgress[entry.UserID] {
			waitingUsers = append(waitingUsers, entry)
		}
	}

	// Sort by wait time (oldest first) and priority
	sort.Slice(waitingUsers, func(i, j int) bool {
		if waitingUsers[i].Priority != waitingUsers[j].Priority {
			return waitingUsers[i].Priority > waitingUsers[j].Priority
		}
		return waitingUsers[i].QueuedAt.Before(waitingUsers[j].QueuedAt)
	})

	// Try to match users
	matched := make(map[string]bool)
	
	for i, user1 := range waitingUsers {
		if matched[user1.UserID] {
			continue
		}

		for j := i + 1; j < len(waitingUsers); j++ {
			user2 := waitingUsers[j]
			
			if matched[user2.UserID] || user1.ChatType != user2.ChatType {
				continue
			}

			// Check if they can be matched
			score := s.calculateMatchScore(&user1.Preferences, &user2.Preferences)
			
			// Lower threshold for users who have been waiting longer
			waitTime1 := time.Since(user1.QueuedAt).Minutes()
			waitTime2 := time.Since(user2.QueuedAt).Minutes()
			avgWaitTime := (waitTime1 + waitTime2) / 2
			
			threshold := 0.3 - (avgWaitTime * 0.01) // Lower threshold as wait time increases
			if threshold < 0.1 {
				threshold = 0.1 // Minimum threshold
			}

			if score >= threshold {
				// Mark users as matched
				matched[user1.UserID] = true
				matched[user2.UserID] = true

				// Create match results and notify (this would be handled by your chat service)
				go s.notifyMatch(user1, user2, score)
				
				// Remove from queue
				s.removeFromMemoryQueue(user1.UserID)
				s.removeFromMemoryQueue(user2.UserID)

				break
			}
		}
	}
}

func (s *MatchingService) notifyMatch(user1, user2 *QueueEntry, score float64) {
	// This would typically send a notification to both users
	// For now, we'll just log the match
	logger.Info("Users matched by background engine", map[string]interface{}{
		"user1_id":    user1.UserID,
		"user2_id":    user2.UserID,
		"match_score": score,
		"user1_wait_time": time.Since(user1.QueuedAt).Seconds(),
		"user2_wait_time": time.Since(user2.QueuedAt).Seconds(),
	})

	// Update matching stats
	s.recordBackgroundMatch(user1, user2, score)
}

func (s *MatchingService) startQueueCleanup() {
	ticker := time.NewTicker(1 * time.Minute) // Run every minute
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupExpiredEntries()
	}
}

func (s *MatchingService) cleanupExpiredEntries() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	expiredUsers := make([]string, 0)

	// Find expired entries
	for userID, entry := range s.memoryQueue {
		if now.After(entry.ExpiresAt) {
			expiredUsers = append(expiredUsers, userID)
		}
	}

	// Remove expired entries
	for _, userID := range expiredUsers {
		delete(s.memoryQueue, userID)
		delete(s.matchingInProgress, userID)

		logger.LogUserAction(userID, "queue_expired", map[string]interface{}{
			"wait_time_seconds": time.Since(s.memoryQueue[userID].QueuedAt).Seconds(),
		})
	}

	// Clean up database
	if len(expiredUsers) > 0 {
		filter := bson.M{
			"$or": []bson.M{
				{"expires_at": bson.M{"$lt": now}},
				{"user_id": bson.M{"$in": expiredUsers}},
			},
		}

		result, err := s.queueCollection.DeleteMany(ctx, filter)
		if err != nil {
			logger.LogError(err, "Failed to cleanup expired queue entries", nil)
		} else if result.DeletedCount > 0 {
			logger.Info("Cleaned up expired queue entries", map[string]interface{}{
				"deleted_count": result.DeletedCount,
			})
		}
	}
}

func (s *MatchingService) startStatsAggregation() {
	ticker := time.NewTicker(1 * time.Hour) // Run every hour
	defer ticker.Stop()

	for range ticker.C {
		s.aggregateHourlyStats()
	}
}

func (s *MatchingService) aggregateHourlyStats() {
	// This would collect statistics about matching performance
	// For now, we'll just log current queue state
	s.mutex.RLock()
	queueSizes := make(map[string]int)
	for _, entry := range s.memoryQueue {
		queueSizes[entry.ChatType]++
	}
	s.mutex.RUnlock()

	logger.Info("Hourly matching stats", map[string]interface{}{
		"queue_sizes": queueSizes,
		"timestamp":   time.Now(),
	})
}

// Statistics and Reporting

func (s *MatchingService) updateMatchingStats(preferences *MatchingPreferences, match *MatchResult) {
	// This would update statistics about successful matches
	// Implementation would depend on your analytics requirements
	logger.Info("Match completed", map[string]interface{}{
		"user_id":      preferences.UserID,
		"partner_id":   match.PartnerID,
		"chat_type":    preferences.ChatType,
		"region":       preferences.Region,
		"language":     preferences.Language,
		"match_score":  match.MatchScore,
		"queue_time":   match.QueueTime,
		"matched_on":   match.MatchedOn,
	})
}

func (s *MatchingService) recordBackgroundMatch(user1, user2 *QueueEntry, score float64) {
	logger.Info("Background match recorded", map[string]interface{}{
		"user1_id":    user1.UserID,
		"user2_id":    user2.UserID,
		"match_score": score,
		"chat_type":   user1.ChatType,
	})
}

// Utility Methods

func (s *MatchingService) GetQueueSize() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	count := 0
	for _, entry := range s.memoryQueue {
		if entry.Status == "waiting" {
			count++
		}
	}

	return int64(count)
}

func (s *MatchingService) GetQueueSizes() map[string]int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sizes := map[string]int{
		"text":  0,
		"video": 0,
		"audio": 0,
	}

	for _, entry := range s.memoryQueue {
		if entry.Status == "waiting" {
			sizes[entry.ChatType]++
		}
	}

	return sizes
}

func (s *MatchingService) GetMatchingStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	totalInQueue := len(s.memoryQueue)
	waitingCount := 0
	totalWaitTime := 0.0

	chatTypeCounts := make(map[string]int)
	regionCounts := make(map[string]int)
	languageCounts := make(map[string]int)

	now := time.Now()

	for _, entry := range s.memoryQueue {
		if entry.Status == "waiting" {
			waitingCount++
			totalWaitTime += now.Sub(entry.QueuedAt).Seconds()
		}

		chatTypeCounts[entry.ChatType]++
		regionCounts[entry.Region]++
		languageCounts[entry.Language]++
	}

	avgWaitTime := 0.0
	if waitingCount > 0 {
		avgWaitTime = totalWaitTime / float64(waitingCount)
	}

	return map[string]interface{}{
		"total_in_queue":       totalInQueue,
		"waiting_count":        waitingCount,
		"average_wait_time":    avgWaitTime,
		"chat_type_breakdown":  chatTypeCounts,
		"region_breakdown":     regionCounts,
		"language_breakdown":   languageCounts,
		"generated_at":         now,
	}
}