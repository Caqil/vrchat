package services

import (
	"context"
	"fmt"
	"time"

	"vrchat/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ChatService struct {
	db            *mongo.Database
	collection    *mongo.Collection
	msgCollection *mongo.Collection
}

type Chat struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RoomID    string             `bson:"room_id" json:"room_id"`
	User1ID   primitive.ObjectID `bson:"user1_id" json:"user1_id"`
	User2ID   primitive.ObjectID `bson:"user2_id" json:"user2_id"`
	Status    string             `bson:"status" json:"status"`       // waiting, active, ended
	ChatType  string             `bson:"chat_type" json:"chat_type"` // text, video, audio
	StartedAt time.Time          `bson:"started_at" json:"started_at"`
	EndedAt   *time.Time         `bson:"ended_at,omitempty" json:"ended_at,omitempty"`
	Duration  int64              `bson:"duration" json:"duration"` // in seconds
	Region    string             `bson:"region" json:"region"`
	Language  string             `bson:"language" json:"language"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

type Message struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	RoomID    string                 `bson:"room_id" json:"room_id"`
	UserID    string                 `bson:"user_id" json:"user_id"`
	Content   string                 `bson:"content" json:"content"`
	Type      string                 `bson:"type" json:"type"` // text, image, file, emoji
	Timestamp time.Time              `bson:"timestamp" json:"timestamp"`
	Flagged   bool                   `bson:"flagged" json:"flagged"`
	Edited    bool                   `bson:"edited" json:"edited"`
	EditedAt  *time.Time             `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	Deleted   bool                   `bson:"deleted" json:"deleted"`
	DeletedAt *time.Time             `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	MetaData  map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
}

func NewChatService(db *mongo.Database) *ChatService {
	return &ChatService{
		db:            db,
		collection:    db.Collection("chats"),
		msgCollection: db.Collection("messages"),
	}
}

// Chat Management

func (s *ChatService) CreateChat(roomID, user1ID, user2ID, chatType string) (*Chat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user1ObjectID, err := primitive.ObjectIDFromHex(user1ID)
	if err != nil {
		return nil, fmt.Errorf("invalid user1ID: %w", err)
	}

	user2ObjectID, err := primitive.ObjectIDFromHex(user2ID)
	if err != nil {
		return nil, fmt.Errorf("invalid user2ID: %w", err)
	}

	chat := &Chat{
		RoomID:    roomID,
		User1ID:   user1ObjectID,
		User2ID:   user2ObjectID,
		Status:    "active",
		ChatType:  chatType,
		StartedAt: time.Now(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result, err := s.collection.InsertOne(ctx, chat)
	if err != nil {
		logger.LogError(err, "Failed to create chat", map[string]interface{}{
			"room_id":   roomID,
			"user1_id":  user1ID,
			"user2_id":  user2ID,
			"chat_type": chatType,
		})
		return nil, fmt.Errorf("failed to create chat: %w", err)
	}

	chat.ID = result.InsertedID.(primitive.ObjectID)
	return chat, nil
}

func (s *ChatService) GetChatByRoomID(roomID string) (*Chat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var chat Chat
	err := s.collection.FindOne(ctx, bson.M{"room_id": roomID}).Decode(&chat)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("chat not found")
		}
		return nil, fmt.Errorf("failed to get chat: %w", err)
	}

	return &chat, nil
}

func (s *ChatService) GetChatByID(chatID primitive.ObjectID) (*Chat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var chat Chat
	err := s.collection.FindOne(ctx, bson.M{"_id": chatID}).Decode(&chat)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("chat not found")
		}
		return nil, fmt.Errorf("failed to get chat: %w", err)
	}

	return &chat, nil
}

func (s *ChatService) EndChat(roomID, userID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the chat first to calculate duration
	chat, err := s.GetChatByRoomID(roomID)
	if err != nil {
		return err
	}

	endTime := time.Now()
	duration := int64(endTime.Sub(chat.StartedAt).Seconds())

	update := bson.M{
		"$set": bson.M{
			"status":     "ended",
			"ended_at":   endTime,
			"duration":   duration,
			"end_reason": reason,
			"ended_by":   userID,
			"updated_at": time.Now(),
		},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"room_id": roomID}, update)
	if err != nil {
		logger.LogError(err, "Failed to end chat", map[string]interface{}{
			"room_id": roomID,
			"user_id": userID,
			"reason":  reason,
		})
		return fmt.Errorf("failed to end chat: %w", err)
	}

	return nil
}

func (s *ChatService) EndChatByID(chatID primitive.ObjectID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the chat first to calculate duration
	chat, err := s.GetChatByID(chatID)
	if err != nil {
		return err
	}

	endTime := time.Now()
	duration := int64(endTime.Sub(chat.StartedAt).Seconds())

	update := bson.M{
		"$set": bson.M{
			"status":     "ended",
			"ended_at":   endTime,
			"duration":   duration,
			"end_reason": reason,
			"updated_at": time.Now(),
		},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": chatID}, update)
	if err != nil {
		logger.LogError(err, "Failed to end chat", map[string]interface{}{
			"chat_id": chatID.Hex(),
			"reason":  reason,
		})
		return fmt.Errorf("failed to end chat: %w", err)
	}

	return nil
}

func (s *ChatService) GetUserActiveChats(userID string) ([]Chat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid userID: %w", err)
	}

	filter := bson.M{
		"status": "active",
		"$or": []bson.M{
			{"user1_id": userObjectID},
			{"user2_id": userObjectID},
		},
	}

	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get active chats: %w", err)
	}
	defer cursor.Close(ctx)

	var chats []Chat
	if err = cursor.All(ctx, &chats); err != nil {
		return nil, fmt.Errorf("failed to decode chats: %w", err)
	}

	return chats, nil
}

func (s *ChatService) GetChatMessages(roomID string, page, limit int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	skip := (page - 1) * limit

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "timestamp", Value: -1}}) // Most recent first

	filter := bson.M{
		"room_id": roomID,
		"deleted": bson.M{"$ne": true},
	}

	cursor, err := s.msgCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}
	defer cursor.Close(ctx)

	var messages []Message
	if err = cursor.All(ctx, &messages); err != nil {
		return nil, fmt.Errorf("failed to decode messages: %w", err)
	}

	return messages, nil
}

func (s *ChatService) GetChatMessagesByID(chatID primitive.ObjectID) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get chat to find room_id
	chat, err := s.GetChatByID(chatID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"room_id": chat.RoomID,
		"deleted": bson.M{"$ne": true},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}) // Chronological order

	cursor, err := s.msgCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}
	defer cursor.Close(ctx)

	var messages []Message
	if err = cursor.All(ctx, &messages); err != nil {
		return nil, fmt.Errorf("failed to decode messages: %w", err)
	}

	return messages, nil
}

// Statistics and Analytics

func (s *ChatService) GetActiveChats() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.collection.CountDocuments(ctx, bson.M{"status": "active"})
	if err != nil {
		logger.LogError(err, "Failed to count active chats", nil)
		return 0
	}

	return count
}

func (s *ChatService) GetTotalChats() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		logger.LogError(err, "Failed to count total chats", nil)
		return 0
	}

	return count
}

func (s *ChatService) GetActiveChatsWithDetails() []map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$match": bson.M{"status": "active"}},
		{"$lookup": bson.M{
			"from":         "users",
			"localField":   "user1_id",
			"foreignField": "_id",
			"as":           "user1",
		}},
		{"$lookup": bson.M{
			"from":         "users",
			"localField":   "user2_id",
			"foreignField": "_id",
			"as":           "user2",
		}},
		{"$project": bson.M{
			"room_id":    1,
			"chat_type":  1,
			"started_at": 1,
			"duration_min": bson.M{"$divide": []interface{}{
				bson.M{"$subtract": []interface{}{"$$NOW", "$started_at"}},
				60000, // milliseconds to minutes
			}},
			"user1_region": bson.M{"$arrayElemAt": []interface{}{"$user1.region", 0}},
			"user2_region": bson.M{"$arrayElemAt": []interface{}{"$user2.region", 0}},
		}},
		{"$limit": 100}, // Limit for performance
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		logger.LogError(err, "Failed to get active chats with details", nil)
		return []map[string]interface{}{}
	}
	defer cursor.Close(ctx)

	var chats []map[string]interface{}
	if err = cursor.All(ctx, &chats); err != nil {
		logger.LogError(err, "Failed to decode active chats", nil)
		return []map[string]interface{}{}
	}

	return chats
}

func (s *ChatService) GetAverageChatDuration() float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$match": bson.M{
			"status":   "ended",
			"duration": bson.M{"$gt": 0},
		}},
		{"$group": bson.M{
			"_id":              nil,
			"avg_duration_sec": bson.M{"$avg": "$duration"},
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		logger.LogError(err, "Failed to calculate average chat duration", nil)
		return 0
	}
	defer cursor.Close(ctx)

	var result []map[string]interface{}
	if err = cursor.All(ctx, &result); err != nil || len(result) == 0 {
		return 0
	}

	if avg, ok := result[0]["avg_duration_sec"].(float64); ok {
		return avg
	}

	return 0
}

func (s *ChatService) GetQueueSize() int64 {
	// This would be implemented based on your matching queue
	// For now, returning a placeholder
	return 0
}

func (s *ChatService) GetMessagesPerMinute() float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Count messages in the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)

	count, err := s.msgCollection.CountDocuments(ctx, bson.M{
		"timestamp": bson.M{"$gte": oneHourAgo},
	})
	if err != nil {
		logger.LogError(err, "Failed to count recent messages", nil)
		return 0
	}

	return float64(count) / 60.0 // Messages per minute
}

// User Chat History

func (s *ChatService) GetUserChatHistory(userID primitive.ObjectID) []map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$match": bson.M{
			"$or": []bson.M{
				{"user1_id": userID},
				{"user2_id": userID},
			},
		}},
		{"$sort": bson.M{"started_at": -1}},
		{"$limit": 50}, // Recent 50 chats
		{"$project": bson.M{
			"room_id":    1,
			"chat_type":  1,
			"status":     1,
			"started_at": 1,
			"ended_at":   1,
			"duration":   1,
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		logger.LogError(err, "Failed to get user chat history", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return []map[string]interface{}{}
	}
	defer cursor.Close(ctx)

	var history []map[string]interface{}
	if err = cursor.All(ctx, &history); err != nil {
		logger.LogError(err, "Failed to decode chat history", nil)
		return []map[string]interface{}{}
	}

	return history
}

func (s *ChatService) GetUserChats(userID primitive.ObjectID) []Chat {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"$or": []bson.M{
			{"user1_id": userID},
			{"user2_id": userID},
		},
	}

	opts := options.Find().SetSort(bson.D{{Key: "started_at", Value: -1}}).SetLimit(20)

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		logger.LogError(err, "Failed to get user chats", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return []Chat{}
	}
	defer cursor.Close(ctx)

	var chats []Chat
	if err = cursor.All(ctx, &chats); err != nil {
		logger.LogError(err, "Failed to decode user chats", nil)
		return []Chat{}
	}

	return chats
}

// Admin Functions

func (s *ChatService) GetChatsWithPagination(filter bson.M, page, limit int) ([]Chat, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	skip := (page - 1) * limit

	// Get total count
	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count chats: %w", err)
	}

	// Get chats
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "started_at", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get chats: %w", err)
	}
	defer cursor.Close(ctx)

	var chats []Chat
	if err = cursor.All(ctx, &chats); err != nil {
		return nil, 0, fmt.Errorf("failed to decode chats: %w", err)
	}

	return chats, total, nil
}

func (s *ChatService) DeleteChat(chatID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get chat first to get room_id for message deletion
	chat, err := s.GetChatByID(chatID)
	if err != nil {
		return err
	}

	// Delete associated messages
	_, err = s.msgCollection.DeleteMany(ctx, bson.M{"room_id": chat.RoomID})
	if err != nil {
		logger.LogError(err, "Failed to delete chat messages", map[string]interface{}{
			"chat_id": chatID.Hex(),
			"room_id": chat.RoomID,
		})
	}

	// Delete chat
	_, err = s.collection.DeleteOne(ctx, bson.M{"_id": chatID})
	if err != nil {
		return fmt.Errorf("failed to delete chat: %w", err)
	}

	return nil
}

func (s *ChatService) BulkChatAction(chatIDs []primitive.ObjectID, action string, data map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{"_id": bson.M{"$in": chatIDs}}

	switch action {
	case "delete":
		// Get room_ids first for message cleanup
		cursor, err := s.collection.Find(ctx, filter, options.Find().SetProjection(bson.M{"room_id": 1}))
		if err != nil {
			return fmt.Errorf("failed to get chat room_ids: %w", err)
		}

		var roomIDs []string
		for cursor.Next(ctx) {
			var chat struct {
				RoomID string `bson:"room_id"`
			}
			if err := cursor.Decode(&chat); err == nil {
				roomIDs = append(roomIDs, chat.RoomID)
			}
		}
		cursor.Close(ctx)

		// Delete messages
		if len(roomIDs) > 0 {
			_, err = s.msgCollection.DeleteMany(ctx, bson.M{"room_id": bson.M{"$in": roomIDs}})
			if err != nil {
				logger.LogError(err, "Failed to delete bulk messages", map[string]interface{}{
					"room_ids": roomIDs,
				})
			}
		}

		// Delete chats
		_, err = s.collection.DeleteMany(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to delete chats: %w", err)
		}

	case "end":
		endTime := time.Now()
		update := bson.M{
			"$set": bson.M{
				"status":     "ended",
				"ended_at":   endTime,
				"end_reason": "admin_action",
				"updated_at": endTime,
			},
		}

		_, err := s.collection.UpdateMany(ctx, filter, update)
		if err != nil {
			return fmt.Errorf("failed to end chats: %w", err)
		}

	case "flag":
		update := bson.M{
			"$set": bson.M{
				"flagged":     true,
				"flag_reason": data["reason"],
				"updated_at":  time.Now(),
			},
		}

		_, err := s.collection.UpdateMany(ctx, filter, update)
		if err != nil {
			return fmt.Errorf("failed to flag chats: %w", err)
		}

	default:
		return fmt.Errorf("unknown bulk action: %s", action)
	}

	return nil
}

func (s *ChatService) ExportChats(format, filterStr string) ([]byte, error) {
	// Implementation would depend on your export requirements
	// This is a placeholder
	return []byte("chat export data"), nil
}

// Analytics

func (s *ChatService) GetChatChartData(period string) map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var dateFilter bson.M
	switch period {
	case "24h":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-24 * time.Hour)}}
	case "7d":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-7 * 24 * time.Hour)}}
	case "30d":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-30 * 24 * time.Hour)}}
	default:
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-7 * 24 * time.Hour)}}
	}

	pipeline := []bson.M{
		{"$match": dateFilter},
		{"$group": bson.M{
			"_id": bson.M{
				"year":  bson.M{"$year": "$started_at"},
				"month": bson.M{"$month": "$started_at"},
				"day":   bson.M{"$dayOfMonth": "$started_at"},
				"hour":  bson.M{"$hour": "$started_at"},
			},
			"total_chats": bson.M{"$sum": 1},
			"text_chats":  bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "text"}}, 1, 0}}},
			"video_chats": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "video"}}, 1, 0}}},
			"audio_chats": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "audio"}}, 1, 0}}},
		}},
		{"$sort": bson.M{"_id": 1}},
		{"$limit": 1000},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		logger.LogError(err, "Failed to get chat chart data", map[string]interface{}{
			"period": period,
		})
		return map[string]interface{}{
			"labels": []string{},
			"data":   []int{},
		}
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil {
		logger.LogError(err, "Failed to decode chat chart data", nil)
		return map[string]interface{}{
			"labels": []string{},
			"data":   []int{},
		}
	}

	labels := make([]string, len(results))
	data := make([]int, len(results))
	textData := make([]int, len(results))
	videoData := make([]int, len(results))
	audioData := make([]int, len(results))

	for i, result := range results {
		dateInfo := result["_id"].(map[string]interface{})
		hour := int(dateInfo["hour"].(int32))
		day := int(dateInfo["day"].(int32))

		labels[i] = fmt.Sprintf("%02d/%02d %02d:00", day, int(dateInfo["month"].(int32)), hour)
		data[i] = int(result["total_chats"].(int32))
		textData[i] = int(result["text_chats"].(int32))
		videoData[i] = int(result["video_chats"].(int32))
		audioData[i] = int(result["audio_chats"].(int32))
	}

	return map[string]interface{}{
		"labels": labels,
		"datasets": []map[string]interface{}{
			{
				"label": "Total Chats",
				"data":  data,
			},
			{
				"label": "Text Chats",
				"data":  textData,
			},
			{
				"label": "Video Chats",
				"data":  videoData,
			},
			{
				"label": "Audio Chats",
				"data":  audioData,
			},
		},
	}
}

func (s *ChatService) GetChatAnalytics(period string) map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var dateFilter bson.M
	switch period {
	case "24h":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-24 * time.Hour)}}
	case "7d":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-7 * 24 * time.Hour)}}
	case "30d":
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-30 * 24 * time.Hour)}}
	default:
		dateFilter = bson.M{"started_at": bson.M{"$gte": time.Now().Add(-7 * 24 * time.Hour)}}
	}

	pipeline := []bson.M{
		{"$match": dateFilter},
		{"$group": bson.M{
			"_id":             nil,
			"total_chats":     bson.M{"$sum": 1},
			"completed_chats": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "ended"}}, 1, 0}}},
			"active_chats":    bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "active"}}, 1, 0}}},
			"text_chats":      bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "text"}}, 1, 0}}},
			"video_chats":     bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "video"}}, 1, 0}}},
			"audio_chats":     bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$chat_type", "audio"}}, 1, 0}}},
			"avg_duration":    bson.M{"$avg": "$duration"},
			"total_duration":  bson.M{"$sum": "$duration"},
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		logger.LogError(err, "Failed to get chat analytics", map[string]interface{}{
			"period": period,
		})
		return map[string]interface{}{}
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err = cursor.All(ctx, &results); err != nil || len(results) == 0 {
		return map[string]interface{}{
			"total_chats":     0,
			"completed_chats": 0,
			"active_chats":    0,
			"text_chats":      0,
			"video_chats":     0,
			"audio_chats":     0,
			"avg_duration":    0,
			"total_duration":  0,
		}
	}

	return results[0]
}

// Message Management

func (s *ChatService) StoreMessage(roomID, userID, content, messageType string, metadata map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	message := Message{
		RoomID:    roomID,
		UserID:    userID,
		Content:   content,
		Type:      messageType,
		Timestamp: time.Now(),
		Flagged:   false,
		Edited:    false,
		Deleted:   false,
		MetaData:  metadata,
	}

	_, err := s.msgCollection.InsertOne(ctx, message)
	if err != nil {
		logger.LogError(err, "Failed to store message", map[string]interface{}{
			"room_id":      roomID,
			"user_id":      userID,
			"message_type": messageType,
		})
		return fmt.Errorf("failed to store message: %w", err)
	}

	return nil
}

func (s *ChatService) FlagMessage(messageID primitive.ObjectID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"flagged":     true,
			"flag_reason": reason,
			"flagged_at":  time.Now(),
		},
	}

	_, err := s.msgCollection.UpdateOne(ctx, bson.M{"_id": messageID}, update)
	if err != nil {
		return fmt.Errorf("failed to flag message: %w", err)
	}

	return nil
}

func (s *ChatService) DeleteMessage(messageID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"deleted":    true,
			"deleted_at": time.Now(),
		},
	}

	_, err := s.msgCollection.UpdateOne(ctx, bson.M{"_id": messageID}, update)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	return nil
}
