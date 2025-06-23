package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"vrchat/internal/utils"
)

type AuthService struct {
	db                        *mongo.Database
	registeredUsersCollection *mongo.Collection
	adminsCollection          *mongo.Collection
	sessionTokensCollection   *mongo.Collection
	refreshTokensCollection   *mongo.Collection
}

type AdminUser struct {
	ID          string     `bson:"_id"`
	Username    string     `bson:"username"`
	Password    string     `bson:"password"`
	Role        string     `bson:"role"`
	Permissions []string   `bson:"permissions"`
	IsActive    bool       `bson:"is_active"`
	LastLogin   *time.Time `bson:"last_login"`
	CreatedAt   time.Time  `bson:"created_at"`
}

type RegisteredUser struct {
	ID         primitive.ObjectID `bson:"_id"`
	Email      string             `bson:"email"`
	Password   string             `bson:"password"`
	Username   string             `bson:"username"`
	Language   string             `bson:"language"`
	Region     string             `bson:"region"`
	Interests  []string           `bson:"interests"`
	IsVerified bool               `bson:"is_verified"`
	IsActive   bool               `bson:"is_active"`
	IsBanned   bool               `bson:"is_banned"`
	LastLogin  *time.Time         `bson:"last_login"`
	CreatedAt  time.Time          `bson:"created_at"`
}

func NewAuthService(db *mongo.Database) *AuthService {
	return &AuthService{
		db:                        db,
		registeredUsersCollection: db.Collection("registered_users"),
		adminsCollection:          db.Collection("admins"),
		sessionTokensCollection:   db.Collection("session_tokens"),
		refreshTokensCollection:   db.Collection("refresh_tokens"),
	}
}

// Admin Authentication Methods
func (s *AuthService) ValidateAdminCredentials(username, password string) (*AdminUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var admin AdminUser
	err := s.adminsCollection.FindOne(ctx, bson.M{"username": username}).Decode(&admin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("admin not found")
		}
		return nil, err
	}

	if !utils.CheckPassword(password, admin.Password) {
		return nil, fmt.Errorf("invalid password")
	}

	return &admin, nil
}

func (s *AuthService) GetAdminByID(adminID string) (*AdminUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var admin AdminUser
	err := s.adminsCollection.FindOne(ctx, bson.M{"_id": adminID}).Decode(&admin)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}

func (s *AuthService) UpdateAdminLastLogin(adminID, ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.adminsCollection.UpdateOne(ctx,
		bson.M{"_id": adminID},
		bson.M{
			"$set": bson.M{
				"last_login":    time.Now(),
				"last_login_ip": ip,
			},
		})

	return err
}

// User Authentication Methods
func (s *AuthService) ValidateUserCredentials(email, password string) (*RegisteredUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user RegisteredUser
	err := s.registeredUsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	if !utils.CheckPassword(password, user.Password) {
		return nil, fmt.Errorf("invalid password")
	}

	return &user, nil
}

func (s *AuthService) GetUserByEmail(email string) (*RegisteredUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user RegisteredUser
	err := s.registeredUsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *AuthService) CreateUser(userData map[string]interface{}) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.registeredUsersCollection.InsertOne(ctx, userData)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *AuthService) UpdateUserLastLogin(userID primitive.ObjectID, ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.registeredUsersCollection.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"last_login":    time.Now(),
				"last_login_ip": ip,
			},
		})

	return err
}

func (s *AuthService) VerifyUserEmail(email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.registeredUsersCollection.UpdateOne(ctx,
		bson.M{"email": email},
		bson.M{
			"$set": bson.M{
				"is_verified": true,
				"verified_at": time.Now(),
			},
		})

	return err
}

func (s *AuthService) UpdateUserPassword(userID, hashedPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	_, err = s.registeredUsersCollection.UpdateOne(ctx,
		bson.M{"_id": objectID},
		bson.M{
			"$set": bson.M{
				"password":            hashedPassword,
				"password_updated_at": time.Now(),
			},
		})

	return err
}

func (s *AuthService) EmailExists(email string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.registeredUsersCollection.CountDocuments(ctx, bson.M{"email": email})
	return err == nil && count > 0
}

func (s *AuthService) UsernameExists(username string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.registeredUsersCollection.CountDocuments(ctx, bson.M{"username": username})
	return err == nil && count > 0
}

func (s *AuthService) InvalidateUserSessions(userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Invalidate all session tokens for this user
	_, err := s.sessionTokensCollection.UpdateMany(ctx,
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}})

	if err != nil {
		return err
	}

	// Invalidate all refresh tokens for this user
	_, err = s.refreshTokensCollection.UpdateMany(ctx,
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}})

	return err
}

// Social Authentication Methods
func (s *AuthService) CreateOrGetSocialUser(userInfo map[string]interface{}, provider string) (*RegisteredUser, bool, error) {
	email := userInfo["email"].(string)
	name := userInfo["name"].(string)

	// Check if user already exists
	user, err := s.GetUserByEmail(email)
	if err == nil {
		// User exists, update social provider info if needed
		s.UpdateUserSocialProvider(user.ID, provider, userInfo)
		return user, false, nil
	}

	// Create new user from social login
	userData := map[string]interface{}{
		"email":                email,
		"username":             s.GenerateUsernameFromEmail(email),
		"display_name":         name,
		"is_verified":          true, // Social logins are considered verified
		"is_active":            true,
		"is_banned":            false,
		"social_provider":      provider,
		"social_provider_data": userInfo,
		"registration_date":    time.Now(),
		"created_at":           time.Now(),
		"updated_at":           time.Now(),
	}

	userID, err := s.CreateUser(userData)
	if err != nil {
		return nil, false, err
	}

	// Get the created user
	objectID, _ := primitive.ObjectIDFromHex(userID)
	newUser := &RegisteredUser{
		ID:         objectID,
		Email:      email,
		Username:   userData["username"].(string),
		IsVerified: true,
		IsActive:   true,
		IsBanned:   false,
		CreatedAt:  time.Now(),
	}

	return newUser, true, nil
}

func (s *AuthService) UpdateUserSocialProvider(userID primitive.ObjectID, provider string, providerData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.registeredUsersCollection.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"social_provider":      provider,
				"social_provider_data": providerData,
				"updated_at":           time.Now(),
			},
		})

	return err
}

func (s *AuthService) GenerateUsernameFromEmail(email string) string {
	// Generate username from email
	parts := strings.Split(email, "@")
	username := parts[0]

	// Clean up username
	username = strings.ReplaceAll(username, ".", "_")
	username = strings.ReplaceAll(username, "+", "_")

	// Check if username exists and add suffix if needed
	baseUsername := username
	counter := 1
	for s.UsernameExists(username) {
		username = fmt.Sprintf("%s%d", baseUsername, counter)
		counter++
	}

	return username
}
