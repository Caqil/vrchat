package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Admin Authentication - ENHANCED for admin panel

func (h *AuthHandler) AdminLogin(c *gin.Context) {
	var loginData struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"username": "Username is required",
			"password": "Password is required",
		})
		return
	}

	// Validate credentials
	admin, err := h.validateAdminCredentials(loginData.Username, loginData.Password)
	if err != nil {
		logger.LogSecurityEvent("admin_login_failed", "", c.ClientIP(), map[string]interface{}{
			"username": loginData.Username,
			"reason":   err.Error(),
		})
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check if admin is active
	if !admin.IsActive {
		logger.LogSecurityEvent("admin_login_blocked", admin.ID, c.ClientIP(), map[string]interface{}{
			"username": loginData.Username,
			"reason":   "Account inactive",
		})
		utils.ErrorResponse(c, http.StatusForbidden, "Account is inactive")
		return
	}

	// Generate JWT token
	token, err := utils.GenerateAdminJWT(admin.ID, admin.Username, admin.Role, admin.Permissions)
	if err != nil {
		logger.LogError(err, "Failed to generate admin JWT", map[string]interface{}{
			"admin_id": admin.ID,
		})
		utils.InternalErrorResponse(c, "Failed to generate authentication token")
		return
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateAdminRefreshToken(admin.ID)
	if err != nil {
		logger.LogError(err, "Failed to generate refresh token", map[string]interface{}{
			"admin_id": admin.ID,
		})
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Update last login
	h.updateAdminLastLogin(admin.ID, c.ClientIP())

	// Log successful login
	logger.LogAdminAction(admin.ID, "admin_login", "", map[string]interface{}{
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	})

	response := map[string]interface{}{
		"admin": map[string]interface{}{
			"id":          admin.ID,
			"username":    admin.Username,
			"role":        admin.Role,
			"permissions": admin.Permissions,
			"is_active":   admin.IsActive,
		},
		"token":         token,
		"refresh_token": refreshToken,
		"expires_at":    time.Now().Add(8 * time.Hour),
	}

	utils.SuccessResponseWithMessage(c, "Admin login successful", response)
}

func (h *AuthHandler) AdminLogout(c *gin.Context) {
	token := c.GetString("admin_token")
	adminID := c.GetString("admin_id")

	if token != "" {
		// Invalidate the token
		if err := utils.InvalidateToken(token); err != nil {
			logger.LogError(err, "Failed to invalidate admin token", map[string]interface{}{
				"admin_id": adminID,
			})
		}
	}

	// Log logout
	logger.LogAdminAction(adminID, "admin_logout", "", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Admin logout successful", nil)
}

func (h *AuthHandler) VerifyAdminToken(c *gin.Context) {
	adminID := c.GetString("admin_id")
	username := c.GetString("admin_username")
	role := c.GetString("admin_role")
	permissions, _ := c.Get("admin_permissions")

	response := map[string]interface{}{
		"admin": map[string]interface{}{
			"id":          adminID,
			"username":    username,
			"role":        role,
			"permissions": permissions,
		},
		"valid": true,
	}

	utils.SuccessResponse(c, response)
}

func (h *AuthHandler) RefreshAdminToken(c *gin.Context) {
	var refreshData struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&refreshData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Validate refresh token
	adminID, err := utils.ValidateAdminRefreshToken(refreshData.RefreshToken)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Get admin details
	admin, err := h.getAdminByID(adminID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Admin not found")
		return
	}

	// Check if admin is still active
	if !admin.IsActive {
		utils.ErrorResponse(c, http.StatusForbidden, "Admin account is inactive")
		return
	}

	// Generate new tokens
	newToken, err := utils.GenerateAdminJWT(admin.ID, admin.Username, admin.Role, admin.Permissions)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate new token")
		return
	}

	newRefreshToken, err := utils.GenerateAdminRefreshToken(admin.ID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate new refresh token")
		return
	}

	// Revoke old refresh token
	utils.RevokeRefreshToken(refreshData.RefreshToken)

	response := map[string]interface{}{
		"token":         newToken,
		"refresh_token": newRefreshToken,
		"expires_at":    time.Now().Add(8 * time.Hour),
	}

	utils.SuccessResponseWithMessage(c, "Token refreshed successfully", response)
}

// Regular User Authentication (existing functionality, keeping as is)

func (h *AuthHandler) Register(c *gin.Context) {
	var registerData struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required,min=3,max=20"`
		Password string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&registerData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"email":    "Valid email is required",
			"username": "Username must be 3-20 characters",
			"password": "Password must be at least 8 characters",
		})
		return
	}

	// Check if user already exists
	if h.userExists(registerData.Email, registerData.Username) {
		utils.ErrorResponse(c, http.StatusConflict, "User with this email or username already exists")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerData.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to process password")
		return
	}

	// Create user
	user := map[string]interface{}{
		"email":       registerData.Email,
		"username":    registerData.Username,
		"password":    string(hashedPassword),
		"is_verified": false,
		"is_active":   true,
		"created_at":  time.Now(),
		"updated_at":  time.Now(),
	}

	db := database.GetDatabase()
	collection := db.Collection("registered_users")
	result, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to create user")
		return
	}

	userID := result.InsertedID.(primitive.ObjectID).Hex()

	// Generate JWT token
	token, err := utils.GenerateUserJWT(userID, registerData.Username, "user")
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate token")
		return
	}

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":       userID,
			"email":    registerData.Email,
			"username": registerData.Username,
		},
		"token": token,
	}

	utils.SuccessResponseWithMessage(c, "User registered successfully", response)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var loginData struct {
		EmailOrUsername string `json:"email_or_username" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"email_or_username": "Email or username is required",
			"password":          "Password is required",
		})
		return
	}

	// Find user by email or username
	user, err := h.findUserByEmailOrUsername(loginData.EmailOrUsername)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check if user is active
	if !user.IsActive {
		utils.ErrorResponse(c, http.StatusForbidden, "Account is inactive")
		return
	}

	// Generate JWT token
	token, err := utils.GenerateUserJWT(user.ID.Hex(), user.Username, "user")
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate token")
		return
	}

	// Update last login
	h.updateUserLastLogin(user.ID.Hex(), c.ClientIP())

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":       user.ID.Hex(),
			"email":    user.Email,
			"username": user.Username,
		},
		"token": token,
	}

	utils.SuccessResponseWithMessage(c, "Login successful", response)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	token := c.GetString("token")
	userID := c.GetString("user_id")

	if token != "" {
		utils.InvalidateToken(token)
	}

	logger.LogUserAction(userID, "user_logout", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Logout successful", nil)
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	// Implementation for email verification
	utils.SuccessResponseWithMessage(c, "Email verification functionality not implemented", nil)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	// Implementation for forgot password
	utils.SuccessResponseWithMessage(c, "Forgot password functionality not implemented", nil)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	// Implementation for reset password
	utils.SuccessResponseWithMessage(c, "Reset password functionality not implemented", nil)
}

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	// Implementation for Google OAuth
	utils.SuccessResponseWithMessage(c, "Google auth functionality not implemented", nil)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	// Implementation for Google OAuth callback
	utils.SuccessResponseWithMessage(c, "Google auth callback functionality not implemented", nil)
}

func (h *AuthHandler) FacebookAuth(c *gin.Context) {
	// Implementation for Facebook OAuth
	utils.SuccessResponseWithMessage(c, "Facebook auth functionality not implemented", nil)
}

func (h *AuthHandler) FacebookCallback(c *gin.Context) {
	// Implementation for Facebook OAuth callback
	utils.SuccessResponseWithMessage(c, "Facebook auth callback functionality not implemented", nil)
}

// Helper methods - ENHANCED for admin panel

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
	Username   string             `bson:"username"`
	Password   string             `bson:"password"`
	IsVerified bool               `bson:"is_verified"`
	IsActive   bool               `bson:"is_active"`
	LastLogin  *time.Time         `bson:"last_login"`
	CreatedAt  time.Time          `bson:"created_at"`
}

func (h *AuthHandler) validateAdminCredentials(username, password string) (*AdminUser, error) {
	db := database.GetDatabase()
	collection := db.Collection("admins")

	var admin AdminUser
	err := collection.FindOne(context.Background(), bson.M{"username": username}).Decode(&admin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("admin not found")
		}
		return nil, err
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return &admin, nil
}

func (h *AuthHandler) getAdminByID(adminID string) (*AdminUser, error) {
	db := database.GetDatabase()
	collection := db.Collection("admins")

	var admin AdminUser
	err := collection.FindOne(context.Background(), bson.M{"_id": adminID}).Decode(&admin)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}

func (h *AuthHandler) updateAdminLastLogin(adminID, ip string) error {
	db := database.GetDatabase()
	collection := db.Collection("admins")

	update := bson.M{
		"$set": bson.M{
			"last_login": time.Now(),
			"last_ip":    ip,
		},
	}

	_, err := collection.UpdateOne(context.Background(), bson.M{"_id": adminID}, update)
	return err
}

func (h *AuthHandler) userExists(email, username string) bool {
	db := database.GetDatabase()
	collection := db.Collection("registered_users")

	filter := bson.M{
		"$or": []bson.M{
			{"email": email},
			{"username": username},
		},
	}

	count, _ := collection.CountDocuments(context.Background(), filter)
	return count > 0
}

func (h *AuthHandler) findUserByEmailOrUsername(emailOrUsername string) (*RegisteredUser, error) {
	db := database.GetDatabase()
	collection := db.Collection("registered_users")

	filter := bson.M{
		"$or": []bson.M{
			{"email": emailOrUsername},
			{"username": emailOrUsername},
		},
	}

	var user RegisteredUser
	err := collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (h *AuthHandler) updateUserLastLogin(userID, ip string) error {
	db := database.GetDatabase()
	collection := db.Collection("registered_users")

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"last_login": time.Now(),
			"last_ip":    ip,
		},
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, update)
	return err
}
