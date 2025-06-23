package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vrchat/internal/config"
	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Admin Authentication

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
	refreshToken, err := utils.GenerateRefreshToken(admin.ID)
	if err != nil {
		logger.LogError(err, "Failed to generate refresh token", map[string]interface{}{
			"admin_id": admin.ID,
		})
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Update last login
	h.updateAdminLastLogin(admin.ID, c.ClientIP())

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
		utils.InvalidateToken(token)
	}

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
	adminID, err := utils.ValidateRefreshToken(refreshData.RefreshToken)
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

	// Generate new tokens
	newToken, err := utils.GenerateAdminJWT(admin.ID, admin.Username, admin.Role, admin.Permissions)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate new token")
		return
	}

	newRefreshToken, err := utils.GenerateRefreshToken(admin.ID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate new refresh token")
		return
	}

	// Invalidate old refresh token
	utils.InvalidateToken(refreshData.RefreshToken)

	response := map[string]interface{}{
		"token":         newToken,
		"refresh_token": newRefreshToken,
		"expires_at":    time.Now().Add(8 * time.Hour),
	}

	utils.SuccessResponseWithMessage(c, "Token refreshed successfully", response)
}

// User Authentication

func (h *AuthHandler) Register(c *gin.Context) {
	var registerData struct {
		Email     string   `json:"email" binding:"required,email"`
		Password  string   `json:"password" binding:"required,min=8"`
		Username  string   `json:"username" binding:"required,min=3,max=20"`
		Language  string   `json:"language" binding:"required"`
		Region    string   `json:"region"`
		Interests []string `json:"interests"`
	}

	if err := c.ShouldBindJSON(&registerData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"email":    "Valid email is required",
			"password": "Password must be at least 8 characters",
			"username": "Username must be 3-20 characters",
			"language": "Language is required",
		})
		return
	}

	// Validate input data
	if !utils.ValidateEmail(registerData.Email) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid email format")
		return
	}

	if !utils.ValidatePassword(registerData.Password) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Password must contain uppercase, lowercase, numbers, and special characters")
		return
	}

	if !utils.ValidateUsername(registerData.Username) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Username can only contain letters, numbers, and underscores")
		return
	}

	if !utils.ValidateInterests(registerData.Interests) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid interests")
		return
	}

	// Check if email already exists
	if h.emailExists(registerData.Email) {
		utils.ErrorResponse(c, http.StatusConflict, "Email already registered")
		return
	}

	// Check if username already exists
	if h.usernameExists(registerData.Username) {
		utils.ErrorResponse(c, http.StatusConflict, "Username already taken")
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(registerData.Password)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to process password")
		return
	}

	// Get region from IP if not provided
	if registerData.Region == "" {
		regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
		registerData.Region = regionInfo.Code
	}

	// Create user
	user := map[string]interface{}{
		"email":             registerData.Email,
		"password":          hashedPassword,
		"username":          registerData.Username,
		"language":          registerData.Language,
		"region":            registerData.Region,
		"interests":         registerData.Interests,
		"is_verified":       false,
		"is_active":         true,
		"is_banned":         false,
		"registration_ip":   c.ClientIP(),
		"registration_date": time.Now(),
		"created_at":        time.Now(),
		"updated_at":        time.Now(),
	}

	userID, err := h.createUser(user)
	if err != nil {
		logger.LogError(err, "Failed to create user", map[string]interface{}{
			"email": registerData.Email,
		})
		utils.InternalErrorResponse(c, "Failed to create account")
		return
	}

	// Generate email verification token
	verificationToken, err := utils.GenerateEmailVerificationToken(registerData.Email)
	if err != nil {
		logger.LogError(err, "Failed to generate verification token", map[string]interface{}{
			"user_id": userID,
			"email":   registerData.Email,
		})
	} else {
		// Send verification email (implement based on your email service)
		h.sendVerificationEmail(registerData.Email, verificationToken)
	}

	logger.LogUserAction(userID, "user_registered", map[string]interface{}{
		"email":    registerData.Email,
		"username": registerData.Username,
		"ip":       c.ClientIP(),
	})

	response := map[string]interface{}{
		"user_id":               userID,
		"email":                 registerData.Email,
		"username":              registerData.Username,
		"verification_required": true,
		"message":               "Registration successful. Please check your email for verification.",
	}

	utils.SuccessResponseWithMessage(c, "Registration successful", response)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var loginData struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"email":    "Valid email is required",
			"password": "Password is required",
		})
		return
	}

	// Validate credentials
	user, err := h.validateUserCredentials(loginData.Email, loginData.Password)
	if err != nil {
		logger.LogSecurityEvent("user_login_failed", "", c.ClientIP(), map[string]interface{}{
			"email":  loginData.Email,
			"reason": err.Error(),
		})
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Check if user is banned
	if user.IsBanned {
		logger.LogSecurityEvent("user_login_blocked", user.ID.Hex(), c.ClientIP(), map[string]interface{}{
			"email":  loginData.Email,
			"reason": "Account banned",
		})
		utils.ErrorResponse(c, http.StatusForbidden, "Account is banned")
		return
	}

	// Check if user is active
	if !user.IsActive {
		utils.ErrorResponse(c, http.StatusForbidden, "Account is inactive")
		return
	}

	// Generate session token (for registered users, we still use session tokens)
	sessionToken := utils.GenerateSessionToken(user.ID.Hex())

	// Generate refresh token
	refreshToken, err := utils.GenerateRefreshToken(user.ID.Hex())
	if err != nil {
		logger.LogError(err, "Failed to generate refresh token", map[string]interface{}{
			"user_id": user.ID.Hex(),
		})
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Update last login
	h.updateUserLastLogin(user.ID, c.ClientIP())

	logger.LogUserAction(user.ID.Hex(), "user_login", map[string]interface{}{
		"email":      loginData.Email,
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	})

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":          user.ID.Hex(),
			"email":       user.Email,
			"username":    user.Username,
			"language":    user.Language,
			"region":      user.Region,
			"interests":   user.Interests,
			"is_verified": user.IsVerified,
		},
		"session_token": sessionToken,
		"refresh_token": refreshToken,
		"expires_at":    time.Now().Add(24 * time.Hour),
	}

	utils.SuccessResponseWithMessage(c, "Login successful", response)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionToken := c.GetString("session_token")
	userID := c.GetString("user_id")

	if sessionToken != "" {
		utils.InvalidateToken(sessionToken)
	}

	logger.LogUserAction(userID, "user_logout", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Logout successful", nil)
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var verifyData struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&verifyData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Verification token is required")
		return
	}

	// Validate verification token
	email, err := utils.ValidateEmailVerificationToken(verifyData.Token)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid or expired verification token")
		return
	}

	// Update user verification status
	err = h.verifyUserEmail(email)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to verify email")
		return
	}

	logger.LogUserAction("", "email_verified", map[string]interface{}{
		"email": email,
		"ip":    c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Email verified successfully", nil)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var forgotData struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&forgotData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Valid email is required")
		return
	}

	// Check if user exists
	user, err := h.getUserByEmail(forgotData.Email)
	if err != nil {
		// Don't reveal if email exists or not for security
		utils.SuccessResponseWithMessage(c, "If the email exists, a password reset link has been sent", nil)
		return
	}

	// Generate password reset token
	resetToken, err := utils.GeneratePasswordResetToken(user.ID.Hex())
	if err != nil {
		logger.LogError(err, "Failed to generate password reset token", map[string]interface{}{
			"user_id": user.ID.Hex(),
			"email":   forgotData.Email,
		})
		utils.InternalErrorResponse(c, "Failed to generate reset token")
		return
	}

	// Send password reset email
	err = h.sendPasswordResetEmail(forgotData.Email, resetToken)
	if err != nil {
		logger.LogError(err, "Failed to send password reset email", map[string]interface{}{
			"user_id": user.ID.Hex(),
			"email":   forgotData.Email,
		})
	}

	logger.LogUserAction(user.ID.Hex(), "password_reset_requested", map[string]interface{}{
		"email": forgotData.Email,
		"ip":    c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "If the email exists, a password reset link has been sent", nil)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var resetData struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&resetData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"token":        "Reset token is required",
			"new_password": "Password must be at least 8 characters",
		})
		return
	}

	// Validate password strength
	if !utils.ValidatePassword(resetData.NewPassword) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Password must contain uppercase, lowercase, numbers, and special characters")
		return
	}

	// Validate reset token
	userID, err := utils.ValidatePasswordResetToken(resetData.Token)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid or expired reset token")
		return
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(resetData.NewPassword)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to process password")
		return
	}

	// Update user password
	err = h.updateUserPassword(userID, hashedPassword)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to update password")
		return
	}

	// Invalidate the reset token
	utils.InvalidateToken(resetData.Token)

	// Invalidate all existing sessions for this user
	h.invalidateUserSessions(userID)

	logger.LogUserAction(userID, "password_reset", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Password reset successful", nil)
}

// Social Authentication (placeholder implementations)

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	// Implement Google OAuth redirect
	redirectURL := h.getGoogleOAuthURL()
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Authorization code is required")
		return
	}

	// Exchange code for user info
	userInfo, err := h.exchangeGoogleCode(code)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to get user information")
		return
	}

	// Create or get existing user
	user, isNew, err := h.createOrGetSocialUser(userInfo, "google")
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to process social login")
		return
	}

	// Generate session token
	sessionToken := utils.GenerateSessionToken(user.ID.Hex())

	if isNew {
		logger.LogUserAction(user.ID.Hex(), "social_user_registered", map[string]interface{}{
			"provider": "google",
			"email":    userInfo["email"],
			"ip":       c.ClientIP(),
		})
	} else {
		logger.LogUserAction(user.ID.Hex(), "social_user_login", map[string]interface{}{
			"provider": "google",
			"email":    userInfo["email"],
			"ip":       c.ClientIP(),
		})
	}

	// Redirect to frontend with token
	frontendURL := fmt.Sprintf("%s/auth/callback?token=%s&user_id=%s",
		config.Load().App.Domain, sessionToken, user.ID.Hex())
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func (h *AuthHandler) FacebookAuth(c *gin.Context) {
	// Implement Facebook OAuth redirect
	redirectURL := h.getFacebookOAuthURL()
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *AuthHandler) FacebookCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Authorization code is required")
		return
	}

	// Exchange code for user info
	userInfo, err := h.exchangeFacebookCode(code)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to get user information")
		return
	}

	// Create or get existing user
	user, isNew, err := h.createOrGetSocialUser(userInfo, "facebook")
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to process social login")
		return
	}

	// Generate session token
	sessionToken := utils.GenerateSessionToken(user.ID.Hex())

	if isNew {
		logger.LogUserAction(user.ID.Hex(), "social_user_registered", map[string]interface{}{
			"provider": "facebook",
			"email":    userInfo["email"],
			"ip":       c.ClientIP(),
		})
	} else {
		logger.LogUserAction(user.ID.Hex(), "social_user_login", map[string]interface{}{
			"provider": "facebook",
			"email":    userInfo["email"],
			"ip":       c.ClientIP(),
		})
	}

	// Redirect to frontend with token
	frontendURL := fmt.Sprintf("%s/auth/callback?token=%s&user_id=%s",
		config.Load().App.Domain, sessionToken, user.ID.Hex())
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

// Helper methods

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

func (h *AuthHandler) validateAdminCredentials(username, password string) (*AdminUser, error) {
	db := database.GetDB()
	collection := db.Collection("admins")

	var admin AdminUser
	err := collection.FindOne(context.Background(), bson.M{"username": username}).Decode(&admin)
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

func (h *AuthHandler) validateUserCredentials(email, password string) (*RegisteredUser, error) {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	var user RegisteredUser
	err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
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

func (h *AuthHandler) getAdminByID(adminID string) (*AdminUser, error) {
	db := database.GetDB()
	collection := db.Collection("admins")

	var admin AdminUser
	err := collection.FindOne(context.Background(), bson.M{"_id": adminID}).Decode(&admin)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}

func (h *AuthHandler) updateAdminLastLogin(adminID, ip string) {
	db := database.GetDB()
	collection := db.Collection("admins")

	collection.UpdateOne(context.Background(),
		bson.M{"_id": adminID},
		bson.M{
			"$set": bson.M{
				"last_login":    time.Now(),
				"last_login_ip": ip,
			},
		})
}

func (h *AuthHandler) emailExists(email string) bool {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	count, err := collection.CountDocuments(context.Background(), bson.M{"email": email})
	return err == nil && count > 0
}

func (h *AuthHandler) usernameExists(username string) bool {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	count, err := collection.CountDocuments(context.Background(), bson.M{"username": username})
	return err == nil && count > 0
}

func (h *AuthHandler) createUser(user map[string]interface{}) (string, error) {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	result, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (h *AuthHandler) getUserByEmail(email string) (*RegisteredUser, error) {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	var user RegisteredUser
	err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (h *AuthHandler) updateUserLastLogin(userID primitive.ObjectID, ip string) {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	collection.UpdateOne(context.Background(),
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"last_login":    time.Now(),
				"last_login_ip": ip,
			},
		})
}

func (h *AuthHandler) verifyUserEmail(email string) error {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	_, err := collection.UpdateOne(context.Background(),
		bson.M{"email": email},
		bson.M{
			"$set": bson.M{
				"is_verified": true,
				"verified_at": time.Now(),
			},
		})

	return err
}

func (h *AuthHandler) updateUserPassword(userID, hashedPassword string) error {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	_, err = collection.UpdateOne(context.Background(),
		bson.M{"_id": objectID},
		bson.M{
			"$set": bson.M{
				"password":            hashedPassword,
				"password_updated_at": time.Now(),
			},
		})

	return err
}

func (h *AuthHandler) invalidateUserSessions(userID string) {
	// Invalidate all session tokens for this user
	db := database.GetDB()
	collection := db.Collection("session_tokens")

	collection.UpdateMany(context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}})

	// Invalidate all refresh tokens for this user
	refreshCollection := db.Collection("refresh_tokens")
	refreshCollection.UpdateMany(context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}})
}

func (h *AuthHandler) sendVerificationEmail(email, token string) error {
	// Implement email sending logic
	// This would integrate with your email service (SendGrid, AWS SES, etc.)

	verificationURL := fmt.Sprintf("%s/auth/verify?token=%s", config.Load().App.Domain, token)

	logger.Info("Sending verification email", map[string]interface{}{
		"email": email,
		"url":   verificationURL,
	})

	// TODO: Implement actual email sending
	return nil
}

func (h *AuthHandler) sendPasswordResetEmail(email, token string) error {
	// Implement email sending logic

	resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s", config.Load().App.Domain, token)

	logger.Info("Sending password reset email", map[string]interface{}{
		"email": email,
		"url":   resetURL,
	})

	// TODO: Implement actual email sending
	return nil
}

// Social authentication helper methods

func (h *AuthHandler) getGoogleOAuthURL() string {
	// Implement Google OAuth URL generation
	baseURL := "https://accounts.google.com/oauth/authorize"
	clientID := "your-google-client-id" // Get from config
	redirectURI := fmt.Sprintf("%s/auth/google/callback", config.Load().App.Domain)

	return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=email+profile",
		baseURL, clientID, redirectURI)
}

func (h *AuthHandler) getFacebookOAuthURL() string {
	// Implement Facebook OAuth URL generation
	baseURL := "https://www.facebook.com/v13.0/dialog/oauth"
	clientID := "your-facebook-app-id" // Get from config
	redirectURI := fmt.Sprintf("%s/auth/facebook/callback", config.Load().App.Domain)

	return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=email",
		baseURL, clientID, redirectURI)
}

func (h *AuthHandler) exchangeGoogleCode(code string) (map[string]interface{}, error) {
	// Implement Google OAuth code exchange
	// This would make HTTP requests to Google's OAuth API

	// Placeholder implementation
	return map[string]interface{}{
		"email":    "user@example.com",
		"name":     "John Doe",
		"picture":  "https://example.com/avatar.jpg",
		"verified": true,
	}, nil
}

func (h *AuthHandler) exchangeFacebookCode(code string) (map[string]interface{}, error) {
	// Implement Facebook OAuth code exchange
	// This would make HTTP requests to Facebook's Graph API

	// Placeholder implementation
	return map[string]interface{}{
		"email":   "user@example.com",
		"name":    "John Doe",
		"picture": "https://example.com/avatar.jpg",
	}, nil
}

func (h *AuthHandler) createOrGetSocialUser(userInfo map[string]interface{}, provider string) (*RegisteredUser, bool, error) {
	email := userInfo["email"].(string)
	name := userInfo["name"].(string)

	// Check if user already exists
	user, err := h.getUserByEmail(email)
	if err == nil {
		// User exists, update social provider info if needed
		h.updateUserSocialProvider(user.ID, provider, userInfo)
		return user, false, nil
	}

	// Create new user from social login
	userData := map[string]interface{}{
		"email":                email,
		"username":             h.generateUsernameFromEmail(email),
		"display_name":         name,
		"is_verified":          true, // Social logins are considered verified
		"is_active":            true,
		"is_banned":            false,
		"social_provider":      provider,
		"social_provider_data": userInfo,
		"registration_ip":      "", // Will be set by caller
		"registration_date":    time.Now(),
		"created_at":           time.Now(),
		"updated_at":           time.Now(),
	}

	userID, err := h.createUser(userData)
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

func (h *AuthHandler) updateUserSocialProvider(userID primitive.ObjectID, provider string, providerData map[string]interface{}) {
	db := database.GetDB()
	collection := db.Collection("registered_users")

	collection.UpdateOne(context.Background(),
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"social_provider":      provider,
				"social_provider_data": providerData,
				"updated_at":           time.Now(),
			},
		})
}

func (h *AuthHandler) generateUsernameFromEmail(email string) string {
	// Generate username from email
	parts := strings.Split(email, "@")
	username := parts[0]

	// Clean up username
	username = strings.ReplaceAll(username, ".", "_")
	username = strings.ReplaceAll(username, "+", "_")

	// Check if username exists and add suffix if needed
	baseUsername := username
	counter := 1
	for h.usernameExists(username) {
		username = fmt.Sprintf("%s%d", baseUsername, counter)
		counter++
	}

	return username
}
