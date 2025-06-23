package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword verifies a password against its hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "omg_" + hex.EncodeToString(bytes), nil
}

// EncryptData encrypts data using AES-GCM
func EncryptData(data, passphrase string) (string, error) {
	key, salt, err := deriveKey(passphrase, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// Combine salt and ciphertext
	result := append(salt, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptData decrypts data using AES-GCM
func DecryptData(encryptedData, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	// Extract salt (first 32 bytes)
	salt := data[:32]
	ciphertext := data[32:]

	key, _, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// deriveKey derives a key from passphrase using scrypt
func deriveKey(passphrase string, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// GenerateTurnCredentials generates TURN server credentials
func GenerateTurnCredentials(username, sharedSecret string) (string, string) {
	// Generate timestamp (expires in 24 hours)
	timestamp := time.Now().Add(24 * time.Hour).Unix()

	// Create username with timestamp
	turnUsername := fmt.Sprintf("%d:%s", timestamp, username)

	// Generate HMAC-SHA1 password
	h := sha256.New()
	h.Write([]byte(turnUsername))
	h.Write([]byte(sharedSecret))
	password := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return turnUsername, password
}

// HashSHA256 creates SHA256 hash of input
func HashSHA256(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateEmailVerificationToken generates email verification token
func GenerateEmailVerificationToken(email string) (string, error) {
	// Create payload with email and timestamp
	payload := fmt.Sprintf("%s:%d", email, time.Now().Unix())

	// Encrypt the payload
	return EncryptData(payload, "email_verification_secret")
}

// ValidateEmailVerificationToken validates email verification token
func ValidateEmailVerificationToken(token string) (string, error) {
	// Decrypt the token
	payload, err := DecryptData(token, "email_verification_secret")
	if err != nil {
		return "", err
	}

	// Parse email from payload (email:timestamp)
	var email string
	var timestamp int64
	_, err = fmt.Sscanf(payload, "%s:%d", &email, &timestamp)
	if err != nil {
		return "", err
	}

	// Check if token is not expired (24 hours)
	if time.Now().Unix()-timestamp > 86400 {
		return "", fmt.Errorf("token expired")
	}

	return email, nil
}

// GeneratePasswordResetToken generates password reset token
func GeneratePasswordResetToken(userID string) (string, error) {
	payload := fmt.Sprintf("%s:%d", userID, time.Now().Unix())
	return EncryptData(payload, "password_reset_secret")
}

// ValidatePasswordResetToken validates password reset token
func ValidatePasswordResetToken(token string) (string, error) {
	payload, err := DecryptData(token, "password_reset_secret")
	if err != nil {
		return "", err
	}

	var userID string
	var timestamp int64
	_, err = fmt.Sscanf(payload, "%s:%d", &userID, &timestamp)
	if err != nil {
		return "", err
	}

	// Token expires in 1 hour
	if time.Now().Unix()-timestamp > 3600 {
		return "", fmt.Errorf("token expired")
	}

	return userID, nil
}
