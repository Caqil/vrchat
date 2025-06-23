package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vrchat/internal/utils"

	"github.com/gin-gonic/gin"
)

// RateLimiter stores rate limiting information
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       *sync.RWMutex
	rate     int
	burst    int
	cleanup  time.Duration
}

// Visitor represents a visitor's rate limiting data
type Visitor struct {
	limiter  *TokenBucket
	lastSeen time.Time
}

// TokenBucket implements token bucket algorithm
type TokenBucket struct {
	tokens   int
	capacity int
	rate     int
	lastTime time.Time
	mu       *sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		mu:       &sync.RWMutex{},
		rate:     rate,
		burst:    burst,
		cleanup:  time.Minute * 3,
	}

	// Start cleanup goroutine
	go rl.cleanupVisitors()

	return rl
}

// Allow checks if request is allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	visitor, exists := rl.visitors[key]
	if !exists {
		visitor = &Visitor{
			limiter: &TokenBucket{
				tokens:   rl.burst,
				capacity: rl.burst,
				rate:     rl.rate,
				lastTime: time.Now(),
				mu:       &sync.Mutex{},
			},
			lastSeen: time.Now(),
		}
		rl.visitors[key] = visitor
	}

	visitor.lastSeen = time.Now()
	return visitor.limiter.Allow()
}

// Allow method for TokenBucket
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime)
	tb.lastTime = now

	// Add tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds()) * tb.rate
	tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cleanupVisitors removes old visitors
func (rl *RateLimiter) cleanupVisitors() {
	for {
		time.Sleep(rl.cleanup)

		rl.mu.Lock()
		for key, visitor := range rl.visitors {
			if time.Since(visitor.lastSeen) > rl.cleanup {
				delete(rl.visitors, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Global rate limiters
var (
	// General API rate limiter
	apiLimiter = NewRateLimiter(100, 20) // 100 requests per second, burst of 20

	// Admin API rate limiter (more permissive)
	adminLimiter = NewRateLimiter(200, 50)

	// WebSocket connection rate limiter
	wsLimiter = NewRateLimiter(10, 5) // 10 connections per second, burst of 5

	// Chat message rate limiter
	chatLimiter = NewRateLimiter(30, 10) // 30 messages per second, burst of 10

	// Login rate limiter (very strict)
	loginLimiter = NewRateLimiter(5, 3) // 5 login attempts per second, burst of 3
)

// RateLimit middleware for general API endpoints
func RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := getClientKey(c)

		if !apiLimiter.Allow(key) {
			c.Header("X-RateLimit-Limit", "100")
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("Retry-After", "60")

			utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}

		c.Header("X-RateLimit-Limit", "100")
		c.Next()
	}
}

// AdminRateLimit middleware for admin endpoints
func AdminRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := getClientKey(c)

		if !adminLimiter.Allow(key) {
			c.Header("X-RateLimit-Limit", "200")
			c.Header("X-RateLimit-Remaining", "0")

			utils.ErrorResponse(c, http.StatusTooManyRequests, "Admin rate limit exceeded")
			c.Abort()
			return
		}

		c.Header("X-RateLimit-Limit", "200")
		c.Next()
	}
}

// WebSocketRateLimit middleware for WebSocket connections
func WebSocketRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := getClientKey(c)

		if !wsLimiter.Allow(key) {
			utils.ErrorResponse(c, http.StatusTooManyRequests, "WebSocket connection limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// ChatRateLimit middleware for chat messages
func ChatRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use user ID if authenticated, otherwise IP
		key := c.GetString("user_id")
		if key == "" {
			key = getClientKey(c)
		}

		if !chatLimiter.Allow(key) {
			utils.ErrorResponse(c, http.StatusTooManyRequests, "Chat rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// LoginRateLimit middleware for login attempts
func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := getClientKey(c)

		if !loginLimiter.Allow(key) {
			c.Header("Retry-After", "300") // 5 minutes

			utils.ErrorResponse(c, http.StatusTooManyRequests, "Too many login attempts. Please try again later.")
			c.Abort()
			return
		}

		c.Next()
	}
}

// CustomRateLimit creates a custom rate limiter middleware
func CustomRateLimit(rate, burst int, keyFunc func(*gin.Context) string) gin.HandlerFunc {
	limiter := NewRateLimiter(rate, burst)

	return func(c *gin.Context) {
		var key string
		if keyFunc != nil {
			key = keyFunc(c)
		} else {
			key = getClientKey(c)
		}

		if !limiter.Allow(key) {
			c.Header("X-RateLimit-Limit", strconv.Itoa(rate))
			c.Header("X-RateLimit-Remaining", "0")

			utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(rate))
		c.Next()
	}
}

// Helper function to get client identifier
func getClientKey(c *gin.Context) string {
	// Try to get user ID first (for authenticated users)
	if userID := c.GetString("user_id"); userID != "" {
		return "user:" + userID
	}

	// Fall back to IP address
	ip := c.ClientIP()

	// Handle cases where we're behind a proxy
	if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			ip = strings.TrimSpace(ips[0])
		}
	} else if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		ip = realIP
	}

	return "ip:" + ip
}

// IPWhitelist middleware to bypass rate limiting for whitelisted IPs
func IPWhitelist(whitelistedIPs []string) gin.HandlerFunc {
	whitelist := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		whitelist[ip] = true
	}

	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		if whitelist[clientIP] {
			c.Set("whitelisted", true)
		}

		c.Next()
	}
}

// Logger middleware with rate limiting info
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}
