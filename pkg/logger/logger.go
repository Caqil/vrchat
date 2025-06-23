package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger represents the application logger
type Logger struct {
	*logrus.Logger
	mu sync.RWMutex
}

// LogLevel represents log levels
type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
	PanicLevel LogLevel = "panic"
)

// LogFormat represents log output formats
type LogFormat string

const (
	JSONFormat LogFormat = "json"
	TextFormat LogFormat = "text"
)

// Config represents logger configuration
type Config struct {
	Level      LogLevel
	Format     LogFormat
	Output     string // file path or "stdout"
	MaxSize    int64  // max file size in MB
	MaxBackups int    // max number of backup files
	MaxAge     int    // max age in days
	Compress   bool   // compress rotated files
}

var (
	instance *Logger
	once     sync.Once
)

// Init initializes the global logger
func Init() {
	once.Do(func() {
		config := getLoggerConfig()
		instance = NewLogger(config)
	})
}

// NewLogger creates a new logger instance
func NewLogger(config Config) *Logger {
	logger := &Logger{
		Logger: logrus.New(),
	}

	// Set log level
	level := getLogrusLevel(config.Level)
	logger.SetLevel(level)

	// Set output format
	if config.Format == JSONFormat {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})
	}

	// Set output destination
	if config.Output == "stdout" || config.Output == "" {
		logger.SetOutput(os.Stdout)
	} else {
		// Create log directory if it doesn't exist
		logDir := filepath.Dir(config.Output)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Printf("Failed to create log directory: %v", err)
			logger.SetOutput(os.Stdout)
		} else {
			// Setup file output with rotation
			writer, err := setupFileOutput(config)
			if err != nil {
				log.Printf("Failed to setup file output: %v", err)
				logger.SetOutput(os.Stdout)
			} else {
				logger.SetOutput(writer)
			}
		}
	}

	// Enable caller reporting
	logger.SetReportCaller(true)

	return logger
}

// setupFileOutput sets up file output with rotation
func setupFileOutput(config Config) (io.Writer, error) {
	// For production, you might want to use lumberjack for log rotation
	// This is a simplified implementation

	file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	// Create a multi-writer to write to both file and stdout in development
	if os.Getenv("APP_ENV") == "development" {
		return io.MultiWriter(file, os.Stdout), nil
	}

	return file, nil
}

// getLoggerConfig returns logger configuration from environment
func getLoggerConfig() Config {
	config := Config{
		Level:      InfoLevel,
		Format:     JSONFormat,
		Output:     "stdout",
		MaxSize:    100, // 100MB
		MaxBackups: 3,
		MaxAge:     28, // 28 days
		Compress:   true,
	}

	// Override with environment variables
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		config.Level = LogLevel(strings.ToLower(level))
	}

	if format := os.Getenv("LOG_FORMAT"); format != "" {
		config.Format = LogFormat(strings.ToLower(format))
	}

	if output := os.Getenv("LOG_OUTPUT"); output != "" {
		config.Output = output
	}

	// In production, default to file output
	if os.Getenv("APP_ENV") == "production" && config.Output == "stdout" {
		config.Output = "logs/app.log"
	}

	return config
}

// getLogrusLevel converts LogLevel to logrus.Level
func getLogrusLevel(level LogLevel) logrus.Level {
	switch level {
	case DebugLevel:
		return logrus.DebugLevel
	case InfoLevel:
		return logrus.InfoLevel
	case WarnLevel:
		return logrus.WarnLevel
	case ErrorLevel:
		return logrus.ErrorLevel
	case FatalLevel:
		return logrus.FatalLevel
	case PanicLevel:
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}

// Global logger functions

// Debug logs a debug message
func Debug(args ...interface{}) {
	if instance != nil {
		instance.Debug(args...)
	}
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	if instance != nil {
		instance.Debugf(format, args...)
	}
}

// Info logs an info message
func Info(args ...interface{}) {
	if instance != nil {
		instance.Info(args...)
	}
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	if instance != nil {
		instance.Infof(format, args...)
	}
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	if instance != nil {
		instance.Warn(args...)
	}
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	if instance != nil {
		instance.Warnf(format, args...)
	}
}

// Error logs an error message
func Error(args ...interface{}) {
	if instance != nil {
		instance.Error(args...)
	}
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	if instance != nil {
		instance.Errorf(format, args...)
	}
}

// Fatal logs a fatal message and exits
func Fatal(args ...interface{}) {
	if instance != nil {
		instance.Fatal(args...)
	}
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	if instance != nil {
		instance.Fatalf(format, args...)
	}
}

// Panic logs a panic message and panics
func Panic(args ...interface{}) {
	if instance != nil {
		instance.Panic(args...)
	}
}

// Panicf logs a formatted panic message and panics
func Panicf(format string, args ...interface{}) {
	if instance != nil {
		instance.Panicf(format, args...)
	}
}

// WithField creates a logger with a field
func WithField(key string, value interface{}) *logrus.Entry {
	if instance != nil {
		return instance.WithField(key, value)
	}
	return nil
}

// WithFields creates a logger with multiple fields
func WithFields(fields logrus.Fields) *logrus.Entry {
	if instance != nil {
		return instance.WithFields(fields)
	}
	return nil
}

// WithError creates a logger with an error field
func WithError(err error) *logrus.Entry {
	if instance != nil {
		return instance.WithError(err)
	}
	return nil
}

// Context-aware logging functions

// LogRequest logs HTTP request information
func LogRequest(method, path, ip, userAgent string, duration time.Duration, statusCode int) {
	WithFields(logrus.Fields{
		"method":      method,
		"path":        path,
		"ip":          ip,
		"user_agent":  userAgent,
		"duration_ms": duration.Milliseconds(),
		"status_code": statusCode,
		"type":        "request",
	}).Info("HTTP Request")
}

// LogUserAction logs user actions
func LogUserAction(userID, action string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"user_id": userID,
		"action":  action,
		"type":    "user_action",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	WithFields(fields).Info("User Action")
}

// LogAdminAction logs admin actions
func LogAdminAction(adminID, action, target string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"admin_id": adminID,
		"action":   action,
		"target":   target,
		"type":     "admin_action",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	WithFields(fields).Warn("Admin Action")
}

// LogChatEvent logs chat-related events
func LogChatEvent(event, roomID, userID string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"event":   event,
		"room_id": roomID,
		"user_id": userID,
		"type":    "chat_event",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	WithFields(fields).Info("Chat Event")
}

// LogSecurityEvent logs security-related events
func LogSecurityEvent(event, userID, ip string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"event":   event,
		"user_id": userID,
		"ip":      ip,
		"type":    "security_event",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	WithFields(fields).Warn("Security Event")
}

// LogError logs detailed error information
func LogError(err error, context string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"error":   err.Error(),
		"context": context,
		"type":    "error_detail",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	// Add stack trace for debugging
	if os.Getenv("APP_ENV") == "development" {
		fields["stack_trace"] = getStackTrace()
	}

	WithFields(fields).Error("Application Error")
}

// LogPerformance logs performance metrics
func LogPerformance(operation string, duration time.Duration, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
		"type":        "performance",
	}

	// Add metadata fields
	for k, v := range metadata {
		fields[k] = v
	}

	// Log as warning if operation takes too long
	if duration > 5*time.Second {
		WithFields(fields).Warn("Slow Operation")
	} else {
		WithFields(fields).Debug("Performance Metric")
	}
}

// Helper functions

// getStackTrace returns stack trace for debugging
func getStackTrace() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// SetLevel changes the logger level at runtime
func SetLevel(level LogLevel) {
	if instance != nil {
		instance.mu.Lock()
		defer instance.mu.Unlock()
		instance.SetLevel(getLogrusLevel(level))
	}
}

// GetLevel returns the current logger level
func GetLevel() LogLevel {
	if instance != nil {
		instance.mu.RLock()
		defer instance.mu.RUnlock()

		switch instance.GetLevel() {
		case logrus.DebugLevel:
			return DebugLevel
		case logrus.InfoLevel:
			return InfoLevel
		case logrus.WarnLevel:
			return WarnLevel
		case logrus.ErrorLevel:
			return ErrorLevel
		case logrus.FatalLevel:
			return FatalLevel
		case logrus.PanicLevel:
			return PanicLevel
		default:
			return InfoLevel
		}
	}
	return InfoLevel
}

// Flush ensures all log entries are written (useful for graceful shutdown)
func Flush() {
	// Since we're using logrus with immediate writes,
	// this is mainly for compatibility with other logging libraries
	if instance != nil {
		// Force any pending writes
		if file, ok := instance.Out.(*os.File); ok {
			file.Sync()
		}
	}
}

// Close closes the logger (useful for file outputs)
func Close() error {
	if instance != nil {
		if file, ok := instance.Out.(*os.File); ok && file != os.Stdout && file != os.Stderr {
			return file.Close()
		}
	}
	return nil
}
