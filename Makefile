.PHONY: build run test clean docker

# Variables
APP_NAME=omegle-backend
DOCKER_IMAGE=omegle-backend:latest

# Build the application
build:
	go build -o bin/$(APP_NAME) ./cmd/server

# Run the application
run:
	go run ./cmd/server/main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Install dependencies
deps:
	go mod download
	go mod tidy

# Run with live reload (requires air)
dev:
	air

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE) .

# Run with Docker Compose
docker-up:
	docker-compose up --build

# Stop Docker Compose
docker-down:
	docker-compose down

# Database migration
migrate:
	go run ./scripts/migrate.go

# Setup development environment
setup:
	./scripts/setup.sh

# Lint code
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Generate documentation
docs:
	swag init -g ./cmd/server/main.go

# Production build
prod-build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/$(APP_NAME) ./cmd/server