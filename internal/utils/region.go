package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"vrchat/pkg/database"

	"go.mongodb.org/mongo-driver/bson"
)

// RegionInfo represents region information
type RegionInfo struct {
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

// IPGeolocationResponse represents IP geolocation API response
type IPGeolocationResponse struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	RegionCode  string  `json:"region_code"`
	RegionName  string  `json:"region_name"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

// Region mapping to server regions
var regionMapping = map[string]string{
	// North America
	"US": "us-east",
	"CA": "us-east",
	"MX": "us-west",

	// Europe
	"GB": "eu-west",
	"DE": "eu-west",
	"FR": "eu-west",
	"IT": "eu-west",
	"ES": "eu-west",
	"NL": "eu-west",
	"SE": "eu-west",
	"NO": "eu-west",
	"FI": "eu-west",
	"DK": "eu-west",
	"IE": "eu-west",
	"CH": "eu-west",
	"AT": "eu-west",
	"BE": "eu-west",
	"LU": "eu-west",
	"PT": "eu-west",

	// Asia Pacific
	"CN": "ap-northeast",
	"JP": "ap-northeast",
	"KR": "ap-northeast",
	"TW": "ap-northeast",
	"HK": "ap-northeast",
	"MO": "ap-northeast",

	"SG": "ap-southeast",
	"MY": "ap-southeast",
	"TH": "ap-southeast",
	"ID": "ap-southeast",
	"PH": "ap-southeast",
	"VN": "ap-southeast",
	"AU": "ap-southeast",
	"NZ": "ap-southeast",
	"IN": "ap-southeast",

	// Default regions for other countries
	"BR": "us-east", // South America -> US East
	"AR": "us-east",
	"CL": "us-east",
	"CO": "us-east",

	"RU": "eu-west", // Russia -> EU West
	"UA": "eu-west",
	"PL": "eu-west",
	"CZ": "eu-west",
	"HU": "eu-west",

	"ZA": "eu-west", // Africa -> EU West
	"EG": "eu-west",
	"NG": "eu-west",
	"KE": "eu-west",
}

// GetRegionFromIP detects region from IP address
func GetRegionFromIP(ip string) (*RegionInfo, error) {
	// Check if it's a private IP
	if isPrivateIP(ip) {
		return getDefaultRegion(), nil
	}

	// Try to get from cache first
	if region := getRegionFromCache(ip); region != nil {
		return region, nil
	}

	// Use IP geolocation service
	region, err := getRegionFromGeolocationAPI(ip)
	if err != nil {
		// Fallback to default region
		return getDefaultRegion(), nil
	}

	// Cache the result
	cacheRegionInfo(ip, region)

	return region, nil
}

// GetRegionFromCountryCode maps country code to server region
func GetRegionFromCountryCode(countryCode string) string {
	if region, exists := regionMapping[strings.ToUpper(countryCode)]; exists {
		return region
	}
	return "us-east" // Default region
}

// GetAvailableRegions returns list of available server regions
func GetAvailableRegions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"code":        "us-east",
			"name":        "US East",
			"description": "United States East Coast",
			"flag":        "🇺🇸",
			"countries":   []string{"US", "CA", "BR", "AR", "CL", "CO"},
		},
		{
			"code":        "us-west",
			"name":        "US West",
			"description": "United States West Coast",
			"flag":        "🇺🇸",
			"countries":   []string{"MX"},
		},
		{
			"code":        "eu-west",
			"name":        "Europe West",
			"description": "Western Europe",
			"flag":        "🇪🇺",
			"countries":   []string{"GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "FI", "DK", "IE", "CH", "AT", "BE", "LU", "PT", "RU", "UA", "PL", "CZ", "HU", "ZA", "EG", "NG", "KE"},
		},
		{
			"code":        "ap-southeast",
			"name":        "Asia Pacific Southeast",
			"description": "Southeast Asia and Oceania",
			"flag":        "🌏",
			"countries":   []string{"SG", "MY", "TH", "ID", "PH", "VN", "AU", "NZ", "IN"},
		},
		{
			"code":        "ap-northeast",
			"name":        "Asia Pacific Northeast",
			"description": "Northeast Asia",
			"flag":        "🌏",
			"countries":   []string{"CN", "JP", "KR", "TW", "HK", "MO"},
		},
	}
}

// isPrivateIP checks if IP is private
func isPrivateIP(ip string) bool {
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		return false
	}

	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")

	private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)

	return private
}

// getRegionFromCache gets region info from cache
func getRegionFromCache(ip string) *RegionInfo {
	db := database.GetDB()
	collection := db.Collection("ip_cache")

	var result struct {
		IP         string     `bson:"ip"`
		RegionInfo RegionInfo `bson:"region_info"`
		CreatedAt  time.Time  `bson:"created_at"`
	}

	err := collection.FindOne(context.Background(), bson.M{
		"ip":         ip,
		"created_at": bson.M{"$gte": time.Now().Add(-24 * time.Hour)}, // Cache for 24 hours
	}).Decode(&result)

	if err != nil {
		return nil
	}

	return &result.RegionInfo
}

// cacheRegionInfo caches region info
func cacheRegionInfo(ip string, region *RegionInfo) {
	db := database.GetDB()
	collection := db.Collection("ip_cache")

	doc := bson.M{
		"ip":          ip,
		"region_info": region,
		"created_at":  time.Now(),
	}

	collection.InsertOne(context.Background(), doc)
}

// getRegionFromGeolocationAPI gets region from IP geolocation API
func getRegionFromGeolocationAPI(ip string) (*RegionInfo, error) {
	// Using ipapi.co as free IP geolocation service
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ip)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var geoResp IPGeolocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&geoResp); err != nil {
		return nil, err
	}

	// Map to our region structure
	region := &RegionInfo{
		Code:        GetRegionFromCountryCode(geoResp.CountryCode),
		Name:        geoResp.RegionName,
		Country:     geoResp.CountryName,
		CountryCode: geoResp.CountryCode,
		City:        geoResp.City,
		Latitude:    geoResp.Latitude,
		Longitude:   geoResp.Longitude,
		Timezone:    geoResp.Timezone,
	}

	return region, nil
}

// getDefaultRegion returns default region for fallback
func getDefaultRegion() *RegionInfo {
	return &RegionInfo{
		Code:        "us-east",
		Name:        "US East",
		Country:     "United States",
		CountryCode: "US",
		City:        "Unknown",
		Latitude:    0,
		Longitude:   0,
		Timezone:    "UTC",
	}
}

// CalculateDistance calculates distance between two geographic points
func CalculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	// Haversine formula implementation
	const R = 6371 // Earth's radius in kilometers

	dLat := (lat2 - lat1) * (3.14159265359 / 180.0)
	dLon := (lon2 - lon1) * (3.14159265359 / 180.0)

	a := 0.5 - (0.5 * (1 + (dLat * dLat / 4))) +
		(lat1*3.14159265359/180.0)*(lat2*3.14159265359/180.0)*
			0.5*(1-(dLon*dLon/4))

	return R * 2 * (3.14159265359/2 - a)
}

// FindNearestRegion finds the nearest server region to user's location
func FindNearestRegion(userLat, userLon float64) string {
	// Server region coordinates (approximate)
	regions := map[string][]float64{
		"us-east":      {39.0458, -76.6413},  // Virginia
		"us-west":      {37.4419, -122.1430}, // California
		"eu-west":      {51.5074, -0.1278},   // London
		"ap-southeast": {1.3521, 103.8198},   // Singapore
		"ap-northeast": {35.6762, 139.6503},  // Tokyo
	}

	nearestRegion := "us-east"
	minDistance := float64(999999)

	for region, coords := range regions {
		distance := CalculateDistance(userLat, userLon, coords[0], coords[1])
		if distance < minDistance {
			minDistance = distance
			nearestRegion = region
		}
	}

	return nearestRegion
}
