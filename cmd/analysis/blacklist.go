package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type BlacklistConfig struct {
	AbuseIPDBAPIKey string
	CacheExpiry     time.Duration
}

type AbuseIPDBResponse struct {
	Data []AbuseIPDBEntry `json:"data"`
}

type AbuseIPDBEntry struct {
	IPAddress                string `json:"ipAddress"`
	IsPublic                 bool   `json:"isPublic"`
	IPVersion                int    `json:"ipVersion"`
	IsWhitelisted            bool   `json:"isWhitelisted"`
	AbuseConfidenceScore     int    `json:"abuseConfidenceScore"`
	CountryCode              string `json:"countryCode"`
	CountryName              string `json:"countryName"`
	ISOCC                    string `json:"isoCode"`
	UsageType                string `json:"usageType"`
	ISP                      string `json:"isp"`
	Domain                   string `json:"domain"`
	TotalReports             int    `json:"totalReports"`
	NumDistinctUsers         int    `json:"numDistinctUsers"`
	LastReportedAt           string `json:"lastReportedAt"`
	PublishDate              string `json:"publishDate"`
	Comments                 string `json:"comments"`
	TotalAcceptedSubmissions int    `json:"totalAcceptedSubmissions"`
}

type IPBlacklistClient struct {
	cfg    BlacklistConfig
	client *http.Client
	cache  *ipCache
}

type ipCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	expiry  time.Duration
}

type cacheEntry struct {
	result *BlacklistResult
	expiry time.Time
}

type BlacklistResult struct {
	IP              string
	IsListed        bool
	ConfidenceScore int
	CountryCode     string
	ISP             string
	TotalReports    int
	ReportTypes     []string
	LastReportedAt  time.Time
}

func NewBlacklistClient(cfg BlacklistConfig) *IPBlacklistClient {
	if cfg.CacheExpiry == 0 {
		cfg.CacheExpiry = 1 * time.Hour
	}
	return &IPBlacklistClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: &ipCache{
			entries: make(map[string]cacheEntry),
			expiry:  cfg.CacheExpiry,
		},
	}
}

func (b *IPBlacklistClient) CheckIP(ctx context.Context, ip string) (*BlacklistResult, error) {
	parsed, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP: %w", err)
	}
	if parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() {
		return &BlacklistResult{IP: ip, IsListed: false}, nil
	}

	b.cache.mu.RLock()
	if cached, ok := b.cache.entries[ip]; ok && time.Now().Before(cached.expiry) {
		b.cache.mu.RUnlock()
		return cached.result, nil
	}
	b.cache.mu.RUnlock()

	result, err := b.queryAbuseIPDB(ctx, ip)
	if err != nil {
		return nil, err
	}

	b.cache.mu.Lock()
	b.cache.entries[ip] = cacheEntry{
		result: result,
		expiry: time.Now().Add(b.cache.expiry),
	}
	b.cache.mu.Unlock()

	return result, nil
}

func (b *IPBlacklistClient) queryAbuseIPDB(ctx context.Context, ip string) (*BlacklistResult, error) {
	if b.cfg.AbuseIPDBAPIKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	url := fmt.Sprintf("https://www.abuseipdb.com/api/v2/check?ip=%s&maxAgeInDays=90&verbose", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", b.cfg.AbuseIPDBAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB API error: %s %s", resp.Status, string(body))
	}

	var abuseResp AbuseIPDBResponse
	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(abuseResp.Data) == 0 {
		return &BlacklistResult{IP: ip, IsListed: false}, nil
	}

	entry := abuseResp.Data[0]
	var lastReported time.Time
	if entry.LastReportedAt != "" {
		lastReported, _ = time.Parse(time.RFC3339, entry.LastReportedAt)
	}

	return &BlacklistResult{
		IP:              ip,
		IsListed:        entry.AbuseConfidenceScore > 0,
		ConfidenceScore: entry.AbuseConfidenceScore,
		CountryCode:     entry.CountryCode,
		ISP:             entry.ISP,
		TotalReports:    entry.TotalReports,
		LastReportedAt:  lastReported,
	}, nil
}

type AutoConfig struct {
	Enabled             bool
	ConfidenceThreshold int
}

var (
	blacklistClient    *IPBlacklistClient
	autoBlacklistCheck = AutoConfig{
		Enabled:             true,
		ConfidenceThreshold: 50,
	}
)

func checkBlacklist(ctx context.Context, event *Event) (verdict string, confidence float64, reason string) {
	if event.EventType != EventTypeNetwork || event.RemoteAddr == "" || blacklistClient == nil {
		return "", 0, ""
	}

	ip := extractIP(event.RemoteAddr)
	if ip == "" {
		return "", 0, ""
	}

	result, err := blacklistClient.CheckIP(ctx, ip)
	if err != nil {
		log.Printf("Blacklist check failed for %s: %v", ip, err)
		return "", 0, ""
	}

	if result.IsListed && result.ConfidenceScore >= autoBlacklistCheck.ConfidenceThreshold {
		return "suspicious", float64(result.ConfidenceScore) / 100.0,
			fmt.Sprintf("IP %s blacklisted (confidence: %d, reports: %d, ISP: %s)",
				ip, result.ConfidenceScore, result.TotalReports, result.ISP)
	}

	return "", 0, ""
}

func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		if strings.Contains(parts[0], ".") {
			return parts[0]
		}
		if strings.Contains(parts[0], "[") {
			return strings.Trim(parts[0], "[]")
		}
	}
	if parsed, err := netip.ParseAddr(parts[0]); err == nil {
		return parsed.String()
	}
	return ""
}
