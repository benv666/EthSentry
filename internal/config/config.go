// internal/config/config.go - Configuration management
package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	BeaconNodeURL              string   `json:"beacon_node_url"`
	ExecutionClientURL         string   `json:"execution_node_url"`
	FallbackBeaconNodeURL      string   `json:"fallback_beacon_node_url"`
	FallbackExecutionClientURL string   `json:"fallback_execution_node_url"`
	TelegramBotToken           string   `json:"telegram_bot_token"`
	TelegramChatID             string   `json:"telegram_chat_id"`
	ValidatorIndices           []int    `json:"validator_indices"`
	CheckInterval              int      `json:"check_interval_minutes"`
	SlotCheckInterval          int      `json:"slot_check_interval_seconds"`
	ProposalLookahead          int      `json:"proposal_lookahead_epochs"`
	SyncCommitteeLookahead     int      `json:"sync_committee_lookahead_epochs"`
	ShoutrrrURLs               []string `json:"shoutrrr_urls"`
	EnablePrometheus           bool     `json:"enable_prometheus"`
	PrometheusPort             int      `json:"prometheus_port"`
	EpochSummaryEnabled        bool     `json:"epoch_summary_enabled"`
}

func Load() (Config, error) {
	var config Config

	// Load from environment variables
	config.BeaconNodeURL = getEnvDefault("BEACON_NODE_URL", "http://localhost:5052")
	config.ExecutionClientURL = getEnvDefault("EXECUTION_CLIENT_URL", "http://localhost:8545")
	config.FallbackBeaconNodeURL = os.Getenv("FALLBACK_BEACON_NODE_URL")
	config.FallbackExecutionClientURL = os.Getenv("FALLBACK_EXECUTION_CLIENT_URL")
	config.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	config.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")

	// Parse validator indices
	if indices := os.Getenv("VALIDATOR_INDICES"); indices != "" {
		parts := strings.Split(indices, ",")
		config.ValidatorIndices = make([]int, 0, len(parts))
		for _, part := range parts {
			if idx, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				config.ValidatorIndices = append(config.ValidatorIndices, idx)
			}
		}
	}

	// Parse intervals
	config.CheckInterval = getEnvInt("CHECK_INTERVAL", 5)
	config.SlotCheckInterval = getEnvInt("SLOT_CHECK_INTERVAL", 12)
	config.ProposalLookahead = getEnvInt("PROPOSAL_LOOKAHEAD", 1)
	config.SyncCommitteeLookahead = getEnvInt("SYNC_COMMITTEE_LOOKAHEAD", 1)

	// Parse Shoutrrr URLs
	if urls := os.Getenv("SHOUTRRR_URLS"); urls != "" {
		config.ShoutrrrURLs = strings.Split(urls, ",")
		for i := range config.ShoutrrrURLs {
			config.ShoutrrrURLs[i] = strings.TrimSpace(config.ShoutrrrURLs[i])
		}
	}

	// Prometheus and feature settings
	config.EnablePrometheus = getEnvBool("ENABLE_PROMETHEUS", false)
	config.PrometheusPort = getEnvInt("PROMETHEUS_PORT", 8080)
	config.EpochSummaryEnabled = getEnvBool("EPOCH_SUMMARY_ENABLED", true)

	// Sort validator indices for consistent ordering
	sort.Ints(config.ValidatorIndices)

	// Validate required fields
	if config.TelegramBotToken == "" {
		return config, fmt.Errorf("TELEGRAM_BOT_TOKEN is required")
	}
	if config.TelegramChatID == "" {
		return config, fmt.Errorf("TELEGRAM_CHAT_ID is required")
	}

	return config, nil
}

func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
