// internal/notifications/telegram.go - Telegram bot and command handling
package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"eth-sentry/internal/config"
)

type TelegramBot struct {
	config     *config.Config
	httpClient *http.Client
	logger     *slog.Logger
	offset     int
}

func NewTelegramBot(cfg *config.Config, logger *slog.Logger) *TelegramBot {
	return &TelegramBot{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (t *TelegramBot) SendMessage(message string) error {
	if t.config.TelegramBotToken == "" || t.config.TelegramChatID == "" {
		return fmt.Errorf("telegram not configured")
	}

	t.logger.Debug("Preparing to send Telegram message",
		"chat_id", t.config.TelegramChatID,
		"message_length", len(message))

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.config.TelegramBotToken)

	payload := map[string]interface{}{
		"chat_id":    t.config.TelegramChatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	t.logger.Debug("Sending Telegram message", "url", url, "payload_size", len(jsonData))

	resp, err := t.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.logger.Error("Telegram request failed", "error", err)
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.logger.Error("Telegram API returned error",
			"status", resp.StatusCode,
			"body", string(body))
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to check for success
	var response struct {
		Ok          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &response); err == nil {
		if response.Ok {
			t.logger.Info("Telegram message sent successfully",
				"message_id", response.Result.MessageID,
				"message_preview", message[:min(50, len(message))])
		} else {
			t.logger.Error("Telegram API response not OK", "description", response.Description)
			return fmt.Errorf("telegram API error: %s", response.Description)
		}
	} else {
		t.logger.Warn("Could not parse Telegram response, but status was OK", "body", string(body))
	}

	return nil
}

func (t *TelegramBot) ProcessCommands(commandHandler func(string, string)) {
	if t.config.TelegramBotToken == "" {
		t.logger.Warn("Telegram bot token not configured, skipping command processing")
		return
	}

	t.logger.Info("Starting Telegram command processor", "chat_id", t.config.TelegramChatID)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=10",
			t.config.TelegramBotToken, t.offset+1)

		var response struct {
			Ok          bool   `json:"ok"`
			Description string `json:"description"`
			Result      []struct {
				UpdateID int `json:"update_id"`
				Message  struct {
					MessageID int `json:"message_id"`
					Date      int `json:"date"`
					From      struct {
						ID        int64  `json:"id"`
						Username  string `json:"username"`
						FirstName string `json:"first_name"`
					} `json:"from"`
					Chat struct {
						ID   int64  `json:"id"`
						Type string `json:"type"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
			} `json:"result"`
		}

		t.logger.Debug("Polling Telegram for updates", "url", url)

		resp, err := t.httpClient.Get(url)
		if err != nil {
			t.logger.Error("Failed to poll Telegram API", "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.logger.Error("Failed to read Telegram response", "error", err)
			continue
		}

		t.logger.Debug("Telegram API response", "status", resp.StatusCode, "body_length", len(body))

		if resp.StatusCode != http.StatusOK {
			t.logger.Error("Telegram API returned error", "status", resp.StatusCode, "body", string(body))
			continue
		}

		if err := json.Unmarshal(body, &response); err != nil {
			t.logger.Error("Failed to parse Telegram response", "error", err, "body", string(body))
			continue
		}

		if !response.Ok {
			t.logger.Error("Telegram API response not OK", "description", response.Description)
			continue
		}

		t.logger.Debug("Received Telegram updates", "count", len(response.Result))

		for _, update := range response.Result {
			if update.UpdateID > t.offset {
				t.offset = update.UpdateID
			}

			// Check if message exists
			if update.Message.Text == "" {
				t.logger.Debug("Skipping update without message text", "update_id", update.UpdateID)
				continue
			}

			// Convert chat ID to string for comparison
			chatIDStr := strconv.FormatInt(update.Message.Chat.ID, 10)
			t.logger.Debug("Processing message",
				"update_id", update.UpdateID,
				"chat_id", chatIDStr,
				"expected_chat_id", t.config.TelegramChatID,
				"from", update.Message.From.Username,
				"text", update.Message.Text)

			if chatIDStr != t.config.TelegramChatID {
				t.logger.Warn("Message from unauthorized chat",
					"chat_id", chatIDStr,
					"expected", t.config.TelegramChatID,
					"from", update.Message.From.Username)
				continue
			}

			commandHandler(update.Message.Text, update.Message.From.Username)
		}
	}
}
