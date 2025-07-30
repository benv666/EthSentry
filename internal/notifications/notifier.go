// internal/notifications/notifier.go - Enhanced notification coordinator with critical/standard channels
package notifications

import (
	"log/slog"
	"strings"
	"time"

	"eth-sentry/internal/config"
)

type NotificationLevel int

const (
	LevelStandard NotificationLevel = iota
	LevelCritical
)

type Notifier struct {
	telegram         *TelegramBot
	standardShoutrrr *ShoutrrrNotifier
	criticalShoutrrr *ShoutrrrNotifier
	logger           *slog.Logger
	config           *config.Config

	// Muting state
	mutedAlerts map[string]time.Time
}

func New(cfg *config.Config, logger *slog.Logger) *Notifier {
	return &Notifier{
		telegram:         NewTelegramBot(cfg, logger),
		standardShoutrrr: NewShoutrrrNotifier(cfg.ShoutrrrURLs, logger),
		criticalShoutrrr: NewShoutrrrNotifier(cfg.CriticalShoutrrrURLs, logger),
		logger:           logger,
		config:           cfg,
		mutedAlerts:      make(map[string]time.Time),
	}
}

func (n *Notifier) Send(message, notificationType string) error {
	return n.SendWithLevel(message, notificationType, LevelStandard)
}

func (n *Notifier) SendCritical(message, notificationType string) error {
	return n.SendWithLevel(message, notificationType, LevelCritical)
}

func (n *Notifier) SendWithLevel(message, notificationType string, level NotificationLevel) error {
	// Check if this should be muted
	if n.config.MuteRepeatingEvents && n.shouldMute(notificationType, level) {
		n.logger.Debug("Notification muted",
			"type", notificationType,
			"level", level,
			"message_preview", message[:min(50, len(message))])
		return nil
	}

	levelStr := "STANDARD"
	if level == LevelCritical {
		levelStr = "CRITICAL"
	}

	n.logger.Info("Sending notification",
		"type", notificationType,
		"level", levelStr,
		"message_length", len(message))

	// Always send to Telegram
	if err := n.telegram.SendMessage(message); err != nil {
		n.logger.Warn("Failed to send Telegram notification", "error", err)
		return err
	}

	// Send to appropriate Shoutrrr channels
	if level == LevelCritical {
		// Critical messages go to both channels
		n.standardShoutrrr.Send(message)
		n.criticalShoutrrr.Send(message)
	} else {
		// Standard messages only go to standard channel
		n.standardShoutrrr.Send(message)
	}

	// Update muting state
	n.updateMutingState(notificationType, level)

	return nil
}

func (n *Notifier) shouldMute(notificationType string, level NotificationLevel) bool {
	// Never mute critical notifications
	if level == LevelCritical {
		return false
	}

	// Never mute certain notification types
	neverMute := []string{
		"startup",
		"shutdown",
		"successful_proposal",
		"upcoming_proposal",
		"sync_committee",
		"telegram_response",
	}

	for _, exempt := range neverMute {
		if notificationType == exempt {
			return false
		}
	}

	// Check if we've sent this type recently
	if lastSent, exists := n.mutedAlerts[notificationType]; exists {
		// Different mute durations for different types
		muteDuration := n.getMuteDuration(notificationType)
		if time.Since(lastSent) < muteDuration {
			return true
		}
	}

	return false
}

func (n *Notifier) getMuteDuration(notificationType string) time.Duration {
	switch {
	case strings.Contains(notificationType, "missed_attestation"):
		return 30 * time.Minute // Mute repeated missed attestation alerts
	case strings.Contains(notificationType, "node_error"):
		return 15 * time.Minute // Mute node error repeats
	case strings.Contains(notificationType, "node_syncing"):
		return 15 * time.Minute // Mute syncing status repeats
	case notificationType == "status_summary":
		return time.Duration(n.config.StatusSummaryInterval) * time.Hour
	case notificationType == "epoch_summary":
		return 1 * time.Hour // Don't spam epoch summaries
	default:
		return 10 * time.Minute // Default mute duration
	}
}

func (n *Notifier) updateMutingState(notificationType string, level NotificationLevel) {
	// Only track muting for non-critical notifications
	if level != LevelCritical {
		n.mutedAlerts[notificationType] = time.Now()
	}
}

func (n *Notifier) StartTelegramCommandProcessor(commandHandler func(string, string)) {
	go n.telegram.ProcessCommands(commandHandler)
}

// Helper function to determine if a notification should be critical
func (n *Notifier) IsCriticalNotification(notificationType string) bool {
	criticalTypes := []string{
		"validator_slashed",
		"node_error",
		"missed_attestation", // Missed attestations are critical
		"startup",
		"shutdown",
	}

	for _, critical := range criticalTypes {
		if strings.Contains(notificationType, critical) {
			return true
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
