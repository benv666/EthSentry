// internal/notifications/shoutrrr.go - Shoutrrr notification handling
package notifications

import (
	"log/slog"

	"github.com/containrrr/shoutrrr"
	router "github.com/containrrr/shoutrrr/pkg/router"
)

type ShoutrrrNotifier struct {
	senders []router.ServiceRouter
	logger  *slog.Logger
	name    string
}

func NewShoutrrrNotifier(urls []string, logger *slog.Logger) *ShoutrrrNotifier {
	var senders []router.ServiceRouter
	var name string

	if len(urls) > 0 {
		name = "shoutrrr"
	} else {
		name = "shoutrrr-empty"
	}

	for i, url := range urls {
		if url == "" {
			continue
		}

		if sender, err := shoutrrr.CreateSender(url); err == nil {
			senders = append(senders, *sender)
			logger.Debug("Created Shoutrrr sender", "index", i, "url_prefix", url[:min(20, len(url))])
		} else {
			logger.Warn("Failed to create Shoutrrr sender", "index", i, "url_prefix", url[:min(20, len(url))], "error", err)
		}
	}

	logger.Info("Initialized Shoutrrr notifier", "sender_count", len(senders), "name", name)

	return &ShoutrrrNotifier{
		senders: senders,
		logger:  logger,
		name:    name,
	}
}

func (s *ShoutrrrNotifier) Send(message string) {
	if len(s.senders) == 0 {
		s.logger.Debug("No Shoutrrr senders configured, skipping", "name", s.name)
		return
	}

	s.logger.Debug("Sending Shoutrrr notification",
		"sender_count", len(s.senders),
		"message_length", len(message),
		"name", s.name)

	successCount := 0
	for i, sender := range s.senders {
		if err := sender.Send(message, nil); err != nil {
			s.logger.Warn("Failed to send Shoutrrr notification",
				"sender_index", i,
				"error", err,
				"name", s.name)
		} else {
			successCount++
			s.logger.Debug("Shoutrrr notification sent successfully",
				"sender_index", i,
				"name", s.name)
		}
	}

	if successCount > 0 {
		s.logger.Info("Shoutrrr notifications sent",
			"success_count", successCount,
			"total_senders", len(s.senders),
			"name", s.name)
	}
}
