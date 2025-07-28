// internal/notifications/shoutrrr.go - Shoutrrr notification handling
package notifications

import (
	"log/slog"

	"github.com/containrrr/shoutrrr"
	router "github.com/containrrr/shoutrrr/pkg/router"

	"eth-sentry/internal/config"
)

type ShoutrrrNotifier struct {
	senders []router.ServiceRouter
	logger  *slog.Logger
}

func NewShoutrrrNotifier(cfg *config.Config, logger *slog.Logger) *ShoutrrrNotifier {
	var senders []router.ServiceRouter

	for _, url := range cfg.ShoutrrrURLs {
		if sender, err := shoutrrr.CreateSender(url); err == nil {
			senders = append(senders, *sender)
		} else {
			logger.Warn("Failed to create Shoutrrr sender", "url", url, "error", err)
		}
	}

	return &ShoutrrrNotifier{
		senders: senders,
		logger:  logger,
	}
}

func (s *ShoutrrrNotifier) Send(message string) {
	for _, sender := range s.senders {
		if err := sender.Send(message, nil); err != nil {
			s.logger.Warn("Failed to send Shoutrrr notification", "error", err)
		}
	}
}
