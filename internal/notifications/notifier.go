// internal/notifications/notifier.go - Main notification coordinator
package notifications

import (
	"log/slog"

	"eth-sentry/internal/config"
)

type Notifier struct {
	telegram *TelegramBot
	shoutrrr *ShoutrrrNotifier
	logger   *slog.Logger
}

func New(cfg *config.Config, logger *slog.Logger) *Notifier {
	return &Notifier{
		telegram: NewTelegramBot(cfg, logger),
		shoutrrr: NewShoutrrrNotifier(cfg, logger),
		logger:   logger,
	}
}

func (n *Notifier) Send(message, notificationType string) error {
	n.logger.Debug("Sending notification", "type", notificationType, "message_length", len(message))

	// Send to Telegram
	if err := n.telegram.SendMessage(message); err != nil {
		n.logger.Warn("Failed to send Telegram notification", "error", err)
		return err
	}

	// Send to Shoutrrr endpoints
	n.shoutrrr.Send(message)
	return nil
}

func (n *Notifier) StartTelegramCommandProcessor(commandHandler func(string, string)) {
	go n.telegram.ProcessCommands(commandHandler)
}
