// internal/monitor/monitor.go - Updated monitoring logic with proper duty management
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"eth-sentry/internal/attestation"
	"eth-sentry/internal/beacon"
	"eth-sentry/internal/config"
	"eth-sentry/internal/duties"
	"eth-sentry/internal/notifications"
	"eth-sentry/internal/prometheus"
	"eth-sentry/internal/types"
)

type Monitor struct {
	config             *config.Config
	beaconClient       *beacon.Client
	dutyManager        *duties.Manager
	attestationChecker *attestation.Checker
	validatorManager   *ValidatorManager
	notifier           *notifications.Notifier
	metrics            *prometheus.Metrics
	logger             *slog.Logger
	lastProcessedSlot  int
	lastProcessedEpoch int
	startupComplete    bool
}

func New(cfg *config.Config, notifier *notifications.Notifier, logger *slog.Logger) *Monitor {
	beaconClient := beacon.NewClient(logger)
	dutyManager := duties.NewManager(beaconClient, logger)
	attestationChecker := attestation.NewChecker(beaconClient, dutyManager, logger)
	validatorManager := NewValidatorManager(cfg.ValidatorIndices, logger)
	metrics := prometheus.New(cfg.EnablePrometheus, cfg.PrometheusPort)

	return &Monitor{
		config:             cfg,
		beaconClient:       beaconClient,
		dutyManager:        dutyManager,
		attestationChecker: attestationChecker,
		validatorManager:   validatorManager,
		notifier:           notifier,
		metrics:            metrics,
		logger:             logger,
		startupComplete:    false,
	}
}

func (m *Monitor) Start(ctx context.Context) {
	m.logger.Info("Starting Enhanced Ethereum Validator Monitor with Proper Attestation Tracking",
		"slot_check_interval", m.config.SlotCheckInterval,
		"full_check_interval", m.config.CheckInterval,
		"validator_count", len(m.config.ValidatorIndices),
		"prometheus_enabled", m.config.EnablePrometheus,
		"mute_repeating_events", m.config.MuteRepeatingEvents)

	// Start telegram command processor
	m.notifier.StartTelegramCommandProcessor(m.handleTelegramCommand)

	// Get initial state
	if currentSlot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL); err == nil {
		m.lastProcessedSlot = currentSlot - 1
		m.lastProcessedEpoch = (currentSlot - 1) / 32

		// Fetch duties for current and next epoch
		currentEpoch := currentSlot / 32
		m.fetchDutiesForEpoch(currentEpoch)
		m.fetchDutiesForEpoch(currentEpoch + 1)
	}

	// Run initial startup check and send startup summary
	m.runStartupCheck()

	// Setup tickers
	slotTicker := time.NewTicker(time.Duration(m.config.SlotCheckInterval) * time.Second)
	fullTicker := time.NewTicker(time.Duration(m.config.CheckInterval) * time.Minute)
	defer slotTicker.Stop()
	defer fullTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Shutting down validator monitor...")

			exitMessage := "🛑 <b>Enhanced Validator Monitor Stopped</b>\n\n" +
				"<i>Monitoring has been temporarily disabled. " +
				"Please restart the service to resume monitoring.</i>"

			m.notifier.SendCritical(exitMessage, "shutdown")
			return

		case <-slotTicker.C:
			m.runSlotCheck()

		case <-fullTicker.C:
			m.runFullCheck()
		}
	}
}

func (m *Monitor) fetchDutiesForEpoch(epoch int) {
	if len(m.config.ValidatorIndices) == 0 {
		return
	}

	m.logger.Info("Fetching duties for epoch", "epoch", epoch, "validator_count", len(m.config.ValidatorIndices))

	if err := m.dutyManager.FetchAndStoreDuties(m.config.BeaconNodeURL, epoch, m.config.ValidatorIndices); err != nil {
		m.logger.Error("Failed to fetch duties for epoch", "epoch", epoch, "error", err)
	} else {
		validatorCount, slotCount, totalDuties := m.dutyManager.GetStats()
		m.logger.Info("Successfully fetched and stored duties",
			"epoch", epoch,
			"validators_with_duties", validatorCount,
			"slots_with_duties", slotCount,
			"total_duties", totalDuties)
	}
}

func (m *Monitor) runStartupCheck() {
	m.logger.Info("Running startup system check")

	// Check all nodes
	nodes, err := m.checkAllNodes()
	if err != nil {
		m.logger.Error("Failed to check nodes during startup", "error", err)
		return
	}

	// Get current epoch info
	currentSlot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL)
	currentEpoch := 0
	epochInfo := "❌ Unknown"
	if err == nil {
		currentEpoch = currentSlot / 32
		epochInfo = fmt.Sprintf("%d (Slot %d)", currentEpoch, currentSlot)
	}

	// Check validator statuses
	activeValidators := 0
	exitingValidators := 0
	validators, err := m.beaconClient.GetValidatorStatuses(m.config.BeaconNodeURL, m.config.ValidatorIndices)
	if err == nil {
		for _, validator := range validators {
			if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
				activeValidators++
			} else if strings.Contains(validator.Status, "exit") {
				exitingValidators++
			}
		}
	}

	// Check upcoming duties
	upcomingProposals := m.getUpcomingProposalsCount(currentEpoch)
	upcomingSyncCommittee := m.getUpcomingSyncCommitteeCount(currentEpoch)

	// Get duty statistics
	validatorCount, slotCount, totalDuties := m.dutyManager.GetStats()

	// Build node status summary
	var nodeStatuses []string
	primaryOK := true
	for _, node := range nodes {
		status := "❌ Failed"
		if node.Error == nil {
			if node.Synced {
				status = "✅ Synced"
			} else {
				status = "⏳ Syncing"
				if strings.Contains(node.Name, "Primary") {
					primaryOK = false
				}
			}
		} else if strings.Contains(node.Name, "Primary") {
			primaryOK = false
		}
		nodeStatuses = append(nodeStatuses, fmt.Sprintf("• %s: %s", node.Name, status))
	}

	// Build startup message
	statusIcon := "🚀"
	if !primaryOK {
		statusIcon = "⚠️"
	}

	message := fmt.Sprintf("%s <b>Validator Monitor Started</b>\n\n"+
		"<b>System Status:</b>\n%s\n"+
		"• Current Epoch: %s\n\n"+
		"<b>Validators:</b>\n"+
		"• Active: %d/%d\n"+
		"• Exiting: %d\n\n"+
		"<b>Duties Loaded:</b>\n"+
		"• Validators: %d\n"+
		"• Slots: %d\n"+
		"• Total: %d\n\n"+
		"<b>Upcoming Duties:</b>\n"+
		"• Proposals: %d\n"+
		"• Sync Committee: %d\n\n"+
		"<b>Monitoring:</b>\n"+
		"• Slot checks: %ds intervals\n"+
		"• Full checks: %dm intervals\n"+
		"• Muting: %v\n\n"+
		"<i>Enhanced monitoring with proper attestation tracking is now active!</i>",
		statusIcon,
		strings.Join(nodeStatuses, "\n"),
		epochInfo,
		activeValidators, len(m.config.ValidatorIndices),
		exitingValidators,
		validatorCount, slotCount, totalDuties,
		upcomingProposals,
		upcomingSyncCommittee,
		m.config.SlotCheckInterval,
		m.config.CheckInterval,
		m.config.MuteRepeatingEvents)

	// Send startup notification (always critical to ensure delivery)
	m.notifier.SendCritical(message, "startup")
	m.startupComplete = true
}

func (m *Monitor) runSlotCheck() {
	currentSlot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL)
	if err != nil {
		if m.startupComplete {
			m.logger.Error("Failed to get current slot", "error", err)
			// Only send node error if we've completed startup
			if m.notifier.IsCriticalNotification("node_error") {
				m.notifier.SendCritical(fmt.Sprintf("🚨 <b>Beacon Node Error</b>\nFailed to get current slot: %v", err), "node_error")
			}
		}
		return
	}

	// Only process if we haven't seen this slot yet
	if currentSlot <= m.lastProcessedSlot {
		return
	}

	m.logger.Debug("Processing new slots", "current_slot", currentSlot, "last_processed", m.lastProcessedSlot)

	// Process each new slot
	for slot := m.lastProcessedSlot + 1; slot <= currentSlot; slot++ {
		// Check for block proposals in this slot
		if err := m.checkProposalPerformance(slot); err != nil {
			m.logger.Debug("Error checking proposal performance", "slot", slot, "error", err)
		}

		// Check attestation inclusions in this slot (this is the key improvement!)
		if m.startupComplete {
			m.checkAttestationInclusionsInSlot(uint64(slot))
		}
	}

	m.lastProcessedSlot = currentSlot

	// Check if we entered a new epoch
	currentEpoch := currentSlot / 32
	if currentEpoch > m.lastProcessedEpoch {
		m.logger.Info("New epoch detected", "epoch", currentEpoch, "slot", currentSlot)

		// Fetch duties for the new epoch ahead
		lookAheadEpoch := currentEpoch + 1
		m.fetchDutiesForEpoch(lookAheadEpoch)

		// Check for missed attestations from previous epochs (after startup)
		if m.lastProcessedEpoch > 0 && m.startupComplete {
			m.checkMissedAttestations(uint64(currentSlot))
		}

		// Clean up old duties to prevent memory leak
		m.dutyManager.CleanupOldDuties(uint64(currentEpoch))

		// Send epoch summary if enabled (but allow muting)
		if m.config.EpochSummaryEnabled && m.startupComplete {
			m.sendEpochSummary(m.lastProcessedEpoch)
		}

		m.lastProcessedEpoch = currentEpoch
		m.metrics.UpdateCurrentEpoch(currentEpoch)
	}
}

func (m *Monitor) checkAttestationInclusionsInSlot(blockSlot uint64) {
	// This is the core of proper attestation checking!
	results, err := m.attestationChecker.CheckAttestationInclusion(m.config.BeaconNodeURL, blockSlot)
	if err != nil {
		m.logger.Debug("Error checking attestation inclusions", "slot", blockSlot, "error", err)
		return
	}

	if len(results) > 0 {
		m.logger.Info("Found attestation inclusions", "slot", blockSlot, "inclusions", len(results))

		// Update metrics and validator manager
		for _, result := range results {
			m.metrics.UpdateAttestation(result.ValidatorIndex, result.Attested)
			// Note: We don't send individual inclusion notifications as they would be spam
			// The important thing is that we're tracking them correctly
		}
	}
}

func (m *Monitor) checkMissedAttestations(currentSlot uint64) {
	// Check for missed attestations with a reasonable lookback
	lookbackSlots := uint64(64) // About 2 epochs worth of slots

	missedAttestations := m.attestationChecker.GetMissedAttestations(currentSlot, lookbackSlots)

	if len(missedAttestations) > 0 {
		m.logger.Warn("Found missed attestations", "count", len(missedAttestations))

		// Send notifications for missed attestations
		for _, missed := range missedAttestations {
			m.metrics.UpdateAttestation(missed.ValidatorIndex, false)

			alertKey := fmt.Sprintf("missed_attestation_%d_%d", missed.ValidatorIndex, missed.Epoch)
			message := fmt.Sprintf("⚠️ <b>Missed Attestation</b>\nValidator: %d\nEpoch: %d\nSlot: %d",
				missed.ValidatorIndex, missed.Epoch, missed.Slot)

			// Missed attestations are critical
			m.notifier.SendCritical(message, alertKey)
		}
	}
}

func (m *Monitor) runFullCheck() {
	if !m.startupComplete {
		return // Skip full checks until startup is complete
	}

	m.logger.Info("Starting full validator monitoring check")

	// Check all nodes
	nodes, err := m.checkAllNodes()
	if err != nil {
		m.logger.Error("Failed to check nodes", "error", err)
		return
	}

	// Update metrics
	m.metrics.UpdateNodeStatus(nodes)

	// Check for node issues and send alerts
	primaryBeaconOk := false
	primaryExecutionOk := false

	for _, node := range nodes {
		if node.Error != nil {
			alertKey := fmt.Sprintf("%s_error", strings.ToLower(strings.ReplaceAll(node.Name, " ", "_")))
			message := fmt.Sprintf("🚨 <b>%s Node Error</b>\nURL: %s\nError: %v",
				node.Name, node.URL, node.Error)
			m.notifier.SendCritical(message, alertKey)
		} else if !node.Synced {
			alertKey := fmt.Sprintf("%s_syncing", strings.ToLower(strings.ReplaceAll(node.Name, " ", "_")))
			message := fmt.Sprintf("⚠️ <b>%s Node Syncing</b>\nURL: %s\nNode is not fully synced",
				node.Name, node.URL)
			m.notifier.Send(message, alertKey) // Node syncing is not critical
		}

		if node.Name == "Primary Beacon" && node.Error == nil && node.Synced {
			primaryBeaconOk = true
		}
		if node.Name == "Primary Execution" && node.Error == nil && node.Synced {
			primaryExecutionOk = true
		}
	}

	if !primaryBeaconOk || !primaryExecutionOk {
		m.logger.Warn("Primary nodes not ready, skipping validator checks")
		return
	}

	// Get current epoch
	currentSlot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL)
	if err != nil {
		m.logger.Error("Failed to get current epoch", "error", err)
		return
	}
	currentEpoch := currentSlot / 32

	// Check validator statuses
	validators, err := m.beaconClient.GetValidatorStatuses(m.config.BeaconNodeURL, m.config.ValidatorIndices)
	if err != nil {
		m.logger.Error("Failed to get validator statuses", "error", err)
		return
	}

	// Update validator states and check for changes
	changes := m.validatorManager.UpdateValidatorStates(validators)
	for _, change := range changes {
		m.logger.Info("Validator state change", "change", change)
		// Send notification for significant changes
		if strings.Contains(change, "slashed") {
			m.notifier.SendCritical(fmt.Sprintf("🚨 <b>Validator Slashed!</b>\n%s", change), "validator_slashed")
		}
	}

	// Update Prometheus metrics
	activeCount := 0
	for _, validator := range validators {
		idx := validator.Index
		balance, _ := strconv.ParseFloat(validator.Balance, 64)
		active := validator.Status == "active_ongoing" && !validator.Validator.Slashed

		m.metrics.UpdateValidatorStatus(idx, validator.Status, balance, active)

		if active {
			activeCount++
		}
	}

	// Check upcoming duties
	m.checkUpcomingProposals(currentEpoch)
	m.checkSyncCommitteeParticipation(currentEpoch)

	// Send periodic status summary (with muting support)
	if m.validatorManager.ShouldSendAlert("status_summary", m.config.StatusSummaryInterval*60) {
		validatorCount, slotCount, totalDuties := m.dutyManager.GetStats()

		message := fmt.Sprintf(
			"✅ <b>Validator Status Summary</b>\n"+
				"Epoch: %d\n"+
				"Active Validators: %d/%d\n"+
				"Duties ValidatorCount: %d\n"+
				"Duties slotCount: %d\n"+
				"Duties Tracked: %d\n"+
				"Nodes: All operational",
			currentEpoch,
			activeCount,
			len(m.config.ValidatorIndices),
			validatorCount,
			slotCount,
			totalDuties)
		m.notifier.Send(message, "status_summary")
	}

	m.logger.Info("Full check completed",
		"epoch", currentEpoch,
		"active_validators", activeCount,
		"total_validators", len(m.config.ValidatorIndices))
}

func (m *Monitor) checkProposalPerformance(slot int) error {
	// Get block info for the slot
	blockInfo, err := m.beaconClient.GetBlock(m.config.BeaconNodeURL, slot)
	if err != nil {
		// No block proposed at this slot
		return nil
	}

	proposerIndex, err := strconv.Atoi(blockInfo.Data.Message.ProposerIndex)
	if err != nil {
		return err
	}

	// Check if this is one of our validators
	states := m.validatorManager.GetStates()
	if _, exists := states[proposerIndex]; !exists {
		return nil // Not our validator
	}

	// Calculate reward (simplified - would need to get actual execution payload data)
	gasUsed, _ := strconv.ParseInt(blockInfo.Data.Message.Body.ExecutionPayload.GasUsed, 0, 64)
	// Simplified reward calculation - in practice you'd need to get tips and base fees
	estimatedReward := gasUsed * 15 // gwei per gas (very rough estimate)

	// Update validator state
	m.validatorManager.UpdateProposal(proposerIndex, slot, estimatedReward)

	// Send notification about successful proposal (never muted)
	epoch := slot / 32
	message := fmt.Sprintf("🎯 <b>Block Proposed!</b>\n"+
		"Validator: %d\n"+
		"Slot: %d\n"+
		"Epoch: %d\n"+
		"Estimated Reward: %.6f ETH",
		proposerIndex, slot, epoch, float64(estimatedReward)/1e9)

	m.notifier.Send(message, "successful_proposal")

	// Update Prometheus metrics
	m.metrics.UpdateProposal(proposerIndex, slot, estimatedReward, true)

	m.logger.Info("Successful block proposal detected",
		"validator", proposerIndex,
		"slot", slot,
		"epoch", epoch,
		"estimated_reward", estimatedReward)

	return nil
}

func (m *Monitor) getUpcomingProposalsCount(currentEpoch int) int {
	count := 0
	validatorIndexMap := make(map[string]bool)
	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.ProposalLookahead; i++ {
		epoch := currentEpoch + i
		duties, err := m.beaconClient.GetProposerDuties(m.config.BeaconNodeURL, epoch)
		if err != nil {
			continue
		}

		for _, duty := range duties {
			if validatorIndexMap[duty.ValidatorIndex] {
				count++
			}
		}
	}

	return count
}

func (m *Monitor) getUpcomingSyncCommitteeCount(currentEpoch int) int {
	count := 0
	validatorIndexMap := make(map[string]bool)
	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.SyncCommitteeLookahead; i++ {
		epoch := currentEpoch + i
		syncCommittee, err := m.beaconClient.GetSyncCommittee(m.config.BeaconNodeURL, epoch)
		if err != nil {
			continue
		}

		for _, validatorIdx := range syncCommittee.Validators {
			if validatorIndexMap[validatorIdx] {
				count++
			}
		}
	}

	return count
}

func (m *Monitor) checkAllNodes() ([]types.NodeStatus, error) {
	var nodes []types.NodeStatus

	// Primary beacon node
	beaconSynced, beaconErr := m.beaconClient.CheckBeaconNodeSync(m.config.BeaconNodeURL)
	nodes = append(nodes, types.NodeStatus{
		Name:   "Primary Beacon",
		URL:    m.config.BeaconNodeURL,
		Synced: beaconSynced,
		Error:  beaconErr,
	})

	// Primary execution node
	executionSynced, executionErr := m.beaconClient.CheckExecutionClientSync(m.config.ExecutionClientURL)
	nodes = append(nodes, types.NodeStatus{
		Name:   "Primary Execution",
		URL:    m.config.ExecutionClientURL,
		Synced: executionSynced,
		Error:  executionErr,
	})

	// Fallback nodes
	if m.config.FallbackBeaconNodeURL != "" {
		fallbackBeaconSynced, fallbackBeaconErr := m.beaconClient.CheckBeaconNodeSync(m.config.FallbackBeaconNodeURL)
		nodes = append(nodes, types.NodeStatus{
			Name:   "Fallback Beacon",
			URL:    m.config.FallbackBeaconNodeURL,
			Synced: fallbackBeaconSynced,
			Error:  fallbackBeaconErr,
		})
	}

	if m.config.FallbackExecutionClientURL != "" {
		fallbackExecutionSynced, fallbackExecutionErr := m.beaconClient.CheckExecutionClientSync(m.config.FallbackExecutionClientURL)
		nodes = append(nodes, types.NodeStatus{
			Name:   "Fallback Execution",
			URL:    m.config.FallbackExecutionClientURL,
			Synced: fallbackExecutionSynced,
			Error:  fallbackExecutionErr,
		})
	}

	return nodes, nil
}

func (m *Monitor) checkUpcomingProposals(currentEpoch int) error {
	validatorIndexMap := make(map[string]bool)
	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.ProposalLookahead; i++ {
		epoch := currentEpoch + i
		duties, err := m.beaconClient.GetProposerDuties(m.config.BeaconNodeURL, epoch)
		if err != nil {
			m.logger.Warn("Failed to get proposer duties", "epoch", epoch, "error", err)
			continue
		}

		for _, duty := range duties {
			if validatorIndexMap[duty.ValidatorIndex] {
				slot, _ := strconv.Atoi(duty.Slot)
				currentSlot, _ := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL)
				timeUntil := time.Duration((slot-currentSlot)*12) * time.Second

				// Send notification for upcoming proposal (never muted)
				if timeUntil < 30*time.Minute && timeUntil > 0 {
					alertKey := fmt.Sprintf("upcoming_proposal_%s_%s", duty.ValidatorIndex, duty.Slot)
					if m.validatorManager.ShouldSendAlert(alertKey, 1440) {
						message := fmt.Sprintf("📅 <b>Upcoming Proposal</b>\n"+
							"Validator: %s\n"+
							"Slot: %s\n"+
							"Epoch: %d\n"+
							"Time: %v",
							duty.ValidatorIndex, duty.Slot, epoch, timeUntil)
						m.notifier.Send(message, "upcoming_proposal")
					}
				}
			}
		}
	}

	return nil
}

func (m *Monitor) checkSyncCommitteeParticipation(currentEpoch int) error {
	validatorIndexMap := make(map[string]bool)
	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.SyncCommitteeLookahead; i++ {
		epoch := currentEpoch + i
		syncCommittee, err := m.beaconClient.GetSyncCommittee(m.config.BeaconNodeURL, epoch)
		if err != nil {
			m.logger.Warn("Failed to get sync committee", "epoch", epoch, "error", err)
			continue
		}

		for _, validatorIdx := range syncCommittee.Validators {
			if validatorIndexMap[validatorIdx] {
				// Send notification for sync committee participation (never muted)
				if epoch == currentEpoch {
					alertKey := fmt.Sprintf("sync_committee_%s_%d", validatorIdx, epoch)
					if m.validatorManager.ShouldSendAlert(alertKey, 1440) {
						message := fmt.Sprintf("🔄 <b>Sync Committee</b>\n"+
							"Validator: %s\n"+
							"Epoch: %d\n"+
							"Status: Active participant",
							validatorIdx, epoch)
						m.notifier.Send(message, "sync_committee")
					}
				}
			}
		}
	}

	return nil
}

func (m *Monitor) sendEpochSummary(epoch int) {
	summary := m.validatorManager.GenerateEpochSummary(epoch)

	activeValidators := 0
	states := m.validatorManager.GetStates()
	for _, state := range states {
		if state.Status == "active_ongoing" {
			activeValidators++
		}
	}

	message := fmt.Sprintf("📊 <b>Epoch %d Summary</b>\n\n"+
		"Active Validators: %d\n"+
		"Successful Proposals: %d\n"+
		"Missed Attestations: %d\n"+
		"Total Rewards: %.6f ETH\n"+
		"Performance: %.1f%%",
		epoch,
		activeValidators,
		summary.SuccessfulProposals,
		summary.MissedAttestations,
		float64(summary.TotalRewards)/1e9,
		func() float64 {
			if activeValidators == 0 {
				return 0
			}
			return float64(activeValidators-summary.MissedAttestations) / float64(activeValidators) * 100
		}())

	m.notifier.Send(message, "epoch_summary")
}

func (m *Monitor) handleTelegramCommand(text, username string) {
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(text)))
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "/") {
		m.logger.Debug("Ignoring non-command message", "text", text, "user", username)
		return
	}

	command := parts[0][1:] // Remove the "/"
	m.logger.Info("Processing Telegram command",
		"command", command,
		"user", username,
		"full_text", text,
		"parts_count", len(parts))

	var response string
	var err error

	switch command {
	case "help":
		response = m.getHelpMessage()
		m.logger.Debug("Sending help message")

	case "status":
		response, err = m.getStatusMessage()
		if err != nil {
			response = "❌ Failed to get status: " + err.Error()
			m.logger.Error("Failed to get status message", "error", err)
		} else {
			m.logger.Debug("Generated status message")
		}

	case "duties":
		response = m.getDutiesMessage()
		m.logger.Debug("Generated duties message")

	case "validator":
		if len(parts) >= 2 {
			if idx, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
				validators, validatorErr := m.beaconClient.GetValidatorStatuses(m.config.BeaconNodeURL, m.config.ValidatorIndices)
				if validatorErr != nil {
					response = "❌ Failed to get validator data: " + validatorErr.Error()
				} else {
					response = m.validatorManager.GetValidatorDetails(idx, validators)
					if response == "" {
						response = fmt.Sprintf("❌ Validator %d not found or not monitored", idx)
						m.logger.Warn("Validator not found", "index", idx)
					} else {
						// Add duty information
						duties := m.dutyManager.GetValidatorDuties(uint64(idx))
						response += fmt.Sprintf("\n\n<b>Recent Duties:</b> %d tracked", len(duties))
						m.logger.Debug("Generated validator details", "index", idx)
					}
				}
			} else {
				response = "❌ Invalid validator index. Usage: /validator <number>"
				m.logger.Warn("Invalid validator index provided", "input", parts[1])
			}
		} else {
			response = "❌ Usage: /validator [index]\nExample: /validator 12345"
			m.logger.Debug("Validator command missing index")
		}

	case "epoch":
		var targetEpoch int
		if len(parts) >= 2 {
			if epochNum, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
				targetEpoch = epochNum
			} else {
				response = "❌ Invalid epoch number. Usage: /epoch <number>"
				m.logger.Warn("Invalid epoch number provided", "input", parts[1])
			}
		} else {
			// Default to last completed epoch
			if currentSlot, epochErr := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL); epochErr == nil {
				targetEpoch = (currentSlot / 32) - 1
			} else {
				response = "❌ Failed to get current epoch"
				m.logger.Error("Failed to get current epoch for default", "error", epochErr)
			}
		}

		if response == "" { // No error yet
			response = m.validatorManager.GetEpochSummaryMessage(targetEpoch)
			if response == "" {
				response = fmt.Sprintf("❌ No summary available for epoch %d", targetEpoch)
				m.logger.Warn("No epoch summary available", "epoch", targetEpoch)
			} else {
				m.logger.Debug("Generated epoch summary", "epoch", targetEpoch)
			}
		}

	default:
		response = "❌ Unknown command: " + command + "\n\nType /help for available commands."
		m.logger.Warn("Unknown command received", "command", command, "user", username)
	}

	// Send the response
	if response != "" {
		if sendErr := m.notifier.Send(response, "telegram_response"); sendErr != nil {
			m.logger.Error("Failed to send Telegram response",
				"command", command,
				"user", username,
				"error", sendErr,
				"response_length", len(response))
		} else {
			m.logger.Info("Telegram command completed successfully",
				"command", command,
				"user", username,
				"response_length", len(response))
		}
	}
}

func (m *Monitor) getHelpMessage() string {
	return "🤖 <b>Enhanced Validator Monitor Commands</b>\n\n" +
		"/help - Show this help message\n" +
		"/status - Show current system status\n" +
		"/duties - Show duty tracking statistics\n" +
		"/validator [index] - Show detailed validator info\n" +
		"/epoch [number] - Show epoch summary (default: last epoch)\n\n" +
		"<i>Monitor is running every " + strconv.Itoa(m.config.SlotCheckInterval) + " seconds for slot checks with proper attestation tracking</i>"
}

func (m *Monitor) getDutiesMessage() string {
	validatorCount, slotCount, totalDuties := m.dutyManager.GetStats()

	currentSlot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL)
	currentEpochInfo := "Unknown"
	if err == nil {
		currentEpoch := currentSlot / 32
		currentEpochInfo = fmt.Sprintf("%d", currentEpoch)
	}

	message := fmt.Sprintf("📋 <b>Duty Tracking Statistics</b>\n\n"+
		"<b>Current Epoch:</b> %s\n"+
		"<b>Validators with Duties:</b> %d\n"+
		"<b>Slots with Duties:</b> %d\n"+
		"<b>Total Duties Tracked:</b> %d\n\n"+
		"<i>Duties are automatically fetched for current and upcoming epochs</i>",
		currentEpochInfo,
		validatorCount,
		slotCount,
		totalDuties)

	return message
}

func (m *Monitor) getStatusMessage() (string, error) {
	nodes, err := m.checkAllNodes()
	if err != nil {
		return "", fmt.Errorf("failed to check nodes: %w", err)
	}

	epochInfo := "❌ Unknown"
	currentEpoch := 0
	if slot, err := m.beaconClient.GetCurrentSlot(m.config.BeaconNodeURL); err == nil {
		currentEpoch = slot / 32
		epochInfo = fmt.Sprintf("%d", currentEpoch)
	}

	validators, err := m.beaconClient.GetValidatorStatuses(m.config.BeaconNodeURL, m.config.ValidatorIndices)
	activeCount := 0
	if err == nil {
		for _, validator := range validators {
			if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
				activeCount++
			}
		}
	}

	var nodeStatuses []string
	for _, node := range nodes {
		status := "❌ Failed"
		if node.Error == nil {
			if node.Synced {
				status = "✅ Synced"
			} else {
				status = "⏳ Syncing"
			}
		}
		nodeStatuses = append(nodeStatuses, fmt.Sprintf("• %s: %s", node.Name, status))
	}

	validatorCount, slotCount, totalDuties := m.dutyManager.GetStats()

	message := fmt.Sprintf(
		"📊 <b>Enhanced Validator Monitor Status</b>\n\n"+
			"<b>Node Status:</b>\n%s\n"+
			"• Current Epoch: %s\n\n"+
			"<b>Validators:</b>\n"+
			"• Active: %d/%d\n"+
			"• Check Interval: %ds (slots), %dm (full)\n"+
			"• Muting: %v\n\n"+
			"<b>Duty Tracking:</b>\n"+
			"• Validators: %d\n"+
			"• Slots: %d\n"+
			"• Total: %d",
		strings.Join(nodeStatuses, "\n"),
		epochInfo,
		activeCount,
		len(m.config.ValidatorIndices),
		m.config.SlotCheckInterval,
		m.config.CheckInterval,
		m.config.MuteRepeatingEvents,
		validatorCount,
		slotCount,
		totalDuties)

	return message, nil
}
