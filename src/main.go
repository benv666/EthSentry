package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containrrr/shoutrrr"
	router "github.com/containrrr/shoutrrr/pkg/router"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configuration structure
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

// Enhanced Beacon chain structures
type BeaconResponse struct {
	Data interface{} `json:"data"`
}

type ValidatorData struct {
	Index     string          `json:"index"`
	Balance   string          `json:"balance"`
	Status    string          `json:"status"`
	Validator ValidatorDetail `json:"validator"`
}

type ValidatorDetail struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	EffectiveBalance      string `json:"effective_balance"`
	Slashed               bool   `json:"slashed"`
	ActivationEpoch       string `json:"activation_eligibility_epoch"`
	ExitEpoch             string `json:"exit_epoch"`
}

type ProposerDuty struct {
	Pubkey         string `json:"pubkey"`
	ValidatorIndex string `json:"validator_index"`
	Slot           string `json:"slot"`
}

type ProposerResponse struct {
	Data []ProposerDuty `json:"data"`
}

type AttesterDuty struct {
	Pubkey                  string `json:"pubkey"`
	ValidatorIndex          string `json:"validator_index"`
	CommitteeIndex          string `json:"committee_index"`
	CommitteeLength         string `json:"committee_length"`
	CommitteesAtSlot        string `json:"committees_at_slot"`
	ValidatorCommitteeIndex string `json:"validator_committee_index"`
	Slot                    string `json:"slot"`
}

type AttesterResponse struct {
	Data []AttesterDuty `json:"data"`
}

type Attestation struct {
	AggregationBits string `json:"aggregation_bits"`
	Data            struct {
		Slot            string `json:"slot"`
		CommitteeIndex  string `json:"committee_index"`
		BeaconBlockRoot string `json:"beacon_block_root"`
		Source          struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"source"`
		Target struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"target"`
	} `json:"data"`
	Signature string `json:"signature"`
}

type AttestationsResponse struct {
	Data []Attestation `json:"data"`
}

type BlockResponse struct {
	Data struct {
		Message struct {
			Slot          string `json:"slot"`
			ProposerIndex string `json:"proposer_index"`
			Body          struct {
				ExecutionPayload struct {
					BlockNumber string `json:"block_number"`
					GasUsed     string `json:"gas_used"`
					GasLimit    string `json:"gas_limit"`
				} `json:"execution_payload"`
			} `json:"body"`
		} `json:"message"`
	} `json:"data"`
}

type SyncCommittee struct {
	Validators          []string   `json:"validators"`
	ValidatorAggregates [][]string `json:"validator_aggregates"`
}

type SyncCommitteeResponse struct {
	Data SyncCommittee `json:"data"`
}

type ExecutionSyncResult struct {
	CurrentBlock  string `json:"currentBlock"`
	HighestBlock  string `json:"highestBlock"`
	StartingBlock string `json:"startingBlock"`
}

type ExecutionSyncStatus struct {
	Result interface{} `json:"result"`
}

type NodeStatus struct {
	Name   string
	URL    string
	Synced bool
	Error  error
}

type ValidatorState struct {
	Index               int
	Status              string
	Slashed             bool
	LastSeen            time.Time
	LastAttestationSlot int
	LastProposalSlot    int
	LastProposalReward  int64
	MissedAttestations  int
	EpochAttestations   map[int]bool
	EpochProposals      map[int]bool
}

type EpochSummary struct {
	Epoch                int
	ValidatorPerformance map[int]*ValidatorPerformance
	TotalRewards         int64
	MissedAttestations   int
	SuccessfulProposals  int
}

type ValidatorPerformance struct {
	Index              int
	AttestationSuccess bool
	ProposalSuccess    bool
	ProposalReward     int64
	MissedAttestation  bool
	CorrectHead        bool
	CorrectTarget      bool
	CorrectSource      bool
}

// Prometheus metrics
var (
	validatorStatusGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "eth_validator_status",
			Help: "Current status of validators (1=active, 0=inactive)",
		},
		[]string{"validator_index", "status"},
	)

	validatorBalanceGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "eth_validator_balance_gwei",
			Help: "Current balance of validators in Gwei",
		},
		[]string{"validator_index"},
	)

	nodeStatusGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "eth_node_status",
			Help: "Node sync status (1=synced, 0=not synced)",
		},
		[]string{"node_name", "node_type"},
	)

	attestationSuccessCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "eth_attestations_total",
			Help: "Total number of attestations by result",
		},
		[]string{"validator_index", "result"},
	)

	proposalSuccessCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "eth_proposals_total",
			Help: "Total number of block proposals by result",
		},
		[]string{"validator_index", "result"},
	)

	proposalRewardGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "eth_proposal_reward_gwei",
			Help: "Reward from block proposal in Gwei",
		},
		[]string{"validator_index", "slot"},
	)

	currentEpochGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "eth_current_epoch",
			Help: "Current beacon chain epoch",
		},
	)
)

type MonitorBot struct {
	config             Config
	httpClient         *http.Client
	lastAlerts         map[string]time.Time
	validatorStates    map[int]*ValidatorState
	epochSummaries     map[int]*EpochSummary
	lastProcessedSlot  int
	lastProcessedEpoch int
	logger             *slog.Logger
	shoutrrrSenders    []*router.ServiceRouter
	telegramOffset     int
}

func NewMonitorBot(config Config) *MonitorBot {
	// Setup structured logging with color output
	opts := &slog.HandlerOptions{
		// Level: slog.LevelInfo,
		AddSource: true,
		Level:     slog.LevelDebug,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	// Initialize Shoutrrr senders
	var shoutrrrSenders []*router.ServiceRouter
	for _, url := range config.ShoutrrrURLs {
		if sender, err := shoutrrr.CreateSender(url); err == nil {
			shoutrrrSenders = append(shoutrrrSenders, sender)
		} else {
			logger.Warn("Failed to create Shoutrrr sender", "url", url, "error", err)
		}
	}

	bot := &MonitorBot{
		config:          config,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		lastAlerts:      make(map[string]time.Time),
		validatorStates: make(map[int]*ValidatorState),
		epochSummaries:  make(map[int]*EpochSummary),
		logger:          logger,
		shoutrrrSenders: shoutrrrSenders,
	}

	// Initialize validator states
	for _, idx := range config.ValidatorIndices {
		bot.validatorStates[idx] = &ValidatorState{
			Index:             idx,
			EpochAttestations: make(map[int]bool),
			EpochProposals:    make(map[int]bool),
		}
	}

	// Setup Prometheus metrics if enabled
	if config.EnablePrometheus {
		prometheus.MustRegister(validatorStatusGauge)
		prometheus.MustRegister(validatorBalanceGauge)
		prometheus.MustRegister(nodeStatusGauge)
		prometheus.MustRegister(attestationSuccessCounter)
		prometheus.MustRegister(proposalSuccessCounter)
		prometheus.MustRegister(proposalRewardGauge)
		prometheus.MustRegister(currentEpochGauge)

		// Start Prometheus server
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			logger.Info("Starting Prometheus server", "port", config.PrometheusPort)
			if err := http.ListenAndServe(fmt.Sprintf(":%d", config.PrometheusPort), nil); err != nil {
				logger.Error("Prometheus server failed", "error", err)
			}
		}()
	}

	return bot
}

func (m *MonitorBot) makeRequest(url string, result interface{}) error {
	m.logger.Debug("Making HTTP request", "url", url)

	resp, err := m.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s - %s", resp.StatusCode, resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	m.logger.Debug("HTTP response received", "status", resp.StatusCode, "body_length", len(body))

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return nil
}

func (m *MonitorBot) makeJSONRPCRequest(url, method string, params []interface{}, result interface{}) error {
	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON-RPC request: %w", err)
	}

	m.logger.Debug("Making JSON-RPC request", "url", url, "method", method)

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("JSON-RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("JSON-RPC HTTP %d: %s - %s", resp.StatusCode, resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JSON-RPC response: %w", err)
	}

	m.logger.Debug("JSON-RPC response received", "status", resp.StatusCode, "body_length", len(body))

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to parse JSON-RPC response: %w", err)
	}

	return nil
}

func (m *MonitorBot) getCurrentSlot() (int, error) {
	var response BeaconResponse
	url := fmt.Sprintf("%s/eth/v1/beacon/headers/head", m.config.BeaconNodeURL)

	err := m.makeRequest(url, &response)
	if err != nil {
		return 0, err
	}

	headerData, ok := response.Data.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("unexpected header data format")
	}

	header, ok := headerData["header"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("unexpected header format")
	}

	message, ok := header["message"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("unexpected message format")
	}

	slotStr, ok := message["slot"].(string)
	if !ok {
		return 0, fmt.Errorf("unexpected slot format")
	}

	slot, err := strconv.Atoi(slotStr)
	if err != nil {
		return 0, err
	}

	return slot, nil
}

func (m *MonitorBot) getCurrentEpoch() (int, error) {
	slot, err := m.getCurrentSlot()
	if err != nil {
		return 0, err
	}

	epoch := slot / 32
	m.logger.Debug("Current epoch retrieved", "epoch", epoch, "slot", slot)

	// Update Prometheus metric
	if m.config.EnablePrometheus {
		currentEpochGauge.Set(float64(epoch))
	}

	return epoch, nil
}

func (m *MonitorBot) getAttesterDuties(epoch int) ([]AttesterDuty, error) {
	if len(m.config.ValidatorIndices) == 0 {
		return []AttesterDuty{}, nil
	}

	indices := make([]string, len(m.config.ValidatorIndices))
	for i, idx := range m.config.ValidatorIndices {
		indices[i] = strconv.Itoa(idx)
	}

	var response AttesterResponse
	url := fmt.Sprintf("%s/eth/v1/validator/duties/attester/%d?index=%s",
		m.config.BeaconNodeURL, epoch, strings.Join(indices, ","))

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (m *MonitorBot) getAttestations(slot int) ([]Attestation, error) {
	var response AttestationsResponse
	url := fmt.Sprintf("%s/eth/v1/beacon/blocks/%d/attestations", m.config.BeaconNodeURL, slot)

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (m *MonitorBot) getBlockInfo(slot int) (*BlockResponse, error) {
	var response BlockResponse
	url := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", m.config.BeaconNodeURL, slot)

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (m *MonitorBot) checkAttestationPerformance(epoch int) error {
	m.logger.Info("Checking attestation performance", "epoch", epoch)

	// Get attester duties for the epoch
	duties, err := m.getAttesterDuties(epoch)
	if err != nil {
		m.logger.Error("Failed to get attester duties", "epoch", epoch, "error", err)
		return err
	}

	if len(duties) == 0 {
		m.logger.Debug("No attester duties found for epoch", "epoch", epoch)
		return nil
	}

	m.logger.Debug("Retrieved attester duties", "epoch", epoch, "count", len(duties))

	dutiesMap := make(map[int]AttesterDuty)
	for _, duty := range duties {
		if idx, err := strconv.Atoi(duty.ValidatorIndex); err == nil {
			dutiesMap[idx] = duty
		}
	}

	// Check each validator's attestation performance
	for validatorIdx := range m.validatorStates {
		duty, hasDuty := dutiesMap[validatorIdx]
		if !hasDuty {
			m.logger.Debug("No attester duty for validator in epoch", "validator", validatorIdx, "epoch", epoch)
			continue
		}

		slot, err := strconv.Atoi(duty.Slot)
		if err != nil {
			m.logger.Warn("Invalid slot in duty", "slot", duty.Slot, "validator", validatorIdx)
			continue
		}

		m.logger.Debug("Checking attestation for validator",
			"validator", validatorIdx,
			"epoch", epoch,
			"duty_slot", slot)

		// Look for attestations in the next few slots (attestations can appear in slot+1 to slot+32)
		attested := false
		correctHead := false
		correctTarget := false
		correctSource := false

		// Check multiple slots where the attestation might appear
		for checkSlot := slot + 1; checkSlot <= slot+3; checkSlot++ {
			m.logger.Debug("Checking slot for attestations", "slot", checkSlot, "validator", validatorIdx)

			attestations, err := m.getAttestations(checkSlot)
			if err != nil {
				m.logger.Debug("Could not get attestations for slot", "slot", checkSlot, "error", err)
				continue // Try next slot
			}

			m.logger.Debug("Retrieved attestations", "slot", checkSlot, "count", len(attestations))

			// Check if validator attested in this slot
			for _, attestation := range attestations {
				if attestation.Data.Slot == duty.Slot &&
					attestation.Data.CommitteeIndex == duty.CommitteeIndex {

					m.logger.Debug("Found matching attestation",
						"attestation_slot", attestation.Data.Slot,
						"committee_index", attestation.Data.CommitteeIndex,
						"duty_slot", duty.Slot,
						"duty_committee", duty.CommitteeIndex)

					// Parse aggregation bits to check if validator participated
					committeeIndex, err := strconv.Atoi(duty.ValidatorCommitteeIndex)
					if err != nil {
						m.logger.Warn("Invalid committee index", "index", duty.ValidatorCommitteeIndex)
						continue
					}

					if m.checkAggregationBit(attestation.AggregationBits, committeeIndex) {
						attested = true
						// TODO - true for now!
						correctHead = true
						correctTarget = true
						correctSource = true

						m.logger.Debug("Validator successfully attested",
							"validator", validatorIdx,
							"slot", slot,
							"correct_head", correctHead,
							"correct_target", correctTarget,
							"correct_source", correctSource,
							"epoch", epoch)
						break
					}
				}
			}

			if attested {
				break // Found attestation, no need to check more slots
			}
		}

		// Update validator state
		state := m.validatorStates[validatorIdx]
		if state.EpochAttestations == nil {
			state.EpochAttestations = make(map[int]bool)
		}
		state.EpochAttestations[epoch] = attested
		state.LastAttestationSlot = slot

		if !attested {
			state.MissedAttestations++

			m.logger.Warn("Missed attestation detected",
				"validator", validatorIdx,
				"epoch", epoch,
				"slot", slot,
				"total_missed", state.MissedAttestations)

			// Send alert for missed attestation
			alertKey := fmt.Sprintf("missed_attestation_%d_%d", validatorIdx, epoch)
			if m.shouldSendAlert(alertKey, 60) {
				message := fmt.Sprintf("⚠️ <b>Missed Attestation</b>\nValidator: %d\nEpoch: %d\nSlot: %d",
					validatorIdx, epoch, slot)
				m.sendNotifications(message, "missed_attestation")
			}
		} else {
			m.logger.Info("Successful attestation confirmed",
				"validator", validatorIdx,
				"epoch", epoch,
				"slot", slot)
		}

		// Update Prometheus metrics
		if m.config.EnablePrometheus {
			result := "missed"
			if attested {
				result = "success"
			}
			attestationSuccessCounter.WithLabelValues(strconv.Itoa(validatorIdx), result).Inc()
		}
	}

	m.logger.Info("Attestation performance check completed", "epoch", epoch)
	return nil
}

func (m *MonitorBot) checkAggregationBit(bits string, position int) bool {
	// Simplified aggregation bit checking
	// In practice, you'd need to properly decode the hex string and check the bit
	return len(bits) > 2 // Placeholder logic
}

func (m *MonitorBot) checkProposalPerformance(slot int) error {
	// Get block info for the slot
	blockInfo, err := m.getBlockInfo(slot)
	if err != nil {
		// No block proposed at this slot
		return nil
	}

	proposerIndex, err := strconv.Atoi(blockInfo.Data.Message.ProposerIndex)
	if err != nil {
		return err
	}

	// Check if this is one of our validators
	state, exists := m.validatorStates[proposerIndex]
	if !exists {
		return nil // Not our validator
	}

	// Calculate reward (simplified - would need to get actual execution payload data)
	gasUsed, _ := strconv.ParseInt(blockInfo.Data.Message.Body.ExecutionPayload.GasUsed, 0, 64)
	// Simplified reward calculation - in practice you'd need to get tips and base fees
	estimatedReward := gasUsed * 15 // gwei per gas (very rough estimate)

	// Update validator state
	state.LastProposalSlot = slot
	state.LastProposalReward = estimatedReward
	epoch := slot / 32
	state.EpochProposals[epoch] = true

	// Send notification about successful proposal
	message := fmt.Sprintf("🎯 <b>Block Proposed!</b>\n"+
		"Validator: %d\n"+
		"Slot: %d\n"+
		"Epoch: %d\n"+
		"Estimated Reward: %.6f ETH",
		proposerIndex, slot, epoch, float64(estimatedReward)/1e9)

	m.sendNotifications(message, "successful_proposal")

	// Update Prometheus metrics
	if m.config.EnablePrometheus {
		proposalSuccessCounter.WithLabelValues(strconv.Itoa(proposerIndex), "success").Inc()
		proposalRewardGauge.WithLabelValues(strconv.Itoa(proposerIndex), strconv.Itoa(slot)).Set(float64(estimatedReward))
	}

	m.logger.Info("Successful block proposal detected",
		"validator", proposerIndex,
		"slot", slot,
		"epoch", epoch,
		"estimated_reward", estimatedReward)

	return nil
}

func (m *MonitorBot) generateEpochSummary(epoch int) *EpochSummary {
	summary := &EpochSummary{
		Epoch:                epoch,
		ValidatorPerformance: make(map[int]*ValidatorPerformance),
	}

	for validatorIdx, state := range m.validatorStates {
		perf := &ValidatorPerformance{
			Index:              validatorIdx,
			AttestationSuccess: state.EpochAttestations[epoch],
			ProposalSuccess:    state.EpochProposals[epoch],
			ProposalReward:     state.LastProposalReward,
		}

		if !perf.AttestationSuccess {
			perf.MissedAttestation = true
			summary.MissedAttestations++
		}

		if perf.ProposalSuccess {
			summary.SuccessfulProposals++
			summary.TotalRewards += perf.ProposalReward
		}

		summary.ValidatorPerformance[validatorIdx] = perf
	}

	return summary
}

func (m *MonitorBot) sendEpochSummary(epoch int) {
	if !m.config.EpochSummaryEnabled {
		return
	}

	summary := m.generateEpochSummary(epoch)
	m.epochSummaries[epoch] = summary

	activeValidators := 0
	for _, state := range m.validatorStates {
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
		float64(activeValidators-summary.MissedAttestations)/float64(activeValidators)*100)

	m.sendNotifications(message, "epoch_summary")
}

func (m *MonitorBot) processTelegramCommands() {
	if m.config.TelegramBotToken == "" {
		m.logger.Warn("Telegram bot token not configured, skipping command processing")
		return
	}

	m.logger.Info("Starting Telegram command processor", "chat_id", m.config.TelegramChatID)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=10",
			m.config.TelegramBotToken, m.telegramOffset+1)

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

		m.logger.Debug("Polling Telegram for updates", "url", url)

		resp, err := m.httpClient.Get(url)
		if err != nil {
			m.logger.Error("Failed to poll Telegram API", "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			m.logger.Error("Failed to read Telegram response", "error", err)
			continue
		}

		m.logger.Debug("Telegram API response", "status", resp.StatusCode, "body_length", len(body))

		if resp.StatusCode != http.StatusOK {
			m.logger.Error("Telegram API returned error", "status", resp.StatusCode, "body", string(body))
			continue
		}

		if err := json.Unmarshal(body, &response); err != nil {
			m.logger.Error("Failed to parse Telegram response", "error", err, "body", string(body))
			continue
		}

		if !response.Ok {
			m.logger.Error("Telegram API response not OK", "description", response.Description)
			continue
		}

		m.logger.Debug("Received Telegram updates", "count", len(response.Result))

		for _, update := range response.Result {
			if update.UpdateID > m.telegramOffset {
				m.telegramOffset = update.UpdateID
			}

			// Check if message exists
			if update.Message.Text == "" {
				m.logger.Debug("Skipping update without message text", "update_id", update.UpdateID)
				continue
			}

			// Convert chat ID to string for comparison
			chatIDStr := strconv.FormatInt(update.Message.Chat.ID, 10)
			m.logger.Debug("Processing message",
				"update_id", update.UpdateID,
				"chat_id", chatIDStr,
				"expected_chat_id", m.config.TelegramChatID,
				"from", update.Message.From.Username,
				"text", update.Message.Text)

			if chatIDStr != m.config.TelegramChatID {
				m.logger.Warn("Message from unauthorized chat",
					"chat_id", chatIDStr,
					"expected", m.config.TelegramChatID,
					"from", update.Message.From.Username)
				continue
			}

			m.handleTelegramCommand(update.Message.Text, update.Message.From.Username)
		}
	}
}

func (m *MonitorBot) handleTelegramCommand(text, username string) {
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

	case "validator":
		if len(parts) >= 2 {
			if idx, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
				response = m.getValidatorDetails(idx)
				if response == "" {
					response = fmt.Sprintf("❌ Validator %d not found or not monitored", idx)
					m.logger.Warn("Validator not found", "index", idx)
				} else {
					m.logger.Debug("Generated validator details", "index", idx)
				}
			} else {
				response = "❌ Invalid validator index. Usage: /validator <number>"
				m.logger.Warn("Invalid validator index provided", "input", parts[1])
			}
		} else {
			response = "❌ Usage: /validator <index>\nExample: /validator 12345"
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
			if currentEpoch, epochErr := m.getCurrentEpoch(); epochErr == nil {
				targetEpoch = currentEpoch - 1
			} else {
				response = "❌ Failed to get current epoch"
				m.logger.Error("Failed to get current epoch for default", "error", epochErr)
			}
		}

		if response == "" { // No error yet
			response = m.getEpochSummaryMessage(targetEpoch)
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
		if sendErr := m.sendTelegramMessage(response); sendErr != nil {
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

func (m *MonitorBot) getHelpMessage() string {
	return "🤖 <b>Validator Monitor Commands</b>\n\n" +
		"/help - Show this help message\n" +
		"/status - Show current system status\n" +
		"/validator [index] - Show detailed validator info\n" +
		"/epoch [number] - Show epoch summary (default: last epoch)\n\n" +
		"<i>Monitor is running every " + strconv.Itoa(m.config.SlotCheckInterval) + " seconds for slot checks</i>"
}

func (m *MonitorBot) getValidatorDetails(index int) string {
	state, exists := m.validatorStates[index]
	if !exists {
		return ""
	}

	validators, err := m.getValidatorStatuses()
	if err != nil {
		return ""
	}

	var validatorData *ValidatorData
	for _, v := range validators {
		if idx, _ := strconv.Atoi(v.Index); idx == index {
			validatorData = &v
			break
		}
	}

	if validatorData == nil {
		return ""
	}

	balance, _ := strconv.ParseFloat(validatorData.Balance, 64)
	effectiveBalance, _ := strconv.ParseFloat(validatorData.Validator.EffectiveBalance, 64)

	currentEpoch, _ := m.getCurrentEpoch()
	recentAttestations := 0
	for i := currentEpoch - 5; i <= currentEpoch; i++ {
		if state.EpochAttestations[i] {
			recentAttestations++
		}
	}

	message := fmt.Sprintf("🔍 <b>Validator %d Details</b>\n\n"+
		"<b>Status:</b> %s\n"+
		"<b>Slashed:</b> %v\n"+
		"<b>Balance:</b> %.6f ETH\n"+
		"<b>Effective Balance:</b> %.6f ETH\n\n"+
		"<b>Recent Performance (last 5 epochs):</b>\n"+
		"• Attestations: %d/5\n"+
		"• Missed Attestations: %d\n"+
		"• Last Attestation: Slot %d\n"+
		"• Last Proposal: Slot %d\n"+
		"• Last Proposal Reward: %.6f ETH\n\n"+
		"<b>Pubkey:</b> <code>%s</code>",
		index,
		validatorData.Status,
		validatorData.Validator.Slashed,
		balance/1e9,
		effectiveBalance/1e9,
		recentAttestations,
		state.MissedAttestations,
		state.LastAttestationSlot,
		state.LastProposalSlot,
		float64(state.LastProposalReward)/1e9,
		// validatorData.Validator.Pubkey[:20]+"...")
		validatorData.Validator.Pubkey)

	return message
}

func (m *MonitorBot) getEpochSummaryMessage(epoch int) string {
	summary, exists := m.epochSummaries[epoch]
	if !exists {
		return ""
	}

	var performanceDetails []string
	for idx, perf := range summary.ValidatorPerformance {
		status := "✅"
		if perf.MissedAttestation {
			status = "❌"
		}
		if perf.ProposalSuccess {
			status += "🎯"
		}
		performanceDetails = append(performanceDetails, fmt.Sprintf("%d: %s", idx, status))
	}

	sort.Strings(performanceDetails)

	message := fmt.Sprintf("📊 <b>Epoch %d Summary</b>\n\n"+
		"<b>Overview:</b>\n"+
		"• Successful Proposals: %d\n"+
		"• Missed Attestations: %d\n"+
		"• Total Rewards: %.6f ETH\n\n"+
		"<b>Validator Performance:</b>\n%s\n\n"+
		"<i>✅ = Attested, ❌ = Missed, 🎯 = Proposed</i>",
		epoch,
		summary.SuccessfulProposals,
		summary.MissedAttestations,
		float64(summary.TotalRewards)/1e9,
		strings.Join(performanceDetails, "\n"))

	return message
}

func (m *MonitorBot) sendNotifications(message, notificationType string) {
	// Send to Telegram
	if m.config.TelegramBotToken != "" && m.config.TelegramChatID != "" {
		m.sendTelegramMessage(message)
	}

	// Send to Shoutrrr endpoints
	for _, sender := range m.shoutrrrSenders {
		if err := sender.Send(message, nil); err != nil {
			m.logger.Warn("Failed to send Shoutrrr notification", "error", err)
		}
	}
}

func (m *MonitorBot) checkBeaconNodeSync(url string) (bool, error) {
	var response BeaconResponse
	apiURL := fmt.Sprintf("%s/eth/v1/node/syncing", url)

	err := m.makeRequest(apiURL, &response)
	if err != nil {
		return false, err
	}

	syncData, ok := response.Data.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected sync data format")
	}

	isSyncing, ok := syncData["is_syncing"].(bool)
	if !ok {
		return false, fmt.Errorf("unexpected is_syncing format")
	}

	synced := !isSyncing
	m.logger.Debug("Beacon node sync status", "url", url, "synced", synced)

	return synced, nil
}

func (m *MonitorBot) checkExecutionClientSync(url string) (bool, error) {
	var response ExecutionSyncStatus

	err := m.makeJSONRPCRequest(url, "eth_syncing", []interface{}{}, &response)
	if err != nil {
		return false, err
	}

	synced := false
	if result, ok := response.Result.(bool); ok {
		synced = !result
	} else if syncResult, ok := response.Result.(map[string]interface{}); ok {
		currentBlock, hasCurrentBlock := syncResult["currentBlock"]
		synced = !hasCurrentBlock || currentBlock == nil
	} else {
		return false, fmt.Errorf("unexpected eth_syncing response format: %T", response.Result)
	}

	m.logger.Debug("Execution node sync status", "url", url, "synced", synced)

	return synced, nil
}

func (m *MonitorBot) checkAllNodes() ([]NodeStatus, error) {
	var nodes []NodeStatus

	// Primary beacon node
	beaconSynced, beaconErr := m.checkBeaconNodeSync(m.config.BeaconNodeURL)
	nodes = append(nodes, NodeStatus{
		Name:   "Primary Beacon",
		URL:    m.config.BeaconNodeURL,
		Synced: beaconSynced,
		Error:  beaconErr,
	})

	// Primary execution node
	executionSynced, executionErr := m.checkExecutionClientSync(m.config.ExecutionClientURL)
	nodes = append(nodes, NodeStatus{
		Name:   "Primary Execution",
		URL:    m.config.ExecutionClientURL,
		Synced: executionSynced,
		Error:  executionErr,
	})

	// Fallback nodes
	if m.config.FallbackBeaconNodeURL != "" {
		fallbackBeaconSynced, fallbackBeaconErr := m.checkBeaconNodeSync(m.config.FallbackBeaconNodeURL)
		nodes = append(nodes, NodeStatus{
			Name:   "Fallback Beacon",
			URL:    m.config.FallbackBeaconNodeURL,
			Synced: fallbackBeaconSynced,
			Error:  fallbackBeaconErr,
		})
	}

	if m.config.FallbackExecutionClientURL != "" {
		fallbackExecutionSynced, fallbackExecutionErr := m.checkExecutionClientSync(m.config.FallbackExecutionClientURL)
		nodes = append(nodes, NodeStatus{
			Name:   "Fallback Execution",
			URL:    m.config.FallbackExecutionClientURL,
			Synced: fallbackExecutionSynced,
			Error:  fallbackExecutionErr,
		})
	}

	// Update Prometheus metrics
	if m.config.EnablePrometheus {
		for _, node := range nodes {
			syncStatus := 0.0
			if node.Synced && node.Error == nil {
				syncStatus = 1.0
			}

			nodeType := "beacon"
			if strings.Contains(strings.ToLower(node.Name), "execution") {
				nodeType = "execution"
			}

			nodeStatusGauge.WithLabelValues(node.Name, nodeType).Set(syncStatus)
		}
	}

	return nodes, nil
}

func (m *MonitorBot) getValidatorStatuses() ([]ValidatorData, error) {
	if len(m.config.ValidatorIndices) == 0 {
		return []ValidatorData{}, nil
	}

	indices := make([]string, len(m.config.ValidatorIndices))
	for i, idx := range m.config.ValidatorIndices {
		indices[i] = strconv.Itoa(idx)
	}

	var response struct {
		Data []ValidatorData `json:"data"`
	}

	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/validators?id=%s",
		m.config.BeaconNodeURL, strings.Join(indices, ","))

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	// Update Prometheus metrics
	if m.config.EnablePrometheus {
		for _, validator := range response.Data {
			idx := validator.Index
			balance, _ := strconv.ParseFloat(validator.Balance, 64)

			validatorBalanceGauge.WithLabelValues(idx).Set(balance)

			status := 0.0
			if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
				status = 1.0
			}
			validatorStatusGauge.WithLabelValues(idx, validator.Status).Set(status)
		}
	}

	return response.Data, nil
}

func (m *MonitorBot) getProposerDuties(epoch int) ([]ProposerDuty, error) {
	var response ProposerResponse
	url := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", m.config.BeaconNodeURL, epoch)

	err := m.makeRequest(url, &response)
	if err != nil {
		if m.config.FallbackBeaconNodeURL != "" {
			url = fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", m.config.FallbackBeaconNodeURL, epoch)
			err = m.makeRequest(url, &response)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return response.Data, nil
}

func (m *MonitorBot) getSyncCommittee(epoch int) (*SyncCommittee, error) {
	var response SyncCommitteeResponse
	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/sync_committees?epoch=%d", m.config.BeaconNodeURL, epoch)

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data, nil
}

func (m *MonitorBot) checkUpcomingProposals(currentEpoch int) ([]string, error) {
	var upcomingProposals []string
	validatorIndexMap := make(map[string]bool)

	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.ProposalLookahead; i++ {
		epoch := currentEpoch + i
		duties, err := m.getProposerDuties(epoch)
		if err != nil {
			m.logger.Warn("Failed to get proposer duties", "epoch", epoch, "error", err)
			continue
		}

		for _, duty := range duties {
			if validatorIndexMap[duty.ValidatorIndex] {
				slot, _ := strconv.Atoi(duty.Slot)
				currentSlot, _ := m.getCurrentSlot()
				timeUntil := time.Duration((slot-currentSlot)*12) * time.Second

				proposal := fmt.Sprintf("Validator %s proposal at slot %s (epoch %d) in %v",
					duty.ValidatorIndex, duty.Slot, epoch, timeUntil)
				upcomingProposals = append(upcomingProposals, proposal)

				// Send notification for upcoming proposal
				if timeUntil < 30*time.Minute && timeUntil > 0 {
					alertKey := fmt.Sprintf("upcoming_proposal_%s_%s", duty.ValidatorIndex, duty.Slot)
					if m.shouldSendAlert(alertKey, 1440) {
						message := fmt.Sprintf("📅 <b>Upcoming Proposal</b>\n"+
							"Validator: %s\n"+
							"Slot: %s\n"+
							"Epoch: %d\n"+
							"Time: %v",
							duty.ValidatorIndex, duty.Slot, epoch, timeUntil)
						m.sendNotifications(message, "upcoming_proposal")
					}
				}
			}
		}
	}

	return upcomingProposals, nil
}

func (m *MonitorBot) checkSyncCommitteeParticipation(currentEpoch int) ([]string, error) {
	var syncCommitteeInfo []string
	validatorIndexMap := make(map[string]bool)

	for _, idx := range m.config.ValidatorIndices {
		validatorIndexMap[strconv.Itoa(idx)] = true
	}

	for i := 0; i <= m.config.SyncCommitteeLookahead; i++ {
		epoch := currentEpoch + i
		syncCommittee, err := m.getSyncCommittee(epoch)
		if err != nil {
			m.logger.Warn("Failed to get sync committee", "epoch", epoch, "error", err)
			continue
		}

		for _, validatorIdx := range syncCommittee.Validators {
			if validatorIndexMap[validatorIdx] {
				info := fmt.Sprintf("Validator %s in sync committee for epoch %d", validatorIdx, epoch)
				syncCommitteeInfo = append(syncCommitteeInfo, info)

				// Send notification for sync committee participation
				if epoch == currentEpoch {
					alertKey := fmt.Sprintf("sync_committee_%s_%d", validatorIdx, epoch)
					if m.shouldSendAlert(alertKey, 1440) {
						message := fmt.Sprintf("🔄 <b>Sync Committee</b>\n"+
							"Validator: %s\n"+
							"Epoch: %d\n"+
							"Status: Active participant",
							validatorIdx, epoch)
						m.sendNotifications(message, "sync_committee")
					}
				}
			}
		}
	}

	return syncCommitteeInfo, nil
}

func (m *MonitorBot) sendTelegramMessage(message string) error {
	if m.config.TelegramBotToken == "" || m.config.TelegramChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	// NOTE: See comment below, this message is unfiltered!

	m.logger.Debug("Preparing to send Telegram message",
		"chat_id", m.config.TelegramChatID,
		"message_length", len(message))

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", m.config.TelegramBotToken)

	payload := map[string]interface{}{
		"chat_id":    m.config.TelegramChatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	m.logger.Debug("Sending Telegram message", "url", url, "payload_size", len(jsonData))

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		m.logger.Error("Telegram request failed", "error", err)
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// NOTE: Telegram doesn't like "invalid" html, e.g. your message containing  <foo> as text.
	// Either html.EscapeString or strings.ReplaceAll(message, "<", "&lt;") or know what you're sending.
	// Currently we do no such filtering!
	if resp.StatusCode != http.StatusOK {
		m.logger.Error("Telegram API returned error",
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
			m.logger.Info("Telegram message sent successfully",
				"message_id", response.Result.MessageID,
				"message_preview", message[:min(50, len(message))])
		} else {
			m.logger.Error("Telegram API response not OK", "description", response.Description)
			return fmt.Errorf("telegram API error: %s", response.Description)
		}
	} else {
		m.logger.Warn("Could not parse Telegram response, but status was OK", "body", string(body))
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *MonitorBot) shouldSendAlert(alertKey string, cooldownMinutes int) bool {
	if lastAlert, exists := m.lastAlerts[alertKey]; exists {
		if time.Since(lastAlert) < time.Duration(cooldownMinutes)*time.Minute {
			return false
		}
	}
	m.lastAlerts[alertKey] = time.Now()
	return true
}

func (m *MonitorBot) hasValidatorStateChanged(validator ValidatorData) bool {
	index, _ := strconv.Atoi(validator.Index)

	current := &ValidatorState{
		Index:             index,
		Status:            validator.Status,
		Slashed:           validator.Validator.Slashed,
		LastSeen:          time.Now(),
		EpochAttestations: make(map[int]bool),
		EpochProposals:    make(map[int]bool),
	}

	previous, exists := m.validatorStates[index]
	if !exists || previous.Status == "" {
		m.validatorStates[index] = current
		return true
	}

	// Copy over historical data
	current.EpochAttestations = previous.EpochAttestations
	current.EpochProposals = previous.EpochProposals
	current.LastAttestationSlot = previous.LastAttestationSlot
	current.LastProposalSlot = previous.LastProposalSlot
	current.LastProposalReward = previous.LastProposalReward
	current.MissedAttestations = previous.MissedAttestations

	changed := previous.Status != current.Status || previous.Slashed != current.Slashed

	if changed {
		// Send state change notification
		var changeType string
		if current.Slashed && !previous.Slashed {
			changeType = "slashed"
		} else if current.Status != previous.Status {
			changeType = "status_change"
		}

		message := fmt.Sprintf("⚠️ <b>Validator State Change</b>\n"+
			"Validator: %d\n"+
			"Old Status: %s\n"+
			"New Status: %s\n"+
			"Slashed: %v",
			index, previous.Status, current.Status, current.Slashed)

		m.sendNotifications(message, changeType)
	}

	m.validatorStates[index] = current
	return changed
}

func (m *MonitorBot) getStatusMessage() (string, error) {
	nodes, err := m.checkAllNodes()
	if err != nil {
		return "", fmt.Errorf("failed to check nodes: %w", err)
	}

	epochInfo := "❌ Unknown"
	currentEpoch := 0
	if epoch, err := m.getCurrentEpoch(); err == nil {
		currentEpoch = epoch
		epochInfo = fmt.Sprintf("%d", epoch)
	}

	validators, err := m.getValidatorStatuses()
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

	var upcomingInfo []string
	if currentEpoch > 0 {
		if proposals, err := m.checkUpcomingProposals(currentEpoch); err == nil && len(proposals) > 0 {
			upcomingInfo = append(upcomingInfo, "<b>Upcoming Proposals:</b>")
			for i, proposal := range proposals {
				if i < 3 { // Limit to first 3
					upcomingInfo = append(upcomingInfo, "• "+proposal)
				}
			}
		}

		if syncInfo, err := m.checkSyncCommitteeParticipation(currentEpoch); err == nil && len(syncInfo) > 0 {
			upcomingInfo = append(upcomingInfo, "<b>Sync Committee:</b>")
			for i, info := range syncInfo {
				if i < 3 { // Limit to first 3
					upcomingInfo = append(upcomingInfo, "• "+info)
				}
			}
		}
	}

	message := fmt.Sprintf(
		"📊 <b>Validator Monitor Status</b>\n\n"+
			"<b>Node Status:</b>\n%s\n"+
			"• Current Epoch: %s\n\n"+
			"<b>Validators:</b>\n"+
			"• Active: %d/%d\n"+
			"• Check Interval: %ds (slots), %dm (full)",
		strings.Join(nodeStatuses, "\n"),
		epochInfo,
		activeCount,
		len(m.config.ValidatorIndices),
		m.config.SlotCheckInterval,
		m.config.CheckInterval)

	if len(upcomingInfo) > 0 {
		message += "\n\n" + strings.Join(upcomingInfo, "\n")
	}

	return message, nil
}

func (m *MonitorBot) runSlotCheck() {
	currentSlot, err := m.getCurrentSlot()
	if err != nil {
		m.logger.Error("Failed to get current slot", "error", err)
		return
	}

	// Only process if we haven't seen this slot yet
	if currentSlot <= m.lastProcessedSlot {
		return
	}

	m.logger.Debug("Processing new slot", "slot", currentSlot, "last_processed", m.lastProcessedSlot)

	// Check for block proposals in recent slots
	for slot := m.lastProcessedSlot + 1; slot <= currentSlot; slot++ {
		if err := m.checkProposalPerformance(slot); err != nil {
			m.logger.Debug("Error checking proposal performance", "slot", slot, "error", err)
		}
	}

	m.lastProcessedSlot = currentSlot

	// Check if we entered a new epoch
	currentEpoch := currentSlot / 32
	if currentEpoch > m.lastProcessedEpoch {
		m.logger.Info("New epoch detected", "epoch", currentEpoch, "slot", currentSlot)

		// Check attestation performance for the completed epoch
		if m.lastProcessedEpoch > 0 {
			if err := m.checkAttestationPerformance(m.lastProcessedEpoch); err != nil {
				m.logger.Error("Failed to check attestation performance", "epoch", m.lastProcessedEpoch, "error", err)
			}

			// Send epoch summary
			m.sendEpochSummary(m.lastProcessedEpoch)
		}

		m.lastProcessedEpoch = currentEpoch
	}
}

func (m *MonitorBot) runFullCheck() {
	m.logger.Info("Starting full validator monitoring check")

	// Check all nodes
	nodes, err := m.checkAllNodes()
	if err != nil {
		m.logger.Error("Failed to check nodes", "error", err)
		return
	}

	// Check for node issues and send alerts
	primaryBeaconOk := false
	primaryExecutionOk := false

	for _, node := range nodes {
		if node.Error != nil {
			alertKey := fmt.Sprintf("%s_error", strings.ToLower(strings.ReplaceAll(node.Name, " ", "_")))
			if m.shouldSendAlert(alertKey, 30) {
				message := fmt.Sprintf("🚨 <b>%s Node Error</b>\nURL: %s\nError: %v",
					node.Name, node.URL, node.Error)
				m.sendNotifications(message, "node_error")
			}
		} else if !node.Synced {
			alertKey := fmt.Sprintf("%s_syncing", strings.ToLower(strings.ReplaceAll(node.Name, " ", "_")))
			if m.shouldSendAlert(alertKey, 30) {
				message := fmt.Sprintf("⚠️ <b>%s Node Syncing</b>\nURL: %s\nNode is not fully synced",
					node.Name, node.URL)
				m.sendNotifications(message, "node_syncing")
			}
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
	currentEpoch, err := m.getCurrentEpoch()
	if err != nil {
		m.logger.Error("Failed to get current epoch", "error", err)
		return
	}

	// Check validator statuses
	validators, err := m.getValidatorStatuses()
	if err != nil {
		m.logger.Error("Failed to get validator statuses", "error", err)
		return
	}

	activeCount := 0
	for _, validator := range validators {
		m.hasValidatorStateChanged(validator)

		if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
			activeCount++
		}
	}

	// Check upcoming duties
	m.checkUpcomingProposals(currentEpoch)
	m.checkSyncCommitteeParticipation(currentEpoch)

	// Send periodic status summary
	if m.shouldSendAlert("status_summary", 360) { // Every 6 hours
		message := fmt.Sprintf(
			"✅ <b>Validator Status Summary</b>\n"+
				"Epoch: %d\n"+
				"Active Validators: %d/%d\n"+
				"Nodes: All operational",
			currentEpoch,
			activeCount,
			len(m.config.ValidatorIndices))
		m.sendNotifications(message, "status_summary")
	}

	m.logger.Info("Full check completed",
		"epoch", currentEpoch,
		"active_validators", activeCount,
		"total_validators", len(m.config.ValidatorIndices))
}

func (m *MonitorBot) Start(ctx context.Context) {
	m.logger.Info("Starting Enhanced Ethereum Validator Monitor",
		"slot_check_interval", m.config.SlotCheckInterval,
		"full_check_interval", m.config.CheckInterval,
		"validator_count", len(m.config.ValidatorIndices),
		"prometheus_enabled", m.config.EnablePrometheus,
		"shoutrrr_endpoints", len(m.shoutrrrSenders))

	// Send startup notification
	message := "🚀 <b>Enhanced Validator Monitor Started</b>\n\n" +
		fmt.Sprintf("• Validators: %d\n", len(m.config.ValidatorIndices)) +
		fmt.Sprintf("• Slot checks: every %ds\n", m.config.SlotCheckInterval) +
		fmt.Sprintf("• Full checks: every %dm\n", m.config.CheckInterval) +
		fmt.Sprintf("• Prometheus: %v\n", m.config.EnablePrometheus) +
		fmt.Sprintf("• Shoutrrr endpoints: %d\n", len(m.shoutrrrSenders)) +
		"\n<i>Enhanced monitoring is now active!</i>"

	m.sendNotifications(message, "startup")

	// Start telegram command processor
	go m.processTelegramCommands()

	// Get initial state
	if currentSlot, err := m.getCurrentSlot(); err == nil {
		m.lastProcessedSlot = currentSlot - 1
		m.lastProcessedEpoch = (currentSlot - 1) / 32
	}

	// Run initial full check
	m.runFullCheck()

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

			m.sendNotifications(exitMessage, "shutdown")
			return

		case <-slotTicker.C:
			m.runSlotCheck()

		case <-fullTicker.C:
			m.runFullCheck()
		}
	}
}

func loadConfig() (Config, error) {
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

	// Prometheus settings
	config.EnablePrometheus = getEnvBool("ENABLE_PROMETHEUS", false)
	config.PrometheusPort = getEnvInt("PROMETHEUS_PORT", 8080)

	// Epoch summary setting
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

func main() {
	config, err := loadConfig()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if len(config.ValidatorIndices) == 0 {
		slog.Warn("No validator indices configured. Only checking node sync status.")
	}

	bot := NewMonitorBot(config)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Received shutdown signal, initiating graceful shutdown...")
		cancel()
	}()

	bot.Start(ctx)
}
