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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Configuration structure
type Config struct {
	BeaconNodeURL            string `json:"beacon_node_url"`
	ExecutionClientURL         string `json:"execution_node_url"`
	FallbackBeaconNodeURL    string `json:"fallback_beacon_node_url"`
	FallbackExecutionClientURL string `json:"fallback_execution_node_url"`
	TelegramBotToken         string `json:"telegram_bot_token"`
	TelegramChatID           string `json:"telegram_chat_id"`
	ValidatorIndices         []int  `json:"validator_indices"`
	CheckInterval            int    `json:"check_interval_minutes"`
	ProposalLookahead        int    `json:"proposal_lookahead_epochs"`
	SyncCommitteeLookahead   int    `json:"sync_committee_lookahead_epochs"`
}

// Beacon chain structures
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
	Index    int
	Status   string
	Slashed  bool
	LastSeen time.Time
}

type MonitorBot struct {
	config          Config
	httpClient      *http.Client
	lastAlerts      map[string]time.Time
	validatorStates map[int]*ValidatorState
	logger          *slog.Logger
}

func NewMonitorBot(config Config) *MonitorBot {
	// Setup structured logging with color output
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &MonitorBot{
		config:          config,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		lastAlerts:      make(map[string]time.Time),
		validatorStates: make(map[int]*ValidatorState),
		logger:          logger,
	}
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
	m.logger.Info("Beacon node sync status", "url", url, "synced", synced, "is_syncing", isSyncing)

	return synced, nil
}

func (m *MonitorBot) checkExecutionClientSync(url string) (bool, error) {
	var response ExecutionSyncStatus

	err := m.makeJSONRPCRequest(url, "eth_syncing", []interface{}{}, &response)
	if err != nil {
		return false, err
	}

	// If eth_syncing returns false, the node is synced
	// If it returns an object, the node is syncing
	synced := false
	if result, ok := response.Result.(bool); ok {
		synced = !result // false means synced
	} else if syncResult, ok := response.Result.(map[string]interface{}); ok {
		// If we get an object, check if it has the expected fields
		currentBlock, hasCurrentBlock := syncResult["currentBlock"]
		synced = !hasCurrentBlock || currentBlock == nil
	} else {
		return false, fmt.Errorf("unexpected eth_syncing response format: %T", response.Result)
	}

	m.logger.Info("Execution node sync status", "url", url, "synced", synced)

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

	// Fallback beacon node (if configured)
	if m.config.FallbackBeaconNodeURL != "" {
		fallbackBeaconSynced, fallbackBeaconErr := m.checkBeaconNodeSync(m.config.FallbackBeaconNodeURL)
		nodes = append(nodes, NodeStatus{
			Name:   "Fallback Beacon",
			URL:    m.config.FallbackBeaconNodeURL,
			Synced: fallbackBeaconSynced,
			Error:  fallbackBeaconErr,
		})
	}

	// Fallback execution node (if configured)
	if m.config.FallbackExecutionClientURL != "" {
		fallbackExecutionSynced, fallbackExecutionErr := m.checkExecutionClientSync(m.config.FallbackExecutionClientURL)
		nodes = append(nodes, NodeStatus{
			Name:   "Fallback Execution",
			URL:    m.config.FallbackExecutionClientURL,
			Synced: fallbackExecutionSynced,
			Error:  fallbackExecutionErr,
		})
	}

	return nodes, nil
}

func (m *MonitorBot) getCurrentEpoch() (int, error) {
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

	// Convert slot to epoch (32 slots per epoch)
	epoch := slot / 32
	m.logger.Info("Current epoch retrieved", "epoch", epoch, "slot", slot)

	return epoch, nil
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

	m.logger.Info("Retrieved validator statuses", "count", len(response.Data))
	for _, validator := range response.Data {
		m.logger.Debug("Validator status",
			"index", validator.Index,
			"status", validator.Status,
			"slashed", validator.Validator.Slashed,
			"balance", validator.Balance)
	}

	return response.Data, nil
}

func (m *MonitorBot) getProposerDuties(epoch int) ([]ProposerDuty, error) {
	var response ProposerResponse
	url := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", m.config.BeaconNodeURL, epoch)

	err := m.makeRequest(url, &response)
	if err != nil {
		m.logger.Debug("Error fetching proposer duties", "url", url, "epoch", epoch, "error", err)
		if m.config.FallbackBeaconNodeURL != "" {
			url = fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", m.config.FallbackBeaconNodeURL, epoch)
			err = m.makeRequest(url, &response)
			if err != nil {
				m.logger.Debug("Error fetching proposer duties using fallback", "url", url, "epoch", epoch, "error", err)
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	m.logger.Debug("Retrieved proposer duties", "epoch", epoch, "count", len(response.Data))

	return response.Data, nil
}

func (m *MonitorBot) getSyncCommittee(epoch int) (*SyncCommittee, error) {
	var response SyncCommitteeResponse
	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/sync_committees?epoch=%d", m.config.BeaconNodeURL, epoch)

	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	m.logger.Debug("Retrieved sync committee", "epoch", epoch, "validators_count", len(response.Data.Validators))

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
				timeUntil := time.Duration((slot-currentEpoch*32)*12) * time.Second
				proposal := fmt.Sprintf("Validator %s proposal at slot %s (epoch %d) in %v",
					duty.ValidatorIndex, duty.Slot, epoch, timeUntil)
				upcomingProposals = append(upcomingProposals, proposal)

				m.logger.Info("Found upcoming proposal",
					"validator", duty.ValidatorIndex,
					"slot", duty.Slot,
					"epoch", epoch,
					"time_until", timeUntil)
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

				m.logger.Info("Found sync committee participation",
					"validator", validatorIdx,
					"epoch", epoch)
			}
		}
	}

	return syncCommitteeInfo, nil
}

func (m *MonitorBot) sendTelegramMessage(message string) error {
	m.logger.Info("Sending Telegram message", "message", message)

	if m.config.TelegramBotToken == "" || m.config.TelegramChatID == "" {
		m.logger.Warn("Telegram not configured", "message", message)
		return fmt.Errorf("telegram not configured")
	}

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

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	m.logger.Info("Telegram message sent successfully")
	return nil
}

func (m *MonitorBot) shouldSendAlert(alertKey string, cooldownMinutes int) bool {
	if lastAlert, exists := m.lastAlerts[alertKey]; exists {
		if time.Since(lastAlert) < time.Duration(cooldownMinutes)*time.Minute {
			m.logger.Debug("Alert suppressed due to cooldown", "key", alertKey, "last_sent", lastAlert)
			return false
		}
	}
	m.lastAlerts[alertKey] = time.Now()
	m.logger.Debug("Alert approved", "key", alertKey)
	return true
}

func (m *MonitorBot) hasValidatorStateChanged(validator ValidatorData) bool {
	index, _ := strconv.Atoi(validator.Index)

	current := &ValidatorState{
		Index:    index,
		Status:   validator.Status,
		Slashed:  validator.Validator.Slashed,
		LastSeen: time.Now(),
	}

	previous, exists := m.validatorStates[index]
	if !exists {
		m.validatorStates[index] = current
		return true // First time seeing this validator
	}

	changed := previous.Status != current.Status || previous.Slashed != current.Slashed
	if changed {
		m.logger.Info("Validator state changed",
			"index", index,
			"old_status", previous.Status,
			"new_status", current.Status,
			"old_slashed", previous.Slashed,
			"new_slashed", current.Slashed)
	}

	m.validatorStates[index] = current
	return changed
}

func (m *MonitorBot) sendStartupNotification() error {
	m.logger.Info("Sending startup notification")

	// Check all nodes
	nodes, err := m.checkAllNodes()
	if err != nil {
		return fmt.Errorf("failed to check nodes: %w", err)
	}

	// Get current epoch
	epochInfo := "❌ Unknown"
	if epoch, err := m.getCurrentEpoch(); err == nil {
		epochInfo = fmt.Sprintf("%d", epoch)
	}

	// Format validator indices (sorted)
	validatorList := "None configured"
	if len(m.config.ValidatorIndices) > 0 {
		indices := make([]string, len(m.config.ValidatorIndices))
		for i, idx := range m.config.ValidatorIndices {
			indices[i] = strconv.Itoa(idx)
		}
		validatorList = strings.Join(indices, ", ")
	}

	// Build node status section
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

	message := fmt.Sprintf(
		"🚀 <b>Validator Monitor Started</b>\n\n"+
			"<b>Node Status:</b>\n%s\n"+
			"• Current Epoch: %s\n\n"+
			"<b>Configuration:</b>\n"+
			"• Validators: %s\n"+
			"• Check Interval: %d minutes\n"+
			"• Telegram: ✅ Connected\n\n"+
			"<i>Monitor is now active and will send alerts as needed.</i>",
		strings.Join(nodeStatuses, "\n"), epochInfo, validatorList, m.config.CheckInterval)

	return m.sendTelegramMessage(message)
}

func (m *MonitorBot) getStatusMessage() (string, error) {
	// Check all nodes
	nodes, err := m.checkAllNodes()
	if err != nil {
		return "", fmt.Errorf("failed to check nodes: %w", err)
	}

	// Get current epoch
	epochInfo := "❌ Unknown"
	currentEpoch := 0
	if epoch, err := m.getCurrentEpoch(); err == nil {
		currentEpoch = epoch
		epochInfo = fmt.Sprintf("%d", epoch)
	}

	// Format validator indices (sorted)
	validatorList := "None configured"
	activeCount := 0
	if len(m.config.ValidatorIndices) > 0 {
		indices := make([]string, len(m.config.ValidatorIndices))
		for i, idx := range m.config.ValidatorIndices {
			indices[i] = strconv.Itoa(idx)
		}
		validatorList = strings.Join(indices, ", ")

		// Get validator statuses
		if validators, err := m.getValidatorStatuses(); err == nil {
			for _, validator := range validators {
				if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
					activeCount++
				}
			}
		}
	}

	// Build node status section
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

	// Get upcoming proposals and sync committee info
	var upcomingInfo []string
	if currentEpoch > 0 {
		if proposals, err := m.checkUpcomingProposals(currentEpoch); err == nil && len(proposals) > 0 {
			upcomingInfo = append(upcomingInfo, "<b>Upcoming Proposals:</b>")
			upcomingInfo = append(upcomingInfo, proposals...)
		}

		if syncInfo, err := m.checkSyncCommitteeParticipation(currentEpoch); err == nil && len(syncInfo) > 0 {
			upcomingInfo = append(upcomingInfo, "<b>Sync Committee:</b>")
			upcomingInfo = append(upcomingInfo, syncInfo...)
		}
	}

	message := fmt.Sprintf(
		"📊 <b>Validator Monitor Status</b>\n\n"+
			"<b>Node Status:</b>\n%s\n"+
			"• Current Epoch: %s\n\n"+
			"<b>Validators:</b>\n"+
			"• Monitored: %s\n"+
			"• Active: %d/%d\n",
		strings.Join(nodeStatuses, "\n"), epochInfo, validatorList, activeCount, len(m.config.ValidatorIndices))

	if len(upcomingInfo) > 0 {
		message += "\n" + strings.Join(upcomingInfo, "\n")
	}

	return message, nil
}

func (m *MonitorBot) processTelegramUpdates() {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=-1&limit=1", m.config.TelegramBotToken)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var response struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID int `json:"update_id"`
				Message  struct {
					MessageID int `json:"message_id"`
					From      struct {
						ID       int    `json:"id"`
						Username string `json:"username"`
					} `json:"from"`
					Chat struct {
						ID string `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
			} `json:"result"`
		}

		resp, err := m.httpClient.Get(url)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if err := json.Unmarshal(body, &response); err != nil {
			continue
		}

		for _, update := range response.Result {
			if update.Message.Chat.ID == m.config.TelegramChatID &&
				strings.ToLower(strings.TrimSpace(update.Message.Text)) == "/status" {

				m.logger.Info("Received status command", "from", update.Message.From.Username)

				if statusMsg, err := m.getStatusMessage(); err == nil {
					m.sendTelegramMessage(statusMsg)
				} else {
					m.sendTelegramMessage("❌ Failed to get status: " + err.Error())
				}
			}
		}
	}
}

func (m *MonitorBot) runCheck() {
	m.logger.Info("Starting validator monitoring check")

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
				m.sendTelegramMessage(fmt.Sprintf("🚨 <b>%s Node Error</b>\nURL: %s\nError: %v",
					node.Name, node.URL, node.Error))
			}
		} else if !node.Synced {
			alertKey := fmt.Sprintf("%s_syncing", strings.ToLower(strings.ReplaceAll(node.Name, " ", "_")))
			if m.shouldSendAlert(alertKey, 30) {
				m.sendTelegramMessage(fmt.Sprintf("⚠️ <b>%s Node Syncing</b>\nURL: %s\nNode is not fully synced",
					node.Name, node.URL))
			}
		}

		// Track primary node status
		if node.Name == "Primary Beacon" && node.Error == nil && node.Synced {
			primaryBeaconOk = true
		}
		if node.Name == "Primary Execution" && node.Error == nil && node.Synced {
			primaryExecutionOk = true
		}
	}

	// Don't continue checks if primary nodes aren't synced
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

	var newInactiveValidators []string
	var newSlashedValidators []string
	activeCount := 0

	for _, validator := range validators {
		// Only send alerts if state has changed
		if m.hasValidatorStateChanged(validator) {
			if validator.Validator.Slashed {
				newSlashedValidators = append(newSlashedValidators, validator.Index)
			} else if validator.Status != "active_ongoing" {
				newInactiveValidators = append(newInactiveValidators,
					fmt.Sprintf("%s (%s)", validator.Index, validator.Status))
			}
		}

		if validator.Status == "active_ongoing" && !validator.Validator.Slashed {
			activeCount++
		}
	}

	// Send alerts for newly slashed validators
	if len(newSlashedValidators) > 0 {
		m.sendTelegramMessage(fmt.Sprintf("🚨 <b>SLASHED VALIDATORS</b>\nValidators: %s",
			strings.Join(newSlashedValidators, ", ")))
	}

	// Send alerts for newly inactive validators
	if len(newInactiveValidators) > 0 {
		m.sendTelegramMessage(fmt.Sprintf("⚠️ <b>Inactive Validators</b>\n%s",
			strings.Join(newInactiveValidators, "\n")))
	}

	// Check upcoming proposals
	upcomingProposals, err := m.checkUpcomingProposals(currentEpoch)
	if err != nil {
		m.logger.Error("Failed to check upcoming proposals", "error", err)
	} else if len(upcomingProposals) > 0 {
		if m.shouldSendAlert("upcoming_proposals", 1440) { // Once per day
			m.sendTelegramMessage(fmt.Sprintf("📅 <b>Upcoming Proposals</b>\n%s",
				strings.Join(upcomingProposals, "\n")))
		}
	}

	// Check sync committee participation
	syncCommitteeInfo, err := m.checkSyncCommitteeParticipation(currentEpoch)
	if err != nil {
		m.logger.Error("Failed to check sync committee", "error", err)
	} else if len(syncCommitteeInfo) > 0 {
		if m.shouldSendAlert("sync_committee", 1440) { // Once per day
			m.sendTelegramMessage(fmt.Sprintf("🔄 <b>Sync Committee</b>\n%s",
				strings.Join(syncCommitteeInfo, "\n")))
		}
	}

	// Send status summary
	if m.shouldSendAlert("status_summary", 360) { // Every 6 hours
		indices := make([]string, len(m.config.ValidatorIndices))
		for i, idx := range m.config.ValidatorIndices {
			indices[i] = strconv.Itoa(idx)
		}

		var nodeStatusLines []string
		for _, node := range nodes {
			status := "❌ Failed"
			if node.Error == nil {
				if node.Synced {
					status = "✅ Synced"
				} else {
					status = "⏳ Syncing"
				}
			}
			nodeStatusLines = append(nodeStatusLines, fmt.Sprintf("%s: %s", node.Name, status))
		}

		message := fmt.Sprintf(
			"✅ <b>Validator Status Summary</b>\n"+
				"Epoch: %d\n"+
				"Validators: %s\n"+
				"Active: %d/%d\n"+
				"Nodes: %s",
			currentEpoch,
			strings.Join(indices, ", "),
			activeCount,
			len(m.config.ValidatorIndices),
			strings.Join(nodeStatusLines, ", "))
		m.sendTelegramMessage(message)
	}

	m.logger.Info("Check completed",
		"epoch", currentEpoch,
		"active_validators", activeCount,
		"total_validators", len(m.config.ValidatorIndices),
		"nodes_checked", len(nodes))
}

func (m *MonitorBot) Start(ctx context.Context) {
	m.logger.Info("Starting Ethereum Validator Monitor Bot",
		"check_interval", m.config.CheckInterval,
		"validator_count", len(m.config.ValidatorIndices),
		"beacon_url", m.config.BeaconNodeURL,
		"execution_url", m.config.ExecutionClientURL)

	// Send startup notification - this must work or we exit
	if err := m.sendStartupNotification(); err != nil {
		m.logger.Error("FATAL: Failed to send startup notification", "error", err)
		os.Exit(1)
	}

	// Start telegram command processor in background
	go m.processTelegramUpdates()

	// Run initial check
	m.runCheck()

	ticker := time.NewTicker(time.Duration(m.config.CheckInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Shutting down validator monitor...")

			exitMessage := "🛑 <b>Validator Monitor Stopped</b>\n\n" +
				"<i>Monitoring has been temporarily disabled. " +
				"Please restart the service to resume monitoring.</i>"

			if err := m.sendTelegramMessage(exitMessage); err != nil {
				m.logger.Error("Failed to send exit notification", "error", err)
			} else {
				m.logger.Info("Exit notification sent")
			}

			return
		case <-ticker.C:
			m.runCheck()
		}
	}
}

func loadConfig() (Config, error) {
	var config Config

	// Load from environment variables
	if url := os.Getenv("BEACON_NODE_URL"); url != "" {
		config.BeaconNodeURL = url
	}
	if url := os.Getenv("EXECUTION_CLIENT_URL"); url != "" {
		config.ExecutionClientURL = url
	}
	if url := os.Getenv("FALLBACK_BEACON_NODE_URL"); url != "" {
		config.FallbackBeaconNodeURL = url
	}
	if url := os.Getenv("FALLBACK_EXECUTION_CLIENT_URL"); url != "" {
		config.FallbackExecutionClientURL = url
	}
	if token := os.Getenv("TELEGRAM_BOT_TOKEN"); token != "" {
		config.TelegramBotToken = token
	}
	if chatID := os.Getenv("TELEGRAM_CHAT_ID"); chatID != "" {
		config.TelegramChatID = chatID
	}
	if indices := os.Getenv("VALIDATOR_INDICES"); indices != "" {
		parts := strings.Split(indices, ",")
		config.ValidatorIndices = make([]int, 0, len(parts))
		for _, part := range parts {
			if idx, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				config.ValidatorIndices = append(config.ValidatorIndices, idx)
			}
		}
	}
	if interval := os.Getenv("CHECK_INTERVAL"); interval != "" {
		if i, err := strconv.Atoi(interval); err == nil {
			config.CheckInterval = i
		}
	}
	if lookahead := os.Getenv("PROPOSAL_LOOKAHEAD"); lookahead != "" {
		if i, err := strconv.Atoi(lookahead); err == nil {
			config.ProposalLookahead = i
		}
	}
	if lookahead := os.Getenv("SYNC_COMMITTEE_LOOKAHEAD"); lookahead != "" {
		if i, err := strconv.Atoi(lookahead); err == nil {
			config.SyncCommitteeLookahead = i
		}
	}

	// Set defaults
	if config.BeaconNodeURL == "" {
		config.BeaconNodeURL = "http://localhost:5052"
	}
	if config.ExecutionClientURL == "" {
		config.ExecutionClientURL = "http://localhost:8545"
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = 5 // 5 minutes default
	}
	if config.ProposalLookahead == 0 {
		config.ProposalLookahead = 1 // Look ahead 1 epoch
	}
	if config.SyncCommitteeLookahead == 0 {
		config.SyncCommitteeLookahead = 1 // Look ahead 1 epoch
	}

	// Sort validator indices for consistent ordering
	for i := 0; i < len(config.ValidatorIndices); i++ {
		for j := i + 1; j < len(config.ValidatorIndices); j++ {
			if config.ValidatorIndices[i] > config.ValidatorIndices[j] {
				config.ValidatorIndices[i], config.ValidatorIndices[j] = config.ValidatorIndices[j], config.ValidatorIndices[i]
			}
		}
	}

	// Validate required fields
	if config.TelegramBotToken == "" {
		return config, fmt.Errorf("TELEGRAM_BOT_TOKEN is required")
	}
	if config.TelegramChatID == "" {
		return config, fmt.Errorf("TELEGRAM_CHAT_ID is required")
	}

	return config, nil
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
