package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Configuration structure
type Config struct {
	BeaconNodeURL    string `json:"beacon_node_url"`
	ExecutionNodeURL string `json:"execution_node_url"`
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
	ValidatorIndices []int  `json:"validator_indices"`
	CheckInterval    int    `json:"check_interval_minutes"`
	ProposalLookahead int   `json:"proposal_lookahead_epochs"`
	SyncCommitteeLookahead int `json:"sync_committee_lookahead_epochs"`
}

// Beacon chain structures
type BeaconResponse struct {
	Data interface{} `json:"data"`
}

type SyncStatus struct {
	HeadSlot  string `json:"head_slot"`
	SyncState string `json:"sync_distance"`
	IsStale   bool   `json:"is_optimistic"`
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
	Validators          []string `json:"validators"`
	ValidatorAggregates []string `json:"validator_aggregates"`
}

type SyncCommitteeResponse struct {
	Data SyncCommittee `json:"data"`
}

type ExecutionSyncStatus struct {
	Result json.RawMessage `json:"result"`
}

type MonitorBot struct {
	config     Config
	httpClient *http.Client
	lastAlerts map[string]time.Time
}

func NewMonitorBot(config Config) *MonitorBot {
	return &MonitorBot{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		lastAlerts: make(map[string]time.Time),
	}
}

func (m *MonitorBot) makeRequest(url string, result interface{}) error {
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, result)
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
		return err
	}

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, result)
}

func (m *MonitorBot) checkBeaconNodeSync() (bool, error) {
	var response BeaconResponse
	url := fmt.Sprintf("%s/eth/v1/node/syncing", m.config.BeaconNodeURL)
	
	err := m.makeRequest(url, &response)
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

	return !isSyncing, nil
}

func (m *MonitorBot) checkExecutionNodeSync() (bool, error) {
	var response ExecutionSyncStatus
	err := m.makeJSONRPCRequest(m.config.ExecutionNodeURL, "eth_syncing", []interface{}{}, &response)
	if err != nil {
		return false, err
	}

	// Check if result is a boolean false (fully synced)
	var isSynced bool
	if err := json.Unmarshal(response.Result, &isSynced); err == nil {
		return isSynced == false, nil
	}

	// Else, it's syncing, decode the full object (optional: inspect if needed)
	var syncDetails struct {
		CurrentBlock  string `json:"currentBlock"`
		HighestBlock  string `json:"highestBlock"`
		StartingBlock string `json:"startingBlock"`
	}
	if err := json.Unmarshal(response.Result, &syncDetails); err != nil {
		return false, fmt.Errorf("unexpected sync result format: %v", err)
	}

	return false, nil
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
	return slot / 32, nil
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

	return response.Data, nil
}

func (m *MonitorBot) getProposerDuties(epoch int) ([]ProposerDuty, error) {
	var response ProposerResponse
	url := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", m.config.BeaconNodeURL, epoch)
	
	err := m.makeRequest(url, &response)
	if err != nil {
		return nil, err
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
			log.Printf("Error getting proposer duties for epoch %d: %v", epoch, err)
			continue
		}

		for _, duty := range duties {
			if validatorIndexMap[duty.ValidatorIndex] {
				slot, _ := strconv.Atoi(duty.Slot)
				timeUntil := time.Duration((slot-currentEpoch*32)*12) * time.Second
				upcomingProposals = append(upcomingProposals, 
					fmt.Sprintf("Validator %s proposal at slot %s (epoch %d) in %v", 
						duty.ValidatorIndex, duty.Slot, epoch, timeUntil))
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
			log.Printf("Error getting sync committee for epoch %d: %v", epoch, err)
			continue
		}

		for _, validatorIdx := range syncCommittee.Validators {
			if validatorIndexMap[validatorIdx] {
				syncCommitteeInfo = append(syncCommitteeInfo, 
					fmt.Sprintf("Validator %s in sync committee for epoch %d", validatorIdx, epoch))
			}
		}
	}

	return syncCommitteeInfo, nil
}

func (m *MonitorBot) sendTelegramMessage(message string) error {
	if m.config.TelegramBotToken == "" || m.config.TelegramChatID == "" {
		log.Printf("Telegram not configured, would send: %s", message)
		return nil
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", m.config.TelegramBotToken)
	
	payload := map[string]interface{}{
		"chat_id":    m.config.TelegramChatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}

	return nil
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

func (m *MonitorBot) runCheck() {
	log.Println("Starting validator monitoring check...")

	// Check beacon node sync
	beaconSynced, err := m.checkBeaconNodeSync()
	if err != nil {
		if m.shouldSendAlert("beacon_node_error", 30) {
			m.sendTelegramMessage(fmt.Sprintf("🚨 <b>Beacon Node Error</b>\nCannot connect to beacon node: %v", err))
		}
		return
	}

	if !beaconSynced {
		if m.shouldSendAlert("beacon_node_syncing", 30) {
			m.sendTelegramMessage("⚠️ <b>Beacon Node Syncing</b>\nBeacon node is not fully synced")
		}
		return
	}

	// Check execution node sync
	executionSynced, err := m.checkExecutionNodeSync()
	if err != nil {
		if m.shouldSendAlert("execution_node_error", 30) {
			m.sendTelegramMessage(fmt.Sprintf("🚨 <b>Execution Node Error</b>\nCannot connect to execution node: %v", err))
		}
		return
	}

	if !executionSynced {
		if m.shouldSendAlert("execution_node_syncing", 30) {
			m.sendTelegramMessage("⚠️ <b>Execution Node Syncing</b>\nExecution node is not fully synced")
		}
		return
	}

	// Get current epoch
	currentEpoch, err := m.getCurrentEpoch()
	if err != nil {
		log.Printf("Error getting current epoch: %v", err)
		return
	}

	// Check validator statuses
	validators, err := m.getValidatorStatuses()
	if err != nil {
		log.Printf("Error getting validator statuses: %v", err)
		return
	}

	var inactiveValidators []string
	var slashedValidators []string
	activeCount := 0

	for _, validator := range validators {
		if validator.Validator.Slashed {
			slashedValidators = append(slashedValidators, validator.Index)
		} else if validator.Status != "active_ongoing" {
			inactiveValidators = append(inactiveValidators, 
				fmt.Sprintf("%s (%s)", validator.Index, validator.Status))
		} else {
			activeCount++
		}
	}

	// Send alerts for inactive or slashed validators
	if len(slashedValidators) > 0 {
		if m.shouldSendAlert("slashed_validators", 60) {
			m.sendTelegramMessage(fmt.Sprintf("🚨 <b>SLASHED VALIDATORS</b>\nValidators: %s", 
				strings.Join(slashedValidators, ", ")))
		}
	}

	if len(inactiveValidators) > 0 {
		if m.shouldSendAlert("inactive_validators", 60) {
			m.sendTelegramMessage(fmt.Sprintf("⚠️ <b>Inactive Validators</b>\n%s", 
				strings.Join(inactiveValidators, "\n")))
		}
	}

	// Check upcoming proposals
	upcomingProposals, err := m.checkUpcomingProposals(currentEpoch)
	if err != nil {
		log.Printf("Error checking upcoming proposals: %v", err)
	} else if len(upcomingProposals) > 0 {
		if m.shouldSendAlert("upcoming_proposals", 1440) { // Once per day
			m.sendTelegramMessage(fmt.Sprintf("📅 <b>Upcoming Proposals</b>\n%s", 
				strings.Join(upcomingProposals, "\n")))
		}
	}

	// Check sync committee participation
	syncCommitteeInfo, err := m.checkSyncCommitteeParticipation(currentEpoch)
	if err != nil {
		log.Printf("Error checking sync committee: %v", err)
	} else if len(syncCommitteeInfo) > 0 {
		if m.shouldSendAlert("sync_committee", 1440) { // Once per day
			m.sendTelegramMessage(fmt.Sprintf("🔄 <b>Sync Committee</b>\n%s", 
				strings.Join(syncCommitteeInfo, "\n")))
		}
	}

	// Send status summary
	if m.shouldSendAlert("status_summary", 360) { // Every 6 hours
		message := fmt.Sprintf(
			"✅ <b>Validator Status Summary</b>\n"+
			"Epoch: %d\n"+
			"Active Validators: %d/%d\n"+
			"Beacon Node: Synced ✅\n"+
			"Execution Node: Synced ✅",
			currentEpoch, activeCount, len(m.config.ValidatorIndices))
		m.sendTelegramMessage(message)
	}

	log.Printf("Check completed. Active validators: %d/%d", activeCount, len(m.config.ValidatorIndices))
}

func (m *MonitorBot) sendStartupNotification() {
	log.Println("Sending startup notification...")
	
	// Test beacon node connection
	beaconStatus := "❌ Failed"
	if synced, err := m.checkBeaconNodeSync(); err == nil {
		if synced {
			beaconStatus = "✅ Synced"
		} else {
			beaconStatus = "⏳ Syncing"
		}
	}

	// Test execution node connection
	executionStatus := "❌ Failed"
	if synced, err := m.checkExecutionNodeSync(); err == nil {
		if synced {
			executionStatus = "✅ Synced"
		} else {
			executionStatus = "⏳ Syncing"
		}
	}

	// Get current epoch
	epochInfo := "❌ Unknown"
	if epoch, err := m.getCurrentEpoch(); err == nil {
		epochInfo = fmt.Sprintf("%d", epoch)
	}

	// Format validator indices
	validatorList := "None configured"
	if len(m.config.ValidatorIndices) > 0 {
		indices := make([]string, len(m.config.ValidatorIndices))
		for i, idx := range m.config.ValidatorIndices {
			indices[i] = strconv.Itoa(idx)
		}
		validatorList = strings.Join(indices, ", ")
	}

	message := fmt.Sprintf(
		"🚀 <b>Validator Monitor Started</b>\n\n"+
		"<b>Node Status:</b>\n"+
		"• Beacon Node: %s\n"+
		"• Execution Node: %s\n"+
		"• Current Epoch: %s\n\n"+
		"<b>Configuration:</b>\n"+
		"• Validators: %s\n"+
		"• Check Interval: %d minutes\n"+
		"• Telegram: ✅ Connected\n\n"+
		"<i>Monitor is now active and will send alerts as needed.</i>",
		beaconStatus, executionStatus, epochInfo, validatorList, m.config.CheckInterval)

	if err := m.sendTelegramMessage(message); err != nil {
		log.Printf("Failed to send startup notification: %v", err)
	} else {
		log.Println("Startup notification sent successfully")
	}
}

func (m *MonitorBot) Start(ctx context.Context) {
	log.Printf("Starting Ethereum Validator Monitor Bot...")
	log.Printf("Check interval: %d minutes", m.config.CheckInterval)
	log.Printf("Monitoring %d validators", len(m.config.ValidatorIndices))

	// Send startup notification
	m.sendStartupNotification()

	// Run initial check
	m.runCheck()

	ticker := time.NewTicker(time.Duration(m.config.CheckInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down monitor bot...")
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
	if url := os.Getenv("EXECUTION_NODE_URL"); url != "" {
		config.ExecutionNodeURL = url
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
	if config.ExecutionNodeURL == "" {
		config.ExecutionNodeURL = "http://localhost:8545"
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = 5 // 5 minutes default
	}
	if config.ProposalLookahead == 0 {
		config.ProposalLookahead = 2 // Look ahead 2 epochs
	}
	if config.SyncCommitteeLookahead == 0 {
		config.SyncCommitteeLookahead = 1 // Look ahead 1 epoch
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
		log.Fatalf("Error loading configuration: %v", err)
	}

	if len(config.ValidatorIndices) == 0 {
		log.Println("Warning: No validator indices configured. Only checking node sync status.")
	}

	bot := NewMonitorBot(config)
	
	ctx := context.Background()
	bot.Start(ctx)
}
