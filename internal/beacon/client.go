// internal/beacon/client.go - Beacon chain API client
package beacon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
}

func NewClient(logger *slog.Logger) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

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

type AttesterDuty struct {
	Pubkey                  string `json:"pubkey"`
	ValidatorIndex          string `json:"validator_index"`
	CommitteeIndex          string `json:"committee_index"`
	CommitteeLength         string `json:"committee_length"`
	CommitteesAtSlot        string `json:"committees_at_slot"`
	ValidatorCommitteeIndex string `json:"validator_committee_index"`
	Slot                    string `json:"slot"`
}

type ProposerDuty struct {
	Pubkey         string `json:"pubkey"`
	ValidatorIndex string `json:"validator_index"`
	Slot           string `json:"slot"`
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

type BlockResponse struct {
	Data struct {
		Message struct {
			Slot          string `json:"slot"`
			ProposerIndex string `json:"proposer_index"`
			Body          struct {
				Attestations     []Attestation `json:"attestations"`
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

type ExecutionSyncStatus struct {
	Result interface{} `json:"result"`
}

func (c *Client) makeRequest(url string, result interface{}) error {
	c.logger.Debug("Making HTTP request", "url", url)

	resp, err := c.httpClient.Get(url)
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

	c.logger.Debug("HTTP response received", "status", resp.StatusCode, "body_length", len(body))

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return nil
}

func (c *Client) makeJSONRPCRequest(url, method string, params []interface{}, result interface{}) error {
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

	c.logger.Debug("Making JSON-RPC request", "url", url, "method", method)

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
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

	c.logger.Debug("JSON-RPC response received", "status", resp.StatusCode, "body_length", len(body))

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to parse JSON-RPC response: %w", err)
	}

	return nil
}

func (c *Client) GetCurrentSlot(beaconURL string) (int, error) {
	var response BeaconResponse
	url := fmt.Sprintf("%s/eth/v1/beacon/headers/head", beaconURL)

	err := c.makeRequest(url, &response)
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

func (c *Client) GetValidatorStatuses(beaconURL string, validatorIndices []int) ([]ValidatorData, error) {
	if len(validatorIndices) == 0 {
		return []ValidatorData{}, nil
	}

	indices := make([]string, len(validatorIndices))
	for i, idx := range validatorIndices {
		indices[i] = strconv.Itoa(idx)
	}

	var response struct {
		Data []ValidatorData `json:"data"`
	}

	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/validators?id=%s",
		beaconURL, strings.Join(indices, ","))

	err := c.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (c *Client) GetAttesterDuties(beaconURL string, epoch int, validatorIndices []int) ([]AttesterDuty, error) {
	if len(validatorIndices) == 0 {
		return []AttesterDuty{}, nil
	}

	indices := make([]string, len(validatorIndices))
	for i, idx := range validatorIndices {
		indices[i] = strconv.Itoa(idx)
	}

	var response struct {
		Data []AttesterDuty `json:"data"`
	}
	url := fmt.Sprintf("%s/eth/v1/validator/duties/attester/%d?index=%s",
		beaconURL, epoch, strings.Join(indices, ","))

	err := c.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (c *Client) GetProposerDuties(beaconURL string, epoch int) ([]ProposerDuty, error) {
	var response struct {
		Data []ProposerDuty `json:"data"`
	}
	url := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", beaconURL, epoch)

	err := c.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (c *Client) GetBlock(beaconURL string, slot int) (*BlockResponse, error) {
	var response BlockResponse
	url := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", beaconURL, slot)

	err := c.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetSyncCommittee(beaconURL string, epoch int) (*SyncCommittee, error) {
	var response struct {
		Data SyncCommittee `json:"data"`
	}
	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/sync_committees?epoch=%d", beaconURL, epoch)

	err := c.makeRequest(url, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data, nil
}

func (c *Client) CheckBeaconNodeSync(url string) (bool, error) {
	var response BeaconResponse
	apiURL := fmt.Sprintf("%s/eth/v1/node/syncing", url)

	err := c.makeRequest(apiURL, &response)
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
	c.logger.Debug("Beacon node sync status", "url", url, "synced", synced)

	return synced, nil
}

func (c *Client) CheckExecutionClientSync(url string) (bool, error) {
	var response ExecutionSyncStatus

	err := c.makeJSONRPCRequest(url, "eth_syncing", []interface{}{}, &response)
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

	c.logger.Debug("Execution node sync status", "url", url, "synced", synced)

	return synced, nil
}

// Helper function to parse aggregation bits and check if validator participated
func CheckAggregationBit(bits string, position int) bool {
	if len(bits) < 3 || !strings.HasPrefix(bits, "0x") {
		return false
	}

	// Remove 0x prefix and convert hex to binary representation
	hexStr := bits[2:]

	// Calculate which hex digit contains our bit
	hexIndex := position / 4
	bitInHex := position % 4

	if hexIndex >= len(hexStr) {
		return false
	}

	// Convert hex digit to integer (process from right to left for little-endian)
	hexDigit := hexStr[len(hexStr)-1-hexIndex]
	var digit int
	if hexDigit >= '0' && hexDigit <= '9' {
		digit = int(hexDigit - '0')
	} else if hexDigit >= 'a' && hexDigit <= 'f' {
		digit = int(hexDigit - 'a' + 10)
	} else if hexDigit >= 'A' && hexDigit <= 'F' {
		digit = int(hexDigit - 'A' + 10)
	} else {
		return false
	}

	// Check if the specific bit is set
	return (digit & (1 << bitInHex)) != 0
}
