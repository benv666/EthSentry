// internal/monitor/validator.go - Validator state management
package monitor

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"eth-sentry/internal/beacon"
	"eth-sentry/internal/types"
)

type ValidatorManager struct {
	states     map[int]*types.ValidatorState
	summaries  map[int]*types.EpochSummary
	lastAlerts map[string]time.Time
	logger     *slog.Logger
}

func NewValidatorManager(validatorIndices []int, logger *slog.Logger) *ValidatorManager {
	states := make(map[int]*types.ValidatorState)

	// Initialize validator states
	for _, idx := range validatorIndices {
		states[idx] = &types.ValidatorState{
			Index:             idx,
			EpochAttestations: make(map[int]bool),
			EpochProposals:    make(map[int]bool),
		}
	}

	return &ValidatorManager{
		states:     states,
		summaries:  make(map[int]*types.EpochSummary),
		lastAlerts: make(map[string]time.Time),
		logger:     logger,
	}
}

func (vm *ValidatorManager) UpdateValidatorStates(validators []beacon.ValidatorData) []string {
	var changes []string

	for _, validator := range validators {
		index, _ := strconv.Atoi(validator.Index)

		current := &types.ValidatorState{
			Index:             index,
			Status:            validator.Status,
			Slashed:           validator.Validator.Slashed,
			LastSeen:          time.Now(),
			EpochAttestations: make(map[int]bool),
			EpochProposals:    make(map[int]bool),
		}

		previous, exists := vm.states[index]
		if !exists || previous.Status == "" {
			vm.states[index] = current
			changes = append(changes, fmt.Sprintf("Validator %d initialized with status %s", index, current.Status))
			continue
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
			var changeType string
			if current.Slashed && !previous.Slashed {
				changeType = "slashed"
			} else if current.Status != previous.Status {
				changeType = "status_change"
			}

			change := fmt.Sprintf("Validator %d: %s -> %s (slashed: %v)",
				index, previous.Status, current.Status, current.Slashed)
			changes = append(changes, change)

			vm.logger.Info("Validator state changed",
				"validator", index,
				"old_status", previous.Status,
				"new_status", current.Status,
				"slashed", current.Slashed,
				"change_type", changeType)
		}

		vm.states[index] = current
	}

	return changes
}

func (vm *ValidatorManager) UpdateAttestationResults(results []types.AttestationResult) {
	for _, result := range results {
		if state, exists := vm.states[result.ValidatorIndex]; exists {
			state.EpochAttestations[result.Epoch] = result.Attested
			state.LastAttestationSlot = result.Slot

			if !result.Attested {
				state.MissedAttestations++
				vm.logger.Warn("Missed attestation recorded",
					"validator", result.ValidatorIndex,
					"epoch", result.Epoch,
					"slot", result.Slot,
					"total_missed", state.MissedAttestations)
			} else {
				vm.logger.Info("Successful attestation recorded",
					"validator", result.ValidatorIndex,
					"epoch", result.Epoch,
					"slot", result.Slot,
					"inclusion_delay", result.InclusionDelay)
			}
		}
	}
}

func (vm *ValidatorManager) UpdateProposal(validatorIndex, slot int, reward int64) {
	if state, exists := vm.states[validatorIndex]; exists {
		epoch := slot / 32
		state.LastProposalSlot = slot
		state.LastProposalReward = reward
		state.EpochProposals[epoch] = true

		vm.logger.Info("Block proposal recorded",
			"validator", validatorIndex,
			"slot", slot,
			"epoch", epoch,
			"reward", reward)
	}
}

func (vm *ValidatorManager) GenerateEpochSummary(epoch int) *types.EpochSummary {
	summary := &types.EpochSummary{
		Epoch:                epoch,
		ValidatorPerformance: make(map[int]*types.ValidatorPerformance),
	}

	for validatorIdx, state := range vm.states {
		perf := &types.ValidatorPerformance{
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

	vm.summaries[epoch] = summary
	return summary
}

func (vm *ValidatorManager) GetValidatorDetails(index int, validators []beacon.ValidatorData) string {
	state, exists := vm.states[index]
	if !exists {
		return ""
	}

	var validatorData *beacon.ValidatorData
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

	// Calculate recent performance (last 5 epochs)
	recentAttestations := 0
	currentEpoch := int(time.Now().Unix() / (12 * 32)) // Rough estimate
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
		validatorData.Validator.Pubkey)

	return message
}

func (vm *ValidatorManager) GetEpochSummaryMessage(epoch int) string {
	summary, exists := vm.summaries[epoch]
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

func (vm *ValidatorManager) ShouldSendAlert(alertKey string, cooldownMinutes int) bool {
	if lastAlert, exists := vm.lastAlerts[alertKey]; exists {
		if time.Since(lastAlert) < time.Duration(cooldownMinutes)*time.Minute {
			return false
		}
	}
	vm.lastAlerts[alertKey] = time.Now()
	return true
}

func (vm *ValidatorManager) GetStates() map[int]*types.ValidatorState {
	return vm.states
}

func (vm *ValidatorManager) GetSummaries() map[int]*types.EpochSummary {
	return vm.summaries
}
