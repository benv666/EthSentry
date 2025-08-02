// internal/duties/manager.go - Duty management for tracking validator committee assignments
package duties

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"eth-sentry/internal/beacon"
)

type DutyType string

const (
	DutyTypeAttestation DutyType = "attestation"
	DutyTypeProposal    DutyType = "proposal"
)

type Duty struct {
	Validator               uint64    `json:"validator"`
	Slot                    uint64    `json:"slot"`
	Epoch                   uint64    `json:"epoch"`
	Type                    DutyType  `json:"type"`
	CommitteeIndex          uint64    `json:"committee_index"`
	ValidatorCommitteeIndex uint64    `json:"validator_committee_index"`
	InclusionDelay          int64     `json:"inclusion_delay"` // -1 = not seen, >= 0 = delay
	CreatedAt               time.Time `json:"created_at"`

	// For debugging
	Pubkey string `json:"pubkey,omitempty"`
}

func (d Duty) String() string {
	return fmt.Sprintf("Duty{Val:%d, Slot:%d, Epoch:%d, Type:%s, CommIdx:%d, VCI:%d, Delay:%d}",
		d.Validator, d.Slot, d.Epoch, d.Type, d.CommitteeIndex, d.ValidatorCommitteeIndex, d.InclusionDelay)
}

type Manager struct {
	// validatorDutiesMap maps validator index to their duties
	validatorDutiesMap map[uint64][]Duty
	// slotDutiesMap maps slot to all duties for that slot (for quick lookup when processing blocks)
	slotDutiesMap map[uint64][]Duty

	mutex        sync.RWMutex
	logger       *slog.Logger
	beaconClient *beacon.Client

	// Configuration
	maxEpochsToKeep int // How many epochs of duty history to maintain
}

func NewManager(beaconClient *beacon.Client, logger *slog.Logger) *Manager {
	return &Manager{
		validatorDutiesMap: make(map[uint64][]Duty),
		slotDutiesMap:      make(map[uint64][]Duty),
		logger:             logger,
		beaconClient:       beaconClient,
		maxEpochsToKeep:    5, // Keep last 5 epochs of duties
	}
}

// FetchAndStoreDuties fetches attester duties for an epoch and stores them
func (m *Manager) FetchAndStoreDuties(beaconURL string, epoch int, validatorIndices []int) error {
	m.logger.Info("Fetching attester duties", "epoch", epoch, "validator_count", len(validatorIndices))

	duties, err := m.beaconClient.GetAttesterDuties(beaconURL, epoch, validatorIndices)
	if err != nil {
		return fmt.Errorf("failed to get attester duties for epoch %d: %w", epoch, err)
	}

	m.logger.Debug("Retrieved raw attester duties", "epoch", epoch, "duties_count", len(duties))

	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, dutyData := range duties {
		validatorIndex, err := strconv.ParseUint(dutyData.ValidatorIndex, 10, 64)
		if err != nil {
			m.logger.Warn("Invalid validator index in duty", "index", dutyData.ValidatorIndex, "error", err)
			continue
		}

		slot, err := strconv.ParseUint(dutyData.Slot, 10, 64)
		if err != nil {
			m.logger.Warn("Invalid slot in duty", "slot", dutyData.Slot, "error", err)
			continue
		}

		committeeIndex, err := strconv.ParseUint(dutyData.CommitteeIndex, 10, 64)
		if err != nil {
			m.logger.Warn("Invalid committee index in duty", "committee_index", dutyData.CommitteeIndex, "error", err)
			continue
		}

		validatorCommitteeIndex, err := strconv.ParseUint(dutyData.ValidatorCommitteeIndex, 10, 64)
		if err != nil {
			m.logger.Warn("Invalid validator committee index in duty", "validator_committee_index", dutyData.ValidatorCommitteeIndex, "error", err)
			continue
		}

		duty := Duty{
			Validator:               validatorIndex,
			Slot:                    slot,
			Epoch:                   uint64(epoch),
			Type:                    DutyTypeAttestation,
			CommitteeIndex:          committeeIndex,
			ValidatorCommitteeIndex: validatorCommitteeIndex,
			InclusionDelay:          -1, // Not seen yet
			CreatedAt:               time.Now(),
			Pubkey:                  dutyData.Pubkey,
		}

		m.addDutyUnsafe(duty)

		m.logger.Debug("Stored attester duty",
			"validator", validatorIndex,
			"slot", slot,
			"epoch", epoch,
			"committee_index", committeeIndex,
			"validator_committee_index", validatorCommitteeIndex,
			"pubkey", dutyData.Pubkey)
	}

	m.logger.Info("Stored attester duties", "epoch", epoch, "stored_count", len(duties))
	return nil
}

// addDutyUnsafe adds a duty without locking (assumes caller has lock)
func (m *Manager) addDutyUnsafe(d Duty) {
	// Add to validator duties map
	if _, ok := m.validatorDutiesMap[d.Validator]; !ok {
		m.validatorDutiesMap[d.Validator] = make([]Duty, 0)
	}

	// Check if duty already exists
	found := false
	vduties := m.validatorDutiesMap[d.Validator]
	for i := 0; i < len(vduties); i++ {
		if vduties[i].Slot == d.Slot && vduties[i].Validator == d.Validator && vduties[i].Type == d.Type {
			found = true
			break
		}
	}

	if !found {
		m.validatorDutiesMap[d.Validator] = append(m.validatorDutiesMap[d.Validator], d)
	}

	// Add to slot duties map
	if _, ok := m.slotDutiesMap[d.Slot]; !ok {
		m.slotDutiesMap[d.Slot] = make([]Duty, 0)
	}

	found = false
	sduties := m.slotDutiesMap[d.Slot]
	for i := 0; i < len(sduties); i++ {
		if sduties[i].Slot == d.Slot && sduties[i].Validator == d.Validator && sduties[i].Type == d.Type {
			found = true
			break
		}
	}

	if !found {
		m.slotDutiesMap[d.Slot] = append(m.slotDutiesMap[d.Slot], d)
	}
}

// updateDutyUnsafe updates an existing duty without locking (assumes caller has lock)
func (m *Manager) updateDutyUnsafe(d Duty) bool {
	updated := false

	// Update in validator duties map
	if vduties, ok := m.validatorDutiesMap[d.Validator]; ok {
		for i := 0; i < len(vduties); i++ {
			if vduties[i].Slot == d.Slot && vduties[i].Validator == d.Validator && vduties[i].Type == d.Type {
				vduties[i] = d
				updated = true
				break
			}
		}
	}

	// Update in slot duties map
	if sduties, ok := m.slotDutiesMap[d.Slot]; ok {
		for i := 0; i < len(sduties); i++ {
			if sduties[i].Slot == d.Slot && sduties[i].Validator == d.Validator && sduties[i].Type == d.Type {
				sduties[i] = d
				break
			}
		}
	}

	if !updated {
		m.logger.Warn("updateDuty called but duty not found", "duty", d.String())
	}

	return updated
}

// GetSlotDuties returns all duties for a specific slot
func (m *Manager) GetSlotDuties(slot uint64) []Duty {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if duties, ok := m.slotDutiesMap[slot]; ok {
		// Return a copy to avoid race conditions
		result := make([]Duty, len(duties))
		copy(result, duties)
		return result
	}

	return []Duty{}
}

// GetValidatorDuties returns all duties for a specific validator
func (m *Manager) GetValidatorDuties(validator uint64) []Duty {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if duties, ok := m.validatorDutiesMap[validator]; ok {
		// Return a copy to avoid race conditions
		result := make([]Duty, len(duties))
		copy(result, duties)
		return result
	}

	return []Duty{}
}

// UpdateDuty updates an existing duty (thread-safe)
func (m *Manager) UpdateDuty(d Duty) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Debug("Updating duty", "duty", d.String())
	return m.updateDutyUnsafe(d)
}

// CleanupOldDuties removes duties older than maxEpochsToKeep
func (m *Manager) CleanupOldDuties(currentEpoch uint64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cutoffEpoch := int64(currentEpoch) - int64(m.maxEpochsToKeep)
	if cutoffEpoch < 0 {
		return
	}

	removedCount := 0

	// Clean validator duties map
	for validator, duties := range m.validatorDutiesMap {
		filteredDuties := make([]Duty, 0, len(duties))
		for _, duty := range duties {
			if int64(duty.Epoch) >= cutoffEpoch {
				filteredDuties = append(filteredDuties, duty)
			} else {
				removedCount++
			}
		}
		if len(filteredDuties) == 0 {
			delete(m.validatorDutiesMap, validator)
		} else {
			m.validatorDutiesMap[validator] = filteredDuties
		}
	}

	// Clean slot duties map
	for slot, duties := range m.slotDutiesMap {
		filteredDuties := make([]Duty, 0, len(duties))
		for _, duty := range duties {
			if int64(duty.Epoch) >= cutoffEpoch {
				filteredDuties = append(filteredDuties, duty)
			}
		}
		if len(filteredDuties) == 0 {
			delete(m.slotDutiesMap, slot)
		} else {
			m.slotDutiesMap[slot] = filteredDuties
		}
	}

	if removedCount > 0 {
		m.logger.Info("Cleaned up old duties",
			"removed_count", removedCount,
			"cutoff_epoch", cutoffEpoch,
			"current_epoch", currentEpoch)
	}
}

// GetStats returns statistics about stored duties
func (m *Manager) GetStats() (int, int, int) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	totalDuties := 0
	for _, duties := range m.validatorDutiesMap {
		totalDuties += len(duties)
	}

	return len(m.validatorDutiesMap), len(m.slotDutiesMap), totalDuties
}
