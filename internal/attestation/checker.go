// internal/attestation/checker.go - Correct attestation performance checking implementation
package attestation

import (
	"fmt"
	"log/slog"
	"strconv"

	"eth-sentry/internal/beacon"
	"eth-sentry/internal/duties"
	"eth-sentry/internal/types"
)

type Checker struct {
	beaconClient *beacon.Client
	dutyManager  *duties.Manager
	logger       *slog.Logger
}

func NewChecker(beaconClient *beacon.Client, dutyManager *duties.Manager, logger *slog.Logger) *Checker {
	return &Checker{
		beaconClient: beaconClient,
		dutyManager:  dutyManager,
		logger:       logger,
	}
}

// CheckAttestationInclusion processes a newly produced block to check for attestation inclusions
// This is the core function that should be called for each new block
func (c *Checker) CheckAttestationInclusion(beaconURL string, blockSlot uint64) ([]types.AttestationResult, error) {
	c.logger.Debug("Checking attestation inclusion for block", "slot", blockSlot)

	// Get the block data
	blockData, err := c.beaconClient.GetBlock(beaconURL, int(blockSlot))
	if err != nil {
		c.logger.Debug("Could not get block for attestation checking", "slot", blockSlot, "error", err)
		return nil, fmt.Errorf("failed to get block %d: %w", blockSlot, err)
	}

	attestations := blockData.Data.Message.Body.Attestations
	c.logger.Debug("Processing block attestations",
		"slot", blockSlot,
		"attestation_count", len(attestations))

	var results []types.AttestationResult

	// Process each attestation in the block
	for attestationIdx, attestation := range attestations {
		attestedSlot, err := strconv.ParseUint(attestation.Data.Slot, 10, 64)
		if err != nil {
			c.logger.Warn("Invalid attested slot in attestation",
				"block_slot", blockSlot,
				"attestation_idx", attestationIdx,
				"slot_string", attestation.Data.Slot,
				"error", err)
			continue
		}

		attestedCommitteeIndex, err := strconv.ParseUint(attestation.Data.CommitteeIndex, 10, 64)
		if err != nil {
			c.logger.Warn("Invalid committee index in attestation",
				"block_slot", blockSlot,
				"attestation_idx", attestationIdx,
				"committee_index_string", attestation.Data.CommitteeIndex,
				"error", err)
			continue
		}

		c.logger.Debug("Processing attestation",
			"block_slot", blockSlot,
			"attestation_idx", attestationIdx,
			"attested_slot", attestedSlot,
			"committee_index", attestedCommitteeIndex,
			"aggregation_bits", attestation.AggregationBits)

		// Get duties for the attested slot
		slotDuties := c.dutyManager.GetSlotDuties(attestedSlot)

		c.logger.Debug("Found duties for attested slot",
			"attested_slot", attestedSlot,
			"duty_count", len(slotDuties))

		// Check each duty for this slot
		for _, duty := range slotDuties {
			// Only process attestation duties that match this attestation's committee
			if duty.Type != duties.DutyTypeAttestation {
				continue
			}

			if duty.CommitteeIndex != attestedCommitteeIndex {
				c.logger.Debug("Committee index mismatch",
					"duty_committee", duty.CommitteeIndex,
					"attestation_committee", attestedCommitteeIndex,
					"validator", duty.Validator)
				continue // Committee index mismatch, this duty doesn't match this attestation
			}

			c.logger.Debug("Found matching duty for attestation",
				"validator", duty.Validator,
				"duty", duty.String(),
				"block_slot", blockSlot,
				"attested_slot", attestedSlot)

			// Check if the validator's bit is set in the aggregation bits
			bitSet := c.checkAggregationBit(attestation.AggregationBits, duty.ValidatorCommitteeIndex)

			inclusionDelay := int64(blockSlot - attestedSlot)

			c.logger.Debug("Checking aggregation bit",
				"validator", duty.Validator,
				"validator_committee_index", duty.ValidatorCommitteeIndex,
				"aggregation_bits", attestation.AggregationBits,
				"bit_set", bitSet,
				"inclusion_delay", inclusionDelay)

			if !bitSet {
				// Validator did not participate in this attestation
				// This could be because:
				// 1. They didn't attest
				// 2. This is a non-canonical vote (low participation)
				// 3. They attested but it wasn't included in this particular aggregation

				bitCount := c.countSetBits(attestation.AggregationBits)
				totalBits := c.getTotalBits(attestation.AggregationBits)

				c.logger.Debug("Validator bit not set in attestation",
					"validator", duty.Validator,
					"duty", duty.String(),
					"bits_set", bitCount,
					"total_bits", totalBits,
					"participation_rate", fmt.Sprintf("%.1f%%", float64(bitCount)/float64(totalBits)*100))

				// If participation is very low, this might be a non-canonical vote
				if bitCount < totalBits/2 {
					c.logger.Debug("Low participation attestation, possibly non-canonical",
						"validator", duty.Validator,
						"bits_set", bitCount,
						"total_bits", totalBits)
				}

				continue // Don't update duty for non-participation
			}

			// Validator participated! Update the duty with inclusion delay
			// But only if this is the first time we see it or if the delay is better
			if duty.InclusionDelay >= 0 && duty.InclusionDelay <= inclusionDelay {
				c.logger.Debug("Already recorded better or equal inclusion delay",
					"validator", duty.Validator,
					"existing_delay", duty.InclusionDelay,
					"new_delay", inclusionDelay)
				continue // Already have this or better inclusion delay
			}

			// Update the duty with the inclusion delay
			updatedDuty := duty
			updatedDuty.InclusionDelay = inclusionDelay

			if c.dutyManager.UpdateDuty(updatedDuty) {
				c.logger.Info("Attestation inclusion confirmed",
					"validator", duty.Validator,
					"attested_slot", attestedSlot,
					"included_slot", blockSlot,
					"inclusion_delay", inclusionDelay,
					"committee_index", attestedCommitteeIndex,
					"validator_committee_index", duty.ValidatorCommitteeIndex)

				// Create result
				result := types.AttestationResult{
					ValidatorIndex: int(duty.Validator),
					Epoch:          int(duty.Epoch),
					Slot:           int(attestedSlot),
					Attested:       true,
					InclusionDelay: int(inclusionDelay),
					CorrectHead:    true, // Simplified - would need actual validation
					CorrectTarget:  true, // Simplified - would need actual validation
					CorrectSource:  true, // Simplified - would need actual validation
				}

				results = append(results, result)
			} else {
				c.logger.Warn("Failed to update duty with inclusion delay",
					"validator", duty.Validator,
					"duty", duty.String())
			}
		}
	}

	c.logger.Debug("Completed attestation inclusion check",
		"block_slot", blockSlot,
		"attestations_processed", len(attestations),
		"inclusions_found", len(results))

	return results, nil
}

// GetMissedAttestations checks for validators that have duties but haven't been included yet
// This should be called after enough time has passed for attestations to be included
func (c *Checker) GetMissedAttestations(currentSlot uint64, lookbackSlots uint64) []types.AttestationResult {
	var missedAttestations []types.AttestationResult

	// Check slots from lookbackSlots ago up to a reasonable cutoff
	// We don't check the most recent slots as attestations might still be incoming
	cutoffSlot := currentSlot - 6 // Don't check last 6 slots (about 1 minute)
	startSlot := currentSlot - lookbackSlots

	c.logger.Debug("Checking for missed attestations",
		"current_slot", currentSlot,
		"start_slot", startSlot,
		"cutoff_slot", cutoffSlot)

	for slot := startSlot; slot <= cutoffSlot; slot++ {
		duties := c.dutyManager.GetSlotDuties(slot)

		for _, duty := range duties {
			// if duty.Type != duties.DutyTypeAttestation { // TODO, fix this, it doesn't like it.
			if duty.Type != "attestation" {
				continue
			}

			if duty.InclusionDelay < 0 {
				// This duty has not been fulfilled
				c.logger.Warn("Missed attestation detected",
					"validator", duty.Validator,
					"slot", slot,
					"epoch", duty.Epoch,
					"committee_index", duty.CommitteeIndex,
					"duty", duty.String())

				result := types.AttestationResult{
					ValidatorIndex: int(duty.Validator),
					Epoch:          int(duty.Epoch),
					Slot:           int(slot),
					Attested:       false,
					InclusionDelay: -1,
					CorrectHead:    false,
					CorrectTarget:  false,
					CorrectSource:  false,
				}

				missedAttestations = append(missedAttestations, result)
			}
		}
	}

	c.logger.Info("Missed attestation check completed",
		"current_slot", currentSlot,
		"slots_checked", cutoffSlot-startSlot+1,
		"missed_count", len(missedAttestations))

	return missedAttestations
}

// checkAggregationBit checks if a specific bit is set in the aggregation bits
// This is based on your previous implementation but adapted for the hex string format
func (c *Checker) checkAggregationBit(bits string, position uint64) bool {
	if len(bits) < 3 || bits[:2] != "0x" {
		c.logger.Warn("Invalid aggregation bits format", "bits", bits)
		return false
	}

	// Remove 0x prefix
	hexStr := bits[2:]

	// Calculate which hex digit contains our bit
	hexIndex := position / 4
	bitInHex := position % 4

	if hexIndex >= uint64(len(hexStr)) {
		c.logger.Warn("Bit position out of range",
			"position", position,
			"hex_length", len(hexStr),
			"hex_index", hexIndex)
		return false
	}

	// Convert hex digit to integer (little-endian: rightmost hex digit is least significant)
	hexDigit := hexStr[uint64(len(hexStr))-1-hexIndex]
	var digit int
	switch {
	case hexDigit >= '0' && hexDigit <= '9':
		digit = int(hexDigit - '0')
	case hexDigit >= 'a' && hexDigit <= 'f':
		digit = int(hexDigit - 'a' + 10)
	case hexDigit >= 'A' && hexDigit <= 'F':
		digit = int(hexDigit - 'A' + 10)
	default:
		c.logger.Warn("Invalid hex digit in aggregation bits",
			"digit", string(hexDigit),
			"position", position)
		return false
	}

	// Check if the specific bit is set
	bitSet := (digit & (1 << bitInHex)) != 0

	c.logger.Debug("Aggregation bit check details",
		"position", position,
		"hex_index", hexIndex,
		"bit_in_hex", bitInHex,
		"hex_digit", string(hexDigit),
		"digit_value", digit,
		"bit_mask", 1<<bitInHex,
		"bit_set", bitSet)

	return bitSet
}

// countSetBits counts the number of set bits in the aggregation bits (for debugging)
func (c *Checker) countSetBits(bits string) int {
	if len(bits) < 3 || bits[:2] != "0x" {
		return 0
	}

	count := 0
	hexStr := bits[2:]

	for _, hexChar := range hexStr {
		var digit int
		switch {
		case hexChar >= '0' && hexChar <= '9':
			digit = int(hexChar - '0')
		case hexChar >= 'a' && hexChar <= 'f':
			digit = int(hexChar - 'a' + 10)
		case hexChar >= 'A' && hexChar <= 'F':
			digit = int(hexChar - 'A' + 10)
		default:
			continue
		}

		// Count bits in this hex digit
		for i := 0; i < 4; i++ {
			if (digit & (1 << i)) != 0 {
				count++
			}
		}
	}

	return count
}

// getTotalBits estimates the total number of bits (for debugging)
func (c *Checker) getTotalBits(bits string) int {
	if len(bits) < 3 || bits[:2] != "0x" {
		return 0
	}

	hexStr := bits[2:]
	return len(hexStr) * 4 // Each hex digit represents 4 bits
}
