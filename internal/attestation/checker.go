// internal/attestation/checker.go - Attestation performance checking
package attestation

import (
	"fmt"
	"log/slog"
	"strconv"

	"eth-sentry/internal/beacon"
	"eth-sentry/internal/types"
)

type Checker struct {
	beaconClient *beacon.Client
	logger       *slog.Logger
}

func NewChecker(beaconClient *beacon.Client, logger *slog.Logger) *Checker {
	return &Checker{
		beaconClient: beaconClient,
		logger:       logger,
	}
}

func (c *Checker) CheckEpochAttestations(beaconURL string, epoch int, validatorIndices []int) ([]types.AttestationResult, error) {
	c.logger.Info("Checking attestation performance", "epoch", epoch)

	// Get attester duties for the epoch
	duties, err := c.beaconClient.GetAttesterDuties(beaconURL, epoch, validatorIndices)
	if err != nil {
		return nil, fmt.Errorf("failed to get attester duties: %w", err)
	}

	if len(duties) == 0 {
		c.logger.Debug("No attester duties found for epoch", "epoch", epoch)
		return []types.AttestationResult{}, nil
	}

	c.logger.Debug("Retrieved attester duties", "epoch", epoch, "count", len(duties))

	// Create map of duties for quick lookup
	dutiesMap := make(map[int]beacon.AttesterDuty)
	for _, duty := range duties {
		if idx, err := strconv.Atoi(duty.ValidatorIndex); err == nil {
			dutiesMap[idx] = duty
		}
	}

	var results []types.AttestationResult

	// Check each validator's attestation performance
	for _, validatorIdx := range validatorIndices {
		duty, hasDuty := dutiesMap[validatorIdx]
		if !hasDuty {
			c.logger.Debug("No attester duty for validator in epoch", "validator", validatorIdx, "epoch", epoch)
			continue
		}

		dutySlot, err := strconv.Atoi(duty.Slot)
		if err != nil {
			c.logger.Warn("Invalid slot in duty", "slot", duty.Slot, "validator", validatorIdx)
			continue
		}

		result := types.AttestationResult{
			ValidatorIndex: validatorIdx,
			Epoch:          epoch,
			Slot:           dutySlot,
			Attested:       false,
			InclusionDelay: -1,
		}

		c.logger.Debug("Checking attestation for validator",
			"validator", validatorIdx,
			"epoch", epoch,
			"duty_slot", dutySlot)

		// Check multiple slots where the attestation might be included
		// Attestations can be included in the slot after the duty slot up to the end of the epoch
		maxCheckSlot := ((epoch + 1) * 32) - 1
		minInclusionDelay := -1

		for checkSlot := dutySlot + 1; checkSlot <= maxCheckSlot && checkSlot <= dutySlot+32; checkSlot++ {
			blockData, err := c.beaconClient.GetBlock(beaconURL, checkSlot)
			if err != nil {
				c.logger.Debug("Could not get block for slot", "slot", checkSlot, "error", err)
				continue
			}

			c.logger.Debug("Checking block for attestations",
				"slot", checkSlot,
				"validator", validatorIdx,
				"attestation_count", len(blockData.Data.Message.Body.Attestations))

			// Check attestations in this block
			for _, attestation := range blockData.Data.Message.Body.Attestations {
				attSlot, _ := strconv.Atoi(attestation.Data.Slot)
				attCommitteeIndex, _ := strconv.Atoi(attestation.Data.CommitteeIndex)
				dutyCommitteeIndex, _ := strconv.Atoi(duty.CommitteeIndex)

				// Check if this attestation matches our validator's duty
				if attSlot == dutySlot && attCommitteeIndex == dutyCommitteeIndex {
					c.logger.Debug("Found matching attestation",
						"attestation_slot", attSlot,
						"committee_index", attCommitteeIndex,
						"duty_slot", dutySlot,
						"duty_committee", dutyCommitteeIndex)

					// Check if our validator participated using committee index
					validatorCommitteeIndex, err := strconv.Atoi(duty.ValidatorCommitteeIndex)
					if err != nil {
						c.logger.Warn("Invalid validator committee index", "index", duty.ValidatorCommitteeIndex)
						continue
					}

					if beacon.CheckAggregationBit(attestation.AggregationBits, validatorCommitteeIndex) {
						inclusionDelay := checkSlot - dutySlot

						// Only update if this is the first time we find it or if it has a better inclusion delay
						if minInclusionDelay == -1 || inclusionDelay < minInclusionDelay {
							result.Attested = true
							result.InclusionDelay = inclusionDelay
							minInclusionDelay = inclusionDelay

							// For now, assume correctness (would need to validate against known correct values)
							result.CorrectHead = true
							result.CorrectTarget = true
							result.CorrectSource = true

							c.logger.Debug("Validator successfully attested",
								"validator", validatorIdx,
								"slot", dutySlot,
								"inclusion_slot", checkSlot,
								"inclusion_delay", inclusionDelay,
								"epoch", epoch)
						}
					}
				}
			}

			// If we found an attestation with inclusion delay 1, we can stop looking
			if result.Attested && result.InclusionDelay == 1 {
				break
			}
		}

		if !result.Attested {
			c.logger.Warn("Missed attestation detected",
				"validator", validatorIdx,
				"epoch", epoch,
				"slot", dutySlot)
		} else {
			c.logger.Info("Successful attestation confirmed",
				"validator", validatorIdx,
				"epoch", epoch,
				"slot", dutySlot,
				"inclusion_delay", result.InclusionDelay)
		}

		results = append(results, result)
	}

	c.logger.Info("Attestation performance check completed", "epoch", epoch, "results", len(results))
	return results, nil
}
