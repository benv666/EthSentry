// internal/types/types.go - Common type definitions
package types

import "time"

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
	InclusionDelay     int
}

type NodeStatus struct {
	Name   string
	URL    string
	Synced bool
	Error  error
}

type AttestationResult struct {
	ValidatorIndex int
	Epoch          int
	Slot           int
	Attested       bool
	InclusionDelay int
	CorrectHead    bool
	CorrectTarget  bool
	CorrectSource  bool
}
