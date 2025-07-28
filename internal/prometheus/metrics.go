// internal/prometheus/metrics.go - Prometheus metrics
package prometheus

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"eth-sentry/internal/types"
)

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

type Metrics struct {
	enabled bool
}

func New(enabled bool, port int) *Metrics {
	if !enabled {
		return &Metrics{enabled: false}
	}

	// Register metrics
	prometheus.MustRegister(validatorStatusGauge)
	prometheus.MustRegister(validatorBalanceGauge)
	prometheus.MustRegister(nodeStatusGauge)
	prometheus.MustRegister(attestationSuccessCounter)
	prometheus.MustRegister(proposalSuccessCounter)
	prometheus.MustRegister(proposalRewardGauge)
	prometheus.MustRegister(currentEpochGauge)

	// Start HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	}()

	return &Metrics{enabled: true}
}

func (m *Metrics) UpdateValidatorStatus(index, status string, balance float64, active bool) {
	if !m.enabled {
		return
	}

	validatorBalanceGauge.WithLabelValues(index).Set(balance)

	statusValue := 0.0
	if active {
		statusValue = 1.0
	}
	validatorStatusGauge.WithLabelValues(index, status).Set(statusValue)
}

func (m *Metrics) UpdateNodeStatus(nodes []types.NodeStatus) {
	if !m.enabled {
		return
	}

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

func (m *Metrics) UpdateAttestation(validatorIndex int, success bool) {
	if !m.enabled {
		return
	}

	result := "missed"
	if success {
		result = "success"
	}
	attestationSuccessCounter.WithLabelValues(strconv.Itoa(validatorIndex), result).Inc()
}

func (m *Metrics) UpdateProposal(validatorIndex, slot int, reward int64, success bool) {
	if !m.enabled {
		return
	}

	result := "missed"
	if success {
		result = "success"
	}
	proposalSuccessCounter.WithLabelValues(strconv.Itoa(validatorIndex), result).Inc()

	if success {
		proposalRewardGauge.WithLabelValues(strconv.Itoa(validatorIndex), strconv.Itoa(slot)).Set(float64(reward))
	}
}

func (m *Metrics) UpdateCurrentEpoch(epoch int) {
	if !m.enabled {
		return
	}
	currentEpochGauge.Set(float64(epoch))
}
