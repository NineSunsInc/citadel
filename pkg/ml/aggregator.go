package ml

import (
	"fmt"
	"sort"
	"strings"
)

// AggregationThresholds defines configurable thresholds for signal aggregation
type AggregationThresholds struct {
	// FastPathBlock: If any signal score >= this, block without further analysis
	FastPathBlock float64 `json:"fast_path_block"`

	// FastPathAllow: If all signals score <= this AND no obfuscation, allow without LLM
	FastPathAllow float64 `json:"fast_path_allow"`

	// BERTEscalation: Escalate to BERT if score >= this (ambiguous range start)
	BERTEscalation float64 `json:"bert_escalation"`

	// SafeguardEscalation: Escalate to Safeguard if still ambiguous after BERT
	SafeguardEscalation float64 `json:"safeguard_escalation"`

	// ObfuscationBoost: Multiply score by this if obfuscation detected + attack found
	ObfuscationBoost float64 `json:"obfuscation_boost"`

	// HighConfidenceThreshold: Signals with confidence >= this are trusted more
	HighConfidenceThreshold float64 `json:"high_confidence_threshold"`

	// LowConfidenceThreshold: Signals with confidence < this trigger bi-directional flow
	LowConfidenceThreshold float64 `json:"low_confidence_threshold"`
}

// DefaultAggregationThresholds returns sensible defaults
func DefaultAggregationThresholds() AggregationThresholds {
	return AggregationThresholds{
		FastPathBlock:           0.85,
		FastPathAllow:           0.05,
		BERTEscalation:          0.30,
		SafeguardEscalation:     0.40,
		ObfuscationBoost:        1.3,
		HighConfidenceThreshold: 0.85,
		LowConfidenceThreshold:  0.70,
	}
}

// AggregatedResult is the final decision after combining all signals
type AggregatedResult struct {
	// FinalScore is the weighted combination of all signals
	FinalScore float64 `json:"final_score"`

	// Action is the recommended action: ALLOW, WARN, BLOCK
	Action string `json:"action"`

	// RiskLevel is the risk classification: MINIMAL, LOW, MEDIUM, HIGH, CRITICAL
	RiskLevel string `json:"risk_level"`

	// Reason explains the decision
	Reason string `json:"reason"`

	// DecisionPath explains which precedence tier made the decision
	DecisionPath string `json:"decision_path"`

	// Signals contains all signals that contributed to the decision
	Signals []DetectionSignal `json:"signals"`

	// WasDeobfuscated indicates if any obfuscation was detected
	WasDeobfuscated bool `json:"was_deobfuscated"`

	// ObfuscationTypes lists all detected obfuscation types
	ObfuscationTypes []ObfuscationType `json:"obfuscation_types,omitempty"`

	// EscalationNeeded indicates if further analysis is needed
	EscalationNeeded EscalationType `json:"escalation_needed,omitempty"`

	// TotalLatencyMs is the sum of all signal latencies
	TotalLatencyMs float64 `json:"total_latency_ms"`
}

// EscalationType indicates what further analysis is needed
type EscalationType string

const (
	EscalationNone      EscalationType = ""          // No escalation needed
	EscalationBERT      EscalationType = "bert"      // Need BERT analysis
	EscalationDeeperGo  EscalationType = "deeper_go" // BERT uncertain, need deeper Go analysis
	EscalationSafeguard EscalationType = "safeguard" // Need Safeguard arbitration
)

// SignalAggregator combines multiple detection signals with precedence logic
type SignalAggregator struct {
	thresholds AggregationThresholds
	signals    []DetectionSignal
}

// NewSignalAggregator creates a new aggregator with default thresholds
func NewSignalAggregator() *SignalAggregator {
	return &SignalAggregator{
		thresholds: DefaultAggregationThresholds(),
		signals:    make([]DetectionSignal, 0),
	}
}

// NewSignalAggregatorWithThresholds creates an aggregator with custom thresholds
func NewSignalAggregatorWithThresholds(t AggregationThresholds) *SignalAggregator {
	return &SignalAggregator{
		thresholds: t,
		signals:    make([]DetectionSignal, 0),
	}
}

// AddSignal adds a detection signal to the aggregator
func (a *SignalAggregator) AddSignal(s DetectionSignal) {
	a.signals = append(a.signals, s)
}

// GetSignal returns a signal by source, or nil if not found
func (a *SignalAggregator) GetSignal(source SignalSource) *DetectionSignal {
	for i := range a.signals {
		if a.signals[i].Source == source {
			return &a.signals[i]
		}
	}
	return nil
}

// HasSignal returns true if a signal from the given source exists
func (a *SignalAggregator) HasSignal(source SignalSource) bool {
	return a.GetSignal(source) != nil
}

// HasObfuscation returns true if any signal detected obfuscation
func (a *SignalAggregator) HasObfuscation() bool {
	for _, s := range a.signals {
		if s.HasObfuscation() {
			return true
		}
	}
	return false
}

// GetAllObfuscationTypes returns all unique obfuscation types from all signals
func (a *SignalAggregator) GetAllObfuscationTypes() []ObfuscationType {
	seen := make(map[ObfuscationType]bool)
	var types []ObfuscationType
	for _, s := range a.signals {
		for _, t := range s.ObfuscationTypes {
			if !seen[t] {
				seen[t] = true
				types = append(types, t)
			}
		}
	}
	return types
}

// ShouldEscalateToBERT determines if BERT analysis is needed
// Returns true if:
// 1. Obfuscation was detected (BERT must see decoded text)
// 2. Score is in ambiguous range (BERTEscalation to FastPathBlock)
// 3. No high-confidence decision has been made
func (a *SignalAggregator) ShouldEscalateToBERT() bool {
	// If obfuscation detected, always escalate to BERT
	if a.HasObfuscation() {
		return true
	}

	// Calculate preliminary score
	score := a.calculateWeightedScore()

	// If in ambiguous range, escalate
	if score >= a.thresholds.BERTEscalation && score < a.thresholds.FastPathBlock {
		return true
	}

	return false
}

// ShouldEscalateToSafeguard determines if Safeguard arbitration is needed
// Returns true if:
// 1. BERT and Go significantly disagree (> 0.3 score difference)
// 2. BERT has low confidence but detected something
// 3. Score is in deep ambiguous range after all analysis
func (a *SignalAggregator) ShouldEscalateToSafeguard() bool {
	bertSignal := a.GetSignal(SignalSourceBERT)
	heuristicSignal := a.GetSignal(SignalSourceHeuristic)

	// If both BERT and heuristic exist, check for disagreement
	if bertSignal != nil && heuristicSignal != nil {
		scoreDiff := abs(bertSignal.Score - heuristicSignal.Score)

		// Significant disagreement
		if scoreDiff > 0.3 {
			return true
		}

		// BERT uncertain + obfuscation detected but BERT says safe
		if bertSignal.IsLowConfidence() && a.HasObfuscation() && bertSignal.IsSafe() {
			return true
		}
	}

	// Calculate current score
	score := a.calculateWeightedScore()

	// Deep ambiguous range
	if score >= a.thresholds.SafeguardEscalation && score <= 0.70 {
		// Check if we have any high-confidence signals
		for _, s := range a.signals {
			if s.IsHighConfidence() {
				return false // Trust high-confidence signal
			}
		}
		return true
	}

	return false
}

// ShouldTriggerDeeperGoAnalysis implements bi-directional feedback
// Returns true when BERT is uncertain and Go should re-analyze
func (a *SignalAggregator) ShouldTriggerDeeperGoAnalysis() bool {
	bertSignal := a.GetSignal(SignalSourceBERT)
	if bertSignal == nil {
		return false
	}

	// BERT has low confidence
	if bertSignal.Confidence < a.thresholds.LowConfidenceThreshold {
		// Case 1: Obfuscation detected but BERT says SAFE - distrust BERT
		if a.HasObfuscation() && bertSignal.IsSafe() {
			return true
		}

		// Case 2: BERT says INJECTION but low confidence + Go disagrees
		heuristicSignal := a.GetSignal(SignalSourceHeuristic)
		if heuristicSignal != nil {
			if bertSignal.IsMalicious() && heuristicSignal.Score < 0.3 {
				// BERT thinks injection but Go saw nothing - verify with deeper analysis
				return true
			}
			if bertSignal.IsSafe() && heuristicSignal.Score > 0.4 {
				// BERT thinks safe but Go suspicious - deeper analysis
				return true
			}
		}
	}

	return false
}

// Aggregate combines all signals using precedence-based logic
// Precedence order:
// TIER 0: Absolute rules (secrets found, score >= 0.95)
// TIER 1: High-confidence layer wins
// TIER 2: Obfuscation gives Go veto power
// TIER 3: Weighted average with confidence adjustment
// TIER 4: Safeguard as final arbiter
func (a *SignalAggregator) Aggregate() AggregatedResult {
	result := AggregatedResult{
		Signals:          a.signals,
		WasDeobfuscated:  a.HasObfuscation(),
		ObfuscationTypes: a.GetAllObfuscationTypes(),
	}

	// Calculate total latency
	for _, s := range a.signals {
		result.TotalLatencyMs += s.LatencyMs
	}

	// === TIER 0: ABSOLUTE RULES ===
	// Check for secrets (any signal with secrets_found metadata)
	for _, s := range a.signals {
		if found, ok := s.Metadata["secrets_found"].(bool); ok && found {
			result.FinalScore = 1.0
			result.Action = "BLOCK"
			result.RiskLevel = "CRITICAL"
			result.Reason = "Secrets/credentials detected"
			result.DecisionPath = "TIER_0_SECRETS"
			return result
		}
	}

	// Check for extremely high scores (no ambiguity)
	for _, s := range a.signals {
		if s.Score >= 0.95 && s.IsHighConfidence() {
			result.FinalScore = s.Score
			result.Action = "BLOCK"
			result.RiskLevel = "CRITICAL"
			result.Reason = fmt.Sprintf("%s: %s", s.Source, strings.Join(s.Reasons, "; "))
			result.DecisionPath = fmt.Sprintf("TIER_0_HIGH_SCORE_%s", s.Source)
			return result
		}
	}

	// === TIER 1: HIGH-CONFIDENCE LAYER WINS ===
	// Sort signals by confidence (highest first)
	highConfSignals := make([]DetectionSignal, 0)
	for _, s := range a.signals {
		if s.IsHighConfidence() {
			highConfSignals = append(highConfSignals, s)
		}
	}

	if len(highConfSignals) > 0 {
		// Sort by confidence descending
		sort.Slice(highConfSignals, func(i, j int) bool {
			return highConfSignals[i].Confidence > highConfSignals[j].Confidence
		})

		topSignal := highConfSignals[0]

		// Check if all high-confidence signals agree
		allAgree := true
		firstLabel := topSignal.Label
		for _, s := range highConfSignals {
			if s.Label != firstLabel {
				allAgree = false
				break
			}
		}

		if allAgree {
			result.FinalScore = topSignal.Score
			result.Action = a.scoreToAction(topSignal.Score)
			result.RiskLevel = a.scoreToRiskLevel(topSignal.Score)
			result.Reason = fmt.Sprintf("High-confidence %s: %s (%.0f%%)",
				topSignal.Source, topSignal.Label, topSignal.Confidence*100)
			result.DecisionPath = "TIER_1_HIGH_CONFIDENCE_AGREEMENT"
			return result
		}
		// High-confidence signals disagree - fall through to TIER 2/3
	}

	// === TIER 2: OBFUSCATION GIVES GO VETO POWER ===
	if a.HasObfuscation() {
		heuristicSignal := a.GetSignal(SignalSourceHeuristic)
		bertSignal := a.GetSignal(SignalSourceBERT)

		if heuristicSignal != nil && bertSignal != nil {
			// Case 1: BERT says SAFE but obfuscation detected
			// Go gets veto power - boost score
			if bertSignal.IsSafe() && bertSignal.Confidence < a.thresholds.HighConfidenceThreshold {
				// Obfuscation + BERT uncertain SAFE = distrust BERT
				boostedScore := heuristicSignal.Score * a.thresholds.ObfuscationBoost
				if boostedScore > 1.0 {
					boostedScore = 1.0
				}

				// Only veto if boosted score is significant
				if boostedScore >= 0.5 {
					result.FinalScore = boostedScore
					result.Action = a.scoreToAction(boostedScore)
					result.RiskLevel = a.scoreToRiskLevel(boostedScore)
					result.Reason = fmt.Sprintf("Obfuscation veto: BERT said SAFE (%.0f%% conf) but %v detected",
						bertSignal.Confidence*100, a.GetAllObfuscationTypes())
					result.DecisionPath = "TIER_2_OBFUSCATION_VETO"
					result.EscalationNeeded = EscalationDeeperGo
					return result
				}
			}

			// Case 2: Both Go and BERT agree on injection + obfuscation = boost confidence
			if bertSignal.IsMalicious() && heuristicSignal.Score >= 0.4 {
				// Obfuscation + agreement = strong signal
				boostedScore := (bertSignal.Score + heuristicSignal.Score) / 2 * a.thresholds.ObfuscationBoost
				if boostedScore > 1.0 {
					boostedScore = 1.0
				}
				result.FinalScore = boostedScore
				result.Action = a.scoreToAction(boostedScore)
				result.RiskLevel = a.scoreToRiskLevel(boostedScore)
				result.Reason = fmt.Sprintf("Obfuscation + agreement: Go=%.2f, BERT=%s (%.0f%%)",
					heuristicSignal.Score, bertSignal.Label, bertSignal.Confidence*100)
				result.DecisionPath = "TIER_2_OBFUSCATION_BOOST"
				return result
			}
		}
	}

	// === TIER 3: CONFIDENCE-WEIGHTED AGGREGATION ===
	score := a.calculateWeightedScore()

	// Apply obfuscation boost if detected and score is moderate
	if a.HasObfuscation() && score >= 0.3 && score < 0.7 {
		score *= a.thresholds.ObfuscationBoost
		if score > 1.0 {
			score = 1.0
		}
	}

	result.FinalScore = score
	result.Action = a.scoreToAction(score)
	result.RiskLevel = a.scoreToRiskLevel(score)
	result.Reason = a.buildAggregationReason()
	result.DecisionPath = "TIER_3_WEIGHTED_AGGREGATION"

	// Check if Safeguard is needed
	if a.ShouldEscalateToSafeguard() && !a.HasSignal(SignalSourceSafeguard) {
		result.EscalationNeeded = EscalationSafeguard
	} else if a.ShouldTriggerDeeperGoAnalysis() && !a.HasSignal(SignalSourceDeeperGo) {
		result.EscalationNeeded = EscalationDeeperGo
	}

	return result
}

// calculateWeightedScore computes the confidence-weighted average of all signals
func (a *SignalAggregator) calculateWeightedScore() float64 {
	if len(a.signals) == 0 {
		return 0.0
	}

	var weightedSum float64
	var totalWeight float64

	for _, s := range a.signals {
		// Weight = layer weight * confidence
		effectiveWeight := s.Weight * s.Confidence
		weightedSum += s.Score * effectiveWeight
		totalWeight += effectiveWeight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

// scoreToAction converts a score to an action
func (a *SignalAggregator) scoreToAction(score float64) string {
	switch {
	case score >= 0.70:
		return "BLOCK"
	case score >= 0.40:
		return "WARN"
	default:
		return "ALLOW"
	}
}

// scoreToRiskLevel converts a score to a risk level
func (a *SignalAggregator) scoreToRiskLevel(score float64) string {
	switch {
	case score >= 0.90:
		return "CRITICAL"
	case score >= 0.70:
		return "HIGH"
	case score >= 0.50:
		return "MEDIUM"
	case score >= 0.30:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// buildAggregationReason creates a human-readable reason for the aggregated score
func (a *SignalAggregator) buildAggregationReason() string {
	if len(a.signals) == 0 {
		return "No signals"
	}

	var parts []string
	for _, s := range a.signals {
		part := fmt.Sprintf("%s=%.2f", s.Source, s.Score)
		if s.Label != "" {
			part += fmt.Sprintf("(%s)", s.Label)
		}
		if s.IsHighConfidence() {
			part += "[HC]"
		} else if s.IsLowConfidence() {
			part += "[LC]"
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, ", ")
}

// abs returns absolute value
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
