package ml

// Action represents a detection verdict for content analysis.
type Action string

const (
	// ActionAllow indicates content is safe to process
	ActionAllow Action = "ALLOW"
	// ActionWarn indicates content is suspicious but not blocked
	ActionWarn Action = "WARN"
	// ActionBlock indicates content should be blocked
	ActionBlock Action = "BLOCK"
)

// String returns the string representation of an Action.
func (a Action) String() string {
	return string(a)
}

// BaseResult contains common fields for all detection results.
// Embed this in specialized result types for consistency.
type BaseResult struct {
	// Action is the verdict: ALLOW, WARN, or BLOCK
	Action Action `json:"action"`
	// Score is the risk score from 0.0 (safe) to 1.0 (dangerous)
	Score float64 `json:"score"`
	// Reason explains why this verdict was reached
	Reason string `json:"reason,omitempty"`
	// LatencyMs is the time taken for this detection in milliseconds
	LatencyMs float64 `json:"latency_ms"`
	// Metadata contains additional context about the detection
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ToAction converts a score to an Action based on thresholds.
// Scores >= blockThreshold return BLOCK.
// Scores >= warnThreshold return WARN.
// Lower scores return ALLOW.
func ToAction(score, warnThreshold, blockThreshold float64) Action {
	if score >= blockThreshold {
		return ActionBlock
	}
	if score >= warnThreshold {
		return ActionWarn
	}
	return ActionAllow
}

// IsBlocked returns true if the action is BLOCK.
func (b *BaseResult) IsBlocked() bool {
	return b.Action == ActionBlock
}

// IsWarning returns true if the action is WARN.
func (b *BaseResult) IsWarning() bool {
	return b.Action == ActionWarn
}

// IsAllowed returns true if the action is ALLOW.
func (b *BaseResult) IsAllowed() bool {
	return b.Action == ActionAllow
}
