package ml

import "context"

// ============================================================================
// OSS STUB: Threat Intelligence Service
// ============================================================================
// TIS integration is a Pro feature.
// This stub provides type definitions so OSS code compiles.
// All methods return safe defaults (no threats detected).

// TISClient provides threat matching (OSS stub - no-op)
type TISClient struct{}

// TISMatchRequest is the request body for /match endpoint (OSS stub)
type TISMatchRequest struct {
	Text            string  `json:"text"`
	Threshold       float64 `json:"threshold,omitempty"`
	IncludePatterns bool    `json:"include_patterns,omitempty"`
}

// TISMatchResponse is the response from TIS (OSS stub)
type TISMatchResponse struct {
	IsThreat  bool     `json:"is_threat"`
	Score     float64  `json:"score"`
	Patterns  []string `json:"patterns"`
	Category  string   `json:"category,omitempty"`
	LatencyMs float64  `json:"latency_ms"`
}

// GetTISClient returns a stub TIS client (always disabled in OSS)
func GetTISClient() *TISClient {
	return &TISClient{}
}

// IsEnabled returns false (TIS disabled in OSS)
func (c *TISClient) IsEnabled() bool { return false }

// SetEnabled is a no-op in OSS
func (c *TISClient) SetEnabled(enabled bool) {}

// Match returns nil (TIS disabled in OSS)
func (c *TISClient) Match(ctx context.Context, text string) (*TISMatchResponse, error) {
	return nil, nil
}

// MatchWithFallback returns safe defaults (TIS disabled in OSS)
func (c *TISClient) MatchWithFallback(ctx context.Context, text string) (isThreat bool, score float64, patterns []string) {
	return false, 0.0, nil
}

// Health returns false (TIS disabled in OSS)
func (c *TISClient) Health(ctx context.Context) bool { return false }
