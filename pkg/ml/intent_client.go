// intent_stub.go - OSS stub for intent classification
//
// This file provides stub implementations for OSS builds.
// The full transformer-based intent classifier requires the Python vision service (Pro feature).
// For production ML classification in OSS, use the Hugot detector (ONNX) or LLM classifier.
//
// NOTE: This file coexists with intent_client.go in the monorepo.
// During OSS extraction, intent_client.go is excluded and this stub provides the types.


package ml

import (
	"context"
	"fmt"
)

// IntentResult represents the response from the intent classifier
type IntentResult struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Model      string  `json:"model"`
	LatencyMs  float64 `json:"latency_ms"`

	AnalyzedText     string   `json:"analyzed_text,omitempty"`
	WasDeobfuscated  bool     `json:"was_deobfuscated,omitempty"`
	ObfuscationTypes []string `json:"obfuscation_types,omitempty"`
}

// IntentClient stub for OSS builds
type IntentClient struct {
	enabled bool
}

// NewIntentClient creates a disabled intent client
func NewIntentClient() *IntentClient {
	return &IntentClient{enabled: false}
}

// IsAvailable always returns false for OSS stub
func (c *IntentClient) IsAvailable() bool {
	return false
}

// ClassifyIntent returns an error for OSS stub
func (c *IntentClient) ClassifyIntent(ctx context.Context, text string) (*IntentResult, error) {
	return nil, fmt.Errorf("intent classifier not available (OSS build)")
}

// ClassifyIntentWithContext returns an error for OSS stub
func (c *IntentClient) ClassifyIntentWithContext(ctx context.Context, text string, deobResult *DeobfuscationResult) (*IntentResult, error) {
	return nil, fmt.Errorf("intent classifier not available (OSS build)")
}
