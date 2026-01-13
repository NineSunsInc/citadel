package ml

import (
	"context"
	"math"
	"time"
)

// ============================================================================
// OSS STUB: Multi-Turn Detection
// ============================================================================
// Multi-turn semantic trajectory analysis is a Pro feature.
// This stub provides type definitions so OSS code compiles.
// All detection methods return safe defaults (no threats detected).

// TurnData represents a single turn in a conversation (OSS stub)
type TurnData struct {
	Content   string
	Role      string
	Timestamp time.Time
}

// PatternRisk represents a detected attack pattern risk (OSS stub)
type PatternRisk struct {
	PatternName      string
	Confidence       float64
	Description      string
	DetectedPhase    string
	PhaseConfidence  float64
	IsPartialPattern bool
}

// StoredPatternSignal stores pattern detection signals (OSS stub)
type StoredPatternSignal struct {
	PatternName string
	Phase       string
	Confidence  float64
	TurnNumber  int
	DetectedAt  time.Time
}

// CrossWindowContext holds prior pattern signals (OSS stub)
type CrossWindowContext struct {
	PriorSignals map[string]*StoredPatternSignal
}

// MultiTurnPatternDetector provides pattern detection (OSS stub - no-op)
type MultiTurnPatternDetector struct{}

// NewMultiTurnPatternDetector creates a stub pattern detector
func NewMultiTurnPatternDetector() *MultiTurnPatternDetector {
	return &MultiTurnPatternDetector{}
}

// DetectAllPatterns returns empty results (OSS stub)
func (d *MultiTurnPatternDetector) DetectAllPatterns(turnHistory []TurnData) []PatternRisk {
	return nil
}

// SemanticMultiTurnDetector provides semantic trajectory analysis (OSS stub - no-op)
type SemanticMultiTurnDetector struct{}

// NewSemanticMultiTurnDetector creates a stub semantic detector
func NewSemanticMultiTurnDetector(semantic *SemanticDetector) *SemanticMultiTurnDetector {
	return &SemanticMultiTurnDetector{}
}

// UnifiedMultiTurnDetector unifies pattern + semantic detection (OSS stub - no-op)
type UnifiedMultiTurnDetector struct{}

// NewUnifiedMultiTurnDetector creates a stub unified detector
// Signature matches the actual Pro version: positional args for pattern, semantic, intent, safeguard, session, cost, config
func NewUnifiedMultiTurnDetector(
	patternDetector *MultiTurnPatternDetector,
	semanticDetector *SemanticMultiTurnDetector,
	intentClient *IntentClient,
	safeguardClient *SafeguardClient,
	sessionStore interface{}, // Session store (nil = in-memory)
	costConfig interface{},   // Cost config (nil = default)
	detectorConfig interface{}, // Detector config (nil = default)
) *UnifiedMultiTurnDetector {
	return &UnifiedMultiTurnDetector{}
}

// UnifiedMultiTurnRequest is the request for multi-turn analysis (OSS stub)
type UnifiedMultiTurnRequest struct {
	SessionID     string
	OrgID         string
	Content       string
	ProfileName   string
	ForceModel    string
	SkipSemantics bool
	SkipLLMJudge  bool
}

// DetectionLayerResults contains detection results (OSS stub)
type DetectionLayerResults struct {
	PatternMatches     []PatternRisk
	SemanticPhase      string
	SemanticConfidence float64
	TrajectoryDrift    float64
	DriftAccelerating  bool
	AggregateScore     float64
	FinalScore         float64 // Combined final score
}

// UnifiedMultiTurnResponse is the response from multi-turn analysis (OSS stub)
type UnifiedMultiTurnResponse struct {
	Verdict      string
	Confidence   float64
	ShouldBlock  bool
	TurnNumber   int
	SessionTurns int
	Detection    DetectionLayerResults
	AuditID      string
}

// Analyze performs multi-turn analysis (OSS stub - returns safe defaults)
func (d *UnifiedMultiTurnDetector) Analyze(ctx context.Context, req *UnifiedMultiTurnRequest) (*UnifiedMultiTurnResponse, error) {
	return &UnifiedMultiTurnResponse{
		Verdict:     "ALLOW",
		Confidence:  0.0,
		ShouldBlock: false,
	}, nil
}

// cosineSimilarityFloat32 calculates cosine similarity between two float32 vectors (OSS stub)
func cosineSimilarityFloat32(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
