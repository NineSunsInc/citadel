package ml

// ============================================================================
// MULTI-TURN DETECTOR FACTORY
// ============================================================================
// Factory registration pattern for multi-turn detection.
// Pro registers its implementation at init time.
// OSS falls back to the basic MultiTurnDetector (pattern + optional semantic).
//
// Follows the same pattern as intent_types.go / intent_client.go.

// multiTurnDetectorFactory is set by Pro via init() registration.
var multiTurnDetectorFactory func(
	semantic *SemanticDetector,
	safeguardClient *SafeguardClient,
	intentClient IntentClassifier,
	intentTypeClassifier *IntentTypeClassifier,
) MultiTurnAnalyzer

// RegisterMultiTurnDetectorFactory registers the Pro MultiTurnAnalyzer factory.
// Called by Pro build at init time.
func RegisterMultiTurnDetectorFactory(factory func(*SemanticDetector, *SafeguardClient, IntentClassifier, *IntentTypeClassifier) MultiTurnAnalyzer) {
	multiTurnDetectorFactory = factory
}

// NewMultiTurnAnalyzer creates a multi-turn analyzer.
// Returns Pro implementation if registered, OSS MultiTurnDetector (pattern-only) otherwise.
func NewMultiTurnAnalyzer(
	semantic *SemanticDetector,
	safeguardClient *SafeguardClient,
	intentClient IntentClassifier,
	intentTypeClassifier *IntentTypeClassifier,
) MultiTurnAnalyzer {
	if multiTurnDetectorFactory != nil {
		return multiTurnDetectorFactory(semantic, safeguardClient, intentClient, intentTypeClassifier)
	}
	// OSS default: existing MultiTurnDetector with optional semantic
	opts := []MTDetectorOption{}
	if semantic != nil {
		opts = append(opts, WithMTSemanticDetector(semantic))
	}
	return NewMultiTurnDetector(opts...)
}
