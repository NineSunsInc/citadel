// Package ml provides configurable detection profiles for tunable security sensitivity.
// This allows applications to set their own risk tolerance based on use case.
package ml

import (
	"strings"
)

// DetectionProfile defines the sensitivity level for threat detection.
// Applications can choose a profile based on their use case and risk tolerance.
type DetectionProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	// Thresholds (higher = more permissive)
	PatternThreshold  float64 `json:"pattern_threshold"`  // Layer 1: Block if score >= this
	SemanticThreshold float64 `json:"semantic_threshold"` // Layer 2: Flag if similarity >= this
	BlockThreshold    float64 `json:"block_threshold"`    // Final: Block if combined >= this
	WarnThreshold     float64 `json:"warn_threshold"`     // Final: Warn if combined >= this

	// Context Modifiers
	EducationalDiscount  float64 `json:"educational_discount"`  // Reduce score for educational context
	CreativeDiscount     float64 `json:"creative_discount"`     // Reduce score for creative/fiction
	HistoricalDiscount   float64 `json:"historical_discount"`   // Reduce score for historical discussion
	ProfessionalDiscount float64 `json:"professional_discount"` // Reduce score for professional security context

	// Session Behavior
	CumulativeRiskDecay float64 `json:"cumulative_risk_decay"` // Per-turn decay rate (0-1)
	MaxCumulativeRisk   float64 `json:"max_cumulative_risk"`   // Cap on cumulative session risk
	AllowRecoveryTurns  int     `json:"allow_recovery_turns"`  // Benign turns before risk decays

	// Category Settings
	EnableEncodingDetection bool `json:"enable_encoding_detection"` // Detect base64/hex attacks
	EnableMultilingual      bool `json:"enable_multilingual"`       // Multilingual attack detection

	// What to do with ambiguous cases
	AmbiguousAction string `json:"ambiguous_action"` // "allow", "warn", "block"
}

// Pre-defined Detection Profiles

// ProfileStrict is for high-security environments (financial, healthcare, legal).
// Low tolerance for false negatives, accepts some false positives.
var ProfileStrict = &DetectionProfile{
	Name:        "strict",
	Description: "High security - financial, healthcare, legal. Minimal false negatives.",

	PatternThreshold:  0.40,
	SemanticThreshold: 0.55,
	BlockThreshold:    0.65,
	WarnThreshold:     0.45,

	EducationalDiscount:  0.05, // Minimal discount
	CreativeDiscount:     0.05,
	HistoricalDiscount:   0.05,
	ProfessionalDiscount: 0.10,

	CumulativeRiskDecay: 0.05, // Slow decay
	MaxCumulativeRisk:   150,
	AllowRecoveryTurns:  5,

	EnableEncodingDetection: true,
	EnableMultilingual:      true,
	AmbiguousAction:         "warn",
}

// ProfileBalanced is the default for most applications.
// Balances security with usability.
var ProfileBalanced = &DetectionProfile{
	Name:        "balanced",
	Description: "Default - good balance of security and usability.",

	PatternThreshold:  0.50,
	SemanticThreshold: 0.65,
	BlockThreshold:    0.75,
	WarnThreshold:     0.55,

	EducationalDiscount:  0.15,
	CreativeDiscount:     0.15,
	HistoricalDiscount:   0.15,
	ProfessionalDiscount: 0.20,

	CumulativeRiskDecay: 0.10, // Moderate decay
	MaxCumulativeRisk:   120,
	AllowRecoveryTurns:  3,

	EnableEncodingDetection: true,
	EnableMultilingual:      true,
	AmbiguousAction:         "warn",
}

// ProfilePermissive is for creative, educational, and research contexts.
// Higher tolerance for security-adjacent content, minimal false positives.
var ProfilePermissive = &DetectionProfile{
	Name:        "permissive",
	Description: "Creative/educational - research, fiction, security education. Minimal false positives.",

	PatternThreshold:  0.60,
	SemanticThreshold: 0.75,
	BlockThreshold:    0.85,
	WarnThreshold:     0.70,

	EducationalDiscount:  0.30, // Large discount
	CreativeDiscount:     0.35,
	HistoricalDiscount:   0.30,
	ProfessionalDiscount: 0.35,

	CumulativeRiskDecay: 0.20, // Fast decay
	MaxCumulativeRisk:   100,
	AllowRecoveryTurns:  2,

	EnableEncodingDetection: true,
	EnableMultilingual:      true,
	AmbiguousAction:         "allow",
}

// ProfileCodeAssistant is optimized for code/development assistants.
// Allows security code discussion while catching actual attacks.
var ProfileCodeAssistant = &DetectionProfile{
	Name:        "code_assistant",
	Description: "Development/coding - allows security code review and vulnerability discussion.",

	PatternThreshold:  0.55,
	SemanticThreshold: 0.70,
	BlockThreshold:    0.80,
	WarnThreshold:     0.60,

	EducationalDiscount:  0.20,
	CreativeDiscount:     0.10,
	HistoricalDiscount:   0.15,
	ProfessionalDiscount: 0.30, // High discount for professional security context

	CumulativeRiskDecay: 0.15,
	MaxCumulativeRisk:   110,
	AllowRecoveryTurns:  2,

	EnableEncodingDetection: true,
	EnableMultilingual:      false, // Code is usually English
	AmbiguousAction:         "allow",
}

// ProfileAISafety is for AI safety research and red-teaming.
// Allows discussion of attacks for defensive purposes.
var ProfileAISafety = &DetectionProfile{
	Name:        "ai_safety",
	Description: "AI safety research - allows attack discussion for defensive purposes.",

	PatternThreshold:  0.65,
	SemanticThreshold: 0.80,
	BlockThreshold:    0.90,
	WarnThreshold:     0.75,

	EducationalDiscount:  0.35,
	CreativeDiscount:     0.25,
	HistoricalDiscount:   0.35,
	ProfessionalDiscount: 0.40,

	CumulativeRiskDecay: 0.25,
	MaxCumulativeRisk:   80,
	AllowRecoveryTurns:  1,

	EnableEncodingDetection: true,
	EnableMultilingual:      true,
	AmbiguousAction:         "allow",
}

// GetProfile returns a profile by name.
func GetProfile(name string) *DetectionProfile {
	switch strings.ToLower(name) {
	case "strict":
		return ProfileStrict
	case "balanced", "default", "":
		return ProfileBalanced
	case "permissive", "creative", "educational":
		return ProfilePermissive
	case "code_assistant", "code", "dev":
		return ProfileCodeAssistant
	case "ai_safety", "research", "red_team":
		return ProfileAISafety
	default:
		return ProfileBalanced
	}
}

// ContextSignals represents detected context in the input.
type ContextSignals struct {
	IsEducational  bool `json:"is_educational"`
	IsCreative     bool `json:"is_creative"`
	IsHistorical   bool `json:"is_historical"`
	IsProfessional bool `json:"is_professional"`
	IsCodeReview   bool `json:"is_code_review"`

	EducationalScore  float64 `json:"educational_score"`
	CreativeScore     float64 `json:"creative_score"`
	HistoricalScore   float64 `json:"historical_score"`
	ProfessionalScore float64 `json:"professional_score"`
}

// DetectContextSignals analyzes text for positive context signals.
func DetectContextSignals(text string) *ContextSignals {
	lower := strings.ToLower(text)
	signals := &ContextSignals{}

	// Educational signals
	educationalPhrases := []string{
		"i'm studying", "for my thesis", "for my course", "i'm learning",
		"educational purposes", "for the exam", "university", "professor",
		"homework", "assignment", "research paper", "academic",
		"can you explain", "how does", "what is the concept",
	}
	for _, phrase := range educationalPhrases {
		if strings.Contains(lower, phrase) {
			signals.EducationalScore += 0.2
		}
	}
	signals.IsEducational = signals.EducationalScore >= 0.2

	// Creative/Fiction signals
	creativePhrases := []string{
		"in my novel", "in my story", "fictional", "character says",
		"creative writing", "screenplay", "dialogue for", "cyberpunk",
		"sci-fi", "fantasy world", "imagine a scenario", "role-play",
		"write a scene", "narrative", "plot",
	}
	for _, phrase := range creativePhrases {
		if strings.Contains(lower, phrase) {
			signals.CreativeScore += 0.2
		}
	}
	signals.IsCreative = signals.CreativeScore >= 0.2

	// Historical signals
	historicalPhrases := []string{
		"in history", "historically", "back in", "in 1988", "in 19",
		"in 200", "the famous", "case study", "incident of",
		"breach of", "hack of", "attack on", "what happened",
		"morris worm", "equifax", "solarwinds", "target breach",
	}
	for _, phrase := range historicalPhrases {
		if strings.Contains(lower, phrase) {
			signals.HistoricalScore += 0.2
		}
	}
	signals.IsHistorical = signals.HistoricalScore >= 0.2

	// Professional security context
	professionalPhrases := []string{
		"penetration test", "security audit", "vulnerability assessment",
		"bug bounty", "responsible disclosure", "security researcher",
		"pentest report", "ethical hacking", "compliance", "cissp",
		"ceh", "oscp", "security certification", "as a security",
		"for the client", "authorized testing",
	}
	for _, phrase := range professionalPhrases {
		if strings.Contains(lower, phrase) {
			signals.ProfessionalScore += 0.25
		}
	}
	signals.IsProfessional = signals.ProfessionalScore >= 0.25

	// Code review context
	codeReviewPhrases := []string{
		"code review", "reviewing code", "this function", "this snippet",
		"security code", "input validation", "sanitize", "sql injection",
		"xss prevention", "csrf token", "auth middleware", "password hash",
	}
	for _, phrase := range codeReviewPhrases {
		if strings.Contains(lower, phrase) {
			signals.IsCodeReview = true
			break
		}
	}

	return signals
}

// ApplyContextDiscount adjusts a risk score based on context signals and profile.
func ApplyContextDiscount(score float64, signals *ContextSignals, profile *DetectionProfile) float64 {
	if profile == nil {
		profile = ProfileBalanced
	}

	discount := 0.0

	if signals.IsEducational {
		discount += profile.EducationalDiscount * signals.EducationalScore
	}
	if signals.IsCreative {
		discount += profile.CreativeDiscount * signals.CreativeScore
	}
	if signals.IsHistorical {
		discount += profile.HistoricalDiscount * signals.HistoricalScore
	}
	if signals.IsProfessional {
		discount += profile.ProfessionalDiscount * signals.ProfessionalScore
	}

	// Apply discount (cap at 50% reduction)
	if discount > 0.5 {
		discount = 0.5
	}

	return score * (1 - discount)
}

// ProfiledDecision makes a block/warn/allow decision based on profile thresholds.
func ProfiledDecision(score float64, profile *DetectionProfile) string {
	if profile == nil {
		profile = ProfileBalanced
	}

	if score >= profile.BlockThreshold {
		return "BLOCK"
	}
	if score >= profile.WarnThreshold {
		return "WARN"
	}
	return "ALLOW"
}
