package ml

// =============================================================================
// TIS UNIFIED CATEGORY NORMALIZER
// Maps attack categories between Go OSS scanner and TIS unified categories.
// Ensures consistent categorization across the entire Citadel stack.
// =============================================================================

// TISCategory represents the unified threat category across OSS and Pro
type TISCategory string

const (
	// Core injection types
	TISCategoryInstructionOverride TISCategory = "instruction_override"
	TISCategoryJailbreak           TISCategory = "jailbreak"
	TISCategoryRoleplay            TISCategory = "roleplay"

	// Data security
	TISCategoryDataExfil TISCategory = "data_exfil"
	TISCategoryDataDump  TISCategory = "data_dump"

	// Execution threats
	TISCategoryCommandInjection TISCategory = "command_injection"
	TISCategoryFileAccess       TISCategory = "file_access"

	// Context attacks
	TISCategoryContextManipulation TISCategory = "context_manipulation"
	TISCategoryTokenExhaustion     TISCategory = "token_exhaustion"
	TISCategoryGoalHijacking       TISCategory = "goal_hijacking"
	TISCategoryAutonomyAbuse       TISCategory = "autonomy_abuse"

	// Advanced attacks
	TISCategoryHallucinationInjection TISCategory = "hallucination_injection"
	TISCategoryMCPInjection           TISCategory = "mcp_injection"
	TISCategoryPaymentFraud           TISCategory = "payment_fraud"

	// Social/psychological
	TISCategoryImpersonation     TISCategory = "impersonation"
	TISCategoryPsychological     TISCategory = "psychological"
	TISCategorySocialEngineering TISCategory = "social_engineering"

	// Technical evasion
	TISCategoryObfuscation       TISCategory = "obfuscation"
	TISCategoryMultiTurn         TISCategory = "multi_turn"
	TISCategoryIndirectInjection TISCategory = "indirect_injection"

	// Catch-all
	TISCategoryUnknown TISCategory = "unknown"
)

// String returns the string representation of a TISCategory
func (c TISCategory) String() string {
	return string(c)
}

// TISCategoryDescriptions provides human-readable descriptions for UI/reports
var TISCategoryDescriptions = map[TISCategory]string{
	TISCategoryInstructionOverride:    "Core prompt injection - bypass/ignore instructions",
	TISCategoryJailbreak:              "DAN, mode switching, persona attacks",
	TISCategoryRoleplay:               "Malicious roleplay persona attacks",
	TISCategoryDataExfil:              "System prompt extraction, secrets exposure",
	TISCategoryDataDump:               "Memory/context dumping",
	TISCategoryCommandInjection:       "Shell/code execution attempts",
	TISCategoryFileAccess:             "Unauthorized file operations",
	TISCategoryContextManipulation:    "Context confusion, window manipulation",
	TISCategoryTokenExhaustion:        "DoS via token overload",
	TISCategoryGoalHijacking:          "Objective/goal manipulation",
	TISCategoryAutonomyAbuse:          "Agent loop/spawn abuse",
	TISCategoryHallucinationInjection: "False memory/information injection",
	TISCategoryMCPInjection:           "MCP tool poisoning, agent attacks",
	TISCategoryPaymentFraud:           "Crypto/payment fraud (x402)",
	TISCategoryImpersonation:          "Authority impersonation",
	TISCategoryPsychological:          "Emotional manipulation",
	TISCategorySocialEngineering:      "Manipulation, urgency, pressure tactics",
	TISCategoryObfuscation:            "Encoding, evasion techniques",
	TISCategoryMultiTurn:              "Crescendo, gradual escalation attacks",
	TISCategoryIndirectInjection:      "External content injection",
	TISCategoryUnknown:                "Unknown/unclassified threat",
}

// TISToOWASP maps TIS categories to OWASP LLM Top 10 identifiers
var TISToOWASP = map[TISCategory]string{
	TISCategoryInstructionOverride:    "LLM01",
	TISCategoryJailbreak:              "LLM01",
	TISCategoryRoleplay:               "LLM01",
	TISCategoryDataExfil:              "LLM02",
	TISCategoryDataDump:               "LLM02",
	TISCategoryCommandInjection:       "LLM03",
	TISCategoryFileAccess:             "LLM03",
	TISCategoryContextManipulation:    "LLM03",
	TISCategoryTokenExhaustion:        "LLM04",
	TISCategoryGoalHijacking:          "LLM05",
	TISCategoryAutonomyAbuse:          "LLM05",
	TISCategoryHallucinationInjection: "LLM09",
	TISCategoryMCPInjection:           "MCP-01",
	TISCategoryPaymentFraud:           "AGENT-04",
	TISCategoryImpersonation:          "LLM01",
	TISCategoryPsychological:          "LLM01",
	TISCategorySocialEngineering:      "LLM01",
	TISCategoryObfuscation:            "LLM01",
	TISCategoryMultiTurn:              "LLM01",
	TISCategoryIndirectInjection:      "LLM08",
	TISCategoryUnknown:                "",
}

// internalCategoryMapping maps Go OSS categories to TIS unified categories
var internalCategoryMapping = map[string]TISCategory{
	// From dynamic_detector.go SemanticThreatCategories
	"instruction_override":   TISCategoryInstructionOverride,
	"authority_bypass":       TISCategoryJailbreak, // Elevated permissions = jailbreak
	"information_extraction": TISCategoryDataExfil, // Prompt extraction
	"roleplay_attack":        TISCategoryRoleplay,
	"code_execution":         TISCategoryCommandInjection,

	// From patterns.go MultiTurnPatterns
	"fiction_frame":  TISCategoryMultiTurn, // Fiction framing is multi-turn setup
	"persona_hijack": TISCategoryJailbreak, // DAN, persona = jailbreak
	"eval_abuse":     TISCategoryJailbreak, // Bad Likert Judge = jailbreak variant
	"escalation":     TISCategoryMultiTurn, // Crescendo = multi-turn

	// From patterns.go PolicyInjectionPatterns
	"safety_disable":       TISCategoryJailbreak,
	"restrictions_disable": TISCategoryJailbreak,
	"filter_disable":       TISCategoryJailbreak,
	"unsafe_mode":          TISCategoryJailbreak,
	"admin_override":       TISCategoryImpersonation,
	"elevated_trust":       TISCategoryImpersonation,
	"xml_policy":           TISCategoryInstructionOverride,
	"ini_policy":           TISCategoryInstructionOverride,

	// CWE-based categories (from CVE feeds)
	"xss":                  TISCategoryCommandInjection,
	"sql_injection":        TISCategoryCommandInjection,
	"code_injection":       TISCategoryCommandInjection,
	"command_injection":    TISCategoryCommandInjection,
	"path_traversal":       TISCategoryFileAccess,
	"deserialization":      TISCategoryCommandInjection,
	"ssrf":                 TISCategoryIndirectInjection,
	"csrf":                 TISCategoryIndirectInjection,
	"auth_bypass":          TISCategoryImpersonation,
	"hardcoded_creds":      TISCategoryDataExfil,
	"info_disclosure":      TISCategoryDataExfil,
	"file_upload":          TISCategoryFileAccess,
	"memory_corruption":    TISCategoryCommandInjection,
	"buffer_overflow":      TISCategoryCommandInjection,
	"use_after_free":       TISCategoryCommandInjection,
	"privilege_escalation": TISCategoryImpersonation,

	// Generic categories
	"vulnerability": TISCategoryUnknown,
	"injection":     TISCategoryCommandInjection,
	"rce":           TISCategoryCommandInjection,
	"dos":           TISCategoryTokenExhaustion,
	"malware":       TISCategoryIndirectInjection,
	"supply_chain":  TISCategoryIndirectInjection,

	// Additional TIS category names (those not already mapped above)
	"jailbreak":               TISCategoryJailbreak,
	"roleplay":                TISCategoryRoleplay,
	"data_exfil":              TISCategoryDataExfil,
	"data_dump":               TISCategoryDataDump,
	"file_access":             TISCategoryFileAccess,
	"context_manipulation":    TISCategoryContextManipulation,
	"token_exhaustion":        TISCategoryTokenExhaustion,
	"goal_hijacking":          TISCategoryGoalHijacking,
	"autonomy_abuse":          TISCategoryAutonomyAbuse,
	"hallucination_injection": TISCategoryHallucinationInjection,
	"mcp_injection":           TISCategoryMCPInjection,
	"payment_fraud":           TISCategoryPaymentFraud,
	"impersonation":           TISCategoryImpersonation,
	"psychological":           TISCategoryPsychological,
	"social_engineering":      TISCategorySocialEngineering,
	"obfuscation":             TISCategoryObfuscation,
	"multi_turn":              TISCategoryMultiTurn,
	"indirect_injection":      TISCategoryIndirectInjection,
}

// obfuscationTypeMapping maps ObfuscationType to TISCategory
var obfuscationTypeMapping = map[ObfuscationType]TISCategory{
	ObfuscationBase64:         TISCategoryObfuscation,
	ObfuscationBase32:         TISCategoryObfuscation,
	ObfuscationHex:            TISCategoryObfuscation,
	ObfuscationROT13:          TISCategoryObfuscation,
	ObfuscationURL:            TISCategoryObfuscation,
	ObfuscationHTML:           TISCategoryObfuscation,
	ObfuscationUnicodeTags:    TISCategoryObfuscation,
	ObfuscationHomoglyphs:     TISCategoryObfuscation,
	ObfuscationReverse:        TISCategoryObfuscation,
	ObfuscationTypoglycemia:   TISCategoryObfuscation,
	ObfuscationGzip:           TISCategoryObfuscation,
	ObfuscationUnicodeEscapes: TISCategoryObfuscation,
	ObfuscationOctalEscapes:   TISCategoryObfuscation,
	ObfuscationASCIIArt:       TISCategoryObfuscation,
	ObfuscationBlockASCII:     TISCategoryObfuscation,
	ObfuscationInvisibleChars: TISCategoryObfuscation,
	ObfuscationZeroWidth:      TISCategoryObfuscation,
	ObfuscationBidiOverride:   TISCategoryObfuscation,
	ObfuscationCombiningChars: TISCategoryObfuscation,
	ObfuscationLeetspeak:      TISCategoryObfuscation,
}

// NormalizeCategory converts any category string to a unified TIS category.
// Handles Go OSS categories, CVE-based categories, and raw TIS categories.
func NormalizeCategory(category string) TISCategory {
	if category == "" {
		return TISCategoryUnknown
	}

	// Direct lookup
	if tis, ok := internalCategoryMapping[category]; ok {
		return tis
	}

	// Keyword-based fallback for unknown categories
	switch {
	case categoryContainsAny(category, "inject", "override", "ignore", "bypass"):
		return TISCategoryInstructionOverride
	case categoryContainsAny(category, "jailbreak", "dan", "unrestrict", "persona"):
		return TISCategoryJailbreak
	case categoryContainsAny(category, "exfil", "extract", "leak", "expose"):
		return TISCategoryDataExfil
	case categoryContainsAny(category, "exec", "shell", "command", "code"):
		return TISCategoryCommandInjection
	case categoryContainsAny(category, "obfusc", "encod", "evas"):
		return TISCategoryObfuscation
	case categoryContainsAny(category, "social", "manipul", "urgen", "pressure"):
		return TISCategorySocialEngineering
	case categoryContainsAny(category, "multi", "turn", "crescendo", "escal"):
		return TISCategoryMultiTurn
	case categoryContainsAny(category, "payment", "fraud", "wallet", "x402"):
		return TISCategoryPaymentFraud
	case categoryContainsAny(category, "imperson", "authority", "admin"):
		return TISCategoryImpersonation
	case categoryContainsAny(category, "file", "path", "traversal"):
		return TISCategoryFileAccess
	case categoryContainsAny(category, "mcp", "tool", "agent"):
		return TISCategoryMCPInjection
	}

	return TISCategoryUnknown
}

// NormalizeObfuscationType converts an ObfuscationType to TISCategory
func NormalizeObfuscationType(ot ObfuscationType) TISCategory {
	if tis, ok := obfuscationTypeMapping[ot]; ok {
		return tis
	}
	return TISCategoryObfuscation // Default all obfuscation to obfuscation category
}

// GetDescription returns the human-readable description for a TIS category
func (c TISCategory) GetDescription() string {
	if desc, ok := TISCategoryDescriptions[c]; ok {
		return desc
	}
	return "Unknown threat category"
}

// GetOWASP returns the OWASP LLM Top 10 mapping for a TIS category
func (c TISCategory) GetOWASP() string {
	if owasp, ok := TISToOWASP[c]; ok {
		return owasp
	}
	return ""
}

// NormalizedResult contains a result with normalized TIS category
type NormalizedResult struct {
	TISCategory            TISCategory `json:"tis_category"`
	TISCategoryDescription string      `json:"tis_category_description"`
	OWASPMapping           string      `json:"owasp_mapping"`
	OriginalCategory       string      `json:"original_category"`
}

// NormalizeResult normalizes a detection result's category to TIS unified format
func NormalizeResult(originalCategory string) NormalizedResult {
	tis := NormalizeCategory(originalCategory)
	return NormalizedResult{
		TISCategory:            tis,
		TISCategoryDescription: tis.GetDescription(),
		OWASPMapping:           tis.GetOWASP(),
		OriginalCategory:       originalCategory,
	}
}

// AllTISCategories returns all valid TIS categories
func AllTISCategories() []TISCategory {
	return []TISCategory{
		TISCategoryInstructionOverride,
		TISCategoryJailbreak,
		TISCategoryRoleplay,
		TISCategoryDataExfil,
		TISCategoryDataDump,
		TISCategoryCommandInjection,
		TISCategoryFileAccess,
		TISCategoryContextManipulation,
		TISCategoryTokenExhaustion,
		TISCategoryGoalHijacking,
		TISCategoryAutonomyAbuse,
		TISCategoryHallucinationInjection,
		TISCategoryMCPInjection,
		TISCategoryPaymentFraud,
		TISCategoryImpersonation,
		TISCategoryPsychological,
		TISCategorySocialEngineering,
		TISCategoryObfuscation,
		TISCategoryMultiTurn,
		TISCategoryIndirectInjection,
		TISCategoryUnknown,
	}
}

// categoryContainsAny checks if the category contains any of the given substrings (case-insensitive)
func categoryContainsAny(category string, substrs ...string) bool {
	lower := categoryToLower(category)
	for _, s := range substrs {
		if categoryContainsSubstr(lower, s) {
			return true
		}
	}
	return false
}

// categoryToLower converts a string to lowercase without importing strings package
func categoryToLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// categoryContainsSubstr checks if s contains substr
func categoryContainsSubstr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
