package ml

import "testing"

func TestNormalizeCategory(t *testing.T) {
	tests := []struct {
		input    string
		expected TISCategory
	}{
		// Go OSS categories
		{"instruction_override", TISCategoryInstructionOverride},
		{"authority_bypass", TISCategoryJailbreak},
		{"information_extraction", TISCategoryDataExfil},
		{"roleplay_attack", TISCategoryRoleplay},
		{"code_execution", TISCategoryCommandInjection},

		// Pattern categories
		{"fiction_frame", TISCategoryMultiTurn},
		{"persona_hijack", TISCategoryJailbreak},
		{"eval_abuse", TISCategoryJailbreak},
		{"escalation", TISCategoryMultiTurn},

		// Policy injection
		{"safety_disable", TISCategoryJailbreak},
		{"admin_override", TISCategoryImpersonation},
		{"xml_policy", TISCategoryInstructionOverride},

		// CWE-based
		{"sql_injection", TISCategoryCommandInjection},
		{"path_traversal", TISCategoryFileAccess},
		{"ssrf", TISCategoryIndirectInjection},

		// Direct TIS categories
		{"jailbreak", TISCategoryJailbreak},
		{"data_exfil", TISCategoryDataExfil},
		{"mcp_injection", TISCategoryMCPInjection},

		// Keyword fallback
		{"unknown_jailbreak_attack", TISCategoryJailbreak},
		{"some_extraction_method", TISCategoryDataExfil},
		{"obfuscation_layer", TISCategoryObfuscation},

		// Unknown
		{"completely_unknown", TISCategoryUnknown},
		{"", TISCategoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeCategory(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeCategory(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTISCategoryDescription(t *testing.T) {
	// Verify all categories have descriptions
	for _, cat := range AllTISCategories() {
		desc := cat.GetDescription()
		if desc == "" {
			t.Errorf("Category %q has no description", cat)
		}
	}
}

func TestTISToOWASPMapping(t *testing.T) {
	// Verify critical categories have OWASP mappings
	critical := []TISCategory{
		TISCategoryInstructionOverride,
		TISCategoryJailbreak,
		TISCategoryDataExfil,
		TISCategoryCommandInjection,
	}

	for _, cat := range critical {
		owasp := cat.GetOWASP()
		if owasp == "" {
			t.Errorf("Critical category %q has no OWASP mapping", cat)
		}
	}
}

func TestNormalizeResult(t *testing.T) {
	result := NormalizeResult("authority_bypass")

	if result.TISCategory != TISCategoryJailbreak {
		t.Errorf("TISCategory = %q, want %q", result.TISCategory, TISCategoryJailbreak)
	}
	if result.OriginalCategory != "authority_bypass" {
		t.Errorf("OriginalCategory = %q, want %q", result.OriginalCategory, "authority_bypass")
	}
	if result.OWASPMapping != "LLM01" {
		t.Errorf("OWASPMapping = %q, want %q", result.OWASPMapping, "LLM01")
	}
	if result.TISCategoryDescription == "" {
		t.Error("TISCategoryDescription should not be empty")
	}
}

func TestNormalizeObfuscationType(t *testing.T) {
	tests := []struct {
		input    ObfuscationType
		expected TISCategory
	}{
		{ObfuscationBase64, TISCategoryObfuscation},
		{ObfuscationHomoglyphs, TISCategoryObfuscation},
		{ObfuscationLeetspeak, TISCategoryObfuscation},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := NormalizeObfuscationType(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeObfuscationType(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
