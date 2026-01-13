package config

import (
	"os"
	"testing"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg == nil {
		t.Fatal("NewDefaultConfig returned nil")
	}

	// Verify some defaults
	if cfg.BlockThreshold <= 0 || cfg.BlockThreshold > 1 {
		t.Errorf("BlockThreshold should be between 0 and 1, got %f", cfg.BlockThreshold)
	}

	if cfg.WarnThreshold <= 0 || cfg.WarnThreshold > 1 {
		t.Errorf("WarnThreshold should be between 0 and 1, got %f", cfg.WarnThreshold)
	}
}

func TestGetSessionSecret_FromEnv(t *testing.T) {
	// Set a known secret
	testSecret := "test-session-secret-12345"
	_ = os.Setenv("CITADEL_SESSION_SECRET", testSecret)
	defer func() { _ = os.Unsetenv("CITADEL_SESSION_SECRET") }()

	secret := getSessionSecret()
	if secret != testSecret {
		t.Errorf("Expected secret from env %q, got %q", testSecret, secret)
	}
}

func TestGetSessionSecret_GeneratesRandom(t *testing.T) {
	// Clear the env var
	_ = os.Unsetenv("CITADEL_SESSION_SECRET")

	secret1 := getSessionSecret()
	if secret1 == "" {
		t.Error("Generated secret should not be empty")
	}

	// Length should be 64 hex chars (32 bytes)
	if len(secret1) != 64 {
		t.Errorf("Expected 64 hex chars, got %d", len(secret1))
	}

	// Each call without env should generate a new secret
	// (in practice, this tests the random generation works)
	secret2 := getSessionSecret()
	if secret1 == secret2 {
		t.Log("Note: Two random secrets matched (very unlikely but possible)")
	}
}

func TestNewLocalConfig(t *testing.T) {
	cfg := NewLocalConfig()
	if cfg == nil {
		t.Fatal("NewLocalConfig returned nil")
	}

	if cfg.LLMProvider != ProviderOllama {
		t.Errorf("Expected Ollama provider, got %s", cfg.LLMProvider)
	}

	if cfg.LLMBaseURL != "http://localhost:11434/v1" {
		t.Errorf("Expected local Ollama URL, got %s", cfg.LLMBaseURL)
	}
}

func TestNewHighSecurityConfig(t *testing.T) {
	cfg := NewHighSecurityConfig()
	if cfg == nil {
		t.Fatal("NewHighSecurityConfig returned nil")
	}

	// High security should have stricter thresholds (lower block threshold = more blocking)
	defaultCfg := NewDefaultConfig()
	if cfg.BlockThreshold >= defaultCfg.BlockThreshold {
		t.Errorf("Expected lower BlockThreshold for high security, got %f >= %f",
			cfg.BlockThreshold, defaultCfg.BlockThreshold)
	}
}

func TestClampInt(t *testing.T) {
	tests := []struct {
		val, min, max, expected int
	}{
		{5, 0, 10, 5},   // Within range
		{-1, 0, 10, 0},  // Below min
		{15, 0, 10, 10}, // Above max
		{0, 0, 10, 0},   // At min
		{10, 0, 10, 10}, // At max
	}

	for _, tt := range tests {
		result := clampInt(tt.val, tt.min, tt.max)
		if result != tt.expected {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d",
				tt.val, tt.min, tt.max, result, tt.expected)
		}
	}
}

func TestGetEnvInt(t *testing.T) {
	// Test with existing env var
	_ = os.Setenv("TEST_INT_VAR", "42")
	defer func() { _ = os.Unsetenv("TEST_INT_VAR") }()

	result := GetEnvInt("TEST_INT_VAR", 10)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}

	// Test with non-existent var (should return default)
	result = GetEnvInt("NON_EXISTENT_VAR_XYZ", 100)
	if result != 100 {
		t.Errorf("Expected default 100, got %d", result)
	}

	// Test with invalid int
	_ = os.Setenv("INVALID_INT_VAR", "not-a-number")
	defer func() { _ = os.Unsetenv("INVALID_INT_VAR") }()

	result = GetEnvInt("INVALID_INT_VAR", 50)
	if result != 50 {
		t.Errorf("Expected default 50 for invalid int, got %d", result)
	}
}

func TestProviderConstants(t *testing.T) {
	providers := []LLMProvider{
		ProviderNone,
		ProviderOllama,
		ProviderOpenRouter,
		ProviderGroq,
		ProviderOpenAI,
		ProviderAnthropic,
		ProviderAzure,
		ProviderCustom,
	}

	for _, p := range providers {
		if p == "" {
			t.Error("Provider constant should not be empty")
		}
	}
}
