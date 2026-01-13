package ml

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewOllamaEmbeddingFunc_Success(t *testing.T) {
	// Create a mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			t.Errorf("Expected path /api/embeddings, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Return mock embedding
		response := struct {
			Embedding []float32 `json:"embedding"`
		}{
			Embedding: []float32{0.1, 0.2, 0.3, 0.4, 0.5},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	embeddingFunc := newOllamaEmbeddingFunc("test-model", server.URL)
	ctx := context.Background()

	embedding, err := embeddingFunc(ctx, "test text")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(embedding) != 5 {
		t.Errorf("Expected 5 dimensions, got %d", len(embedding))
	}
}

func TestNewOllamaEmbeddingFunc_HTTPError(t *testing.T) {
	// Create a mock server that returns HTTP error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	embeddingFunc := newOllamaEmbeddingFunc("test-model", server.URL)
	ctx := context.Background()

	_, err := embeddingFunc(ctx, "test text")
	if err == nil {
		t.Fatal("Expected error for HTTP 500")
	}

	// Error should contain status code and body
	errStr := err.Error()
	if !contains(errStr, "500") {
		t.Errorf("Error should contain status code 500: %s", errStr)
	}
	if !contains(errStr, "Internal server error") {
		t.Errorf("Error should contain response body: %s", errStr)
	}
}

func TestNewOllamaEmbeddingFunc_RateLimited(t *testing.T) {
	// Create a mock server that returns 429
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("Rate limit exceeded"))
	}))
	defer server.Close()

	embeddingFunc := newOllamaEmbeddingFunc("test-model", server.URL)
	ctx := context.Background()

	_, err := embeddingFunc(ctx, "test text")
	if err == nil {
		t.Fatal("Expected error for HTTP 429")
	}

	if !contains(err.Error(), "429") {
		t.Errorf("Error should contain status code 429: %s", err.Error())
	}
}

func TestNewOllamaEmbeddingFunc_InvalidJSON(t *testing.T) {
	// Create a mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	embeddingFunc := newOllamaEmbeddingFunc("test-model", server.URL)
	ctx := context.Background()

	_, err := embeddingFunc(ctx, "test text")
	if err == nil {
		t.Fatal("Expected error for invalid JSON response")
	}

	if !contains(err.Error(), "decode") {
		t.Errorf("Error should mention decode failure: %s", err.Error())
	}
}

func TestNewOllamaEmbeddingFunc_ConnectionError(t *testing.T) {
	// Use an invalid URL to simulate connection error
	embeddingFunc := newOllamaEmbeddingFunc("test-model", "http://localhost:99999")
	ctx := context.Background()

	_, err := embeddingFunc(ctx, "test text")
	if err == nil {
		t.Fatal("Expected error for connection failure")
	}

	if !contains(err.Error(), "request failed") {
		t.Errorf("Error should mention request failure: %s", err.Error())
	}
}

func TestSemanticDetector_NotReady(t *testing.T) {
	// Create a mock server that works for collection creation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			Embedding []float32 `json:"embedding"`
		}{
			Embedding: make([]float32, 384), // Standard embedding size
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	sd, err := NewSemanticDetector(server.URL)
	if err != nil {
		t.Fatalf("Failed to create SemanticDetector: %v", err)
	}

	// Without loading patterns, detector should not be ready
	if sd.IsReady() {
		t.Error("Detector should not be ready before LoadPatterns")
	}

	// Detect should fail
	ctx := context.Background()
	_, err = sd.Detect(ctx, "test input")
	if err == nil {
		t.Error("Expected error when detector is not ready")
	}
}

func TestSemanticDetector_SetThreshold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			Embedding []float32 `json:"embedding"`
		}{
			Embedding: make([]float32, 384),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	sd, err := NewSemanticDetector(server.URL)
	if err != nil {
		t.Fatalf("Failed to create SemanticDetector: %v", err)
	}

	// Default threshold
	if sd.threshold != 0.65 {
		t.Errorf("Expected default threshold 0.65, got %f", sd.threshold)
	}

	// Set new threshold
	sd.SetThreshold(0.8)
	if sd.threshold != 0.8 {
		t.Errorf("Expected threshold 0.8, got %f", sd.threshold)
	}
}

func TestGetCategories(t *testing.T) {
	categories := GetCategories()
	if len(categories) == 0 {
		t.Error("Expected non-empty categories list")
	}

	// Should contain common categories
	expected := []string{"instruction_override", "roleplay", "data_exfil", "benign"}
	for _, exp := range expected {
		found := false
		for _, cat := range categories {
			if cat == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected category %s not found", exp)
		}
	}
}

func TestGetSupportedLanguages(t *testing.T) {
	languages := GetSupportedLanguages()
	if len(languages) == 0 {
		t.Error("Expected non-empty languages list")
	}

	// Should contain common languages
	expected := []string{"en", "es", "fr", "de", "zh", "ja"}
	for _, exp := range expected {
		found := false
		for _, lang := range languages {
			if lang == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected language %s not found", exp)
		}
	}
}

func TestPatternCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			Embedding []float32 `json:"embedding"`
		}{
			Embedding: make([]float32, 384),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	sd, err := NewSemanticDetector(server.URL)
	if err != nil {
		t.Fatalf("Failed to create SemanticDetector: %v", err)
	}

	count := sd.PatternCount()
	if count == 0 {
		t.Error("Expected non-zero pattern count")
	}
	t.Logf("Pattern count: %d", count)
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
