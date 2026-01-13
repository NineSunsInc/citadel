package ml

// local_embedder.go - Local embedding model using Hugot/ONNX
//
// This provides local embedding generation without requiring Ollama.
// Uses sentence-transformers/all-MiniLM-L6-v2 (~80MB) for efficient embeddings.
//
// Architecture:
// - Uses ONNX Runtime via Hugot for fast inference
// - Produces 384-dimensional embeddings
// - Compatible with chromem-go vector database
// - Auto-downloads model on first use if enabled

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/knights-analytics/hugot"
	"github.com/knights-analytics/hugot/options"
	"github.com/knights-analytics/hugot/pipelines"
)

// Embedding model constants
const (
	// EmbeddingModelMiniLM is a small, fast embedding model (80MB, 384 dimensions)
	EmbeddingModelMiniLM = "sentence-transformers/all-MiniLM-L6-v2"

	// EmbeddingModelBGE is a higher quality embedding model (130MB, 384 dimensions)
	EmbeddingModelBGE = "BAAI/bge-small-en-v1.5"

	// DefaultEmbeddingModelPath is the default location for the embedding model
	DefaultEmbeddingModelPath = "./models/all-MiniLM-L6-v2"

	// EmbeddingDimension is the output dimension for MiniLM-L6-v2
	EmbeddingDimension = 384
)

// LocalEmbedder provides local embedding generation using ONNX models.
type LocalEmbedder struct {
	session  *hugot.Session
	pipeline *pipelines.FeatureExtractionPipeline
	mu       sync.RWMutex
	ready    bool
	config   LocalEmbedderConfig
}

// LocalEmbedderConfig configures the local embedder.
// (Named differently from EmbedderConfig in openrouter_embedder.go to avoid collision)
type LocalEmbedderConfig struct {
	ModelPath       string
	ModelName       string
	OnnxLibraryPath string
	BatchSize       int
	Timeout         time.Duration
}

// DefaultLocalEmbedderConfig returns a default configuration using MiniLM.
func DefaultLocalEmbedderConfig() LocalEmbedderConfig {
	return LocalEmbedderConfig{
		ModelPath:       DefaultEmbeddingModelPath,
		ModelName:       EmbeddingModelMiniLM,
		OnnxLibraryPath: getDefaultOnnxPath(),
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// NewLocalEmbedder creates a new local embedder.
// Returns nil and logs a warning if initialization fails (graceful degradation).
func NewLocalEmbedder(cfg LocalEmbedderConfig) (*LocalEmbedder, error) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 32
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	embedder := &LocalEmbedder{
		config: cfg,
		ready:  false,
	}

	if err := embedder.initialize(); err != nil {
		return nil, fmt.Errorf("local embedder initialization failed: %w", err)
	}

	return embedder, nil
}

// NewAutoDetectedLocalEmbedder creates an embedder using auto-detected models.
// Returns nil if no embedding models are available.
func NewAutoDetectedLocalEmbedder() *LocalEmbedder {
	cfg := AutoDetectLocalEmbedderConfig()
	if cfg == nil {
		return nil
	}

	embedder, err := NewLocalEmbedder(*cfg)
	if err != nil {
		log.Printf("Local embedder initialization failed (graceful degradation): %v", err)
		return nil
	}
	return embedder
}

// AutoDetectLocalEmbedderConfig searches for available embedding models.
func AutoDetectLocalEmbedderConfig() *LocalEmbedderConfig {
	// Check environment variable first
	if envPath := os.Getenv("CITADEL_EMBEDDING_MODEL_PATH"); envPath != "" {
		if _, err := os.Stat(filepath.Join(envPath, "model.onnx")); err == nil {
			log.Printf("Using embedding model from CITADEL_EMBEDDING_MODEL_PATH: %s", envPath)
			return &LocalEmbedderConfig{
				ModelPath:       envPath,
				OnnxLibraryPath: getDefaultOnnxPath(),
				BatchSize:       32,
				Timeout:         30 * time.Second,
			}
		}
	}

	// Search common paths
	searchPaths := []struct {
		path  string
		model string
	}{
		{DefaultEmbeddingModelPath, EmbeddingModelMiniLM},
		{"./models/bge-small-en", EmbeddingModelBGE},
	}

	for _, sp := range searchPaths {
		modelOnnx := filepath.Join(sp.path, "model.onnx")
		if _, err := os.Stat(modelOnnx); err == nil {
			log.Printf("Auto-detected embedding model: %s", sp.model)
			return &LocalEmbedderConfig{
				ModelPath:       sp.path,
				ModelName:       sp.model,
				OnnxLibraryPath: getDefaultOnnxPath(),
				BatchSize:       32,
				Timeout:         30 * time.Second,
			}
		}
	}

	// Try auto-download if enabled
	autoDownload := os.Getenv("CITADEL_AUTO_DOWNLOAD_MODEL")
	if autoDownload == "true" || autoDownload == "1" {
		log.Printf("No embedding model found. Auto-downloading %s (~80MB)...", EmbeddingModelMiniLM)
		if err := EnsureEmbeddingModelDownloaded(DefaultEmbeddingModelPath); err != nil {
			log.Printf("Embedding model auto-download failed: %v", err)
			return nil
		}
		return &LocalEmbedderConfig{
			ModelPath:       DefaultEmbeddingModelPath,
			ModelName:       EmbeddingModelMiniLM,
			OnnxLibraryPath: getDefaultOnnxPath(),
			BatchSize:       32,
			Timeout:         30 * time.Second,
		}
	}

	log.Printf("No embedding model found. Set CITADEL_AUTO_DOWNLOAD_MODEL=true to auto-download.")
	return nil
}

// EnsureEmbeddingModelDownloaded downloads the embedding model if not present.
func EnsureEmbeddingModelDownloaded(modelPath string) error {
	if modelPath == "" {
		modelPath = DefaultEmbeddingModelPath
	}

	// Check if already exists
	if _, err := os.Stat(filepath.Join(modelPath, "model.onnx")); err == nil {
		return nil
	}

	downloadMutex.Lock()
	defer downloadMutex.Unlock()

	// Double-check after lock
	if _, err := os.Stat(filepath.Join(modelPath, "model.onnx")); err == nil {
		return nil
	}

	log.Printf("Downloading embedding model %s (~80MB)...", EmbeddingModelMiniLM)

	// Create directory
	if err := os.MkdirAll(modelPath, 0755); err != nil {
		return fmt.Errorf("failed to create model directory: %w", err)
	}

	// Download files from HuggingFace
	baseURL := fmt.Sprintf("%s/%s/resolve/main", HuggingFaceBaseURL, EmbeddingModelMiniLM)
	files := []struct {
		name     string
		required bool
		size     string
	}{
		{"model.onnx", true, "80MB"},
		{"tokenizer.json", true, "700KB"},
		{"config.json", true, "1KB"},
		{"tokenizer_config.json", true, "1KB"},
		{"special_tokens_map.json", true, "1KB"},
	}

	for _, file := range files {
		fileURL := fmt.Sprintf("%s/%s", baseURL, file.name)
		destFile := filepath.Join(modelPath, file.name)

		if _, err := os.Stat(destFile); err == nil {
			log.Printf("  ✓ %s (already exists)", file.name)
			continue
		}

		log.Printf("  ↓ Downloading %s (%s)...", file.name, file.size)
		if err := downloadFile(fileURL, destFile); err != nil {
			if file.required {
				return fmt.Errorf("failed to download %s: %w", file.name, err)
			}
			log.Printf("  ⚠ Optional file %s not available", file.name)
		} else {
			log.Printf("  ✓ %s downloaded", file.name)
		}
	}

	log.Printf("Embedding model downloaded to %s", modelPath)
	return nil
}

// initialize sets up the ONNX session and pipeline.
func (e *LocalEmbedder) initialize() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create session
	session, err := e.createSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	e.session = session

	// Resolve model path
	modelPath := e.config.ModelPath
	if modelPath == "" {
		return fmt.Errorf("no model path specified")
	}

	if _, err := os.Stat(modelPath); err != nil {
		return fmt.Errorf("model path does not exist: %s", modelPath)
	}

	// Create feature extraction pipeline
	config := hugot.FeatureExtractionConfig{
		ModelPath: modelPath,
		Name:      "embedding-generator",
	}

	pipeline, err := hugot.NewPipeline(session, config)
	if err != nil {
		_ = e.session.Destroy() // Cleanup on error; error ignored as we're already returning an error
		return fmt.Errorf("failed to create embedding pipeline: %w", err)
	}

	e.pipeline = pipeline
	e.ready = true
	log.Printf("Local embedder initialized (model: %s)", modelPath)

	return nil
}

// createSession creates the Hugot session.
func (e *LocalEmbedder) createSession() (*hugot.Session, error) {
	// Try ONNX Runtime backend first (fastest) - same approach as hugot_detector.go
	if e.config.OnnxLibraryPath != "" {
		opts := []options.WithOption{
			options.WithOnnxLibraryPath(e.config.OnnxLibraryPath),
		}

		session, err := hugot.NewORTSession(opts...)
		if err == nil {
			log.Printf("Local embedder using ONNX Runtime backend")
			return session, nil
		}
		log.Printf("ONNX Runtime unavailable for embeddings, falling back to Go backend: %v", err)
	}

	// Fall back to pure Go backend (slower but no dependencies)
	session, err := hugot.NewGoSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create Go session: %w", err)
	}
	log.Printf("Local embedder using pure Go backend (slower, consider installing ONNX Runtime)")
	return session, nil
}

// IsReady returns true if the embedder is ready for use.
func (e *LocalEmbedder) IsReady() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ready
}

// Dimension returns the embedding dimension (384 for MiniLM-L6-v2).
func (e *LocalEmbedder) Dimension() int {
	return EmbeddingDimension // 384
}

// Embed generates an embedding for a single text (implements EmbeddingProvider).
func (e *LocalEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	embeddings, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}
	return embeddings[0], nil
}

// EmbedBatch generates embeddings for multiple texts (implements EmbeddingProvider).
func (e *LocalEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.ready || e.pipeline == nil {
		return nil, fmt.Errorf("local embedder not ready")
	}

	if len(texts) == 0 {
		return [][]float32{}, nil
	}

	// Run feature extraction
	result, err := e.pipeline.RunPipeline(texts)
	if err != nil {
		return nil, fmt.Errorf("embedding generation failed: %w", err)
	}

	// Convert to [][]float32
	embeddings := make([][]float32, len(texts))
	for i := range texts {
		if i < len(result.Embeddings) {
			embeddings[i] = result.Embeddings[i]
		}
	}

	return embeddings, nil
}

// EmbedSingle is an alias for Embed (for backward compatibility).
func (e *LocalEmbedder) EmbedSingle(ctx context.Context, text string) ([]float32, error) {
	return e.Embed(ctx, text)
}

// Close releases resources.
func (e *LocalEmbedder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ready = false
	if e.session != nil {
		return e.session.Destroy()
	}
	return nil
}

// EmbeddingFunc returns a function compatible with chromem-go's embedding interface.
func (e *LocalEmbedder) EmbeddingFunc() func(ctx context.Context, text string) ([]float32, error) {
	return func(ctx context.Context, text string) ([]float32, error) {
		return e.EmbedSingle(ctx, text)
	}
}
