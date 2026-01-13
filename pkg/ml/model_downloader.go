package ml

// model_downloader.go - Auto-download BERT models for OSS distribution
//
// This allows the OSS binary to automatically download the tihilya ModernBERT
// model on first use, eliminating the need for users to run setup scripts.
//
// Only downloads the minimal files needed for ONNX inference (~605MB):
// - model.onnx (599MB) - The ONNX model
// - tokenizer.json (3.5MB) - Tokenizer vocabulary
// - config.json (1.4KB) - Model configuration
// - tokenizer_config.json (20KB) - Tokenizer configuration
// - special_tokens_map.json (694B) - Special tokens

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// DefaultModelPath is the default location for downloaded models
const DefaultModelPath = "./models/modernbert-base"

// DefaultModelRepo is the HuggingFace repository for the default model
const DefaultModelRepo = "tihilya/modernbert-base-prompt-injection-detection"

// HuggingFaceBaseURL is the base URL for HuggingFace model downloads
const HuggingFaceBaseURL = "https://huggingface.co"

// modelFiles lists the minimal files needed for ONNX inference
var modelFiles = []struct {
	Name     string
	Required bool
	Size     string // Human-readable size for progress
}{
	{"model.onnx", true, "599MB"},
	{"tokenizer.json", true, "3.5MB"},
	{"config.json", true, "1.4KB"},
	{"tokenizer_config.json", true, "20KB"},
	{"special_tokens_map.json", true, "694B"},
}

// downloadMutex prevents concurrent downloads of the same model
var downloadMutex sync.Mutex

// EnsureModelDownloaded checks if the model exists and downloads it if not.
// This is the main entry point for auto-download functionality.
func EnsureModelDownloaded(modelPath string) error {
	if modelPath == "" {
		modelPath = DefaultModelPath
	}

	// Check if model already exists
	if ModelExists(modelPath) {
		return nil
	}

	// Prevent concurrent downloads
	downloadMutex.Lock()
	defer downloadMutex.Unlock()

	// Double-check after acquiring lock
	if ModelExists(modelPath) {
		return nil
	}

	log.Printf("Model not found at %s. Downloading tihilya ModernBERT model...", modelPath)
	log.Printf("This is a one-time download (~605MB). The model is Apache 2.0 licensed.")

	return DownloadModel(DefaultModelRepo, modelPath)
}

// ModelExists checks if a valid ONNX model exists at the given path.
func ModelExists(modelPath string) bool {
	onnxPath := filepath.Join(modelPath, "model.onnx")
	tokenizerPath := filepath.Join(modelPath, "tokenizer.json")

	// Both model.onnx and tokenizer.json must exist
	if _, err := os.Stat(onnxPath); err != nil {
		return false
	}
	if _, err := os.Stat(tokenizerPath); err != nil {
		return false
	}
	return true
}

// DownloadModel downloads a model from HuggingFace to the specified path.
func DownloadModel(repoID, destPath string) error {
	// Create destination directory
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create model directory: %w", err)
	}

	baseURL := fmt.Sprintf("%s/%s/resolve/main", HuggingFaceBaseURL, repoID)

	for _, file := range modelFiles {
		fileURL := fmt.Sprintf("%s/%s", baseURL, file.Name)
		destFile := filepath.Join(destPath, file.Name)

		// Skip if file already exists
		if _, err := os.Stat(destFile); err == nil {
			log.Printf("  ✓ %s (already exists)", file.Name)
			continue
		}

		log.Printf("  ↓ Downloading %s (%s)...", file.Name, file.Size)
		if err := downloadFile(fileURL, destFile); err != nil {
			if file.Required {
				return fmt.Errorf("failed to download %s: %w", file.Name, err)
			}
			log.Printf("  ⚠ Optional file %s not available: %v", file.Name, err)
		} else {
			log.Printf("  ✓ %s downloaded", file.Name)
		}
	}

	log.Printf("Model downloaded successfully to %s", destPath)
	return nil
}

// downloadFile downloads a file from URL to destPath with progress indication.
func downloadFile(url, destPath string) error {
	// Create temporary file for atomic download
	tmpPath := destPath + ".tmp"
	defer func() { _ = os.Remove(tmpPath) }() // Clean up on failure

	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = out.Close() }()

	// Make HTTP request
	resp, err := http.Get(url) //nolint:gosec // URL is controlled
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Copy with progress (for large files)
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Close before rename (required on Windows)
	_ = out.Close()

	// Atomic rename
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("failed to finalize download: %w", err)
	}

	return nil
}

// GetModelSize returns the total size of model files in human-readable format.
func GetModelSize(modelPath string) string {
	var totalBytes int64
	_ = filepath.Walk(modelPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalBytes += info.Size()
		}
		return nil
	})

	if totalBytes < 1024 {
		return fmt.Sprintf("%d B", totalBytes)
	} else if totalBytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(totalBytes)/1024)
	} else if totalBytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(totalBytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(totalBytes)/(1024*1024*1024))
}
