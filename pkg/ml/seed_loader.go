// Package ml provides the seed loader for bootstrapping threat seeds from YAML.
package ml

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// SeedLoader loads threat seeds from YAML files into the vector store.
type SeedLoader struct {
	store       VectorStore
	embedder    EmbeddingProvider
	seedDir     string
	loadedFiles map[string]time.Time
	mu          sync.RWMutex
}

// NewSeedLoader creates a new seed loader.
func NewSeedLoader(store VectorStore, embedder EmbeddingProvider, seedDir string) *SeedLoader {
	return &SeedLoader{
		store:       store,
		embedder:    embedder,
		seedDir:     seedDir,
		loadedFiles: make(map[string]time.Time),
	}
}

// LoadAll loads all YAML seed files from the configured directory.
func (l *SeedLoader) LoadAll(ctx context.Context) (int, error) {
	files, err := filepath.Glob(filepath.Join(l.seedDir, "*.yaml"))
	if err != nil {
		return 0, fmt.Errorf("failed to list seed files: %w", err)
	}

	totalLoaded := 0
	for _, file := range files {
		loaded, err := l.LoadFile(ctx, file)
		if err != nil {
			// Log error but continue with other files
			fmt.Printf("[SeedLoader] Error loading %s: %v\n", file, err)
			continue
		}
		totalLoaded += loaded
	}

	return totalLoaded, nil
}

// LoadFile loads a single YAML seed file.
func (l *SeedLoader) LoadFile(ctx context.Context, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %w", err)
	}

	// Determine file type based on structure
	filename := filepath.Base(path)

	var loaded int
	var loadErr error

	switch {
	case strings.Contains(filename, "multiturn_semantic_seeds"):
		loaded, loadErr = l.loadMultiTurnSeeds(ctx, data)
	case strings.Contains(filename, "agentic_threats"):
		loaded, loadErr = l.loadAgenticThreats(ctx, data)
	case strings.Contains(filename, "injection_seed"):
		loaded, loadErr = l.loadInjectionSeeds(ctx, data)
	case strings.Contains(filename, "semantic_intents"):
		loaded, loadErr = l.loadSemanticIntents(ctx, data)
	default:
		// Try generic seed format
		loaded, loadErr = l.loadGenericSeeds(ctx, data)
	}

	if loadErr != nil {
		return 0, loadErr
	}

	// Track loaded file
	l.mu.Lock()
	l.loadedFiles[path] = time.Now()
	l.mu.Unlock()

	return loaded, nil
}

// =============================================================================
// Multi-Turn Semantic Seeds (multiturn_semantic_seeds.yaml)
// =============================================================================

type multiTurnSeedsFile struct {
	Patterns       map[string]multiTurnPattern `yaml:"patterns"`
	BenignPatterns map[string][]string         `yaml:"benign_patterns"`
}

type multiTurnPattern struct {
	Description           string                 `yaml:"description"`
	Severity              float64                `yaml:"severity"`
	Phases                map[string]phaseConfig `yaml:"phases"`
	Sequence              []string               `yaml:"sequence"`
	MinPhasesForDetection int                    `yaml:"min_phases_for_detection"`
}

type phaseConfig struct {
	Description string   `yaml:"description"`
	Threshold   float64  `yaml:"threshold"`
	Examples    []string `yaml:"examples"`
}

func (l *SeedLoader) loadMultiTurnSeeds(ctx context.Context, data []byte) (int, error) {
	var file multiTurnSeedsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("failed to parse multi-turn seeds: %w", err)
	}

	seeds := make([]*ThreatSeed, 0)

	// Convert patterns to seeds
	for patternName, pattern := range file.Patterns {
		for phaseName, phase := range pattern.Phases {
			for _, example := range phase.Examples {
				category := fmt.Sprintf("multiturn_%s", patternName)
				seed := &ThreatSeed{
					ID:       uuid.New(),
					Category: category,
					Text:     example,
					Severity: pattern.Severity * phase.Threshold,
					Phase:    phaseName,
					Language: detectLanguage(example),
					Tags:     []string{"multiturn", patternName, phaseName},
					Metadata: map[string]any{
						"pattern":     patternName,
						"phase":       phaseName,
						"threshold":   phase.Threshold,
						"description": phase.Description,
						"sequence":    pattern.Sequence,
						"min_phases":  pattern.MinPhasesForDetection,
					},
					Source: "yaml",
					Active: true,
				}
				seeds = append(seeds, seed)
			}
		}
	}

	// Add benign patterns as negative examples
	for category, examples := range file.BenignPatterns {
		for _, example := range examples {
			seed := &ThreatSeed{
				ID:       uuid.New(),
				Category: "benign_" + category,
				Text:     example,
				Severity: 0.0, // Benign = 0 severity
				Language: detectLanguage(example),
				Tags:     []string{"benign", category},
				Source:   "yaml",
				Active:   true,
			}
			seeds = append(seeds, seed)
		}
	}

	// Bulk upsert
	return l.store.BulkUpsert(ctx, seeds)
}

// =============================================================================
// Agentic Threats (agentic_threats_seed.yaml)
// =============================================================================

type agenticThreatsFile struct {
	SeedData []agenticSeed `yaml:"seed_data"`
}

type agenticSeed struct {
	Text     string  `yaml:"text"`
	Category string  `yaml:"category"`
	Severity float64 `yaml:"severity"`
}

func (l *SeedLoader) loadAgenticThreats(ctx context.Context, data []byte) (int, error) {
	var file agenticThreatsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("failed to parse agentic threats: %w", err)
	}

	seeds := make([]*ThreatSeed, 0, len(file.SeedData))
	for _, s := range file.SeedData {
		seed := &ThreatSeed{
			ID:       uuid.New(),
			Category: s.Category,
			Text:     s.Text,
			Severity: s.Severity,
			Language: detectLanguage(s.Text),
			Tags:     []string{"agentic", s.Category},
			Source:   "yaml",
			Active:   true,
		}
		seeds = append(seeds, seed)
	}

	return l.store.BulkUpsert(ctx, seeds)
}

// =============================================================================
// Injection Seeds (injection_seed.yaml)
// =============================================================================

type injectionSeedsFile struct {
	SeedData []injectionSeed `yaml:"seed_data"`
}

type injectionSeed struct {
	Text     string `yaml:"text"`
	Category string `yaml:"category"`
	Lang     string `yaml:"lang"`
}

func (l *SeedLoader) loadInjectionSeeds(ctx context.Context, data []byte) (int, error) {
	var file injectionSeedsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("failed to parse injection seeds: %w", err)
	}

	seeds := make([]*ThreatSeed, 0, len(file.SeedData))
	for _, s := range file.SeedData {
		severity := 0.85 // Default severity
		if s.Category == "benign" {
			severity = 0.0
		}

		seed := &ThreatSeed{
			ID:       uuid.New(),
			Category: s.Category,
			Text:     s.Text,
			Severity: severity,
			Language: s.Lang,
			Tags:     []string{"injection", s.Category, s.Lang},
			Source:   "yaml",
			Active:   true,
		}
		seeds = append(seeds, seed)
	}

	return l.store.BulkUpsert(ctx, seeds)
}

// =============================================================================
// Semantic Intents (semantic_intents.yaml)
// =============================================================================

type semanticIntentsFile struct {
	RiskVectors   map[string][]string `yaml:"risk_vectors"`
	BenignVectors map[string][]string `yaml:"benign_vectors"`
}

func (l *SeedLoader) loadSemanticIntents(ctx context.Context, data []byte) (int, error) {
	var file semanticIntentsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("failed to parse semantic intents: %w", err)
	}

	seeds := make([]*ThreatSeed, 0)

	// Process Risk Vectors
	for category, examples := range file.RiskVectors {
		severity := 0.85 // Default severity
		if strings.Contains(category, "benign") {
			severity = 0.0
		}

		for _, example := range examples {
			seed := &ThreatSeed{
				ID:       uuid.New(),
				Category: category,
				Text:     example,
				Severity: severity,
				Language: detectLanguage(example),
				Tags:     []string{"semantic", category},
				Source:   "yaml",
				Active:   true,
			}
			seeds = append(seeds, seed)
		}
	}

	// Process Benign Vectors
	for category, examples := range file.BenignVectors {
		for _, example := range examples {
			seed := &ThreatSeed{
				ID:       uuid.New(),
				Category: "benign_" + category,
				Text:     example,
				Severity: 0.0, // Explicitly benign
				Language: detectLanguage(example),
				Tags:     []string{"semantic", "benign", category},
				Source:   "yaml",
				Active:   true,
			}
			seeds = append(seeds, seed)
		}
	}

	return l.store.BulkUpsert(ctx, seeds)
}

// =============================================================================
// Generic Seeds (fallback parser)
// =============================================================================

type genericSeedsFile struct {
	Seeds []genericSeed `yaml:"seeds"`
}

type genericSeed struct {
	Text     string            `yaml:"text"`
	Category string            `yaml:"category"`
	Severity float64           `yaml:"severity"`
	Tags     []string          `yaml:"tags"`
	Metadata map[string]string `yaml:"metadata"`
}

func (l *SeedLoader) loadGenericSeeds(ctx context.Context, data []byte) (int, error) {
	var file genericSeedsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("failed to parse generic seeds: %w", err)
	}

	if len(file.Seeds) == 0 {
		return 0, nil
	}

	seeds := make([]*ThreatSeed, 0, len(file.Seeds))
	for _, s := range file.Seeds {
		metadata := make(map[string]any)
		for k, v := range s.Metadata {
			metadata[k] = v
		}

		seed := &ThreatSeed{
			ID:       uuid.New(),
			Category: s.Category,
			Text:     s.Text,
			Severity: s.Severity,
			Language: detectLanguage(s.Text),
			Tags:     s.Tags,
			Metadata: metadata,
			Source:   "yaml",
			Active:   true,
		}
		seeds = append(seeds, seed)
	}

	return l.store.BulkUpsert(ctx, seeds)
}

// =============================================================================
// Legacy compatibility types
// =============================================================================

// Note: InjectionPattern is defined in semantic.go for backward compatibility.

// SeedFile represents the YAML structure for injection seed files (legacy).
type SeedFile struct {
	SeedData []SeedEntry `yaml:"seed_data"`
}

// SeedEntry represents a single seed pattern from YAML (legacy).
type SeedEntry struct {
	Text     string  `yaml:"text"`
	Category string  `yaml:"category"`
	Lang     string  `yaml:"lang,omitempty"`
	Severity float32 `yaml:"severity,omitempty"`
}

// DefaultSeedFiles lists the YAML files to load, in order.
var DefaultSeedFiles = []string{
	"injection_seed.yaml",
	"agentic_threats_seed.yaml",
	"multiturn_semantic_seeds.yaml",
	"semantic_intents.yaml",
}

// LoadSeedsFromYAML loads injection patterns from a single YAML file (legacy).
func LoadSeedsFromYAML(filepath string) ([]InjectionPattern, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read seed file %s: %w", filepath, err)
	}

	var seedFile SeedFile
	if err := yaml.Unmarshal(data, &seedFile); err != nil {
		return nil, fmt.Errorf("failed to parse seed file %s: %w", filepath, err)
	}

	patterns := make([]InjectionPattern, 0, len(seedFile.SeedData))
	for _, entry := range seedFile.SeedData {
		pattern := InjectionPattern{
			Text:     entry.Text,
			Category: entry.Category,
		}

		if entry.Lang != "" {
			pattern.Language = entry.Lang
		} else {
			pattern.Language = "en"
		}

		if entry.Severity > 0 {
			pattern.Severity = entry.Severity
		} else {
			pattern.Severity = defaultSeverityForCategory(entry.Category)
		}

		patterns = append(patterns, pattern)
	}

	return patterns, nil
}

// LoadAllSeeds loads patterns from all seed files in a config directory (legacy).
func LoadAllSeeds(configDir string) ([]InjectionPattern, error) {
	var allPatterns []InjectionPattern

	for _, filename := range DefaultSeedFiles {
		fullPath := filepath.Join(configDir, filename)

		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		patterns, err := LoadSeedsFromYAML(fullPath)
		if err != nil {
			// Log warning but continue with other files
			fmt.Fprintf(os.Stderr, "[WARN] Failed to load seeds from %s: %v\n", fullPath, err)
			continue
		}

		allPatterns = append(allPatterns, patterns...)
	}

	if len(allPatterns) == 0 {
		return getMultiLanguagePatterns(), nil
	}

	return allPatterns, nil
}

// FindConfigDir searches for the config directory containing seed files.
func FindConfigDir() string {
	candidates := []string{
		os.Getenv("CITADEL_SEED_CONFIG_DIR"),
		// OSS paths (for standalone deployments)
		"./config/seeds",
		"./seeds",
		"./config",
		"../config/seeds",
		// Docker/container paths
		"/app/config",
		"/etc/citadel/seeds",
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		testPath := filepath.Join(candidate, "injection_seed.yaml")
		if _, err := os.Stat(testPath); err == nil {
			return candidate
		}
	}

	return ""
}

// defaultSeverityForCategory returns a default severity for categories.
func defaultSeverityForCategory(category string) float32 {
	highSeverity := map[string]bool{
		"instruction_override": true,
		"data_exfil":           true,
		"system_access":        true,
		"mcp_injection":        true,
		"goal_hijacking":       true,
		"code_execution":       true,
	}

	mediumSeverity := map[string]bool{
		"roleplay_attack":    true,
		"obfuscation":        true,
		"encoding_attack":    true,
		"trust_exploitation": true,
		"rag_poisoning":      true,
	}

	if highSeverity[category] {
		return 0.9
	}
	if mediumSeverity[category] {
		return 0.7
	}
	return 0.5
}

// =============================================================================
// Helpers
// =============================================================================

// detectLanguage performs basic language detection based on character ranges.
func detectLanguage(text string) string {
	if text == "" {
		return "en"
	}

	for _, r := range text {
		switch {
		case r >= 0x4E00 && r <= 0x9FFF:
			return "zh" // Chinese
		case r >= 0x3040 && r <= 0x309F:
			return "ja" // Japanese Hiragana
		case r >= 0x30A0 && r <= 0x30FF:
			return "ja" // Japanese Katakana
		case r >= 0xAC00 && r <= 0xD7AF:
			return "ko" // Korean
		case r >= 0x0600 && r <= 0x06FF:
			return "ar" // Arabic
		case r >= 0x0590 && r <= 0x05FF:
			return "he" // Hebrew
		case r >= 0x0400 && r <= 0x04FF:
			return "ru" // Russian/Cyrillic
		case r >= 0x0900 && r <= 0x097F:
			return "hi" // Hindi
		}
	}

	// Check for accented Latin characters (European languages)
	hasAccent := false
	for _, r := range text {
		if r >= 0x00C0 && r <= 0x017F {
			hasAccent = true
			break
		}
	}

	if hasAccent {
		lowerText := strings.ToLower(text)
		switch {
		case strings.Contains(lowerText, "ignoriere") || strings.Contains(lowerText, "zeige"):
			return "de"
		case strings.Contains(lowerText, "ignora") || strings.Contains(lowerText, "toutes"):
			return "fr"
		case strings.Contains(lowerText, "olvida"):
			return "es"
		case strings.Contains(lowerText, "ignorar") || strings.Contains(lowerText, "esqueça"):
			return "pt"
		}
	}

	return "en"
}

// GetLoadedFiles returns the list of loaded files and their load times.
func (l *SeedLoader) GetLoadedFiles() map[string]time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make(map[string]time.Time)
	for k, v := range l.loadedFiles {
		result[k] = v
	}
	return result
}
