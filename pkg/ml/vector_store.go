// Package ml provides vector store abstraction for threat detection.
// OSS version: interfaces and types only (PgVectorStore is Pro feature)
package ml

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
)

// Vector store errors
var (
	ErrVectorStoreUnavailable = errors.New("vector store unavailable")
	ErrSeedNotFound           = errors.New("seed not found")
	ErrInvalidEmbedding       = errors.New("invalid embedding dimensions")
)

// ThreatSeed represents a semantic threat pattern for detection.
type ThreatSeed struct {
	ID        uuid.UUID      `json:"id" db:"id"`
	OrgID     *uuid.UUID     `json:"org_id,omitempty" db:"organization_id"` // nil = global
	Category  string         `json:"category" db:"category"`
	Text      string         `json:"text" db:"text"`
	Embedding []float32      `json:"embedding,omitempty" db:"embedding"`
	Severity  float64        `json:"severity" db:"severity"`
	Phase     string         `json:"phase,omitempty" db:"phase"` // multi-turn phase
	Language  string         `json:"language" db:"language"`
	Tags      []string       `json:"tags,omitempty" db:"tags"`
	Metadata  map[string]any `json:"metadata,omitempty" db:"metadata"`
	Source    string         `json:"source" db:"source"` // yaml, user, learned
	Active    bool           `json:"active" db:"active"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" db:"updated_at"`
}

// SeedMatch represents a semantic similarity match result.
type SeedMatch struct {
	Seed       *ThreatSeed `json:"seed"`
	Similarity float64     `json:"similarity"` // 0.0 to 1.0
	Distance   float64     `json:"distance"`   // L2 distance
}

// VectorStore defines the interface for threat seed storage and retrieval.
type VectorStore interface {
	// Health check
	IsHealthy() bool

	// Seed management
	UpsertSeed(ctx context.Context, seed *ThreatSeed) error
	GetSeed(ctx context.Context, id uuid.UUID) (*ThreatSeed, error)
	DeleteSeed(ctx context.Context, id uuid.UUID) error
	ListSeeds(ctx context.Context, category string, limit int) ([]*ThreatSeed, error)

	// Semantic search
	SearchSimilar(ctx context.Context, embedding []float32, category string, limit int, minSimilarity float64) ([]SeedMatch, error)
	SearchByText(ctx context.Context, text string, category string, limit int) ([]SeedMatch, error)

	// Batch operations
	BulkUpsert(ctx context.Context, seeds []*ThreatSeed) (int, error)

	// Statistics
	GetStats() map[string]any

	// Cleanup
	Close() error
}

// EmbeddingProvider generates embeddings for text.
type EmbeddingProvider interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)
	Dimension() int
}

// CosineSimilarityF32 calculates similarity between two float32 vectors.
func CosineSimilarityF32(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// L2Distance calculates Euclidean distance between two float32 vectors.
func L2Distance(a, b []float32) float64 {
	if len(a) != len(b) {
		return math.MaxFloat64
	}

	var sum float64
	for i := range a {
		diff := float64(a[i]) - float64(b[i])
		sum += diff * diff
	}

	return math.Sqrt(sum)
}
