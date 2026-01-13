package ml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"
)

// sharedTransport is defined in http.go for connection pooling across all ML clients

// OllamaClient handles communication with the local Ollama instance.
type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

func NewOllamaClient(url, model string) *OllamaClient {
	return &OllamaClient{
		BaseURL: url,
		Model:   model,
		Client:  &http.Client{Timeout: 5 * time.Second, Transport: sharedTransport},
	}
}

// GetEmbedding fetches the vector representation of a prompt.
func (c *OllamaClient) GetEmbedding(prompt string) ([]float64, error) {
	reqBody := map[string]string{
		"model":  c.Model,
		"prompt": prompt,
	}
	jsonData, _ := json.Marshal(reqBody)

	resp, err := c.Client.Post(c.BaseURL+"/api/embeddings", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama api error: %s", resp.Status)
	}

	var result struct {
		Embedding []float64 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Embedding, nil
}

// CosineSimilarity calculates the angle between two vectors.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	dotProduct := 0.0
	normA := 0.0
	normB := 0.0

	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
