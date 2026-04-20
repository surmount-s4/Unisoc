// Package llmwatcher implements the 5-second LLM inference stage.
// It reads newly-detected events from security_events and firewall_events,
// batches them, calls Ollama for enrichment, and writes results to llm_pass_1.
package llmwatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"uls-detection-server/internal/models"
)

// ---------------------------------------------------------------------------
// Ollama response shapes
// ---------------------------------------------------------------------------

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format"` // "json"
	Options ollamaOptions `json:"options"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
	NumPredict  int     `json:"num_predict"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// ---------------------------------------------------------------------------
// Circuit breaker — simple threshold counter, lock-free
// ---------------------------------------------------------------------------

type circuitBreaker struct {
	failures    atomic.Int32
	openUntil   atomic.Int64  // Unix nano; 0 = closed
	threshold   int32
	openSeconds int64
}

func newCircuitBreaker(threshold int32, openDuration time.Duration) *circuitBreaker {
	return &circuitBreaker{
		threshold:   threshold,
		openSeconds: int64(openDuration.Seconds()),
	}
}

func (cb *circuitBreaker) IsOpen() bool {
	ot := cb.openUntil.Load()
	if ot == 0 {
		return false
	}
	if time.Now().UnixNano() > ot {
		// Reset
		cb.openUntil.Store(0)
		cb.failures.Store(0)
		return false
	}
	return true
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.failures.Store(0)
	cb.openUntil.Store(0)
}

func (cb *circuitBreaker) RecordFailure() {
	n := cb.failures.Add(1)
	if n >= cb.threshold {
		openUntil := time.Now().Add(time.Duration(cb.openSeconds) * time.Second).UnixNano()
		cb.openUntil.Store(openUntil)
	}
}

// ---------------------------------------------------------------------------
// OllamaClient
// ---------------------------------------------------------------------------

// OllamaClient sends event batches to a local Ollama instance for LLM analysis.
type OllamaClient struct {
	baseURL string
	model   string
	timeout time.Duration
	http    *http.Client
	circuit *circuitBreaker
}

// NewOllamaClient creates a ready-to-use OllamaClient.
// baseURL e.g. "http://localhost:11434", model e.g. "mistral".
func NewOllamaClient(baseURL, model string, timeout time.Duration) *OllamaClient {
	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		timeout: timeout,
		http: &http.Client{
			Timeout: timeout + 5*time.Second, // http transport > context timeout
		},
		circuit: newCircuitBreaker(3, 60*time.Second),
	}
}

// IsAvailable returns false quickly if the circuit is open.
func (c *OllamaClient) IsAvailable() bool {
	return !c.circuit.IsOpen()
}

// Analyze sends a batch of LLMInput events to Ollama and returns structured results.
// On failure it records the failure in the circuit breaker and returns an error.
func (c *OllamaClient) Analyze(ctx context.Context, inputs []models.LLMInput) (models.LLMOutput, error) {
	if c.circuit.IsOpen() {
		return models.LLMOutput{}, fmt.Errorf("circuit open: Ollama unavailable")
	}
	if len(inputs) == 0 {
		return models.LLMOutput{Results: []models.LLMEventResult{}}, nil
	}

	prompt := BuildWindowPrompt(inputs)

	reqBody, _ := json.Marshal(ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: ollamaOptions{
			Temperature: 0.0, // deterministic
			NumPredict:  1024,
		},
	})

	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("ollama http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("ollama status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // max 64KB
	if err != nil {
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("read body: %w", err)
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("parse ollama envelope: %w", err)
	}

	var out models.LLMOutput
	if err := json.Unmarshal([]byte(ollamaResp.Response), &out); err != nil {
		// LLM returned unparseable JSON — record failure but don't open circuit
		// (model may have produced partial output under load)
		c.circuit.RecordFailure()
		return models.LLMOutput{}, fmt.Errorf("parse llm json: %w — raw: %.200s", err, ollamaResp.Response)
	}

	latency := time.Since(start).Milliseconds()
	out.Model = c.model
	out.LatencyMs = latency
	c.circuit.RecordSuccess()

	// Ensure result slice length matches input
	padLLMResults(&out, len(inputs))
	return out, nil
}

// padLLMResults fills in missing result entries if the LLM returns fewer than expected.
func padLLMResults(out *models.LLMOutput, expected int) {
	got := len(out.Results)
	for i := got; i < expected; i++ {
		out.Results = append(out.Results, models.LLMEventResult{
			Index:      i,
			Severity:   "",
			Confidence: 0,
			Error:      "missing from LLM response",
		})
	}
}
