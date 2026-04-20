package correlationengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type LLMClient struct {
	url   string
	model string
	http  *http.Client
}

func NewLLMClient(url, model string, timeoutSeconds int) *LLMClient {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	return &LLMClient{
		url:   strings.TrimSpace(url),
		model: strings.TrimSpace(model),
		http: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

type ollamaRequest struct {
	Model   string            `json:"model"`
	Prompt  string            `json:"prompt"`
	Stream  bool              `json:"stream"`
	Format  string            `json:"format,omitempty"`
	Options map[string]any    `json:"options,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

func (c *LLMClient) Correlate(ctx context.Context, payload CorrelationPayload) (CorrelationLLMResult, string, error) {
	var zero CorrelationLLMResult

	if c.url == "" {
		return zero, "", fmt.Errorf("correlator LLM URL is empty")
	}
	if c.model == "" {
		return zero, "", fmt.Errorf("correlator LLM model is empty")
	}

	prompt, err := BuildCorrelationPrompt(payload)
	if err != nil {
		return zero, "", fmt.Errorf("build prompt: %w", err)
	}

	reqBody, err := json.Marshal(ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": 0.0,
			"num_predict": 2500,
		},
	})
	if err != nil {
		return zero, "", fmt.Errorf("marshal correlator request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return zero, "", fmt.Errorf("build correlator request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return zero, "", fmt.Errorf("correlator http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return zero, "", fmt.Errorf("correlator status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return zero, "", fmt.Errorf("read correlator response: %w", err)
	}

	var env ollamaResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return zero, "", fmt.Errorf("parse ollama envelope: %w", err)
	}

	raw := strings.TrimSpace(env.Response)
	if raw == "" {
		return zero, raw, fmt.Errorf("empty correlator response")
	}

	var out CorrelationLLMResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		clean, ok := extractJSONObject(raw)
		if !ok {
			return zero, raw, fmt.Errorf("parse correlator json: %w", err)
		}
		if err := json.Unmarshal([]byte(clean), &out); err != nil {
			return zero, raw, fmt.Errorf("parse extracted correlator json: %w", err)
		}
	}

	assessment := strings.ToLower(strings.TrimSpace(out.OverallAssessment))
	switch assessment {
	case "malicious", "suspicious", "healthy", "safe":
	default:
		out.OverallAssessment = "suspicious"
	}

	return out, raw, nil
}

func extractJSONObject(s string) (string, bool) {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start == -1 || end == -1 || end <= start {
		return "", false
	}
	return s[start : end+1], true
}
