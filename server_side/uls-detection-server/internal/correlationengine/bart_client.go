package correlationengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type BARTClientConfig struct {
	InProcess    bool
	ServiceURL   string
	ServiceModel string
	ModelID      string
	ModelPath    string
	PythonBin    string
	RunnerPath   string
	Timeout      time.Duration
}

type BARTClient struct {
	mode       string // inprocess | http
	url        string
	model      string
	modelRef   string
	runnerPath string
	timeout    time.Duration
	http       *http.Client
	runner     *bartRunner
	initErr    error
}

type bartRunner struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
}

func NewBARTClient(cfg BARTClientConfig) *BARTClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	if strings.TrimSpace(cfg.ModelID) == "" {
		cfg.ModelID = "facebook/bart-large-mnli"
	}
	if strings.TrimSpace(cfg.PythonBin) == "" {
		cfg.PythonBin = "python"
	}
	if strings.TrimSpace(cfg.RunnerPath) == "" {
		cfg.RunnerPath = "internal/correlationengine/bart_runner.py"
	}

	client := &BARTClient{
		url:        strings.TrimSpace(cfg.ServiceURL),
		model:      strings.TrimSpace(cfg.ServiceModel),
		runnerPath: resolveRunnerPath(cfg.RunnerPath),
		timeout:    cfg.Timeout,
		http: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	if strings.TrimSpace(cfg.ModelPath) != "" {
		client.modelRef = strings.TrimSpace(cfg.ModelPath)
	} else {
		client.modelRef = strings.TrimSpace(cfg.ModelID)
	}

	if client.model == "" {
		client.model = strings.TrimSpace(cfg.ModelID)
	}

	if cfg.InProcess {
		runner, resolvedModel, err := startBARTInProcessRunner(cfg.PythonBin, cfg.RunnerPath, cfg.ModelID, cfg.ModelPath)
		if err == nil {
			client.mode = "inprocess"
			client.runner = runner
			if resolvedModel != "" {
				client.model = resolvedModel
				client.modelRef = resolvedModel
			}
			log.Printf("[correlationengine] BART in-process enabled model=%s", client.model)
			return client
		}

		if client.url != "" {
			client.mode = "http"
			if client.modelRef == "" {
				client.modelRef = client.model
			}
			log.Printf("[correlationengine] BART in-process startup failed (%v); falling back to HTTP endpoint", err)
			return client
		}

		client.initErr = fmt.Errorf("bart in-process startup failed: %w", err)
		return client
	}

	if client.url != "" {
		client.mode = "http"
		if client.modelRef == "" {
			client.modelRef = client.model
		}
		return client
	}

	client.initErr = fmt.Errorf("no BART backend configured")
	return client
}

func (c *BARTClient) StartupInfo() string {
	switch c.mode {
	case "inprocess":
		modelRef := strings.TrimSpace(c.modelRef)
		if modelRef == "" {
			modelRef = strings.TrimSpace(c.model)
		}
		runnerPath := strings.TrimSpace(c.runnerPath)
		if runnerPath == "" {
			runnerPath = "unknown"
		}
		return fmt.Sprintf("mode=inprocess model=%s model_ref=%s runner=%s", strings.TrimSpace(c.model), modelRef, runnerPath)
	case "http":
		return fmt.Sprintf("mode=http model=%s endpoint=%s", strings.TrimSpace(c.model), strings.TrimSpace(c.url))
	default:
		if c.initErr != nil {
			return fmt.Sprintf("mode=unavailable error=%v", c.initErr)
		}
		return "mode=unconfigured"
	}
}

func startBARTInProcessRunner(pythonBin, runnerPath, modelID, modelPath string) (*bartRunner, string, error) {
	runnerPath = resolveRunnerPath(runnerPath)
	if _, err := os.Stat(runnerPath); err != nil {
		return nil, "", fmt.Errorf("runner script not found at %s: %w", runnerPath, err)
	}

	args := []string{"-u", runnerPath, "--model-id", modelID}
	if strings.TrimSpace(modelPath) != "" {
		args = append(args, "--model-path", modelPath)
	}

	cmd := exec.Command(pythonBin, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, "", fmt.Errorf("open runner stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("open runner stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, "", fmt.Errorf("open runner stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("start runner process: %w", err)
	}

	go streamRunnerStderr(stderr)

	outReader := bufio.NewReader(stdout)
	readyLine, err := readLineWithTimeout(outReader, 180*time.Second)
	if err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, "", fmt.Errorf("wait for runner readiness: %w", err)
	}

	var ready map[string]any
	if err := json.Unmarshal([]byte(readyLine), &ready); err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, "", fmt.Errorf("parse runner readiness response: %w", err)
	}

	if isReady, _ := ready["ready"].(bool); !isReady {
		errMsg := firstString(ready, "error")
		if errMsg == "" {
			errMsg = "runner returned not ready"
		}
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, "", fmt.Errorf(errMsg)
	}

	resolvedModel := firstString(ready, "model")

	return &bartRunner{
		cmd:    cmd,
		stdin:  stdin,
		stdout: outReader,
	}, resolvedModel, nil
}

func resolveRunnerPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}

func streamRunnerStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		log.Printf("[bart-runner] %s", line)
	}
}

func readLineWithTimeout(r *bufio.Reader, timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line: strings.TrimSpace(line), err: err}
	}()

	select {
	case out := <-ch:
		if out.err != nil {
			return "", out.err
		}
		return out.line, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for runner response")
	}
}

func (c *BARTClient) Validate() error {
	if c.initErr != nil {
		return c.initErr
	}
	switch c.mode {
	case "inprocess":
		if c.runner == nil {
			return fmt.Errorf("bart in-process runner is not initialized")
		}
		return nil
	case "http":
		if c.url == "" {
			return fmt.Errorf("bart service url is empty")
		}
		return nil
	default:
		return fmt.Errorf("bart backend mode is not configured")
	}
}

func (c *BARTClient) Close() {
	if c.runner == nil {
		return
	}

	c.runner.mu.Lock()
	defer c.runner.mu.Unlock()

	if c.runner.stdin != nil {
		_ = c.runner.stdin.Close()
	}
	if c.runner.cmd != nil {
		if c.runner.cmd.Process != nil {
			_ = c.runner.cmd.Process.Kill()
		}
		_ = c.runner.cmd.Wait()
	}
	c.runner = nil
}

type bartClassifyRequest struct {
	Model     string           `json:"model,omitempty"`
	Text      string           `json:"text"`
	Event     WindowsPassEvent `json:"event"`
	Threshold float64          `json:"threshold"`
}

func (c *BARTClient) Classify(ctx context.Context, ev WindowsPassEvent, windowStart, windowEnd time.Time, threshold float64) (BARTDecision, error) {
	decision := BARTDecision{
		LLMPassID:      ev.ID,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
		AgentHost:      ev.AgentHost,
		EventID:        ev.EventID,
		Classification: "benign",
		Confidence:     0,
		Threshold:      threshold,
		Model:          c.model,
	}

	if err := c.Validate(); err != nil {
		return decision, err
	}

	if c.mode == "inprocess" {
		return c.classifyInProcess(ctx, decision, ev, threshold)
	}

	return c.classifyHTTP(ctx, decision, ev, threshold)
}

func (c *BARTClient) classifyHTTP(ctx context.Context, decision BARTDecision, ev WindowsPassEvent, threshold float64) (BARTDecision, error) {

	reqBody, err := json.Marshal(bartClassifyRequest{
		Model:     c.model,
		Text:      strings.TrimSpace(ev.FinalSummary),
		Event:     ev,
		Threshold: threshold,
	})
	if err != nil {
		return decision, fmt.Errorf("marshal bart request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return decision, fmt.Errorf("build bart request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return decision, fmt.Errorf("bart http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return decision, fmt.Errorf("bart status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return decision, fmt.Errorf("read bart response: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return decision, fmt.Errorf("parse bart response: %w", err)
	}

	decision.RawResponse = raw
	decision.Model = firstString(raw, "model", "bart_model")
	if decision.Model == "" {
		decision.Model = c.model
	}

	label := strings.ToLower(strings.TrimSpace(firstString(raw, "classification", "label", "verdict", "result")))
	confidence := firstFloat(raw, "confidence", "score", "probability")
	if label == "" {
		label = "benign"
	}

	isMalicious := strings.Contains(label, "malicious") && confidence >= threshold
	if isMalicious {
		decision.Classification = "malicious"
	} else {
		decision.Classification = "benign"
	}
	decision.Confidence = confidence
	return decision, nil
}

func (c *BARTClient) classifyInProcess(ctx context.Context, decision BARTDecision, ev WindowsPassEvent, threshold float64) (BARTDecision, error) {
	type runnerRequest struct {
		Text      string   `json:"text"`
		Threshold float64  `json:"threshold"`
		Labels    []string `json:"labels"`
	}

	req := runnerRequest{
		Text:      strings.TrimSpace(ev.FinalSummary),
		Threshold: threshold,
		Labels:    []string{"Malicious", "Benign"},
	}

	lineReq, err := json.Marshal(req)
	if err != nil {
		return decision, fmt.Errorf("marshal in-process bart request: %w", err)
	}

	r := c.runner
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return decision, ctx.Err()
	default:
	}

	if _, err := r.stdin.Write(append(lineReq, '\n')); err != nil {
		return decision, fmt.Errorf("write to bart runner: %w", err)
	}

	line, err := readLineWithTimeout(r.stdout, c.timeout)
	if err != nil {
		return decision, fmt.Errorf("read from bart runner: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return decision, fmt.Errorf("parse bart runner response: %w", err)
	}

	decision.RawResponse = raw
	decision.Model = firstString(raw, "model")
	if decision.Model == "" {
		decision.Model = c.model
	}

	if runnerErr := firstString(raw, "error"); runnerErr != "" {
		return decision, fmt.Errorf("bart runner error: %s", runnerErr)
	}

	label := strings.ToLower(strings.TrimSpace(firstString(raw, "classification", "label", "verdict", "result")))
	confidence := firstFloat(raw, "confidence", "score", "probability")
	if label == "" {
		label = "benign"
	}

	isMalicious := strings.Contains(label, "malicious") && confidence >= threshold
	if isMalicious {
		decision.Classification = "malicious"
	} else {
		decision.Classification = "benign"
	}
	decision.Confidence = confidence

	return decision, nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s, ok := v.(string)
			if ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func firstFloat(m map[string]any, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case float64:
				return t
			case float32:
				return float64(t)
			case int:
				return float64(t)
			case int64:
				return float64(t)
			case json.Number:
				f, err := t.Float64()
				if err == nil {
					return f
				}
			case string:
				var n json.Number = json.Number(strings.TrimSpace(t))
				f, err := n.Float64()
				if err == nil {
					return f
				}
			}
		}
	}
	return 0
}
