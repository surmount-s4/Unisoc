package correlationengine

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"uls-detection-server/internal/database"
)

// Engine is the new unbiased cross-source correlation runtime.
type Engine struct {
	db   *database.DB
	cfg  Config
	bart *BARTClient
	llm  *LLMClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(db *database.DB, cfg Config) *Engine {
	cfg.setDefaults()

	llmTimeoutSec := int(cfg.CorrelatorLLMTimeout.Seconds())

	return &Engine{
		db:  db,
		cfg: cfg,
		bart: NewBARTClient(BARTClientConfig{
			InProcess:    cfg.BARTInProcess,
			ServiceURL:   cfg.BARTServiceURL,
			ServiceModel: cfg.BARTModel,
			ModelID:      cfg.BARTModelID,
			ModelPath:    cfg.BARTModelPath,
			PythonBin:    cfg.BARTPythonBinary,
			RunnerPath:   cfg.BARTRunnerPath,
			Timeout:      cfg.BARTTimeout,
		}),
		llm: NewLLMClient(cfg.CorrelatorLLMURL, cfg.CorrelatorLLMModel, llmTimeoutSec),
	}
}

func (e *Engine) Start(parent context.Context) {
	if !e.cfg.Enabled {
		log.Println("[correlationengine] disabled by config")
		return
	}

	e.ctx, e.cancel = context.WithCancel(parent)
	if e.bart != nil {
		log.Printf("[correlationengine] BART backend: %s", e.bart.StartupInfo())
		if err := e.bart.Validate(); err != nil {
			log.Printf("[correlationengine] BART startup validation warning: %v", err)
		}
	}
	e.wg.Add(1)
	go e.loop()
	log.Printf("[correlationengine] started (window=%dm tick=%ds)", e.cfg.WindowMinutes, e.cfg.TickSeconds)
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	if e.bart != nil {
		e.bart.Close()
	}
	log.Println("[correlationengine] stopped")
}

func (e *Engine) loop() {
	defer e.wg.Done()

	// Run once on startup so operators do not wait for first ticker edge.
	e.runOnce()

	ticker := time.NewTicker(time.Duration(e.cfg.TickSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.runOnce()
		}
	}
}

func (e *Engine) runOnce() {
	windowStart, windowEnd := LastClosedWindow(time.Now(), e.cfg.WindowMinutes)

	windowID, acquired, err := e.tryStartWindow(e.ctx, windowStart, windowEnd)
	if err != nil {
		log.Printf("[correlationengine] acquire window failed: %v", err)
		return
	}
	if !acquired {
		return
	}

	if err := e.processWindow(windowID, windowStart, windowEnd); err != nil {
		log.Printf("[correlationengine] window %s..%s failed: %v", windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339), err)
		_ = e.markWindowFailed(e.ctx, windowID, err.Error())
	}
}

func (e *Engine) processWindow(windowID int64, windowStart, windowEnd time.Time) error {
	windowsEvents, err := e.fetchWindowsPassEvents(e.ctx, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("fetch windows events: %w", err)
	}

	maliciousWindows, benignCount, err := e.classifyWindowsEvents(windowStart, windowEnd, windowsEvents)
	if err != nil {
		return fmt.Errorf("bart classify windows events: %w", err)
	}

	firewallEvents, err := e.fetchFirewallEvents(e.ctx, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("fetch firewall events: %w", err)
	}

	scadaEvents, err := e.fetchScadaEvents(e.ctx, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("fetch scada events: %w", err)
	}

	// Build host-scoped process chain evidence from GUID relationships.
	hosts := make([]string, 0, len(maliciousWindows))
	for _, ev := range maliciousWindows {
		if strings.TrimSpace(ev.AgentHost) != "" {
			hosts = append(hosts, ev.AgentHost)
		}
	}
	hosts = uniqueNonEmpty(hosts)
	sort.Strings(hosts)

	processChainEvidence := make(map[string]map[string]any)
	if len(hosts) > 0 {
		chains, err := e.buildAndStoreProcessChains(e.ctx, windowStart, windowEnd, hosts)
		if err != nil {
			log.Printf("[correlationengine] process chain persistence warning: %v", err)
		} else {
			processChainEvidence = chains
		}
	}

	payload := CorrelationPayload{
		WindowStart:          windowStart,
		WindowEnd:            windowEnd,
		WindowsEvents:        maliciousWindows,
		FirewallEvents:       firewallEvents,
		ScadaEvents:          scadaEvents,
		ProcessChainEvidence: processChainEvidence,
	}
	payload.Counts.WindowsTotal = len(windowsEvents)
	payload.Counts.WindowsMalicious = len(maliciousWindows)
	payload.Counts.WindowsBenign = benignCount
	payload.Counts.FirewallTotal = len(firewallEvents)
	payload.Counts.ScadaTotal = len(scadaEvents)

	totalForCorrelation := len(maliciousWindows) + len(firewallEvents) + len(scadaEvents)
	assessment := "healthy"
	conf := 1.0
	incidents := make([]CorrelationIncident, 0)

	if totalForCorrelation > 0 {
		result, _, err := e.llm.Correlate(e.ctx, payload)
		if err != nil {
			return fmt.Errorf("llm correlate: %w", err)
		}
		assessment = strings.ToLower(strings.TrimSpace(result.OverallAssessment))
		if assessment == "" {
			assessment = "suspicious"
		}
		conf = result.Confidence
		incidents = result.IncidentCandidates
	}

	if len(incidents) > 0 {
		if err := e.saveIncidents(e.ctx, windowStart, windowEnd, incidents); err != nil {
			return fmt.Errorf("save incidents: %w", err)
		}
	}

	if err := e.markWindowDone(
		e.ctx,
		windowID,
		len(windowsEvents),
		len(maliciousWindows),
		len(firewallEvents),
		len(scadaEvents),
		assessment,
		conf,
	); err != nil {
		return fmt.Errorf("mark window done: %w", err)
	}

	log.Printf("[correlationengine] window done %s..%s windows=%d malicious=%d benign=%d fw=%d scada=%d assessment=%s",
		windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339),
		len(windowsEvents), len(maliciousWindows), benignCount, len(firewallEvents), len(scadaEvents), assessment,
	)

	return nil
}

func (e *Engine) classifyWindowsEvents(windowStart, windowEnd time.Time, events []WindowsPassEvent) ([]WindowsPassEvent, int, error) {
	if len(events) == 0 {
		return nil, 0, nil
	}
	if err := e.bart.Validate(); err != nil {
		return nil, 0, fmt.Errorf("bart client unavailable: %w", err)
	}

	malicious := make([]WindowsPassEvent, 0, len(events))
	benign := 0
	for _, ev := range events {
		ctx, cancel := context.WithTimeout(e.ctx, e.cfg.BARTTimeout)
		decision, err := e.bart.Classify(ctx, ev, windowStart, windowEnd, e.cfg.BARTConfidenceThreshold)
		cancel()
		if err != nil {
			decision.ErrorText = err.Error()
			_ = e.saveBARTDecision(e.ctx, decision)
			return nil, 0, err
		}

		if err := e.saveBARTDecision(e.ctx, decision); err != nil {
			return nil, 0, fmt.Errorf("persist bart decision: %w", err)
		}

		if decision.Classification == "malicious" {
			malicious = append(malicious, ev)
		} else {
			benign++
		}
	}
	return malicious, benign, nil
}
