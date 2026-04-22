package llmwatcher

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"uls-detection-server/internal/database"
	"uls-detection-server/internal/models"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds all tunable parameters for the LLM watcher.
type Config struct {
	OllamaURL     string        // e.g. "http://localhost:11434"; empty = disabled
	Model         string        // e.g. "mistral", "llama3"
	WindowSeconds int           // poll interval; default 5
	Timeout       time.Duration // per-LLM-call timeout; default 30s
	IncludeInfo   bool          // if true, send INFO events to LLM (default false)
	MaxBatchSize  int           // cap events per LLM call; default 50
	OutChanBuffer int           // output channel capacity (windows); default 10
}

func (c *Config) setDefaults() {
	if c.Model == "" {
		c.Model = "mistral"
	}
	if c.WindowSeconds <= 0 {
		c.WindowSeconds = 5
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = 50
	}
	if c.OutChanBuffer <= 0 {
		c.OutChanBuffer = 10
	}
}

// ---------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------

// Watcher is the 5-second LLM inference stage.
// It runs independently of the hot enrichment path and never blocks ingestion.
type Watcher struct {
	db     *database.DB
	cfg    Config
	ollama *OllamaClient // nil when LLM disabled

	// out is written by the poll goroutine and drained by the writer goroutine.
	out chan []models.LLMPassEvent

	// lastPoll tracks the high-watermark timestamp for DB polling.
	lastPoll time.Time

	// Metrics (atomic, safe to read without lock)
	WindowsProcessed  atomic.Int64
	EventsEnriched    atomic.Int64
	LLMCallsMade      atomic.Int64
	PassthroughEvents atomic.Int64
	DroppedWindows    atomic.Int64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a Watcher. If cfg.OllamaURL is empty the watcher runs in
// pure passthrough mode (copies rule-based fields to llm_pass_1 without any LLM call).
func New(db *database.DB, cfg Config) *Watcher {
	cfg.setDefaults()
	w := &Watcher{
		db:       db,
		cfg:      cfg,
		out:      make(chan []models.LLMPassEvent, cfg.OutChanBuffer),
		lastPoll: time.Now(),
	}
	if cfg.OllamaURL != "" {
		w.ollama = NewOllamaClient(cfg.OllamaURL, cfg.Model, cfg.Timeout)
		log.Printf("[llmwatcher] LLM enabled: url=%s model=%s window=%ds",
			cfg.OllamaURL, cfg.Model, cfg.WindowSeconds)
	} else {
		log.Printf("[llmwatcher] LLM disabled — passthrough mode (set OLLAMA_URL to enable)")
	}
	return w
}

// Start launches the poll goroutine and the DB-writer goroutine.
func (w *Watcher) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	w.wg.Add(2)
	go w.pollLoop(ctx)
	go w.writeLoop(ctx)
}

// Stop gracefully shuts down both goroutines and waits for them to finish.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	log.Printf("[llmwatcher] stopped. windows=%d events=%d llm_calls=%d passthrough=%d dropped=%d",
		w.WindowsProcessed.Load(), w.EventsEnriched.Load(),
		w.LLMCallsMade.Load(), w.PassthroughEvents.Load(), w.DroppedWindows.Load())
}

// ---------------------------------------------------------------------------
// Poll goroutine — runs every WindowSeconds
// ---------------------------------------------------------------------------

func (w *Watcher) pollLoop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(time.Duration(w.cfg.WindowSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-ticker.C:
			w.processWindow(ctx, tick)
		}
	}
}

func (w *Watcher) processWindow(ctx context.Context, windowEnd time.Time) {
	windowStart := w.lastPoll
	w.lastPoll = windowEnd

	// ── 1. Fetch new events from both tables (indexed by timestamp) ──────────
	winInputs, err := w.fetchWindowsEvents(ctx, windowStart, windowEnd)
	if err != nil {
		log.Printf("[llmwatcher] fetch windows events: %v", err)
	}
	fwInputs, err := w.fetchFirewallEvents(ctx, windowStart, windowEnd)
	if err != nil {
		log.Printf("[llmwatcher] fetch firewall events: %v", err)
	}

	total := len(winInputs) + len(fwInputs)
	if total == 0 {
		return
	}

	// ── 2. Deduplicate by fingerprint within this window ─────────────────────
	winInputs = w.dedupByFingerprint(winInputs)
	fwInputs = w.dedupByFingerprint(fwInputs)

	// ── 3. Enforce max batch size ─────────────────────────────────────────────
	winInputs = capSlice(winInputs, w.cfg.MaxBatchSize)
	fwInputs = capSlice(fwInputs, w.cfg.MaxBatchSize)

	// ── 4. LLM inference — both sources in parallel ───────────────────────────
	var (
		winOut models.LLMOutput
		fwOut  models.LLMOutput
		llmErr error
	)

	llmEnabled := w.ollama != nil && w.ollama.IsAvailable()

	if llmEnabled {
		var mu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if len(winInputs) == 0 {
				return
			}
			out, err := w.ollama.Analyze(ctx, winInputs, w.cfg.WindowSeconds)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("[llmwatcher] windows LLM error: %v — using passthrough", err)
				winOut = mergePassthrough(winInputs)
				llmErr = err
			} else {
				winOut = out
				w.LLMCallsMade.Add(1)
			}
		}()

		go func() {
			defer wg.Done()
			if len(fwInputs) == 0 {
				return
			}
			out, err := w.ollama.Analyze(ctx, fwInputs, w.cfg.WindowSeconds)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("[llmwatcher] firewall LLM error: %v — using passthrough", err)
				fwOut = mergePassthrough(fwInputs)
			} else {
				fwOut = out
				w.LLMCallsMade.Add(1)
			}
		}()

		wg.Wait()
		_ = llmErr // logged above; passthrough already set
	} else {
		// passthrough: rule-based fields copied directly
		winOut = mergePassthrough(winInputs)
		fwOut = mergePassthrough(fwInputs)
		w.PassthroughEvents.Add(int64(len(winInputs) + len(fwInputs)))
	}

	// ── 5. Merge inputs + LLM outputs → LLMPassEvents ────────────────────────
	rows := w.buildPassRows(windowStart, winInputs, winOut, "windows", llmEnabled)
	rows = append(rows, w.buildPassRows(windowStart, fwInputs, fwOut, "firewall", llmEnabled)...)

	if len(rows) == 0 {
		return
	}

	// ── 6. Send to writer goroutine via non-blocking channel ──────────────────
	select {
	case w.out <- rows:
		w.WindowsProcessed.Add(1)
		w.EventsEnriched.Add(int64(len(rows)))
	default:
		// Channel full (writer backpressure): drop window, never block the ticker
		w.DroppedWindows.Add(1)
		log.Printf("[llmwatcher] output channel full — dropped window with %d rows", len(rows))
	}
}

// ---------------------------------------------------------------------------
// Writer goroutine — drains the output channel and batch-inserts to DB
// ---------------------------------------------------------------------------

func (w *Watcher) writeLoop(ctx context.Context) {
	defer w.wg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain any remaining rows before exit
			for {
				select {
				case rows := <-w.out:
					w.flushRows(context.Background(), rows)
				default:
					return
				}
			}
		case rows := <-w.out:
			w.flushRows(ctx, rows)
		}
	}
}

func (w *Watcher) flushRows(ctx context.Context, rows []models.LLMPassEvent) {
	if err := database.InsertLLMPassEvents(ctx, w.db, rows); err != nil {
		log.Printf("[llmwatcher] db insert error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DB fetch helpers
// ---------------------------------------------------------------------------

func (w *Watcher) fetchWindowsEvents(ctx context.Context, from, to time.Time) ([]models.LLMInput, error) {
	sevFilter := "'LOW','MEDIUM','HIGH','CRITICAL'"
	if w.cfg.IncludeInfo {
		sevFilter = "'INFO','LOW','MEDIUM','HIGH','CRITICAL'"
	}

	query := fmt.Sprintf(`
		SELECT
			COALESCE(agent_host,'') AS agent_host,
			COALESCE(eventid_0,'')  AS event_id,
			COALESCE(severity,'')   AS rule_severity,
			COALESCE(mitre_technique,'') AS mitre_technique,
			COALESCE(detection_module,'') AS detection_module,
			COALESCE(event_details,'')  AS event_details,
			COALESCE(sourceip_2,'')  AS src_ip,
			COALESCE(destinationip_2,'') AS dst_ip,
			COALESCE(destinationport_2,'') AS dst_port,
			COALESCE(image_2,'')    AS process_name,
			COALESCE(commandline_2,'')   AS command_line,
			timestamp
		FROM security_events
		WHERE timestamp > $1 AND timestamp <= $2
		  AND severity IN (%s)
		ORDER BY timestamp ASC
		LIMIT $3`, sevFilter)

	rows, err := w.db.Pool().Query(ctx, query, from, to, w.cfg.MaxBatchSize*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []models.LLMInput
	for rows.Next() {
		var inp models.LLMInput
		var ts time.Time
		if err := rows.Scan(
			&inp.AgentHost, &inp.EventID, &inp.RuleSeverity,
			&inp.MitreTechnique, &inp.DetectionModule, &inp.EventDetails,
			&inp.SrcIP, &inp.DstIP, &inp.DstPort,
			&inp.ProcessName, &inp.CommandLine, &ts,
		); err != nil {
			continue
		}
		inp.SourceType = "windows"
		inp.Timestamp = ts.Format(time.RFC3339)
		inp.FingerprintHash = fingerprint(inp)
		inputs = append(inputs, inp)
	}
	return inputs, rows.Err()
}

func (w *Watcher) fetchFirewallEvents(ctx context.Context, from, to time.Time) ([]models.LLMInput, error) {
	sevFilter := "'LOW','MEDIUM','HIGH','CRITICAL'"
	if w.cfg.IncludeInfo {
		sevFilter = "'INFO','LOW','MEDIUM','HIGH','CRITICAL'"
	}

	query := fmt.Sprintf(`
		SELECT
			COALESCE(device_name,'') AS agent_host,
			COALESCE(log_type,'')    AS event_id,
			COALESCE(threat_level,'') AS rule_severity,
			COALESCE(mitre_technique,'') AS mitre_technique,
			COALESCE(detection_module,'') AS detection_module,
			COALESCE(event_details,'')  AS event_details,
			COALESCE(src_ip,'')      AS src_ip,
			COALESCE(dst_ip,'')      AS dst_ip,
			COALESCE(dst_port,'')    AS dst_port,
			COALESCE(action,'')      AS action,
			COALESCE(sent_bytes,'')  AS sent_bytes,
			received_at
		FROM firewall_events
		WHERE received_at > $1 AND received_at <= $2
		  AND threat_level IN (%s)
		ORDER BY received_at ASC
		LIMIT $3`, sevFilter)

	rows, err := w.db.Pool().Query(ctx, query, from, to, w.cfg.MaxBatchSize*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []models.LLMInput
	for rows.Next() {
		var inp models.LLMInput
		var ts time.Time
		if err := rows.Scan(
			&inp.AgentHost, &inp.EventID, &inp.RuleSeverity,
			&inp.MitreTechnique, &inp.DetectionModule, &inp.EventDetails,
			&inp.SrcIP, &inp.DstIP, &inp.DstPort,
			&inp.Action, &inp.SentBytes, &ts,
		); err != nil {
			continue
		}
		inp.SourceType = "firewall"
		inp.Timestamp = ts.Format(time.RFC3339)
		inp.FingerprintHash = fingerprint(inp)
		inputs = append(inputs, inp)
	}
	return inputs, rows.Err()
}

// ---------------------------------------------------------------------------
// Row building helpers
// ---------------------------------------------------------------------------

func (w *Watcher) buildPassRows(windowTS time.Time, inputs []models.LLMInput, out models.LLMOutput, sourceType string, llmEnabled bool) []models.LLMPassEvent {
	rows := make([]models.LLMPassEvent, 0, len(inputs))
	llmSeverity := verdictToSeverity(out.Verdict)
	llmConfidence := confidenceFromVerdict(out.Verdict)
	llmSummary := strings.TrimSpace(out.Reasoning)
	if len(out.IOA) > 0 {
		if llmSummary == "" {
			llmSummary = "No malicious activity detected."
		}
		llmSummary = llmSummary + " | IOA: " + strings.Join(out.IOA, "; ")
	}

	for _, inp := range inputs {
		row := models.LLMPassEvent{
			SourceType:   sourceType,
			WindowTS:     windowTS,
			AgentHost:    inp.AgentHost,
			SrcIP:        inp.SrcIP,
			DstIP:        inp.DstIP,
			DstPort:      inp.DstPort,
			EventID:      inp.EventID,
			RawSummary:   inp.EventDetails,
			RuleSeverity: inp.RuleSeverity,
			RuleMitre:    inp.MitreTechnique,
			RuleIsIOA:    inp.MitreTechnique != "",
			LLMEnabled:   llmEnabled,
		}

		row.LLMSeverity = llmSeverity
		row.LLMSummary = llmSummary
		row.LLMIsIOA = len(out.IOA) > 0
		row.LLMIsIOC = len(out.IOC) > 0
		row.LLMIOCValues = iocValuesToString(out.IOC)
		row.LLMIOAValues = ioaValuesToString(out.IOA)
		row.LLMMitre = ""
		row.LLMConfidence = llmConfidence
		row.LLMModel = out.Model
		row.LLMLatencyMs = out.LatencyMs

		// Final resolved: prefer LLM output, fall back to rule-based
		row.FinalSeverity = coalesce(row.LLMSeverity, row.RuleSeverity)
		row.FinalSummary = coalesce(row.LLMSummary, row.RawSummary)
		row.FinalMitre = coalesce(row.LLMMitre, row.RuleMitre)

		rows = append(rows, row)
	}
	return rows
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// fingerprint computes a SHA-256 hash of the behavioural identity of an event.
// Matches the same fields as the dedup module so the watcher benefits from
// the same deduplication semantics across windows.
func fingerprint(inp models.LLMInput) string {
	raw := strings.Join([]string{
		inp.AgentHost, inp.EventID, inp.MitreTechnique,
		inp.DetectionModule, inp.ProcessName, inp.DstIP, inp.DstPort,
	}, "|")
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:8]) // first 8 bytes = 16 hex chars, sufficient for dedup
}

// dedupByFingerprint removes duplicate events within a single window.
func (w *Watcher) dedupByFingerprint(inputs []models.LLMInput) []models.LLMInput {
	seen := make(map[string]struct{}, len(inputs))
	out := inputs[:0]
	for _, inp := range inputs {
		if _, dup := seen[inp.FingerprintHash]; !dup {
			seen[inp.FingerprintHash] = struct{}{}
			out = append(out, inp)
		}
	}
	return out
}

// capSlice truncates a slice to maxLen.
func capSlice(inputs []models.LLMInput, maxLen int) []models.LLMInput {
	if len(inputs) > maxLen {
		return inputs[:maxLen]
	}
	return inputs
}

// coalesce returns the first non-empty string.
func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
