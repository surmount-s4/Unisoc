package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"uls-detection-server/internal/database"
)

// ─── Configuration ────────────────────────────────────────────────────────────

const (
	// How far back to look for related events when correlating.
	CorrelationWindow = 10 * time.Minute

	// How often the engine runs its correlation pass.
	CorrelationInterval = 30 * time.Second
)

// ─── Lightweight event structs for in-memory correlation ─────────────────────

// WindowEvent is a minimal representation of any event within the time window.
type WindowEvent struct {
	ID              int64
	Timestamp       time.Time
	Source          string // "windows" | "firewall"
	EventID         string // Windows EventID or Sophos log_type
	SrcIP           string
	DstIP           string
	DstPort         string
	AgentHost       string // hostname (windows events only)
	MitreTechnique  string
	Severity        string
	EventDetails    string
	// Firewall-specific
	Action          string
	SentBytes       string
	// Windows-specific
	CommandLine     string
	ImagePath       string
	GrantedAccess   string
	LogonType       string
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine periodically queries the DB for recent events across both tables
// and runs correlation rules to produce CorrelationIncident records.
type Engine struct {
	db         *database.DB
	useLLMPass bool // when true, read from llm_pass_1 instead of raw tables
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// New creates a new correlation Engine.
// useLLMPass=true reads from llm_pass_1 (LLM-enriched); false reads raw tables.
func New(db *database.DB, useLLMPass bool) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	if useLLMPass {
		log.Println("[Correlator] Using llm_pass_1 as event source (LLM-enriched mode)")
	} else {
		log.Println("[Correlator] Using raw security_events + firewall_events (rule-based mode)")
	}
	return &Engine{db: db, useLLMPass: useLLMPass, ctx: ctx, cancel: cancel}
}

// Start launches the background correlation loop.
func (e *Engine) Start() {
	log.Println("[Correlator] Starting cross-source correlation engine")
	e.wg.Add(1)
	go e.loop()
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop() {
	e.cancel()
	e.wg.Wait()
	log.Println("[Correlator] Stopped")
}

func (e *Engine) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(CorrelationInterval)
	defer ticker.Stop()

	// Run once immediately on startup
	e.runPass()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.runPass()
		}
	}
}

// runPass executes one full correlation pass.
func (e *Engine) runPass() {
	since := time.Now().Add(-CorrelationWindow)

	var winEvents, fwEvents []WindowEvent
	var err error

	if e.useLLMPass {
		// Read LLM-enriched events from llm_pass_1.
		// This gives the correlation rules access to LLM severity, refined MITRE,
		// and extracted IOCs instead of just the rule-based fields.
		winEvents, err = e.queryLLMPassEvents(since, "windows")
		if err != nil {
			log.Printf("[Correlator] llm_pass_1/windows query error: %v", err)
			return
		}
		fwEvents, err = e.queryLLMPassEvents(since, "firewall")
		if err != nil {
			log.Printf("[Correlator] llm_pass_1/firewall query error: %v", err)
			return
		}
	} else {
		// Existing behaviour: read directly from raw source tables.
		winEvents, err = e.queryWindowsEvents(since)
		if err != nil {
			log.Printf("[Correlator] Windows query error: %v", err)
			return
		}
		fwEvents, err = e.queryFirewallEvents(since)
		if err != nil {
			log.Printf("[Correlator] Firewall query error: %v", err)
			return
		}
	}

	if len(winEvents)+len(fwEvents) == 0 {
		return
	}
	log.Printf("[Correlator] Pass: %d Windows + %d Firewall events", len(winEvents), len(fwEvents))

	// Build an index: IP → []WindowEvent (from both sources)
	byIP := buildIPIndex(append(winEvents, fwEvents...))

	incidents := []Incident{}
	incidents = append(incidents, ruleC2BeaconConfirmed(winEvents, fwEvents, byIP)...)
	incidents = append(incidents, ruleBruteForceWithFirewall(winEvents, fwEvents, byIP)...)
	incidents = append(incidents, ruleCredDumpToExfil(winEvents, fwEvents, byIP)...)
	incidents = append(incidents, ruleLateralMovementConfirmed(winEvents, fwEvents, byIP)...)
	incidents = append(incidents, ruleFirewallDenyThenSuccess(winEvents, fwEvents, byIP)...)

	for _, inc := range incidents {
		if err := e.saveIncident(inc); err != nil {
			log.Printf("[Correlator] Save incident error: %v", err)
			continue
		}
		log.Printf("[Correlator] 🚨 [%s] %s | IP=%s HOST=%s | %s",
			inc.Severity, inc.IncidentType, inc.AffectedIP, inc.AffectedHost, inc.Description)
	}
}

// ─── DB Queries ───────────────────────────────────────────────────────────────

func (e *Engine) queryWindowsEvents(since time.Time) ([]WindowEvent, error) {
	rows, err := e.db.Pool().Query(e.ctx, `
		SELECT id, timestamp, eventid_0,
		       COALESCE(sourceip_2,''), COALESCE(destinationip_2,''), COALESCE(destinationport_2,''),
		       COALESCE(computer_0,''), COALESCE(agent_host,''),
		       COALESCE(mitre_technique,''), COALESCE(severity,'INFO'),
		       COALESCE(event_details,''),
		       COALESCE(commandline_2,''), COALESCE(image_2,''),
		       COALESCE(grantedaccess_2,''), COALESCE(logontype_3,''),
		       COALESCE(ipaddress_3,'')
		FROM security_events
		WHERE timestamp >= $1
		  AND severity NOT IN ('INFO','')
		ORDER BY timestamp ASC
		LIMIT 5000
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []WindowEvent
	for rows.Next() {
		var ev WindowEvent
		var computer, agentHost, ipAddress3 string
		ev.Source = "windows"
		if err := rows.Scan(
			&ev.ID, &ev.Timestamp, &ev.EventID,
			&ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&computer, &agentHost,
			&ev.MitreTechnique, &ev.Severity, &ev.EventDetails,
			&ev.CommandLine, &ev.ImagePath,
			&ev.GrantedAccess, &ev.LogonType,
			&ipAddress3,
		); err != nil {
			continue
		}
		ev.AgentHost = agentHost
		if ev.AgentHost == "" {
			ev.AgentHost = computer
		}
		// Prefer ipAddress_3 (Security log source IP) over SourceIp_2 (Sysmon)
		if ev.SrcIP == "" && ipAddress3 != "" {
			ev.SrcIP = ipAddress3
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (e *Engine) queryFirewallEvents(since time.Time) ([]WindowEvent, error) {
	rows, err := e.db.Pool().Query(e.ctx, `
		SELECT id, received_at,
		       COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,''),
		       COALESCE(mitre_technique,''), COALESCE(threat_level,'INFO'),
		       COALESCE(event_details,''), COALESCE(action,''),
		       COALESCE(sent_bytes,'0'), COALESCE(log_type,''),
		       COALESCE(threat_type,'')
		FROM firewall_events
		WHERE received_at >= $1
		  AND threat_level NOT IN ('INFO','')
		ORDER BY received_at ASC
		LIMIT 5000
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []WindowEvent
	for rows.Next() {
		var ev WindowEvent
		var logType, threatType string
		ev.Source = "firewall"
		if err := rows.Scan(
			&ev.ID, &ev.Timestamp,
			&ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&ev.MitreTechnique, &ev.Severity,
			&ev.EventDetails, &ev.Action,
			&ev.SentBytes, &logType, &threatType,
		); err != nil {
			continue
		}
		ev.EventID = logType + "/" + threatType
		events = append(events, ev)
	}
	return events, rows.Err()
}

// queryLLMPassEvents reads WindowEvents from llm_pass_1 for the given source_type.
// Used when useLLMPass=true; gives correlation rules the LLM-enriched severity and summary.
func (e *Engine) queryLLMPassEvents(since time.Time, sourceType string) ([]WindowEvent, error) {
	rows, err := e.db.Pool().Query(e.ctx, `
		SELECT
		    COALESCE(agent_host,''), COALESCE(event_id,''),
		    COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,''),
		    COALESCE(final_mitre,''), COALESCE(final_severity,'INFO'),
		    COALESCE(final_summary,''),
		    created_at
		FROM llm_pass_1
		WHERE created_at >= $1
		  AND source_type = $2
		  AND final_severity NOT IN ('INFO','')
		ORDER BY created_at ASC
		LIMIT 5000
	`, since, sourceType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []WindowEvent
	for rows.Next() {
		var ev WindowEvent
		ev.Source = sourceType
		if err := rows.Scan(
			&ev.AgentHost, &ev.EventID,
			&ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&ev.MitreTechnique, &ev.Severity,
			&ev.EventDetails, &ev.Timestamp,
		); err != nil {
			continue
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// buildIPIndex creates a map of IP → all events (both sources) involving that IP.
func buildIPIndex(events []WindowEvent) map[string][]WindowEvent {
	idx := make(map[string][]WindowEvent)
	for _, ev := range events {
		if ev.SrcIP != "" {
			idx[ev.SrcIP] = append(idx[ev.SrcIP], ev)
		}
		if ev.DstIP != "" && ev.DstIP != ev.SrcIP {
			idx[ev.DstIP] = append(idx[ev.DstIP], ev)
		}
	}
	return idx
}

// ─── Incident persistence ─────────────────────────────────────────────────────

// Incident mirrors CorrelationIncident for internal use.
type Incident struct {
	CreatedAt       time.Time
	IncidentType    string
	Severity        string
	Confidence      string
	AffectedHost    string
	AffectedIP      string
	MitreTechniques string
	Description     string
	Evidence        string
	WindowStart     time.Time
	WindowEnd       time.Time
	SourceCount     int
}

func (e *Engine) saveIncident(inc Incident) error {
	_, err := e.db.Pool().Exec(e.ctx, `
		INSERT INTO correlation_incidents
		  (created_at, incident_type, severity, confidence,
		   affected_host, affected_ip, mitre_techniques,
		   description, evidence,
		   window_start, window_end, source_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT DO NOTHING
	`,
		time.Now(),
		inc.IncidentType, inc.Severity, inc.Confidence,
		inc.AffectedHost, inc.AffectedIP, inc.MitreTechniques,
		inc.Description, inc.Evidence,
		inc.WindowStart, inc.WindowEnd, inc.SourceCount,
	)
	return err
}

// marshalEvidence serialises a slice of WindowEvents to a compact JSON string.
func marshalEvidence(events []WindowEvent) string {
	type ev struct {
		Source    string    `json:"src"`
		Timestamp time.Time `json:"ts"`
		Details   string    `json:"details"`
		IP        string    `json:"ip,omitempty"`
	}
	out := make([]ev, 0, len(events))
	for _, e := range events {
		out = append(out, ev{
			Source:    e.Source,
			Timestamp: e.Timestamp,
			Details:   e.EventDetails,
			IP:        e.SrcIP,
		})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// joinMITRE combines non-empty, non-duplicate MITRE IDs from a list of events.
func joinMITRE(events []WindowEvent) string {
	seen := map[string]bool{}
	var ids []string
	for _, e := range events {
		for _, t := range strings.Split(e.MitreTechnique, ",") {
			t = strings.TrimSpace(t)
			if t != "" && !seen[t] {
				seen[t] = true
				ids = append(ids, t)
			}
		}
	}
	return strings.Join(ids, ",")
}

// earliest returns the minimum timestamp among a slice of events.
func earliest(events []WindowEvent) time.Time {
	t := time.Now()
	for _, e := range events {
		if e.Timestamp.Before(t) {
			t = e.Timestamp
		}
	}
	return t
}

// latest returns the maximum timestamp among a slice of events.
func latest(events []WindowEvent) time.Time {
	var t time.Time
	for _, e := range events {
		if e.Timestamp.After(t) {
			t = e.Timestamp
		}
	}
	return t
}

// inWindow checks if two events occurred within a given duration of each other.
func inWindow(a, b WindowEvent, window time.Duration) bool {
	diff := a.Timestamp.Sub(b.Timestamp)
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}

// ipToHost returns the best host label for a given IP (checking Windows events).
func ipToHost(ip string, winEvents []WindowEvent) string {
	for _, e := range winEvents {
		if (e.SrcIP == ip || e.DstIP == ip) && e.AgentHost != "" {
			return e.AgentHost
		}
	}
	return fmt.Sprintf("host@%s", ip)
}
