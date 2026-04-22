package correlationengine

import "time"

// Config controls runtime behavior for the correlation engine v2.
type Config struct {
	Enabled                 bool
	EngineName              string
	TickSeconds             int
	WindowMinutes           int
	BARTInProcess           bool
	BARTServiceURL          string
	BARTModel               string
	BARTModelID             string
	BARTModelPath           string
	BARTPythonBinary        string
	BARTRunnerPath          string
	BARTTimeout             time.Duration
	BARTConfidenceThreshold float64
	CorrelatorLLMURL        string
	CorrelatorLLMModel      string
	CorrelatorLLMTimeout    time.Duration
	MaxWindowsEvents        int
	MaxFirewallEvents       int
	MaxScadaEvents          int
}

func (c *Config) setDefaults() {
	if c.EngineName == "" {
		c.EngineName = "correlationengine_v2"
	}
	if c.TickSeconds <= 0 {
		c.TickSeconds = 60
	}
	if c.WindowMinutes <= 0 {
		c.WindowMinutes = 10
	}
	if !c.BARTInProcess && c.BARTServiceURL == "" {
		// Default to in-process mode when no external service URL is configured.
		c.BARTInProcess = true
	}
	if c.BARTModelID == "" {
		c.BARTModelID = "facebook/bart-large-mnli"
	}
	if c.BARTPythonBinary == "" {
		c.BARTPythonBinary = "python"
	}
	if c.BARTRunnerPath == "" {
		c.BARTRunnerPath = "internal/correlationengine/bart_runner.py"
	}
	if c.BARTTimeout <= 0 {
		c.BARTTimeout = 15 * time.Second
	}
	if c.BARTConfidenceThreshold <= 0 {
		c.BARTConfidenceThreshold = 0.30
	}
	if c.CorrelatorLLMTimeout <= 0 {
		c.CorrelatorLLMTimeout = 60 * time.Second
	}
	if c.MaxWindowsEvents <= 0 {
		c.MaxWindowsEvents = 3000
	}
	if c.MaxFirewallEvents <= 0 {
		c.MaxFirewallEvents = 5000
	}
	if c.MaxScadaEvents <= 0 {
		c.MaxScadaEvents = 5000
	}
}

// WindowsPassEvent is read from llm_pass_1 and then BART-gated.
type WindowsPassEvent struct {
	ID            int64     `json:"id"`
	WindowTS      time.Time `json:"window_ts"`
	CreatedAt     time.Time `json:"created_at"`
	AgentHost     string    `json:"agent_host"`
	SrcIP         string    `json:"src_ip"`
	DstIP         string    `json:"dst_ip"`
	DstPort       string    `json:"dst_port"`
	EventID       string    `json:"event_id"`
	FinalSeverity string    `json:"final_severity"`
	FinalSummary  string    `json:"final_summary"`
	FinalMitre    string    `json:"final_mitre"`
}

// FirewallWindowEvent is read from firewall_events for a correlation window.
type FirewallWindowEvent struct {
	ID             int64     `json:"id"`
	ReceivedAt     time.Time `json:"received_at"`
	SrcIP          string    `json:"src_ip"`
	DstIP          string    `json:"dst_ip"`
	DstPort        string    `json:"dst_port"`
	Action         string    `json:"action"`
	ThreatLevel    string    `json:"threat_level"`
	MitreTechnique string    `json:"mitre_technique"`
	EventDetails   string    `json:"event_details"`
}

// ScadaWindowEvent is read from scada_logs for a correlation window.
type ScadaWindowEvent struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Source         string    `json:"source"`
	Tag            string    `json:"tag"`
	Name           string    `json:"name"`
	Message        string    `json:"message"`
	State          string    `json:"state"`
	Classification string    `json:"classification"`
	Username       string    `json:"username"`
	Userlocation   string    `json:"userlocation"`
	RawLog         string    `json:"raw_log"`
}

// BARTDecision is the per-event classification output.
type BARTDecision struct {
	LLMPassID      int64          `json:"llm_pass_id"`
	WindowStart    time.Time      `json:"window_start"`
	WindowEnd      time.Time      `json:"window_end"`
	AgentHost      string         `json:"agent_host"`
	EventID        string         `json:"event_id"`
	Classification string         `json:"classification"` // malicious | benign
	Confidence     float64        `json:"confidence"`
	Threshold      float64        `json:"threshold"`
	Model          string         `json:"model"`
	RawResponse    map[string]any `json:"raw_response"`
	ErrorText      string         `json:"error_text,omitempty"`
}

// CorrelationIncident is a normalized incident candidate produced by the correlator LLM.
type CorrelationIncident struct {
	IncidentType    string   `json:"incident_type"`
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	AffectedHost    string   `json:"affected_host"`
	AffectedIP      string   `json:"affected_ip"`
	MitreTechniques []string `json:"mitre_techniques"`
	Description     string   `json:"description"`
	Evidence        []string `json:"evidence"`
}

// CorrelationLLMResult is the strict parser target for correlator output.
type CorrelationLLMResult struct {
	OverallAssessment   string                `json:"overall_assessment"` // malicious | suspicious | healthy | safe
	Confidence          float64               `json:"confidence"`
	Summary             string                `json:"summary"`
	IncidentCandidates  []CorrelationIncident `json:"incident_candidates"`
	AttackChainProgress []map[string]any      `json:"attack_chain_progression"`
	Recommendations     []string              `json:"recommendations"`
}

// CorrelationPayload is sent to the correlator LLM.
type CorrelationPayload struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`

	Counts struct {
		WindowsTotal     int `json:"windows_total"`
		WindowsMalicious int `json:"windows_malicious"`
		WindowsBenign    int `json:"windows_benign"`
		FirewallTotal    int `json:"firewall_total"`
		ScadaTotal       int `json:"scada_total"`
	} `json:"counts"`

	WindowsEvents  []WindowsPassEvent    `json:"windows_events"`
	FirewallEvents []FirewallWindowEvent `json:"firewall_events"`
	ScadaEvents    []ScadaWindowEvent    `json:"scada_events"`

	// ProcessChainEvidence is keyed by host and includes GUID-derived creation
	// and source-target process relationship trees for this correlation window.
	ProcessChainEvidence map[string]map[string]any `json:"process_chain_evidence,omitempty"`
}
