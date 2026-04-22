package models

import "time"

// ---------------------------------------------------------------------------
// LLMInput — minimal normalised view of one event sent to the LLM.
// Fields are chosen for maximum signal, minimum token cost.
// ---------------------------------------------------------------------------

// LLMInput represents the normalised fields sent to the LLM for one event.
type LLMInput struct {
	SourceType      string `json:"source_type"`      // "windows" | "firewall"
	AgentHost       string `json:"agent_host"`       // originating host
	EventID         string `json:"event_id"`         // Windows event ID or Sophos log_type
	RuleSeverity    string `json:"rule_severity"`    // severity from rule-based detector
	MitreTechnique  string `json:"mitre_technique"`  // ATT&CK technique(s) from rules
	DetectionModule string `json:"detection_module"` // e.g. "Execution", "CredentialAccess"
	EventDetails    string `json:"event_details"`    // rule-based short description
	SrcIP           string `json:"src_ip,omitempty"`
	DstIP           string `json:"dst_ip,omitempty"`
	DstPort         string `json:"dst_port,omitempty"`
	ProcessName     string `json:"process_name,omitempty"` // image_2 for windows
	CommandLine     string `json:"command_line,omitempty"` // commandline_2 truncated to 300 chars
	Action          string `json:"action,omitempty"`       // firewall Allow/Deny
	SentBytes       string `json:"sent_bytes,omitempty"`   // firewall transfer volume
	Timestamp       string `json:"timestamp"`              // ISO8601
	FingerprintHash string `json:"-"`                      // pre-computed SHA-256, not sent to LLM
}

// ---------------------------------------------------------------------------
// LLMOutput — structured JSON the LLM is asked to return per 5-second window.
// ---------------------------------------------------------------------------

// LLMOutput is the JSON object expected back from the LLM using forensic prompt.
type LLMOutput struct {
	Verdict   string   `json:"verdict"`   // Info | Warning | Critical
	Reasoning string   `json:"reasoning"` // concise forensic explanation
	IOC       []string `json:"ioc"`       // IoC list from model output
	IOA       []string `json:"ioa"`       // IoA list from model output

	// Model metadata
	Model      string `json:"model,omitempty"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	TokensUsed int    `json:"tokens_used,omitempty"`
}

// ---------------------------------------------------------------------------
// LLMPassEvent — one row in the llm_pass_1 table.
// ---------------------------------------------------------------------------

// LLMPassEvent is a unified, LLM-enriched event stored in llm_pass_1.
// It is the single input table for the correlation engine when LLM is enabled.
type LLMPassEvent struct {
	// Source linkage
	SourceEventID int64     `json:"source_event_id"` // id from security_events or firewall_events (0 if unknown)
	SourceType    string    `json:"source_type"`     // "windows" | "firewall"
	WindowTS      time.Time `json:"window_ts"`       // start of the 5-sec poll window

	// Normalised identity fields (shared semantic anchor for correlation)
	AgentHost string `json:"agent_host"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	DstPort   string `json:"dst_port"`
	EventID   string `json:"event_id"`

	// Rule-based fields (always populated)
	RawSummary   string `json:"raw_summary"` // EventDetails from detector
	RuleSeverity string `json:"rule_severity"`
	RuleMitre    string `json:"rule_mitre"`
	RuleIsIOA    bool   `json:"rule_is_ioa"`

	// LLM-enriched fields (null/zero if LLM disabled or circuit open)
	LLMSeverity   string  `json:"llm_severity"`
	LLMSummary    string  `json:"llm_short_summary"`
	LLMIsIOA      bool    `json:"llm_is_ioa"`
	LLMIsIOC      bool    `json:"llm_is_ioc"`
	LLMIOCValues  string  `json:"llm_ioc_values"` // comma-separated
	LLMIOAValues  string  `json:"llm_ioa_values"` // comma-separated
	LLMMitre      string  `json:"llm_mitre_technique"`
	LLMConfidence float64 `json:"llm_confidence"`
	LLMModel      string  `json:"llm_model"`
	LLMLatencyMs  int64   `json:"llm_latency_ms"`
	LLMEnabled    bool    `json:"llm_enabled"` // false = passthrough mode

	// Final resolved fields: LLM output preferred, rule-based fallback
	FinalSeverity string `json:"final_severity"`
	FinalSummary  string `json:"final_summary"`
	FinalMitre    string `json:"final_mitre"`
}
