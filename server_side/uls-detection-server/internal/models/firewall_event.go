package models

import "time"

// FirewallEvent represents a normalized Sophos XG / SFOS firewall log event.
// Field names mirror the JSON keys produced by sophos_syslog_receiver.py.
type FirewallEvent struct {
	// ── Source metadata ──────────────────────────────────────────────────────
	ReceivedAt time.Time `json:"received_at"`
	SensorIP   string    `json:"sensor_ip"`
	RawLog     string    `json:"raw_log"`

	// ── Device ───────────────────────────────────────────────────────────────
	DeviceName string `json:"device_name"`
	DeviceID   string `json:"device_id"`

	// ── Timestamps ───────────────────────────────────────────────────────────
	LogDate  string `json:"log_date"`
	LogTime  string `json:"log_time"`
	Timezone string `json:"timezone"`

	// ── Classification ───────────────────────────────────────────────────────
	LogID        string `json:"log_id"`
	LogType      string `json:"log_type"`
	LogComponent string `json:"log_component"`
	LogSubtype   string `json:"log_subtype"`
	Status       string `json:"status"`
	Priority     string `json:"priority"`
	Action       string `json:"action"` // ALLOW | DROP | DENY | REJECT

	// ── Source network ───────────────────────────────────────────────────────
	SrcIP          string `json:"src_ip"`
	SrcPort        string `json:"src_port"`
	SrcMAC         string `json:"src_mac"`
	SrcCountry     string `json:"src_country_code"`
	SrcZone        string `json:"src_zone"`
	SrcZoneType    string `json:"src_zone_type"` // LAN | WAN | DMZ …
	SrcTransIP     string `json:"src_trans_ip"`

	// ── Destination network ──────────────────────────────────────────────────
	DstIP       string `json:"dst_ip"`
	DstPort     string `json:"dst_port"`
	DstCountry  string `json:"dst_country_code"`
	DstZone     string `json:"dst_zone"`
	DstZoneType string `json:"dst_zone_type"`

	// ── Protocol ─────────────────────────────────────────────────────────────
	Protocol  string `json:"protocol"`
	EtherType string `json:"ether_type"`
	ConnEvent string `json:"conn_event"` // Start | Stop
	ConnID    string `json:"conn_id"`

	// ── Traffic stats ────────────────────────────────────────────────────────
	SentBytes string `json:"sent_bytes"`
	RecvBytes string `json:"recv_bytes"`
	SentPkts  string `json:"sent_pkts"`
	RecvPkts  string `json:"recv_pkts"`

	// ── Firewall policy ──────────────────────────────────────────────────────
	FwRuleID  string `json:"fw_rule_id"`
	NatRuleID string `json:"nat_rule_id"`
	FwType    string `json:"fw_type"`

	// ── User ─────────────────────────────────────────────────────────────────
	User      string `json:"user"`
	UserGroup string `json:"user_group"`

	// ── Application (DPI) ────────────────────────────────────────────────────
	AppName string `json:"app_name"`
	AppRisk string `json:"app_risk"`

	// ── Threat / IPS / ATP ───────────────────────────────────────────────────
	Message        string `json:"message"`
	Severity       string `json:"severity"`
	Classification string `json:"classification"`
	URL            string `json:"url"`

	// ── Detection results (populated server-side) ─────────────────────────
	ThreatLevel     string `json:"threat_level"`
	ThreatType      string `json:"threat_type"`
	MitreTechnique  string `json:"mitre_technique"`
	DetectionModule string `json:"detection_module"`
	EventDetails    string `json:"event_details"`
}

// FirewallDetectionResult carries detection output for a FirewallEvent.
type FirewallDetectionResult struct {
	ThreatLevel     string // INFO | LOW | MEDIUM | HIGH | CRITICAL
	ThreatType      string
	MitreTechnique  string
	DetectionModule string
	EventDetails    string
}

// CorrelationIncident represents a confirmed multi-source attack sequence.
type CorrelationIncident struct {
	// ── Identity ─────────────────────────────────────────────────────────────
	CreatedAt    time.Time `json:"created_at"`
	IncidentType string    `json:"incident_type"`
	Severity     string    `json:"severity"`     // MEDIUM | HIGH | CRITICAL
	Confidence   string    `json:"confidence"`   // LOW | MEDIUM | HIGH

	// ── Attribution ──────────────────────────────────────────────────────────
	AffectedHost string `json:"affected_host"` // hostname from Windows events
	AffectedIP   string `json:"affected_ip"`   // IP linking both source types

	// ── MITRE ────────────────────────────────────────────────────────────────
	MitreTechniques string `json:"mitre_techniques"` // comma-separated

	// ── Description ──────────────────────────────────────────────────────────
	Description string `json:"description"`
	Evidence    string `json:"evidence"` // JSON snippet of linked events

	// ── Time window ──────────────────────────────────────────────────────────
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	SourceCount int       `json:"source_count"` // number of distinct log sources
}
