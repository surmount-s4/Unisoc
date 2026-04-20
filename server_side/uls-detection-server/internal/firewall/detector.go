package firewall

import (
	"strconv"
	"strings"

	"uls-detection-server/internal/models"
)

// Detector applies threat detection rules to Sophos firewall events.
type Detector struct{}

// New returns a new firewall Detector.
func New() *Detector { return &Detector{} }

// Detect evaluates a FirewallEvent against all detection rules and returns
// the highest-confidence FirewallDetectionResult found.
func (d *Detector) Detect(e *models.FirewallEvent) models.FirewallDetectionResult {
	info := models.FirewallDetectionResult{ThreatLevel: "INFO"}

	action      := strings.ToUpper(e.Action)
	dstPort     := e.DstPort
	srcIP        := e.SrcIP
	dstIP        := e.DstIP
	protocol    := strings.ToUpper(e.Protocol)
	logType     := strings.ToLower(e.LogType)
	logComp     := strings.ToLower(e.LogComponent)
	srcZoneType := strings.ToUpper(e.SrcZoneType)
	dstZoneType := strings.ToUpper(e.DstZoneType)

	// ── IDS / IPS / ATP / Sandbox alerts ────────────────────────────────────
	if strings.Contains(logType, "ids") ||
		strings.Contains(logType, "ips") ||
		strings.Contains(logType, "atp") ||
		strings.Contains(logType, "sandbox") ||
		strings.Contains(logComp, "intrusion") ||
		strings.Contains(logComp, "advanced threat") {

		tl := "HIGH"
		if strings.EqualFold(e.Severity, "critical") {
			tl = "CRITICAL"
		}
		return models.FirewallDetectionResult{
			ThreatLevel:     tl,
			ThreatType:      "IDS_IPS_ALERT",
			MitreTechnique:  "T1190",
			DetectionModule: "Firewall_IDS",
			EventDetails:    "Sophos IDS/ATP: " + e.Message + " | class=" + e.Classification + " src=" + srcIP,
		}
	}

	// ── Known C2 / RAT ports ─────────────────────────────────────────────────
	c2Ports := map[string]bool{
		"4444": true, "4445": true, "5555": true, "6666": true,
		"7777": true, "1337": true, "31337": true, "9001": true,
		"9030": true, "6667": true, "6697": true, // Tor / IRC C2
	}
	if c2Ports[dstPort] {
		tl := "CRITICAL" // allowed outbound = worst case
		if action == "DROP" || action == "DENY" || action == "REJECT" {
			tl = "HIGH" // blocked but still noteworthy
		}
		return models.FirewallDetectionResult{
			ThreatLevel:     tl,
			ThreatType:      "C2_PORT_OUTBOUND",
			MitreTechnique:  "T1571",
			DetectionModule: "Firewall_C2",
			EventDetails: "Connection to known C2 port " + dstPort + ": " +
				srcIP + " → " + dstIP + " [" + action + "]",
		}
	}

	// ── External inbound to sensitive internal ports ──────────────────────
	sensitivePorts := map[string]string{
		"22": "SSH", "3389": "RDP", "5985": "WinRM-HTTP",
		"5986": "WinRM-HTTPS", "445": "SMB", "135": "RPC",
		"137": "NetBIOS", "139": "NetBIOS-Session",
		"1433": "MSSQL", "3306": "MySQL", "5432": "PostgreSQL",
		"27017": "MongoDB", "6379": "Redis", "9200": "Elasticsearch",
	}
	if svc, ok := sensitivePorts[dstPort]; ok && srcZoneType == "WAN" && dstZoneType == "LAN" {
		tl := "MEDIUM"
		if action == "ALLOW" {
			tl = "HIGH" // external reached an internal sensitive port!
		}
		tech := "T1133" // External Remote Services
		if dstPort == "22" || dstPort == "3389" {
			tech = "T1021.001" // Remote Desktop / SSH
		}
		return models.FirewallDetectionResult{
			ThreatLevel:     tl,
			ThreatType:      "EXTERNAL_ACCESS_SENSITIVE_PORT",
			MitreTechnique:  tech,
			DetectionModule: "Firewall_ExternalAccess",
			EventDetails: "External → internal " + svc + " (" + dstPort + "): " +
				srcIP + " → " + dstIP + " [" + action + "]",
		}
	}

	// ── Internal → Internal on lateral-movement ports ─────────────────────
	lateralPorts := map[string]string{
		"445": "SMB", "3389": "RDP", "5985": "WinRM",
		"22": "SSH", "135": "RPC", "5986": "WinRM-HTTPS",
	}
	if svc, ok := lateralPorts[dstPort]; ok && srcZoneType == "LAN" && dstZoneType == "LAN" {
		return models.FirewallDetectionResult{
			ThreatLevel:     "MEDIUM",
			ThreatType:      "LATERAL_MOVEMENT_INDICATOR",
			MitreTechnique:  "T1021",
			DetectionModule: "Firewall_LateralMovement",
			EventDetails: "Internal host using " + svc + " to reach another internal host: " +
				srcIP + " → " + dstIP,
		}
	}

	// ── Large outbound transfer (potential exfiltration) ──────────────────
	sent, _ := strconv.ParseInt(e.SentBytes, 10, 64)
	if sent > 50_000_000 && srcZoneType == "LAN" && dstZoneType == "WAN" { // >50 MB
		return models.FirewallDetectionResult{
			ThreatLevel:     "MEDIUM",
			ThreatType:      "LARGE_OUTBOUND_TRANSFER",
			MitreTechnique:  "T1041",
			DetectionModule: "Firewall_Exfil",
			EventDetails: "Large outbound from " + srcIP + ": " +
				e.SentBytes + " bytes → " + dstIP + " [" + e.AppName + "]",
		}
	}

	// ── DNS over TCP (DNS tunneling indicator) ────────────────────────────
	if dstPort == "53" && protocol == "TCP" {
		return models.FirewallDetectionResult{
			ThreatLevel:     "MEDIUM",
			ThreatType:      "DNS_OVER_TCP",
			MitreTechnique:  "T1071.004",
			DetectionModule: "Firewall_DNSTunnel",
			EventDetails:    "DNS over TCP from " + srcIP + " – possible tunneling",
		}
	}

	// ── Non-HTTP/S traffic on port 80/443 (protocol anomaly) ─────────────
	if (dstPort == "80" || dstPort == "443") && protocol != "TCP" && protocol != "" {
		return models.FirewallDetectionResult{
			ThreatLevel:     "LOW",
			ThreatType:      "PROTOCOL_ANOMALY",
			MitreTechnique:  "T1571",
			DetectionModule: "Firewall_Anomaly",
			EventDetails:    "Non-TCP traffic on port " + dstPort + " proto=" + protocol + " from " + srcIP,
		}
	}

	// ── Denied connection (low severity; useful for correlation) ──────────
	if action == "DROP" || action == "DENY" || action == "REJECT" {
		return models.FirewallDetectionResult{
			ThreatLevel:     "LOW",
			ThreatType:      "FIREWALL_DENY",
			MitreTechnique:  "",
			DetectionModule: "Firewall_Policy",
			EventDetails: "Blocked: " + srcIP + " → " + dstIP + ":" + dstPort +
				" [" + protocol + "] rule=" + e.FwRuleID,
		}
	}

	return info
}
