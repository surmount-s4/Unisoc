package correlator

// ─── Correlation Rules ────────────────────────────────────────────────────────
//
// Each rule function receives the full slices of Windows and Firewall events
// plus the IP-keyed index, and returns zero or more Incidents.
//
// Rules look for temporal co-occurrence (within CorrelationWindow) of events
// from different log sources that, together, constitute an attack sequence.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"strconv"
	"strings"
	"time"
)

// ─── Rule 1: C2 Beacon Confirmed ────────────────────────────────────────────
//
// Windows (Sysmon Event 3): Process connects to a suspicious port/IP.
// Firewall: Sees the same outbound connection (allowed).
// Together → confirmed C2 beacon, not just a Sysmon false positive.
func ruleC2BeaconConfirmed(
	winEvents, fwEvents []WindowEvent,
	byIP map[string][]WindowEvent,
) []Incident {

	c2Ports := map[string]bool{
		"4444": true, "5555": true, "6666": true, "7777": true,
		"1337": true, "31337": true, "9001": true, "9030": true,
	}

	var incidents []Incident

	for _, we := range winEvents {
		// Windows: flagged as C2 / CommandAndControl tactic
		if !strings.Contains(we.MitreTechnique, "T1571") &&
			!strings.Contains(we.MitreTechnique, "T1071") {
			continue
		}
		if we.DstIP == "" {
			continue
		}

		// Look for a matching firewall event from the same source IP within the window
		for _, fe := range fwEvents {
			if fe.SrcIP != we.SrcIP && fe.SrcIP != we.AgentHost {
				continue
			}
			if !c2Ports[fe.DstPort] && fe.DstIP != we.DstIP {
				continue
			}
			if !inWindow(we, fe, CorrelationWindow) {
				continue
			}
			if strings.ToUpper(fe.Action) != "ALLOW" {
				continue // firewall blocked it; that's separate
			}

			evidence := []WindowEvent{we, fe}
			incidents = append(incidents, Incident{
				CreatedAt:       time.Now(),
				IncidentType:    "C2_BEACON_CONFIRMED",
				Severity:        "CRITICAL",
				Confidence:      "HIGH",
				AffectedHost:    we.AgentHost,
				AffectedIP:      we.SrcIP,
				MitreTechniques: joinMITRE(evidence),
				Description: "C2 beacon confirmed by both Sysmon and Sophos firewall: " +
					we.AgentHost + " (" + we.SrcIP + ") → " + fe.DstIP + ":" + fe.DstPort,
				Evidence:    marshalEvidence(evidence),
				WindowStart: earliest(evidence),
				WindowEnd:   latest(evidence),
				SourceCount: 2,
			})
		}
	}
	return incidents
}

// ─── Rule 2: Brute Force Attack Confirmed ───────────────────────────────────
//
// Windows (Security 4625): Multiple failed logons from an external IP.
// Firewall: Blocked connection attempts from the same IP to port 3389/445/22.
// Together → confirmed brute force attack, both layers aware of it.
func ruleBruteForceWithFirewall(
	winEvents, fwEvents []WindowEvent,
	byIP map[string][]WindowEvent,
) []Incident {

	// Count failed logons (4625) per source IP
	failsByIP := map[string][]WindowEvent{}
	for _, we := range winEvents {
		if we.EventID != "4625" {
			continue
		}
		if we.SrcIP == "" || we.SrcIP == "127.0.0.1" || we.SrcIP == "-" {
			continue
		}
		failsByIP[we.SrcIP] = append(failsByIP[we.SrcIP], we)
	}

	bruteForPorts := map[string]bool{"3389": true, "445": true, "22": true, "5985": true}
	var incidents []Incident

	for srcIP, fails := range failsByIP {
		if len(fails) < 5 { // require at least 5 failures
			continue
		}

		// Find firewall blocks from the same IP
		var fwCorrelated []WindowEvent
		for _, fe := range fwEvents {
			if fe.SrcIP != srcIP {
				continue
			}
			if !bruteForPorts[fe.DstPort] {
				continue
			}
			if strings.ToUpper(fe.Action) != "DROP" &&
				strings.ToUpper(fe.Action) != "DENY" &&
				strings.ToUpper(fe.Action) != "REJECT" {
				continue
			}
			if !inWindow(fails[0], fe, CorrelationWindow) {
				continue
			}
			fwCorrelated = append(fwCorrelated, fe)
		}

		if len(fwCorrelated) == 0 {
			continue
		}

		evidence := append(fails, fwCorrelated...)
		host := ipToHost(srcIP, winEvents)

		incidents = append(incidents, Incident{
			CreatedAt:       time.Now(),
			IncidentType:    "BRUTE_FORCE_CONFIRMED",
			Severity:        "HIGH",
			Confidence:      "HIGH",
			AffectedHost:    host,
			AffectedIP:      srcIP,
			MitreTechniques: "T1110,T1110.001",
			Description: "Brute force confirmed: " + srcIP +
				" caused " + strconv.Itoa(len(fails)) + " Windows logon failures" +
				" + " + strconv.Itoa(len(fwCorrelated)) + " firewall blocks",
			Evidence:    marshalEvidence(evidence),
			WindowStart: earliest(evidence),
			WindowEnd:   latest(evidence),
			SourceCount: 2,
		})
	}
	return incidents
}

// ─── Rule 3: Credential Dump → Exfiltration ─────────────────────────────────
//
// Windows (Sysmon 10): LSASS memory access detected on host X.
// Firewall: Large outbound transfer from X's IP within the window.
// Together → credential dump followed by potential data exfiltration.
func ruleCredDumpToExfil(
	winEvents, fwEvents []WindowEvent,
	byIP map[string][]WindowEvent,
) []Incident {

	var incidents []Incident

	for _, we := range winEvents {
		// LSASS access = T1003.001
		if !strings.Contains(we.MitreTechnique, "T1003") {
			continue
		}
		if we.SrcIP == "" {
			continue
		}

		// Find large outbound from the same host IP after the cred dump
		for _, fe := range fwEvents {
			if fe.SrcIP != we.SrcIP {
				continue
			}
			if fe.Timestamp.Before(we.Timestamp) {
				continue // exfil must come *after* the dump
			}
			if fe.Timestamp.Sub(we.Timestamp) > CorrelationWindow {
				continue
			}

			sent, _ := strconv.ParseInt(fe.SentBytes, 10, 64)
			if sent < 10_000_000 { // exfil threshold: 10 MB
				continue
			}
			if strings.ToUpper(fe.Action) != "ALLOW" {
				continue
			}

			evidence := []WindowEvent{we, fe}
			incidents = append(incidents, Incident{
				CreatedAt:       time.Now(),
				IncidentType:    "CRED_DUMP_THEN_EXFIL",
				Severity:        "CRITICAL",
				Confidence:      "HIGH",
				AffectedHost:    we.AgentHost,
				AffectedIP:      we.SrcIP,
				MitreTechniques: "T1003.001,T1041",
				Description: "Credential dump on " + we.AgentHost +
					" followed by " + fe.SentBytes + " bytes exfiltrated → " + fe.DstIP,
				Evidence:    marshalEvidence(evidence),
				WindowStart: earliest(evidence),
				WindowEnd:   latest(evidence),
				SourceCount: 2,
			})
		}
	}
	return incidents
}

// ─── Rule 4: Lateral Movement Confirmed ─────────────────────────────────────
//
// Windows (Security 4624): Successful logon from host A to host B.
// Firewall: Internal SMB/RDP/WinRM traffic from A → B around the same time.
// Together → confirmed lateral movement hop.
func ruleLateralMovementConfirmed(
	winEvents, fwEvents []WindowEvent,
	byIP map[string][]WindowEvent,
) []Incident {

	lateralPorts := map[string]bool{
		"445": true, "3389": true, "5985": true, "5986": true, "22": true,
	}
	var incidents []Incident

	for _, we := range winEvents {
		// Successful network logon from a remote IP
		if we.EventID != "4624" {
			continue
		}
		if we.LogonType != "3" && we.LogonType != "10" { // Network / RemoteInteractive
			continue
		}
		if we.SrcIP == "" || we.SrcIP == "127.0.0.1" || we.SrcIP == "-" {
			continue
		}

		// Find firewall traffic from the same source to the same dest host
		for _, fe := range fwEvents {
			if fe.SrcIP != we.SrcIP {
				continue
			}
			if !lateralPorts[fe.DstPort] {
				continue
			}
			if strings.ToUpper(fe.Action) != "ALLOW" {
				continue
			}
			if !inWindow(we, fe, CorrelationWindow) {
				continue
			}

			evidence := []WindowEvent{we, fe}
			incidents = append(incidents, Incident{
				CreatedAt:       time.Now(),
				IncidentType:    "LATERAL_MOVEMENT_CONFIRMED",
				Severity:        "HIGH",
				Confidence:      "HIGH",
				AffectedHost:    we.AgentHost,
				AffectedIP:      we.SrcIP,
				MitreTechniques: "T1021," + we.MitreTechnique,
				Description: "Lateral movement: " + we.SrcIP +
					" → " + we.AgentHost + " (logon type " + we.LogonType + ")" +
					" confirmed by firewall on port " + fe.DstPort,
				Evidence:    marshalEvidence(evidence),
				WindowStart: earliest(evidence),
				WindowEnd:   latest(evidence),
				SourceCount: 2,
			})
		}
	}
	return incidents
}

// ─── Rule 5: Firewall Deny → Windows Success (Firewall Bypass) ───────────────
//
// Firewall: Blocked traffic from IP X to host Y.
// Windows: Successful logon (4624) on Y from IP X shortly after.
// Together → attacker bypassed or worked around the firewall block.
func ruleFirewallDenyThenSuccess(
	winEvents, fwEvents []WindowEvent,
	byIP map[string][]WindowEvent,
) []Incident {

	var incidents []Incident

	for _, fe := range fwEvents {
		action := strings.ToUpper(fe.Action)
		if action != "DROP" && action != "DENY" && action != "REJECT" {
			continue
		}
		if fe.SrcIP == "" {
			continue
		}

		for _, we := range winEvents {
			if we.EventID != "4624" {
				continue
			}
			if we.SrcIP != fe.SrcIP {
				continue
			}
			// Logon must happen AFTER the firewall block
			if !we.Timestamp.After(fe.Timestamp) {
				continue
			}
			if we.Timestamp.Sub(fe.Timestamp) > CorrelationWindow {
				continue
			}

			evidence := []WindowEvent{fe, we}
			incidents = append(incidents, Incident{
				CreatedAt:       time.Now(),
				IncidentType:    "FIREWALL_BYPASS_SUSPECTED",
				Severity:        "CRITICAL",
				Confidence:      "MEDIUM",
				AffectedHost:    we.AgentHost,
				AffectedIP:      fe.SrcIP,
				MitreTechniques: "T1562.004,T1078",
				Description: "Firewall blocked " + fe.SrcIP + " → " + fe.DstIP +
					":" + fe.DstPort + " but Windows shows successful logon from same IP on " +
					we.AgentHost + " shortly after",
				Evidence:    marshalEvidence(evidence),
				WindowStart: earliest(evidence),
				WindowEnd:   latest(evidence),
				SourceCount: 2,
			})
		}
	}
	return incidents
}

// ─── internal helpers (re-exported from engine.go via same package) ───────────

// severityRank converts severity strings to a comparable integer.
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

// maxSeverity returns the highest severity string from a set of events.
func maxSeverity(events []WindowEvent) string {
	best := "LOW"
	for _, e := range events {
		if severityRank(e.Severity) > severityRank(best) {
			best = e.Severity
		}
	}
	return best
}
