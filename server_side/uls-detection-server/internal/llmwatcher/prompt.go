package llmwatcher

import (
	"fmt"
	"strings"

	"uls-detection-server/internal/models"
)

// BuildWindowPrompt constructs the forensic prompt for one 5-second window.
func BuildWindowPrompt(inputs []models.LLMInput, windowSeconds int) string {
	if windowSeconds <= 0 {
		windowSeconds = 5
	}

	prompt := fmt.Sprintf(`You are a digital forensic analyst. Analyze the following system logs collected over a %d-second window.

Instructions:
1. If malicious activity is detected:
   - Provide the forensic evidence and cause.
   - Extract Indicators of Compromise (IoCs): IPs, domains, file paths, hashes, registry keys, etc.
   - Extract Indicators of Attack (IoAs): persistence, privilege escalation, lateral movement, defense evasion, etc.
2. If benign, respond strictly with: "No malicious activity detected."
3. Always respond in JSON with this exact schema:

{
  "verdict": "Info | Warning | Critical",
  "reasoning": "Concise forensic explanation (if malicious, else 'No malicious activity detected.')",
  "ioc": ["list of IoCs if any, else []"],
  "ioa": ["list of IoAs if any, else []"]
}
`, windowSeconds)

	var sb strings.Builder
	sb.WriteString(prompt)
	sb.WriteString("\nSystem logs:\n\n")

	for i, ev := range inputs {
		sb.WriteString(fmt.Sprintf("[%d] source=%s host=%q event_id=%q rule_severity=%s mitre=%q module=%q\n",
			i, ev.SourceType, ev.AgentHost, ev.EventID,
			ev.RuleSeverity, ev.MitreTechnique, ev.DetectionModule))
		sb.WriteString(fmt.Sprintf("    rule_detail=%q\n", ev.EventDetails))

		if ev.SrcIP != "" || ev.DstIP != "" {
			sb.WriteString(fmt.Sprintf("    network: %s -> %s:%s\n", ev.SrcIP, ev.DstIP, ev.DstPort))
		}
		if ev.ProcessName != "" {
			sb.WriteString(fmt.Sprintf("    process: %q\n", ev.ProcessName))
		}
		if ev.CommandLine != "" {
			line := ev.CommandLine
			if len(line) > 300 {
				line = line[:300] + "..."
			}
			sb.WriteString(fmt.Sprintf("    cmdline: %q\n", line))
		}
		if ev.Action != "" {
			sb.WriteString(fmt.Sprintf("    fw_action: %s sent_bytes: %s\n", ev.Action, ev.SentBytes))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "..."
}

// mergePassthrough converts a []LLMInput to a window-level forensic output when LLM is disabled.
func mergePassthrough(inputs []models.LLMInput) models.LLMOutput {
	verdict := "Info"
	reasoning := "No malicious activity detected."
	ioc := make([]string, 0, 8)
	ioa := make([]string, 0, 8)

	for _, inp := range inputs {
		sevVerdict := severityToVerdict(inp.RuleSeverity)
		if verdictRank(sevVerdict) > verdictRank(verdict) {
			verdict = sevVerdict
		}

		if strings.TrimSpace(inp.EventDetails) != "" && reasoning == "No malicious activity detected." {
			reasoning = truncate(strings.TrimSpace(inp.EventDetails), 300)
		}

		if inp.SrcIP != "" {
			ioc = append(ioc, inp.SrcIP)
		}
		if inp.DstIP != "" {
			ioc = append(ioc, inp.DstIP)
		}
		if inp.DstPort != "" {
			ioc = append(ioc, "port:"+inp.DstPort)
		}
		if inp.MitreTechnique != "" {
			ioa = append(ioa, "mitre:"+inp.MitreTechnique)
		}
	}

	ioc = uniqueStrings(ioc)
	ioa = uniqueStrings(ioa)

	if verdict == "Info" && len(ioc) == 0 && len(ioa) == 0 {
		reasoning = "No malicious activity detected."
	}

	return models.LLMOutput{
		Verdict:   verdict,
		Reasoning: reasoning,
		IOC:       ioc,
		IOA:       ioa,
		Model:     "passthrough",
		LatencyMs: 0,
	}
}

// iocValuesToString joins a slice of IOC values to a comma-separated string.
func iocValuesToString(vals []string) string {
	return strings.Join(vals, ",")
}

// ioaValuesToString joins a slice of IOA values to a comma-separated string.
func ioaValuesToString(vals []string) string {
	return strings.Join(vals, ",")
}

func verdictToSeverity(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "critical":
		return "CRITICAL"
	case "warning":
		return "MEDIUM"
	case "info":
		return "INFO"
	default:
		return ""
	}
}

func confidenceFromVerdict(verdict string) float64 {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "critical":
		return 0.90
	case "warning":
		return 0.70
	case "info":
		return 0.40
	default:
		return 0
	}
}

func severityToVerdict(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return "Critical"
	case "MEDIUM", "LOW":
		return "Warning"
	default:
		return "Info"
	}
}

func verdictRank(verdict string) int {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
