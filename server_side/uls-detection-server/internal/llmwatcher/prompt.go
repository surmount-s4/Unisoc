package llmwatcher

import (
	"fmt"
	"strings"

	"uls-detection-server/internal/models"
)

// ---------------------------------------------------------------------------
// Prompt construction for LLM security event analysis
// ---------------------------------------------------------------------------

const systemInstruction = `You are a security analyst AI. Analyse security events and return a JSON object.
Return ONLY valid JSON. No markdown, no explanation, no code blocks.
The JSON must have this exact structure:
{
  "results": [
    {
      "index": 0,
      "severity": "HIGH",
      "is_ioa": true,
      "is_ioc": false,
      "ioc_values": [],
      "short_summary": "One sentence, max 80 chars, describing what happened",
      "mitre_technique": "T1059.001",
      "confidence": 0.92
    }
  ]
}

Severity must be one of: INFO, LOW, MEDIUM, HIGH, CRITICAL
is_ioa = true if the event matches a behavioural attack pattern (tool-agnostic)
is_ioc = true if a concrete artifact (IP, hash, domain, path) indicates compromise
ioc_values = extracted artifact strings (empty array if none)
mitre_technique = ATT&CK technique ID(s), comma-separated; use the rule hint if correct
confidence = how confident you are, 0.0-1.0
`

// BuildWindowPrompt constructs a single prompt for a batch of events from one window.
// Events are rendered as a compact numbered table to minimise token usage.
func BuildWindowPrompt(inputs []models.LLMInput) string {
	var sb strings.Builder

	sb.WriteString(systemInstruction)
	sb.WriteString("\n\nAnalyse the following ")
	sb.WriteString(fmt.Sprintf("%d security event(s):\n\n", len(inputs)))

	for i, ev := range inputs {
		sb.WriteString(fmt.Sprintf("[%d] source=%s host=%q event_id=%q rule_severity=%s mitre=%q module=%q\n",
			i, ev.SourceType, ev.AgentHost, ev.EventID,
			ev.RuleSeverity, ev.MitreTechnique, ev.DetectionModule))
		sb.WriteString(fmt.Sprintf("    rule_detail=%q\n", ev.EventDetails))

		if ev.SrcIP != "" || ev.DstIP != "" {
			sb.WriteString(fmt.Sprintf("    network: %s → %s:%s\n", ev.SrcIP, ev.DstIP, ev.DstPort))
		}
		if ev.ProcessName != "" {
			sb.WriteString(fmt.Sprintf("    process: %q\n", ev.ProcessName))
		}
		if ev.CommandLine != "" {
			line := ev.CommandLine
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			sb.WriteString(fmt.Sprintf("    cmdline: %q\n", line))
		}
		if ev.Action != "" {
			sb.WriteString(fmt.Sprintf("    fw_action: %s sent_bytes: %s\n", ev.Action, ev.SentBytes))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Return results array with one entry per event (index 0 to ")
	sb.WriteString(fmt.Sprintf("%d).\n", len(inputs)-1))

	return sb.String()
}

// passthroughResult builds an LLMEventResult from rule-based fields when LLM is disabled.
func passthroughResult(i int, input models.LLMInput) models.LLMEventResult {
	return models.LLMEventResult{
		Index:          i,
		Severity:       input.RuleSeverity,
		IsIOA:          input.MitreTechnique != "",
		IsIOC:          false,
		IOCValues:      []string{},
		ShortSummary:   truncate(input.EventDetails, 80),
		MitreTechnique: input.MitreTechnique,
		Confidence:     0.8, // rule-based rules are high-precision; use 0.8 as canonical fallback
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// mergePassthrough converts a []LLMInput to a passthrough LLMOutput without any LLM call.
func mergePassthrough(inputs []models.LLMInput) models.LLMOutput {
	results := make([]models.LLMEventResult, len(inputs))
	for i, inp := range inputs {
		results[i] = passthroughResult(i, inp)
	}
	return models.LLMOutput{
		Results:   results,
		Model:     "passthrough",
		LatencyMs: 0,
	}
}

// iocValuesToString joins a slice of IOC values to a comma-separated string.
func iocValuesToString(vals []string) string {
	return strings.Join(vals, ",")
}

