package correlationengine

import (
	"encoding/json"
	"fmt"
)

const correlatorSystemPrompt = `You are a SOC analyst specializing in MITRE ATT&CK attack-chain reconstruction.
Use ONLY the evidence provided. Do not speculate.
Return ONLY valid JSON (no markdown, no commentary).
You must remain unbiased: if evidence does not show malicious behavior, return a healthy/safe assessment.
If process_chain_evidence is present, treat GUID parent-child and source-target relationships as primary forensic evidence.
When asserting incidents or attack progression, cite the concrete GUID lineage in the evidence fields.

Required JSON schema:
{
  "overall_assessment": "malicious | suspicious | healthy | safe",
  "confidence": 0.0,
  "summary": "short explanation",
  "incident_candidates": [
    {
      "incident_type": "string",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "confidence": "LOW | MEDIUM | HIGH",
      "affected_host": "string",
      "affected_ip": "string",
      "mitre_techniques": ["Txxxx", "Txxxx.xxx"],
      "description": "string",
      "evidence": ["string"]
    }
  ],
  "attack_chain_progression": [
    {
      "stage": 1,
      "tactic": "TAxxxx tactic name",
      "techniques": ["Txxxx"],
      "evidence": "string",
      "process_chain_links": ["parent_guid -> child_guid"]
    }
  ],
  "recommendations": ["string"]
}
`

func BuildCorrelationPrompt(payload CorrelationPayload) (string, error) {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}

	prompt := fmt.Sprintf(`%s

Analyze this 10-minute window payload and respond in the required JSON schema.

Payload:
%s`, correlatorSystemPrompt, string(b))

	return prompt, nil
}
