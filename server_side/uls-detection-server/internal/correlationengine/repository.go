package correlationengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (e *Engine) tryStartWindow(ctx context.Context, start, end time.Time) (int64, bool, error) {
	var id int64
	err := e.db.Pool().QueryRow(ctx, `
		INSERT INTO correlation_windows (engine_name, window_start, window_end, status)
		VALUES ($1, $2, $3, 'processing')
		ON CONFLICT (engine_name, window_start, window_end) DO NOTHING
		RETURNING id
	`, e.cfg.EngineName, start, end).Scan(&id)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return id, true, nil
}

func (e *Engine) markWindowDone(ctx context.Context, windowID int64, windowsTotal, windowsMalicious, fwTotal, scadaTotal int, assessment string, conf float64) error {
	_, err := e.db.Pool().Exec(ctx, `
		UPDATE correlation_windows
		SET status = 'done',
		    finished_at = NOW(),
		    windows_events_total = $2,
		    windows_events_malicious = $3,
		    firewall_events_total = $4,
		    scada_events_total = $5,
		    llm_assessment = $6,
		    llm_confidence = $7,
		    error_text = NULL
		WHERE id = $1
	`, windowID, windowsTotal, windowsMalicious, fwTotal, scadaTotal, assessment, conf)
	return err
}

func (e *Engine) markWindowFailed(ctx context.Context, windowID int64, errText string) error {
	_, err := e.db.Pool().Exec(ctx, `
		UPDATE correlation_windows
		SET status = 'failed',
		    finished_at = NOW(),
		    error_text = $2
		WHERE id = $1
	`, windowID, truncate(errText, 1500))
	return err
}

func (e *Engine) fetchWindowsPassEvents(ctx context.Context, start, end time.Time) ([]WindowsPassEvent, error) {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT id, COALESCE(window_ts, created_at), created_at,
		       COALESCE(agent_host,''), COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,''),
		       COALESCE(event_id,''), COALESCE(final_severity,''), COALESCE(final_summary,''), COALESCE(final_mitre,'')
		FROM llm_pass_1
		WHERE source_type = 'windows'
		  AND COALESCE(window_ts, created_at) >= $1
		  AND COALESCE(window_ts, created_at) < $2
		ORDER BY COALESCE(window_ts, created_at) ASC
		LIMIT $3
	`, start, end, e.cfg.MaxWindowsEvents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]WindowsPassEvent, 0, 256)
	for rows.Next() {
		var ev WindowsPassEvent
		if err := rows.Scan(
			&ev.ID, &ev.WindowTS, &ev.CreatedAt,
			&ev.AgentHost, &ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&ev.EventID, &ev.FinalSeverity, &ev.FinalSummary, &ev.FinalMitre,
		); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (e *Engine) fetchFirewallEvents(ctx context.Context, start, end time.Time) ([]FirewallWindowEvent, error) {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT id, received_at, COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,''),
		       COALESCE(action,''), COALESCE(threat_level,''), COALESCE(mitre_technique,''), COALESCE(event_details,'')
		FROM firewall_events
		WHERE received_at >= $1
		  AND received_at < $2
		ORDER BY received_at ASC
		LIMIT $3
	`, start, end, e.cfg.MaxFirewallEvents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]FirewallWindowEvent, 0, 256)
	for rows.Next() {
		var ev FirewallWindowEvent
		if err := rows.Scan(
			&ev.ID, &ev.ReceivedAt, &ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&ev.Action, &ev.ThreatLevel, &ev.MitreTechnique, &ev.EventDetails,
		); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (e *Engine) fetchScadaEvents(ctx context.Context, start, end time.Time) ([]ScadaWindowEvent, error) {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT id, timestamp, COALESCE(source,''), COALESCE(tag,''), COALESCE(name,''),
		       COALESCE(message,''), COALESCE(state,''), COALESCE(classification,''),
		       COALESCE(username,''), COALESCE(userlocation,''), COALESCE(raw_log,'')
		FROM scada_logs
		WHERE timestamp >= $1
		  AND timestamp < $2
		ORDER BY timestamp ASC
		LIMIT $3
	`, start, end, e.cfg.MaxScadaEvents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ScadaWindowEvent, 0, 128)
	for rows.Next() {
		var ev ScadaWindowEvent
		if err := rows.Scan(
			&ev.ID, &ev.Timestamp, &ev.Source, &ev.Tag, &ev.Name,
			&ev.Message, &ev.State, &ev.Classification,
			&ev.Username, &ev.Userlocation, &ev.RawLog,
		); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (e *Engine) saveBARTDecision(ctx context.Context, d BARTDecision) error {
	var rawJSON []byte
	if d.RawResponse != nil {
		b, err := json.Marshal(d.RawResponse)
		if err == nil {
			rawJSON = b
		}
	}

	_, err := e.db.Pool().Exec(ctx, `
		INSERT INTO bart_event_decisions (
			window_start, window_end, llm_pass_id, agent_host, event_id,
			classification, confidence, threshold, model, raw_response, error_text
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, d.WindowStart, d.WindowEnd, d.LLMPassID, d.AgentHost, d.EventID,
		d.Classification, d.Confidence, d.Threshold, d.Model, rawJSON, nullableText(d.ErrorText))
	return err
}

func (e *Engine) saveIncidents(ctx context.Context, windowStart, windowEnd time.Time, incidents []CorrelationIncident) error {
	for _, inc := range incidents {
		mitre := strings.Join(inc.MitreTechniques, ",")
		evidenceMap := map[string]any{
			"evidence": inc.Evidence,
		}
		evidenceJSON, _ := json.Marshal(evidenceMap)

		_, err := e.db.Pool().Exec(ctx, `
			INSERT INTO correlation_incidents
			(created_at, incident_type, severity, confidence, affected_host, affected_ip, mitre_techniques,
			 description, evidence, window_start, window_end, source_count)
			VALUES (NOW(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		`, inc.IncidentType, inc.Severity, inc.Confidence,
			nullableText(inc.AffectedHost), nullableText(inc.AffectedIP), nullableText(mitre),
			nullableText(inc.Description), string(evidenceJSON), windowStart, windowEnd, 3)
		if err != nil {
			return fmt.Errorf("insert incident %s: %w", inc.IncidentType, err)
		}
	}
	return nil
}

func nullableText(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
