package database

import (
	"context"
	"fmt"
	"log"
	"strings"

	"uls-detection-server/internal/models"
)

// InitLLMPassSchema creates the llm_pass_1 table and its indexes.
// Safe to call multiple times (IF NOT EXISTS).
func InitLLMPassSchema(ctx context.Context, db *DB) error {
	query := `
CREATE TABLE IF NOT EXISTS llm_pass_1 (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Source linkage
    source_type     TEXT NOT NULL,      -- 'windows' | 'firewall'
    window_ts       TIMESTAMPTZ,        -- start of the 5-sec poll window

    -- Normalised identity (shared semantic anchor for correlation)
    agent_host      TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    dst_port        TEXT,
    event_id        TEXT,

    -- Rule-based fields (always populated)
    raw_summary     TEXT,
    rule_severity   TEXT,
    rule_mitre      TEXT,
    rule_is_ioa     BOOLEAN DEFAULT FALSE,

    -- LLM-enriched fields (NULL if LLM disabled or circuit open)
    llm_severity        TEXT,
    llm_short_summary   TEXT,
    llm_is_ioa          BOOLEAN,
    llm_is_ioc          BOOLEAN,
    llm_ioc_values      TEXT,
    llm_mitre_technique TEXT,
    llm_confidence      FLOAT,
    llm_model           TEXT,
    llm_latency_ms      BIGINT,
    llm_enabled         BOOLEAN DEFAULT FALSE,

    -- Final resolved: LLM preferred, rule-based fallback
    final_severity  TEXT NOT NULL,
    final_summary   TEXT NOT NULL,
    final_mitre     TEXT
);

CREATE INDEX IF NOT EXISTS idx_llm_created_at  ON llm_pass_1(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_src_ip      ON llm_pass_1(src_ip);
CREATE INDEX IF NOT EXISTS idx_llm_agent_host  ON llm_pass_1(agent_host);
CREATE INDEX IF NOT EXISTS idx_llm_severity    ON llm_pass_1(final_severity);
CREATE INDEX IF NOT EXISTS idx_llm_source_type ON llm_pass_1(source_type);
CREATE INDEX IF NOT EXISTS idx_llm_window_ts   ON llm_pass_1(window_ts);
`
	if _, err := db.pool.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create llm_pass_1 schema: %w", err)
	}
	log.Println("llm_pass_1 schema initialized")
	return nil
}

// InsertLLMPassEvents batch-inserts a slice of LLMPassEvent rows into llm_pass_1.
// Uses a single multi-row INSERT for O(1) round trips per window.
func InsertLLMPassEvents(ctx context.Context, db *DB, events []models.LLMPassEvent) error {
	if len(events) == 0 {
		return nil
	}

	columns := []string{
		"source_type", "window_ts",
		"agent_host", "src_ip", "dst_ip", "dst_port", "event_id",
		"raw_summary", "rule_severity", "rule_mitre", "rule_is_ioa",
		"llm_severity", "llm_short_summary", "llm_is_ioa", "llm_is_ioc",
		"llm_ioc_values", "llm_mitre_technique", "llm_confidence",
		"llm_model", "llm_latency_ms", "llm_enabled",
		"final_severity", "final_summary", "final_mitre",
	}

	numCols := len(columns)
	placeholders := make([]string, len(events))
	args := make([]interface{}, 0, len(events)*numCols)

	for i, e := range events {
		pts := make([]string, numCols)
		for j := 0; j < numCols; j++ {
			pts[j] = fmt.Sprintf("$%d", i*numCols+j+1)
		}
		placeholders[i] = "(" + strings.Join(pts, ",") + ")"

		args = append(args,
			e.SourceType, e.WindowTS,
			e.AgentHost, e.SrcIP, e.DstIP, e.DstPort, e.EventID,
			e.RawSummary, e.RuleSeverity, e.RuleMitre, e.RuleIsIOA,
			nullStr(e.LLMSeverity), nullStr(e.LLMSummary), e.LLMIsIOA, e.LLMIsIOC,
			nullStr(e.LLMIOCValues), nullStr(e.LLMMitre), nullFloat(e.LLMConfidence),
			nullStr(e.LLMModel), nullInt(e.LLMLatencyMs), e.LLMEnabled,
			e.FinalSeverity, e.FinalSummary, nullStr(e.FinalMitre),
		)
	}

	query := fmt.Sprintf(
		"INSERT INTO llm_pass_1 (%s) VALUES %s",
		strings.Join(columns, ","),
		strings.Join(placeholders, ","),
	)

	_, err := db.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to insert llm_pass_1 events: %w", err)
	}

	log.Printf("[llm_pass_1] inserted %d rows", len(events))
	return nil
}

// nullStr returns nil for empty strings so the DB stores NULL instead of "".
func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullFloat(f float64) interface{} {
	if f == 0 {
		return nil
	}
	return f
}

func nullInt(n int64) interface{} {
	if n == 0 {
		return nil
	}
	return n
}
