package correlationengine

import (
	"context"
	"fmt"
	"log"

	"uls-detection-server/internal/database"
)

// InitSchema creates correlation engine v2 state and audit tables.
func InitSchema(ctx context.Context, db *database.DB) error {
	query := `
CREATE TABLE IF NOT EXISTS correlation_windows (
    id BIGSERIAL PRIMARY KEY,
    engine_name TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    windows_events_total INTEGER NOT NULL DEFAULT 0,
    windows_events_malicious INTEGER NOT NULL DEFAULT 0,
    firewall_events_total INTEGER NOT NULL DEFAULT 0,
    scada_events_total INTEGER NOT NULL DEFAULT 0,
    llm_assessment TEXT,
    llm_confidence DOUBLE PRECISION,
    error_text TEXT,
    UNIQUE (engine_name, window_start, window_end)
);

CREATE INDEX IF NOT EXISTS idx_corr_windows_status ON correlation_windows(status);
CREATE INDEX IF NOT EXISTS idx_corr_windows_window_start ON correlation_windows(window_start);

CREATE TABLE IF NOT EXISTS bart_event_decisions (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    llm_pass_id BIGINT,
    agent_host TEXT,
    event_id TEXT,
    classification TEXT NOT NULL,
    confidence DOUBLE PRECISION,
    threshold DOUBLE PRECISION,
    model TEXT,
    raw_response JSONB,
    error_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_bart_decisions_window_start ON bart_event_decisions(window_start);
CREATE INDEX IF NOT EXISTS idx_bart_decisions_classification ON bart_event_decisions(classification);
CREATE INDEX IF NOT EXISTS idx_bart_decisions_host ON bart_event_decisions(agent_host);

CREATE TABLE IF NOT EXISTS process_chain (
    id BIGSERIAL PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    source_host TEXT NOT NULL,
    chain_type TEXT NOT NULL,
    chain_json JSONB NOT NULL,
    stats_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (window_start, window_end, source_host, chain_type)
);

CREATE INDEX IF NOT EXISTS idx_process_chain_window ON process_chain(window_start, window_end);
CREATE INDEX IF NOT EXISTS idx_process_chain_host ON process_chain(source_host);
CREATE INDEX IF NOT EXISTS idx_process_chain_gin ON process_chain USING GIN (chain_json);
`

	if _, err := db.Pool().Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to initialize correlationengine schema: %w", err)
	}

	log.Println("correlationengine schema initialized")
	return nil
}
