package database

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"uls-detection-server/internal/models"
)

// InitScadaSchema creates the scada_logs table
func InitScadaSchema(ctx context.Context, db *DB) error {
	query := `
CREATE TABLE IF NOT EXISTS scada_logs (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
	timestamp TIMESTAMPTZ,
    tag TEXT,
    name TEXT,
    message TEXT,
    state TEXT,
    classification TEXT,
    username TEXT,
    userlocation TEXT,
    raw_log TEXT,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scada_timestamp ON scada_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_scada_source ON scada_logs(source);

DO $$
BEGIN
	-- Backward-compatible migration: convert legacy TEXT timestamp to TIMESTAMPTZ.
	IF EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'scada_logs'
		  AND column_name = 'timestamp'
		  AND data_type = 'text'
	) THEN
		ALTER TABLE scada_logs
		ALTER COLUMN timestamp TYPE TIMESTAMPTZ
		USING (
			CASE
				WHEN timestamp IS NULL OR btrim(timestamp) = '' THEN inserted_at
				WHEN timestamp ~ '^\\d{4}-\\d{2}-\\d{2}[T ]' THEN timestamp::timestamptz
				ELSE inserted_at
			END
		);
	END IF;
END $$;
`

	if _, err := db.pool.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create scada schema: %w", err)
	}
	log.Println("SCADA schema initialized")
	return nil
}

// InsertScadaEvents batch-inserts SCADA events into scada_logs
func (db *DB) InsertScadaEvents(ctx context.Context, events []models.ScadaEvent) error {
	if len(events) == 0 {
		return nil
	}

	columns := []string{"source", "timestamp", "tag", "name", "message", "state", "classification", "username", "userlocation", "raw_log"}
	numCols := len(columns)

	placeholders := make([]string, len(events))
	args := make([]interface{}, 0, len(events)*numCols)

	for i, e := range events {
		pts := make([]string, numCols)
		for j := 0; j < numCols; j++ {
			pts[j] = fmt.Sprintf("$%d", i*numCols+j+1)
		}
		placeholders[i] = "(" + strings.Join(pts, ",") + ")"

		ts := parseScadaTimestamp(e.Timestamp, e.ReceivedAt)

		args = append(args,
			e.Source, ts, e.Tag, e.Name, e.Message, e.State, e.Classification, e.Username, e.Userlocation, e.RawLog,
		)
	}

	query := fmt.Sprintf("INSERT INTO scada_logs (%s) VALUES %s", strings.Join(columns, ","), strings.Join(placeholders, ","))

	if _, err := db.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to insert scada events: %w", err)
	}

	log.Printf("Inserted %d scada events", len(events))
	return nil
}

func parseScadaTimestamp(input string, fallback time.Time) time.Time {
	if fallback.IsZero() {
		fallback = time.Now().UTC()
	} else {
		fallback = fallback.UTC()
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return fallback
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05.0000000Z",
		"2006-01-02T15:04:05Z",
	}

	for _, format := range formats {
		if ts, err := time.Parse(format, input); err == nil {
			return ts.UTC()
		}
	}

	return fallback
}
