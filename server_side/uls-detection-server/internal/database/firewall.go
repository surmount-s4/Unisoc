package database

import (
	"context"
	"fmt"
	"log"
	"strings"

	"uls-detection-server/internal/models"
)

// InitFirewallSchema creates the firewall_events and correlation_incidents tables.
func InitFirewallSchema(ctx context.Context, db *DB) error {
	query := `
-- ─── Firewall events ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS firewall_events (
    id              BIGSERIAL PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sensor_ip       TEXT,
    raw_log         TEXT,

    -- Device
    device_name     TEXT,
    device_id       TEXT,

    -- Timestamps
    log_date        TEXT,
    log_time        TEXT,
    timezone        TEXT,

    -- Classification
    log_id          TEXT,
    log_type        TEXT,
    log_component   TEXT,
    log_subtype     TEXT,
    status          TEXT,
    priority        TEXT,
    action          TEXT,   -- ALLOW | DROP | DENY | REJECT

    -- Source network
    src_ip          TEXT,
    src_port        TEXT,
    src_mac         TEXT,
    src_country_code TEXT,
    src_zone        TEXT,
    src_zone_type   TEXT,
    src_trans_ip    TEXT,

    -- Destination network
    dst_ip          TEXT,
    dst_port        TEXT,
    dst_country_code TEXT,
    dst_zone        TEXT,
    dst_zone_type   TEXT,

    -- Protocol
    protocol        TEXT,
    ether_type      TEXT,
    conn_event      TEXT,
    conn_id         TEXT,

    -- Traffic stats
    sent_bytes      TEXT,
    recv_bytes      TEXT,
    sent_pkts       TEXT,
    recv_pkts       TEXT,

    -- Firewall policy
    fw_rule_id      TEXT,
    nat_rule_id     TEXT,
    fw_type         TEXT,

    -- User
    "user"          TEXT,
    user_group      TEXT,

    -- Application (DPI)
    app_name        TEXT,
    app_risk        TEXT,

    -- Threat / IPS / ATP
    message         TEXT,
    severity        TEXT,
    classification  TEXT,
    url             TEXT,

    -- Detection results
    threat_level     TEXT,
    threat_type      TEXT,
    mitre_technique  TEXT,
    detection_module TEXT,
    event_details    TEXT
);

CREATE INDEX IF NOT EXISTS idx_fw_received_at   ON firewall_events(received_at);
CREATE INDEX IF NOT EXISTS idx_fw_src_ip        ON firewall_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_ip        ON firewall_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_port      ON firewall_events(dst_port);
CREATE INDEX IF NOT EXISTS idx_fw_action        ON firewall_events(action);
CREATE INDEX IF NOT EXISTS idx_fw_threat_level  ON firewall_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_fw_mitre         ON firewall_events(mitre_technique);

-- ─── Correlation incidents ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_incidents (
    id                  BIGSERIAL PRIMARY KEY,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    incident_type       TEXT NOT NULL,
    severity            TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    affected_host       TEXT,
    affected_ip         TEXT,
    mitre_techniques    TEXT,
    description         TEXT,
    evidence            TEXT,   -- JSON blob
    window_start        TIMESTAMPTZ,
    window_end          TIMESTAMPTZ,
    source_count        INTEGER DEFAULT 2
);

CREATE INDEX IF NOT EXISTS idx_corr_created_at    ON correlation_incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_corr_severity      ON correlation_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_corr_affected_ip   ON correlation_incidents(affected_ip);
CREATE INDEX IF NOT EXISTS idx_corr_incident_type ON correlation_incidents(incident_type);
`

	_, err := db.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create firewall/correlation schema: %w", err)
	}

	log.Println("Firewall + correlation schema initialized")
	return nil
}

// InsertFirewallEvents batch-inserts Sophos firewall events.
func (db *DB) InsertFirewallEvents(ctx context.Context, events []models.FirewallEvent) error {
	if len(events) == 0 {
		return nil
	}

	columns := []string{
        "received_at", "sensor_ip", "raw_log", "device_name", "device_id",
		"log_date", "log_time", "timezone",
		"log_id", "log_type", "log_component", "log_subtype",
		"status", "priority", "action",
		"src_ip", "src_port", "src_mac", "src_country_code",
		"src_zone", "src_zone_type", "src_trans_ip",
		"dst_ip", "dst_port", "dst_country_code", "dst_zone", "dst_zone_type",
		"protocol", "ether_type", "conn_event", "conn_id",
		"sent_bytes", "recv_bytes", "sent_pkts", "recv_pkts",
		"fw_rule_id", "nat_rule_id", "fw_type",
		`"user"`, "user_group",
		"app_name", "app_risk",
		"message", "severity", "classification", "url",
		"threat_level", "threat_type", "mitre_technique",
		"detection_module", "event_details",
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
            e.ReceivedAt, e.SensorIP, e.RawLog, e.DeviceName, e.DeviceID,
			e.LogDate, e.LogTime, e.Timezone,
			e.LogID, e.LogType, e.LogComponent, e.LogSubtype,
			e.Status, e.Priority, e.Action,
			e.SrcIP, e.SrcPort, e.SrcMAC, e.SrcCountry,
			e.SrcZone, e.SrcZoneType, e.SrcTransIP,
			e.DstIP, e.DstPort, e.DstCountry, e.DstZone, e.DstZoneType,
			e.Protocol, e.EtherType, e.ConnEvent, e.ConnID,
			e.SentBytes, e.RecvBytes, e.SentPkts, e.RecvPkts,
			e.FwRuleID, e.NatRuleID, e.FwType,
			e.User, e.UserGroup,
			e.AppName, e.AppRisk,
			e.Message, e.Severity, e.Classification, e.URL,
			e.ThreatLevel, e.ThreatType, e.MitreTechnique,
			e.DetectionModule, e.EventDetails,
		)
	}

	query := fmt.Sprintf(
		"INSERT INTO firewall_events (%s) VALUES %s",
		strings.Join(columns, ","),
		strings.Join(placeholders, ","),
	)

	_, err := db.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to insert firewall events: %w", err)
	}

	log.Printf("Inserted %d firewall events", len(events))
	return nil
}
