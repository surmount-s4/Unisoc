-- PostgreSQL Schema for Universal Log Parser Storage
-- Stores parser profiles for dynamic log ingestion
-- Supports both rule-based and LLM-based parsing modes

BEGIN;

-- ============================================================================
-- Create log_parsers Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_parsers (
    -- Identity
    parser_id TEXT PRIMARY KEY,                 -- Unique identifier (e.g., 'checkpoint-fw-v1')
    parser_name TEXT NOT NULL UNIQUE,           -- Human-readable name (e.g., 'Checkpoint Firewall')
    description TEXT,                            -- Optional description
    
    -- Processing Mode
    mode TEXT NOT NULL,                          -- 'rule-based', 'llm-based', or 'hybrid'
    format_type TEXT NOT NULL,                   -- 'CSV', 'JSON', 'KEY_VALUE', 'SYSLOG', 'CEF', 'CUSTOM'
    
    -- Parsing Configuration
    parsing_rules JSONB NOT NULL,                -- Rule-based extraction logic
    /*
    Example for CSV:
    {
      "delimiter": ",",
      "has_header": true,
      "columns": ["Time", "Action", "Src IP", "Dst IP"],
      "skip_lines": 0
    }
    
    Example for KEY_VALUE:
    {
      "pair_delimiter": " ",
      "key_value_separator": "=",
      "quote_char": "\""
    }
    */
    
    field_mappings JSONB NOT NULL,               -- Maps detected fields to pipeline schema
    /*
    Example:
    {
      "Time": "timestamp",
      "Src IP": "source_ip",
      "Dst IP": "dest_ip",
      "Action": "severity",
      "Message": "log"
    }
    */
    
    timestamp_config JSONB,                      -- Timestamp parsing configuration
    /*
    Example:
    {
      "field": "Time",
      "format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
    }
    */
    
    validation_rules JSONB,                      -- Data validation rules
    /*
    Example:
    {
      "required_fields": ["timestamp", "source_ip", "log"],
      "ip_fields": ["source_ip", "dest_ip"],
      "numeric_fields": ["src_port", "dst_port"]
    }
    */
    
    -- LLM Configuration (for llm-based or hybrid mode)
    llm_instructions TEXT,                       -- LLM-generated parsing instructions
    llm_model TEXT,                              -- Model used (e.g., 'gpt-4', 'llama3')
    llm_confidence DECIMAL(3,2),                 -- Confidence score from LLM (0.00-1.00)
    
    -- Sample Data
    sample_logs TEXT[],                          -- Example logs used to create parser
    
    -- Metadata
    source_identifier TEXT,                      -- Identifier to match logs to parser (e.g., device name)
    vendor TEXT,                                 -- Vendor name (e.g., 'Sophos', 'Fortinet', 'Checkpoint')
    log_type TEXT,                               -- Type of logs (e.g., 'firewall', 'ids', 'web-proxy')
    
    -- Status
    active BOOLEAN DEFAULT TRUE,                 -- Is this parser active?
    version TEXT DEFAULT '1.0',                  -- Parser version
    
    -- Statistics
    logs_processed BIGINT DEFAULT 0,             -- Total logs processed with this parser
    parse_success_rate DECIMAL(5,2),             -- Success rate (0.00-100.00)
    avg_parse_time_ms INTEGER,                   -- Average parsing time in milliseconds
    last_used TIMESTAMPTZ,                       -- Last time this parser was used
    
    -- Audit
    created_by TEXT,                             -- User who created this parser
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- Create parser_usage_logs Table (Optional - for analytics)
-- ============================================================================

CREATE TABLE IF NOT EXISTS parser_usage_logs (
    id BIGSERIAL PRIMARY KEY,
    parser_id TEXT REFERENCES log_parsers(parser_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    logs_count INTEGER,                          -- Number of logs parsed in this batch
    success_count INTEGER,                       -- Successfully parsed logs
    failure_count INTEGER,                       -- Failed to parse logs
    parse_time_ms INTEGER,                       -- Time taken to parse
    error_message TEXT                           -- Error details if any
);

-- ============================================================================
-- Create Indexes
-- ============================================================================

-- Parser lookup indexes
CREATE INDEX IF NOT EXISTS idx_parsers_name ON log_parsers(parser_name);
CREATE INDEX IF NOT EXISTS idx_parsers_vendor ON log_parsers(vendor);
CREATE INDEX IF NOT EXISTS idx_parsers_format ON log_parsers(format_type);
CREATE INDEX IF NOT EXISTS idx_parsers_active ON log_parsers(active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_parsers_mode ON log_parsers(mode);

-- Source matching index
CREATE INDEX IF NOT EXISTS idx_parsers_source ON log_parsers(source_identifier);

-- Usage tracking indexes
CREATE INDEX IF NOT EXISTS idx_parser_usage_parser ON parser_usage_logs(parser_id);
CREATE INDEX IF NOT EXISTS idx_parser_usage_timestamp ON parser_usage_logs(timestamp DESC);

-- JSONB field indexes for faster querying
CREATE INDEX IF NOT EXISTS idx_parsers_field_mappings ON log_parsers USING GIN (field_mappings);
CREATE INDEX IF NOT EXISTS idx_parsers_parsing_rules ON log_parsers USING GIN (parsing_rules);

-- ============================================================================
-- Create Trigger for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_parser_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER parser_update_timestamp
BEFORE UPDATE ON log_parsers
FOR EACH ROW
EXECUTE FUNCTION update_parser_timestamp();

-- ============================================================================
-- Add Comments for Documentation
-- ============================================================================

COMMENT ON TABLE log_parsers IS 'Stores parser profiles for universal log ingestion. Supports rule-based, LLM-based, and hybrid parsing modes.';

COMMENT ON COLUMN log_parsers.parser_id IS 'Unique identifier for the parser (e.g., checkpoint-fw-v1)';
COMMENT ON COLUMN log_parsers.mode IS 'Processing mode: rule-based (fast), llm-based (smart), or hybrid (both)';
COMMENT ON COLUMN log_parsers.format_type IS 'Log format: CSV, JSON, KEY_VALUE, SYSLOG, CEF, or CUSTOM';
COMMENT ON COLUMN log_parsers.parsing_rules IS 'JSON configuration for rule-based parsing (delimiters, columns, etc.)';
COMMENT ON COLUMN log_parsers.field_mappings IS 'Maps detected fields to pipeline standard fields (source_ip, dest_ip, etc.)';
COMMENT ON COLUMN log_parsers.validation_rules IS 'Data validation rules (required fields, data types, formats)';
COMMENT ON COLUMN log_parsers.llm_instructions IS 'LLM-generated parsing instructions for complex formats';
COMMENT ON COLUMN log_parsers.sample_logs IS 'Example logs used to train/create this parser';
COMMENT ON COLUMN log_parsers.source_identifier IS 'Used to auto-select parser based on log source (device name, IP, etc.)';

COMMENT ON TABLE parser_usage_logs IS 'Tracks parser usage statistics and performance metrics';

-- ============================================================================
-- Insert Default Parsers (Examples)
-- ============================================================================

-- Sophos Firewall CSV Parser
INSERT INTO log_parsers (
    parser_id,
    parser_name,
    description,
    mode,
    format_type,
    parsing_rules,
    field_mappings,
    timestamp_config,
    validation_rules,
    sample_logs,
    source_identifier,
    vendor,
    log_type,
    version
) VALUES (
    'sophos-fw-csv-v1',
    'Sophos Firewall CSV',
    'Parser for Sophos XG Firewall CSV format logs',
    'rule-based',
    'CSV',
    '{
        "delimiter": ",",
        "has_header": false,
        "columns": ["Time", "Log comp", "Log subtype", "Username", "Firewall rule", "Firewall rule name", "NAT rule", "NAT rule name", "In interface", "Out interface", "Src IP", "Dst IP", "Src port", "Dst port", "Protocol", "Rule type", "Live PCAP", "Message", "Log occurrence"],
        "skip_lines": 0
    }'::jsonb,
    '{
        "Time": "timestamp",
        "Log comp": "log_comp",
        "Log subtype": "log_subtype",
        "Src IP": "source_ip",
        "Dst IP": "dest_ip",
        "Src port": "src_port",
        "Dst port": "dst_port",
        "Protocol": "protocol",
        "Message": "log"
    }'::jsonb,
    '{
        "field": "Time",
        "format": "%Y-%m-%d %H:%M:%S",
        "timezone": "UTC"
    }'::jsonb,
    '{
        "required_fields": ["timestamp", "source_ip", "log"],
        "ip_fields": ["source_ip", "dest_ip"]
    }'::jsonb,
    ARRAY['2025-10-13 13:15:37,Firewall Rule,Allowed,,13,ENZ To WAN,8,EMS AP,Port5,Port2_ppp,192.168.0.62,162.159.61.3,48367,443,TCP,1,Open PCAP,,1'],
    'sophos',
    'Sophos',
    'firewall',
    '1.0'
) ON CONFLICT (parser_id) DO NOTHING;

-- Generic JSON Parser
INSERT INTO log_parsers (
    parser_id,
    parser_name,
    description,
    mode,
    format_type,
    parsing_rules,
    field_mappings,
    validation_rules,
    source_identifier,
    vendor,
    log_type,
    version
) VALUES (
    'generic-json-v1',
    'Generic JSON Logs',
    'Parser for standard JSON formatted logs',
    'rule-based',
    'JSON',
    '{
        "nested_fields": true,
        "flatten": true
    }'::jsonb,
    '{
        "timestamp": "timestamp",
        "src_ip": "source_ip",
        "dst_ip": "dest_ip",
        "message": "log",
        "severity": "severity"
    }'::jsonb,
    '{
        "required_fields": ["timestamp", "log"]
    }'::jsonb,
    'json',
    'Generic',
    'mixed',
    '1.0'
) ON CONFLICT (parser_id) DO NOTHING;

COMMIT;

-- ============================================================================
-- Verification Queries
-- ============================================================================

SELECT 'Parser Storage Schema Created' AS status;
SELECT '================================' AS separator;

-- Show table structure
\d log_parsers

-- Show installed parsers
SELECT parser_id, parser_name, mode, format_type, vendor, active 
FROM log_parsers 
ORDER BY created_at DESC;

-- Show indexes
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE tablename = 'log_parsers'
ORDER BY indexname;

-- Success message
SELECT 'SUCCESS: Parser storage schema created with 2 default parsers' AS result;
