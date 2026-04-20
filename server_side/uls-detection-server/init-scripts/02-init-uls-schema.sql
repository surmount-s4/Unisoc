-- ULS unified schema bootstrap for PostgreSQL/TimescaleDB
-- Safe to run multiple times.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        BEGIN
            CREATE EXTENSION IF NOT EXISTS timescaledb;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping timescaledb extension creation (insufficient privileges).';
        END;
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- security_events
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    agent_host TEXT,
    agent_timestamp TEXT,

    timestamp TIMESTAMPTZ,
    process_id TEXT,
    process_name TEXT,
    command_line TEXT,
    username TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    file_path TEXT,
    registry_key TEXT,

    severity TEXT,
    mitre_technique TEXT,
    detection_module TEXT,
    event_details TEXT,
    additional_context TEXT,

    timecreated_0 TEXT,
    providername_0 TEXT,
    providerguid_0 TEXT,
    eventid_0 TEXT,
    version_0 TEXT,
    level_0 TEXT,
    task_0 TEXT,
    opcode_0 TEXT,
    keywords_0 TEXT,
    eventrecordid_0 TEXT,
    executionprocessid_0 TEXT,
    executionthreadid_0 TEXT,
    channel_0 TEXT,
    computer_0 TEXT,
    securityuserid_0 TEXT,

    eventdata_1 TEXT,
    systemdata_1 TEXT,
    userdata_1 TEXT,

    utctime_2 TEXT,
    processguid_2 TEXT,
    processid_2 TEXT,
    image_2 TEXT,
    fileversion_2 TEXT,
    description_2 TEXT,
    product_2 TEXT,
    company_2 TEXT,
    commandline_2 TEXT,
    currentdirectory_2 TEXT,
    user_2 TEXT,
    logonguid_2 TEXT,
    logonid_2 TEXT,
    terminalsessionid_2 TEXT,
    integritylevel_2 TEXT,
    hashes_2 TEXT,
    parentprocessguid_2 TEXT,
    parentprocessid_2 TEXT,
    parentimage_2 TEXT,
    parentcommandline_2 TEXT,
    rulename_2 TEXT,
    targetfilename_2 TEXT,
    creationutctime_2 TEXT,
    previouscreationutctime_2 TEXT,
    protocol_2 TEXT,
    initiated_2 TEXT,
    sourceisipv6_2 TEXT,
    sourceip_2 TEXT,
    sourcehostname_2 TEXT,
    sourceport_2 TEXT,
    sourceportname_2 TEXT,
    destinationisipv6_2 TEXT,
    destinationip_2 TEXT,
    destinationhostname_2 TEXT,
    destinationport_2 TEXT,
    destinationportname_2 TEXT,
    state_2 TEXT,
    version_2 TEXT,
    schemaversion_2 TEXT,
    imageloaded_2 TEXT,
    signed_2 TEXT,
    signature_2 TEXT,
    signaturestatus_2 TEXT,
    sourceprocessguid_2 TEXT,
    sourceprocessid_2 TEXT,
    sourceimage_2 TEXT,
    targetprocessid_2 TEXT,
    targetimage_2 TEXT,
    newthreadid_2 TEXT,
    startaddress_2 TEXT,
    startmodule_2 TEXT,
    startfunction_2 TEXT,
    device_2 TEXT,
    sourcethreadid_2 TEXT,
    targetprocessguid_2 TEXT,
    grantedaccess_2 TEXT,
    calltrace_2 TEXT,
    eventtype_2 TEXT,
    targetobject_2 TEXT,
    details_2 TEXT,
    newname_2 TEXT,
    hash_2 TEXT,
    configuration_2 TEXT,
    configurationfilehash_2 TEXT,
    pipename_2 TEXT,
    operation_2 TEXT,
    name_2 TEXT,
    query_2 TEXT,
    type_2 TEXT,
    destination_2 TEXT,
    consumer_2 TEXT,
    filter_2 TEXT,
    queryname_2 TEXT,
    querytype_2 TEXT,
    querystatus_2 TEXT,
    queryresults_2 TEXT,
    isexecutable_2 TEXT,
    archived_2 TEXT,
    session_2 TEXT,
    clientinfo_2 TEXT,
    parentuser_2 TEXT,
    rawaccessread_2 TEXT,
    eventnamespace_2 TEXT,

    logontype_3 TEXT,
    targetusername_3 TEXT,
    ipaddress_3 TEXT,
    workstationname_3 TEXT,
    failurereason_3 TEXT,
    newprocessname_3 TEXT,
    subjectusername_3 TEXT,
    newprocessid_3 TEXT,
    taskname_3 TEXT,
    taskcontent_3 TEXT,
    servicename_3 TEXT,
    servicefilename_3 TEXT,
    servicetype_3 TEXT,
    imagepath_3 TEXT,
    accountname_3 TEXT,
    processname_3 TEXT,
    subjectlogonid_3 TEXT,
    privilegelist_3 TEXT,
    originalfilename_3 TEXT,
    status_3 TEXT,
    substatus_3 TEXT,
    callercomputername_3 TEXT,
    ticketencryptiontype_3 TEXT,
    certthumbprint_3 TEXT,
    authenticationpackagename_3 TEXT,
    logonprocessname_3 TEXT,
    sessionid_3 TEXT,
    clientname_3 TEXT,
    actionname_3 TEXT,
    service_3 TEXT,

    logsource_5 TEXT,
    eventcategory_5 TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_eventid ON security_events(eventid_0);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_mitre ON security_events(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_security_events_agent ON security_events(agent_host);
CREATE INDEX IF NOT EXISTS idx_security_events_logsource ON security_events(logsource_5);
CREATE INDEX IF NOT EXISTS idx_security_events_image ON security_events(image_2);
CREATE INDEX IF NOT EXISTS idx_security_events_destip ON security_events(destinationip_2);

-- -----------------------------------------------------------------------------
-- firewall_events and correlation_incidents
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_events (
    id BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sensor_ip TEXT,
    raw_log TEXT,

    device_name TEXT,
    device_id TEXT,

    log_date TEXT,
    log_time TEXT,
    timezone TEXT,

    log_id TEXT,
    log_type TEXT,
    log_component TEXT,
    log_subtype TEXT,
    status TEXT,
    priority TEXT,
    action TEXT,

    src_ip TEXT,
    src_port TEXT,
    src_mac TEXT,
    src_country_code TEXT,
    src_zone TEXT,
    src_zone_type TEXT,
    src_trans_ip TEXT,

    dst_ip TEXT,
    dst_port TEXT,
    dst_country_code TEXT,
    dst_zone TEXT,
    dst_zone_type TEXT,

    protocol TEXT,
    ether_type TEXT,
    conn_event TEXT,
    conn_id TEXT,

    sent_bytes TEXT,
    recv_bytes TEXT,
    sent_pkts TEXT,
    recv_pkts TEXT,

    fw_rule_id TEXT,
    nat_rule_id TEXT,
    fw_type TEXT,

    "user" TEXT,
    user_group TEXT,

    app_name TEXT,
    app_risk TEXT,

    message TEXT,
    severity TEXT,
    classification TEXT,
    url TEXT,

    threat_level TEXT,
    threat_type TEXT,
    mitre_technique TEXT,
    detection_module TEXT,
    event_details TEXT
);

CREATE INDEX IF NOT EXISTS idx_fw_received_at ON firewall_events(received_at);
CREATE INDEX IF NOT EXISTS idx_fw_src_ip ON firewall_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_ip ON firewall_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_port ON firewall_events(dst_port);
CREATE INDEX IF NOT EXISTS idx_fw_action ON firewall_events(action);
CREATE INDEX IF NOT EXISTS idx_fw_threat_level ON firewall_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_fw_mitre ON firewall_events(mitre_technique);

CREATE TABLE IF NOT EXISTS correlation_incidents (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    affected_host TEXT,
    affected_ip TEXT,
    mitre_techniques TEXT,
    description TEXT,
    evidence TEXT,
    window_start TIMESTAMPTZ,
    window_end TIMESTAMPTZ,
    source_count INTEGER DEFAULT 2
);

CREATE INDEX IF NOT EXISTS idx_corr_created_at ON correlation_incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlation_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_corr_affected_ip ON correlation_incidents(affected_ip);
CREATE INDEX IF NOT EXISTS idx_corr_incident_type ON correlation_incidents(incident_type);

-- -----------------------------------------------------------------------------
-- scada_logs
-- -----------------------------------------------------------------------------
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
END
$$;

-- -----------------------------------------------------------------------------
-- llm_pass_1
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS llm_pass_1 (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    source_type TEXT NOT NULL,
    window_ts TIMESTAMPTZ,

    agent_host TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port TEXT,
    event_id TEXT,

    raw_summary TEXT,
    rule_severity TEXT,
    rule_mitre TEXT,
    rule_is_ioa BOOLEAN DEFAULT FALSE,

    llm_severity TEXT,
    llm_short_summary TEXT,
    llm_is_ioa BOOLEAN,
    llm_is_ioc BOOLEAN,
    llm_ioc_values TEXT,
    llm_mitre_technique TEXT,
    llm_confidence FLOAT,
    llm_model TEXT,
    llm_latency_ms BIGINT,
    llm_enabled BOOLEAN DEFAULT FALSE,

    final_severity TEXT NOT NULL,
    final_summary TEXT NOT NULL,
    final_mitre TEXT
);

CREATE INDEX IF NOT EXISTS idx_llm_created_at ON llm_pass_1(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_src_ip ON llm_pass_1(src_ip);
CREATE INDEX IF NOT EXISTS idx_llm_agent_host ON llm_pass_1(agent_host);
CREATE INDEX IF NOT EXISTS idx_llm_severity ON llm_pass_1(final_severity);
CREATE INDEX IF NOT EXISTS idx_llm_source_type ON llm_pass_1(source_type);
CREATE INDEX IF NOT EXISTS idx_llm_window_ts ON llm_pass_1(window_ts);

-- -----------------------------------------------------------------------------
-- correlationengine v2 tables
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- TimescaleDB hypertable conversion (optional, when extension is available)
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    existing_pkey_name TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- security_events: partition by event timestamp for watcher/process-chain scans.
        UPDATE security_events
        SET timestamp = COALESCE(timestamp, created_at, NOW())
        WHERE timestamp IS NULL;

        ALTER TABLE security_events
        ALTER COLUMN timestamp SET NOT NULL;

                SELECT c.conname
                INTO existing_pkey_name
                FROM pg_constraint c
                WHERE c.conrelid = 'security_events'::regclass
                    AND c.contype = 'p'
                    AND pg_get_constraintdef(c.oid) <> 'PRIMARY KEY (timestamp, id)'
                LIMIT 1;

                IF existing_pkey_name IS NOT NULL THEN
                        EXECUTE format('ALTER TABLE security_events DROP CONSTRAINT %I', existing_pkey_name);
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'security_events'::regclass
              AND contype = 'p'
              AND pg_get_constraintdef(oid) = 'PRIMARY KEY (timestamp, id)'
        ) THEN
            ALTER TABLE security_events
            ADD CONSTRAINT security_events_pkey PRIMARY KEY (timestamp, id);
        END IF;

        PERFORM create_hypertable(
            'security_events',
            'timestamp',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );

        -- firewall_events: partition by receive time for firewall/LLM windows.
                SELECT c.conname
                INTO existing_pkey_name
                FROM pg_constraint c
                WHERE c.conrelid = 'firewall_events'::regclass
                    AND c.contype = 'p'
                    AND pg_get_constraintdef(c.oid) <> 'PRIMARY KEY (received_at, id)'
                LIMIT 1;

                IF existing_pkey_name IS NOT NULL THEN
                        EXECUTE format('ALTER TABLE firewall_events DROP CONSTRAINT %I', existing_pkey_name);
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'firewall_events'::regclass
              AND contype = 'p'
              AND pg_get_constraintdef(oid) = 'PRIMARY KEY (received_at, id)'
        ) THEN
            ALTER TABLE firewall_events
            ADD CONSTRAINT firewall_events_pkey PRIMARY KEY (received_at, id);
        END IF;

        PERFORM create_hypertable(
            'firewall_events',
            'received_at',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );

        -- llm_pass_1: partition by window timestamp for correlation windows.
        UPDATE llm_pass_1
        SET window_ts = COALESCE(window_ts, created_at)
        WHERE window_ts IS NULL;

        ALTER TABLE llm_pass_1
        ALTER COLUMN window_ts SET NOT NULL;

                SELECT c.conname
                INTO existing_pkey_name
                FROM pg_constraint c
                WHERE c.conrelid = 'llm_pass_1'::regclass
                    AND c.contype = 'p'
                    AND pg_get_constraintdef(c.oid) <> 'PRIMARY KEY (window_ts, id)'
                LIMIT 1;

                IF existing_pkey_name IS NOT NULL THEN
                        EXECUTE format('ALTER TABLE llm_pass_1 DROP CONSTRAINT %I', existing_pkey_name);
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'llm_pass_1'::regclass
              AND contype = 'p'
              AND pg_get_constraintdef(oid) = 'PRIMARY KEY (window_ts, id)'
        ) THEN
            ALTER TABLE llm_pass_1
            ADD CONSTRAINT llm_pass_1_pkey PRIMARY KEY (window_ts, id);
        END IF;

        PERFORM create_hypertable(
            'llm_pass_1',
            'window_ts',
            chunk_time_interval => INTERVAL '6 hours',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
    END IF;
END
$$;
