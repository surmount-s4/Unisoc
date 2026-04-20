# ULS Detection Server

Comprehensive implementation guide for how each feature works, how data flows through the system, and how to operate it in production.

## 1) What this service does

The ULS Detection Server ingests security telemetry from multiple sources, applies detections, enriches events with optional LLM logic, and performs cross-source correlation to generate incidents.

Active telemetry paths:
- Windows telemetry from RabbitMQ queue `security_events`
- Sophos firewall telemetry from RabbitMQ queue `firewall_events`
- SCADA telemetry from RabbitMQ queue `scada_logs` and optional internal HTTP endpoint `/ingest_scada`

Core outputs:
- Raw and detected Windows events in `security_events` table
- Raw and detected firewall events in `firewall_events` table
- Raw SCADA events in `scada_logs` table
- LLM pass output in `llm_pass_1`
- Correlation state and outputs in `correlation_windows`, `bart_event_decisions`, `process_chain`, `correlation_incidents`

## 2) Runtime architecture

### 2.1 Active modules in current main runtime

The running entrypoint is `cmd/server/main.go` and actively wires:
- `internal/database`
- `internal/queue`
- `internal/detector` (Windows detection)
- `internal/firewall` (firewall detection)
- `internal/llmwatcher` (5-second LLM enrichment pass)
- `internal/correlationengine` (windowed correlation engine v2)

### 2.2 Present but not currently wired by main runtime

These packages exist in repository but are not currently constructed from `cmd/server/main.go`:
- `internal/enrichment`
- `internal/dbwriter`
- `internal/dedup`
- `internal/correlator` (older correlator path)
- `internal/config` (older env config loader)

Treat these as optional/legacy building blocks unless you explicitly rewire entrypoint.

## 3) End-to-end data flow

## 3.1 High level flow

```text
[Windows Agent] ----> RabbitMQ: security_events ----> main.go windows batch loop
                                                       -> detector.Detect()
                                                       -> database.InsertEvents()
                                                       -> PostgreSQL: security_events

[Firewall Receiver] -> RabbitMQ: firewall_events ----> runFirewallPipeline goroutine
                                                       -> firewall.Detector.Detect()
                                                       -> database.InsertFirewallEvents()
                                                       -> PostgreSQL: firewall_events

[SCADA Receiver] ----> RabbitMQ: scada_logs ---------> runScadaPipeline goroutine
                                                       -> database.InsertScadaEvents()
                                                       -> PostgreSQL: scada_logs

[Optional HTTP] POST /ingest_scada ------------------> RabbitMQ publisher to scada_logs

[LLM Watcher] polls 5-second windows from security_events + firewall_events
             -> optional Ollama classification
             -> writes llm_pass_1

[Correlation Engine v2] 10-minute tumbling window
                       -> fetch llm_pass_1 (windows), firewall_events, scada_logs
                       -> BART classify windows pass rows (malicious vs benign)
                       -> build process-chain evidence from Sysmon GUIDs
                       -> correlator LLM evaluates cross-source payload
                       -> write incidents to correlation_incidents
                       -> write audit state to correlation_windows + bart_event_decisions
```

### 3.2 Message acknowledgment and reliability semantics

All RabbitMQ consumers run with manual ack (`auto-ack=false`), which provides at-least-once delivery behavior.

- On successful batch processing: `Ack(false)` per message
- On transient processing/DB failures: `Nack(false, true)` to requeue
- On malformed payloads that cannot be parsed: `Nack(false, false)` to drop/reject

Implication:
- Processing is resilient to temporary DB outages.
- Producers should be idempotent or downstream should tolerate duplicate delivery on retries.

## 4) Feature-by-feature deep dive

## 4.1 Windows ingestion and detection

Pipeline:
1. Consume message from queue `security_events`.
2. Accept either JSON array of `SecurityEvent` or single `SecurityEvent`.
3. Accumulate batch by count (`BATCH_SIZE`) or time (`BATCH_DELAY_MS`).
4. For each event in batch, run `detector.Detect(event)`.
5. Detection fields are populated onto event:
   - `severity`
   - `mitre_technique`
   - `detection_module`
   - `event_details`
   - `additional_context`
6. Bulk insert to `security_events` table.

How rules work:
- Detector precompiles regex patterns at startup for speed.
- Rules are dispatched by log source and event type:
  - Sysmon events (for example Event IDs 1, 3, 7, 10, 11, 22, 23)
  - Security log events (for example 4624, 4625, 4688, 4697, 4768, 4769)
  - System log events (for example 7045, 7036, 104)
- Many rules are early-return style: first high-confidence match returns result quickly.

Primary use:
- Convert raw Windows telemetry into actionable detections with MITRE mapping and severity.

## 4.2 Firewall ingestion and detection

Pipeline:
1. Consume from queue `firewall_events` (if queue connection succeeds).
2. Accept array or single `FirewallEvent` JSON payload.
3. Batch by count/time.
4. Run firewall detector for each event.
5. Store in `firewall_events` with detection outputs.

Key firewall detection classes include:
- IDS/IPS/ATP alerts
- C2/known suspicious port usage
- WAN to LAN sensitive service exposure
- Internal lateral movement indicators
- Large outbound transfer indicators
- DNS over TCP anomalies
- Policy deny telemetry

Primary use:
- Add network-layer behavior and policy-level evidence for correlation.

## 4.3 SCADA ingestion

SCADA has two ingress paths:

A) RabbitMQ path
- Consume queue `scada_logs`
- Batch and insert into `scada_logs`

B) Internal HTTP path
- Endpoint: `POST /ingest_scada`
- Accepts single object or array of `ScadaEvent`
- Required fields for each event: `timestamp`, `tag`, `name`, `message`
- `source` defaults to `Unknown_SCADA` if empty
- If `received_at` missing, server sets current time
- Server republishes payload to SCADA RabbitMQ queue, then normal SCADA pipeline persists to DB

Primary use:
- Integrate ICS/SCADA events into the same timeline used by correlation.

## 4.4 Database schema initialization and persistence

At startup, main initializes schemas in this order:
1. `InitSchema` for `security_events`
2. `InitFirewallSchema` for `firewall_events` and `correlation_incidents`
3. `InitScadaSchema` for `scada_logs`
4. `InitLLMPassSchema` for `llm_pass_1`
5. `correlationengine.InitSchema` for `correlation_windows`, `bart_event_decisions`, `process_chain`

Key storage characteristics:
- Batch multi-row inserts for throughput
- Timestamp indexes for windowed reads
- Source IP and severity indexes for common query patterns
- SCADA table includes backward-compatible migration from text timestamp to timestamptz

Primary use:
- Keep ingest and detection path fast while supporting analytics and correlation queries.

## 4.5 LLM watcher (pass-1 enrichment)

The LLM watcher is asynchronous and non-blocking to ingestion path.

Execution model:
- Runs periodic poll loop every `LLM_WINDOW_SECONDS` (default 5 sec)
- Pulls new rows from:
  - `security_events` (Windows)
  - `firewall_events` (firewall)
- Filters by severity (default LOW+ unless `IncludeInfo` true)
- Deduplicates within window by fingerprint
- Caps batch sizes (`MaxBatchSize`)
- Calls Ollama in parallel for windows and firewall batches when enabled
- Falls back to passthrough output when LLM is disabled/unavailable
- Writes unified rows into `llm_pass_1`

Persisted forensic fields in `llm_pass_1`:
- `llm_severity`: normalized severity from forensic verdict (`Info|Warning|Critical`)
- `llm_short_summary`: forensic reasoning text
- `llm_is_ioc`: boolean flag when IoCs are present
- `llm_ioc_values`: comma-separated IoC list
- `llm_is_ioa`: boolean flag when IoAs are present
- `llm_ioa_values`: comma-separated IoA list

Important behavior guarantees:
- Ingestion path is never blocked by LLM path.
- If output channel is full, watcher drops that window and records dropped metric.
- Circuit breaker opens after repeated Ollama failures to avoid constant timeout storms.

Final field resolution in `llm_pass_1`:
- `final_severity` = `llm_severity` if present, else `rule_severity`
- `final_summary` = `llm_short_summary` if present, else `raw_summary`
- `final_mitre` = `llm_mitre_technique` if present, else `rule_mitre`

Primary use:
- Create normalized, confidence-scored, compact event representations for correlation.

## 4.6 Correlation engine v2

Correlation engine v2 is a tumbling-window runtime that performs unbiased cross-source reasoning.

Windowing:
- Uses last closed UTC window of `CORR_WINDOW_MINUTES` (default 10 min)
- Runs every `CORR_TICK_SECONDS` (default 60 sec)
- Uses `correlation_windows` table to acquire one owner per window (`UNIQUE` lock pattern)

Per-window processing sequence:
1. Fetch windows events from `llm_pass_1` (`source_type='windows'`).
2. BART pre-classify each windows pass row as malicious or benign using threshold `BART_CONFIDENCE_THRESHOLD`.
3. Persist every BART decision into `bart_event_decisions`.
4. Keep only malicious windows rows for next stage.
5. Fetch firewall rows from `firewall_events` in same window.
6. Fetch SCADA rows from `scada_logs` in same window.
7. Build process chain evidence from Sysmon GUID relations in `security_events`:
   - process creation tree (parent-child)
   - source-target interaction tree (remote thread/process access style links)
8. Send full payload to correlator LLM (Ollama-compatible endpoint).
9. Parse incident candidates and persist to `correlation_incidents`.
10. Mark window done/failed in `correlation_windows` with counts and assessment.

Assessment logic:
- If no events for correlation, defaults healthy with confidence 1.0.
- With events, correlator LLM provides:
  - overall assessment (`malicious`, `suspicious`, `healthy`, `safe`)
  - incident candidates
  - attack chain progression
  - recommendations

Primary use:
- Move from per-event alerts to multi-source, time-bound attack narratives.

## 4.7 Internal HTTP SCADA bridge

Endpoint details:
- Path: `/ingest_scada`
- Method: `POST`
- Port: `SCADA_HTTP_PORT` (default 5001)
- Behavior: validation then publish to SCADA queue

Use case:
- Fast direct API ingestion from local integrations that cannot publish AMQP directly.

## 4.8 Queue connection resilience

Publisher and consumer implement reconnection loops:
- Detect closed channels via notifications
- Retry reconnect up to 30 attempts with incremental backoff
- Fail fast if unrecoverable after max attempts

Use case:
- Survive broker restarts and temporary network interruptions.

## 5) Data contracts

## 5.1 Windows input payload

Expected payload type in queue `security_events`:
- JSON object or JSON array of `SecurityEvent`

Server accepts large normalized field set (Levels 0/1/2/3/5), including:
- Event identity and source fields (`EventID_0`, `LogSource_5`)
- Sysmon detail fields (`Image_2`, `CommandLine_2`, `DestinationIp_2`, `DestinationPort_2`)
- Security event fields (`LogonType_3`, `IpAddress_3`, etc)

## 5.2 Firewall input payload

Expected payload type in queue `firewall_events`:
- JSON object or JSON array of `FirewallEvent`

Common high-value fields:
- `src_ip`, `dst_ip`, `dst_port`, `protocol`, `action`
- `log_type`, `log_component`, `severity`, `message`
- `src_zone_type`, `dst_zone_type`, `sent_bytes`

## 5.3 SCADA input payload

Expected payload type in queue `scada_logs` or HTTP `/ingest_scada`:
- JSON object or JSON array of `ScadaEvent`

Required for HTTP path validation:
- `timestamp`, `tag`, `name`, `message`

## 6) Configuration and feature toggles

Environment variables read by current `main.go`:

### RabbitMQ
- `RABBITMQ_HOST` (default `localhost`)
- `RABBITMQ_PORT` (default `5672`)
- `RABBITMQ_USER` (default `guest`)
- `RABBITMQ_PASS` (default `guest`)
- `RABBITMQ_QUEUE` (default `security_events`)
- `RABBITMQ_FW_QUEUE` (default `firewall_events`)
- `RABBITMQ_SCADA_QUEUE` (default `scada_logs`)

### PostgreSQL
- `POSTGRES_HOST` (default `localhost`)
- `POSTGRES_PORT` (default `5432`)
- `POSTGRES_USER` (default `postgres`)
- `POSTGRES_PASS` (default `postgres`)
- `POSTGRES_DB` (default `security_logs`)

### Batching
- `BATCH_SIZE` (default `100`)
- `BATCH_DELAY_MS` (default `1000`)

### LLM watcher pass-1
- `OLLAMA_URL` (empty means disabled/passthrough)
- `OLLAMA_MODEL` (default `mistral`)
- `LLM_WINDOW_SECONDS` (default `5`)
- `LLM_PASS_ENABLED` (present but not used by current main flow control)

### Correlation engine v2
- `CORRELATION_ENGINE_V2_ENABLED` (default `true`)
- `CORR_WINDOW_MINUTES` (default `10`)
- `CORR_TICK_SECONDS` (default `60`)
- `BART_INPROCESS` (default `true`; enables local in-process runner)
- `BART_MODEL_ID` (default `facebook/bart-large-mnli`)
- `BART_MODEL_PATH` (optional local model directory)
- `BART_PYTHON_BIN` (default `python`)
- `BART_RUNNER_PATH` (default `internal/correlationengine/bart_runner.py`)
- `BART_SERVICE_URL` (optional HTTP fallback backend)
- `BART_MODEL` (optional model hint for HTTP fallback)
- `BART_TIMEOUT_SECONDS` (default `15`)
- `BART_CONFIDENCE_THRESHOLD` (default `0.30`)
- `CORR_LLM_URL` (fallbacks to `OLLAMA_URL` if empty)
- `CORR_LLM_MODEL` (fallback to `OLLAMA_MODEL`)
- `CORR_LLM_TIMEOUT_SECONDS` (default `90`)

### Internal SCADA HTTP bridge
- `SCADA_HTTP_PORT` (default `5001`)

## 7) How to run

## 7.1 Start compose stack (always-on ingestion)

This project includes infrastructure compose file:

```bash
docker compose up -d
```

Services provided by compose:
- TimescaleDB/PostgreSQL on `5432`
- RabbitMQ on `5672`
- RabbitMQ Management UI on `15672`
- ULS server (always-on Windows queue ingest + SCADA queue ingest)
- Internal SCADA HTTP ingest bridge on `5001`
- Go universal syslog receiver on UDP `5514`

If you want only infra and no receiver container, run:

```bash
docker compose up -d timescaledb rabbitmq
```

If you want infra + server only (without UDP syslog receiver), run:

```bash
docker compose up -d timescaledb rabbitmq uls-server
```

## 7.2 Run server manually (optional)

```bash
go mod tidy
go run ./cmd/server
```

or build binary:

```bash
go build -o uls-server ./cmd/server
./uls-server
```

Note:
- In compose mode, `uls-server` is already started as a service.
- Windows source collection itself still runs on Windows hosts via `ULS_Agent.ps1` and publishes to RabbitMQ `security_events`.

### 7.2.1 Install in-process BART dependencies

The in-process BART pre-classifier requires Python and two packages on the server host.

Install:

```bash
python -m pip install --upgrade pip
python -m pip install transformers torch
```

If your host uses `python3`, run:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install transformers torch
```

### 7.2.2 Smoke test BART runner locally

Run a one-line request directly against the local runner before starting the Go server.

Linux/macOS shell:

```bash
printf '{"text":"Encoded PowerShell downloading payload","threshold":0.30,"labels":["Malicious","Benign"]}\n' | python3 -u internal/correlationengine/bart_runner.py --model-id facebook/bart-large-mnli
```

Windows PowerShell:

```powershell
'{"text":"Encoded PowerShell downloading payload","threshold":0.30,"labels":["Malicious","Benign"]}' | python -u internal/correlationengine/bart_runner.py --model-id facebook/bart-large-mnli
```

Expected output pattern:
- First line: readiness JSON with `"ready": true`
- Second line: classification JSON containing `classification`, `confidence`, and `model`

If this test works, start the server with:
- `BART_INPROCESS=true`
- `BART_MODEL_ID=facebook/bart-large-mnli`
- Optional `BART_MODEL_PATH` for an offline local model directory

## 7.3 Recommended startup order

1. Start PostgreSQL and RabbitMQ.
2. Ensure source producers are publishing to expected queues.
3. Start server.
4. Confirm startup logs for:
   - schema initialization success
   - pipeline activation lines for firewall and scada
   - llmwatcher status (enabled or passthrough)
  - BART backend summary line (mode, model_ref, runner or endpoint)
  - correlationengine started

Runtime reliability notes:
- Windows, firewall, and SCADA consumers auto re-subscribe after RabbitMQ delivery channel closures.
- On malformed payloads, messages are rejected without requeue; on transient DB errors, messages are requeued.

## 7.4 Run the Go universal syslog receiver (replaces Python dependency)

This project now includes a native Go syslog receiver command:
- `cmd/syslog-receiver`

Purpose:
- Listen on UDP syslog.
- Parse generic key-value logs, FortiGate key-value logs, and CEF.
- Normalize into the internal firewall event schema.
- Batch publish to RabbitMQ queue `firewall_events` (or configured queue).

Build and run:

```bash
go build -o uls-syslog-receiver ./cmd/syslog-receiver
./uls-syslog-receiver --host 0.0.0.0 --port 5514 --rmq-host localhost --rmq-port 5672 --rmq-user admin --rmq-pass admin --rmq-queue firewall_events
```

Optional flags:
- `--batch-size` (default `50`)
- `--flush-sec` (default `2`)
- `--verbose`

Environment variable equivalents:
- `SYSLOG_HOST`, `SYSLOG_PORT`
- `SYSLOG_BATCH_SIZE`, `SYSLOG_FLUSH_SEC`
- `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USER`, `RABBITMQ_PASS`, `RABBITMQ_FW_QUEUE`

Behavior notes:
- If RabbitMQ is unavailable at startup, receiver runs in stdout-only mode.
- Receiver periodically retries and auto-attaches to RabbitMQ once reachable.
- Published messages remain compatible with existing `runFirewallPipeline` ingestion path.

### 7.4.1 FortiGate format support details

FortiGate traffic/syslog records are typically key-value pairs such as:
- `date`, `time`, `devname`, `devid`, `logid`, `type`, `subtype`, `level`
- `srcip`, `srcport`, `dstip`, `dstport`, `action`, `proto`, `policyid`
- `sentbyte`, `rcvdbyte`, `sentpkt`, `rcvdpkt`, `service`, `msg`

The Go receiver maps these to internal fields used by detection and correlation, including:
- `src_ip`, `dst_ip`, `dst_port`, `action`, `protocol`
- `threat_level` pipeline inputs (`log_type`, `log_subtype`, `severity`, `message`)
- transfer counters (`sent_bytes`, `recv_bytes`)

Protocol normalization is applied for common FortiGate numeric values:
- `proto=6` -> `TCP`
- `proto=17` -> `UDP`
- `proto=1` -> `ICMP`

## 8) Practical usage patterns

## 8.1 Rule-only operation (no LLM)

Set:
- `OLLAMA_URL=` (empty)
- `CORRELATION_ENGINE_V2_ENABLED=false` if you do not have BART/Correlator services

Result:
- Windows/firewall/scada ingestion and rule detections continue
- `llm_pass_1` receives passthrough rows
- no correlation window processing if engine disabled

## 8.2 Full enrichment and correlation

Set:
- `OLLAMA_URL` for pass-1 enrichment
- `BART_INPROCESS=true` and `BART_MODEL_ID=facebook/bart-large-mnli` for local BART gating
- `CORR_LLM_URL` for final cross-source reasoning (or rely on OLLAMA fallback)
- `CORRELATION_ENGINE_V2_ENABLED=true`

Result:
- Full chain from raw events to correlated incidents

## 8.3 SCADA-only API bridge usage

POST sample:

```bash
curl -X POST http://localhost:5001/ingest_scada \
  -H "Content-Type: application/json" \
  -d '[
    {
      "source": "PLC_A",
      "timestamp": "2026-01-05T12:10:30Z",
      "tag": "PUMP_12_STATUS",
      "name": "Pump 12",
      "message": "Unexpected stop",
      "classification": "alert"
    }
  ]'
```

## 9) Operational verification queries

Use these SQL checks to validate flow quickly.

```sql
SELECT count(*) FROM security_events;
SELECT count(*) FROM firewall_events;
SELECT count(*) FROM scada_logs;
SELECT count(*) FROM llm_pass_1;
SELECT count(*) FROM correlation_incidents;
```

Recent ingestion sanity:

```sql
SELECT created_at, severity, mitre_technique, event_details
FROM security_events
ORDER BY created_at DESC
LIMIT 20;
```

Recent LLM pass rows:

```sql
SELECT created_at, source_type, final_severity, final_mitre, final_summary, llm_enabled
FROM llm_pass_1
ORDER BY created_at DESC
LIMIT 20;
```

Window audit:

```sql
SELECT window_start, window_end, status,
       windows_events_total, windows_events_malicious,
       firewall_events_total, scada_events_total,
       llm_assessment, llm_confidence, error_text
FROM correlation_windows
ORDER BY window_start DESC
LIMIT 20;
```

Incidents:

```sql
SELECT created_at, incident_type, severity, confidence, affected_host, affected_ip
FROM correlation_incidents
ORDER BY created_at DESC
LIMIT 20;
```

## 10) Failure modes and troubleshooting

## 10.1 BART URL missing while correlation v2 enabled

Symptom:
- Correlation windows marked failed when windows events exist.

Reason:
- Engine requires either in-process BART runner (`BART_INPROCESS=true`) or a reachable `BART_SERVICE_URL`.

Fix:
- Preferred: enable in-process runner with `BART_INPROCESS=true` and `BART_MODEL_ID=facebook/bart-large-mnli`.
- Alternative: set `BART_SERVICE_URL` to reachable classifier endpoint.

## 10.2 LLM endpoint unstable

Symptom:
- LLM watcher logs errors and fallback behavior.

Reason:
- Ollama timeout/unavailability opens circuit breaker temporarily.

Fix:
- Stabilize LLM endpoint, tune timeout, scale model host.

## 10.3 Queue payload parsing failures

Symptom:
- Parse errors and messages dropped with `Nack(requeue=false)`.

Fix:
- Validate producers emit JSON matching expected object/array shapes.

## 10.4 Backpressure in LLM watcher output channel

Symptom:
- Dropped windows metric increases.

Fix:
- Increase DB capacity, tune batch sizes, or increase watcher output buffer in code.

## 11) Security and performance notes

- Database uses connection pool defaults (`MaxConns=20`, `MinConns=5`).
- Batch inserts reduce write overhead significantly versus row-by-row writes.
- Rule detection path is deterministic and fast due to precompiled regex patterns.
- LLM operations are isolated from ingestion path to avoid data loss during LLM outages.
- Correlation windows are idempotent by unique `(engine_name, window_start, window_end)`.

## 12) Folder map (what to read first)

- `cmd/server/main.go`: runtime orchestration and pipeline wiring
- `internal/detector`: Windows detection logic
- `internal/firewall`: firewall detection logic
- `internal/llmwatcher`: pass-1 LLM enrichment
- `internal/correlationengine`: window processing, BART gating, incident generation
- `internal/database`: schemas and insert paths
- `internal/queue`: RabbitMQ consumer/publisher with reconnect
- `docker-compose.yml`: local infra dependencies

## 13) Quick decision matrix

Use this if you are deciding what to enable:

- Need only raw detections in DB: enable ingestion, disable correlation v2.
- Need explainable per-event enrichment: enable LLM watcher (`OLLAMA_URL`).
- Need incident-level narratives across sources: enable v2 with BART + correlator LLM endpoints.
- Need ICS integration quickly: use `/ingest_scada` bridge and/or `scada_logs` queue.

---

If you want, this README can be extended with sequence diagrams and sample producer payload files per source (Windows, firewall, SCADA) for direct integration testing.
