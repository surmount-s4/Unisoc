# ULS — Unified Log System
### Multi-Source Security Detection, Firewall Correlation & Threat Hunting Platform

> A self-hosted, air-gap-capable, zero-licensing-cost security monitoring platform.  
> Collects Windows endpoint telemetry + Sophos firewall logs, performs real-time MITRE ATT&CK detection, and cross-correlates multi-source events into confirmed attack chains — stored in TimescaleDB for threat hunting.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Key Capabilities](#key-capabilities)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [1. Infrastructure (Docker)](#1-infrastructure-docker)
  - [2. Go Detection Server](#2-go-detection-server)
  - [3. Windows Agent](#3-windows-agent-source-side)
  - [4. Sophos Firewall Receiver](#4-sophos-firewall-receiver)
- [Configuration Reference](#configuration-reference)
- [Detection Engine](#detection-engine)
  - [IOA vs IOC](#ioa-vs-ioc)
  - [Severity Levels](#severity-levels)
  - [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Correlation Engine](#correlation-engine)
- [Deduplication](#deduplication)
- [Database Schema](#database-schema)
- [Threat Hunting Queries](#threat-hunting-queries)
- [Roadmap](#roadmap)

---

## Architecture Overview

```
┌────────────────────────────────┐      ┌─────────────────────────────────────────────────────┐
│         SOURCE SIDE            │      │                    SERVER SIDE                       │
│                                │      │                                                      │
│  ┌─────────────────────────┐   │      │  ┌──────────────┐   ┌─────────────┐                 │
│  │  ULS_Agent.ps1          │   │      │  │  Enrichment  │   │  Firewall   │                 │
│  │  (Windows endpoint)     │──▶│AMQP  │  │  Workers (N) │   │  Pipeline   │                 │
│  │                         │   │──────│─▶│  detector.go │   │  detector   │                 │
│  │  • Sysmon logs          │   │      │  └──────┬───────┘   └──────┬──────┘                 │
│  │  • Security log (4xxx)  │   │      │         │                  │                         │
│  │  • System log (7xxx)    │   │      │  ┌──────▼──────────────────▼──────┐                 │
│  │  • Application log      │   │      │  │      Deduplication Engine      │                 │
│  └─────────────────────────┘   │      │  │      (SHA-256 fingerprinting)  │                 │
│                                │      │  └──────┬─────────────────────────┘                 │
│  ┌─────────────────────────┐   │      │         │                                            │
│  │sophos_syslog_receiver.py│   │      │  ┌──────▼────────────────────────────────────────┐  │
│  │  (Sophos XG / SFOS)     │──▶│UDP   │  │              TimescaleDB                      │  │
│  │                         │   │5514  │  │  • security_events    (Windows telemetry)      │  │
│  │  • Firewall Allow/Drop  │   │──────│─▶│  • firewall_events    (Sophos telemetry)       │  │
│  │  • IDS/IPS/ATP alerts   │   │      │  │  • correlation_incidents (attack chains)       │  │
│  │  • Application control  │   │      │  └──────────────────────────────────────────────┘  │
│  └─────────────────────────┘   │      │                   ▲                                  │
│                                │      │  ┌────────────────┴──────────────────────────────┐  │
│         RabbitMQ               │      │  │         Correlation Engine                    │  │
│  ┌─────────────────────────┐   │      │  │  Runs every 30s · Links events across sources │  │
│  │  security_events queue  │   │      │  │  • C2 Beacon Confirmed                       │  │
│  │  firewall_events queue  │   │      │  │  • Brute Force Confirmed                     │  │
│  └─────────────────────────┘   │      │  │  • Cred Dump → Exfil                         │  │
└────────────────────────────────┘      │  │  • Lateral Movement Confirmed                │  │
                                        │  │  • Firewall Bypass Suspected                 │  │
                                        │  └──────────────────────────────────────────────┘  │
                                        └─────────────────────────────────────────────────────┘
```

**End-to-end latency:** ~200ms – 2 seconds (endpoint event → database row)

---

## Key Capabilities

| Capability | Detail |
|---|---|
| **MITRE ATT&CK Coverage** | 85.8% — 97 of 113 techniques across 14 tactics |
| **Log Sources** | Sysmon (Events 1,3,7,8,10,11,12,13,14,17,18,22,23), Windows Security (4624–5140), Windows System (7036,7045,104), Sophos XG firewall (all log types) |
| **Detection Engine** | Pre-compiled regex, zero heap allocation per rule, <5ms per event |
| **Cross-Source Correlation** | 5 rules linking Windows + Sophos events by shared IP within a 10-minute sliding window |
| **Alert Deduplication** | SHA-256 fingerprinting with 5-minute suppression window, 60–90% noise reduction |
| **Data Sovereignty** | 100% on-premise; no telemetry sent to vendor clouds; air-gap capable |
| **Throughput** | Tested at >5,000 events/second with 8 enrichment workers |

---

## Components

```
unisoc_log_analysis/
└── CUSTOM_LOGGERS/
    ├── source_side/
    │   ├── ULS_Agent.ps1                  ← Windows PowerShell collection agent
    │   └── sophos_syslog_receiver.py      ← Sophos syslog UDP receiver + RabbitMQ forwarder
    │
    └── server_side/
        └── uls-detection-server/
            ├── cmd/server/main.go          ← Main entrypoint, wires all pipelines
            ├── docker-compose.yml          ← TimescaleDB + RabbitMQ infrastructure
            ├── go.mod
            └── internal/
                ├── models/
                │   ├── event.go            ← SecurityEvent + DetectionResult structs
                │   └── firewall_event.go   ← FirewallEvent + CorrelationIncident structs
                ├── detector/
                │   └── detector.go         ← 2048-line MITRE ATT&CK detection engine
                ├── firewall/
                │   └── detector.go         ← Sophos-specific threat detection rules
                ├── correlator/
                │   ├── engine.go           ← Cross-source correlation engine
                │   └── rules.go            ← 5 correlation rules
                ├── dedup/
                │   └── dedup.go            ← Alert deduplication (SHA-256 + sliding window)
                ├── enrichment/
                │   └── service.go          ← N-worker enrichment pool
                ├── database/
                │   ├── connection.go       ← pgxpool connection
                │   ├── schema.go           ← security_events table + indexes
                │   ├── firewall.go         ← firewall_events + correlation_incidents tables
                │   └── insert.go           ← Bulk insert logic
                ├── dbwriter/
                │   └── service.go          ← Batch writer with retry + backoff
                └── queue/
                    ├── consumer.go         ← RabbitMQ consumer with auto-reconnect
                    └── publisher.go        ← RabbitMQ publisher with confirms
```

---

## Prerequisites

| Component | Version | Purpose |
|---|---|---|
| Go | ≥ 1.21 | Detection server compilation |
| Docker + Docker Compose | any recent | TimescaleDB + RabbitMQ |
| Python | ≥ 3.9 | Sophos syslog receiver |
| Windows | 10/11 or Server 2019+ | ULS Agent host |
| Sysmon | ≥ 15 | Endpoint event collection |
| Sophos XG / SFOS | any | Firewall log source (optional) |

---

## Quick Start

### 1. Infrastructure (Docker)

```bash
# Clone / navigate to the server directory
cd CUSTOM_LOGGERS/server_side/uls-detection-server

# Copy environment template
cp .env.example .env
# Edit .env to set database and RabbitMQ passwords

# Start TimescaleDB + RabbitMQ
docker compose up -d

# Verify health
docker compose ps
# Both services should show "healthy"
```

Default ports:
- `5432` — TimescaleDB (PostgreSQL)  
- `5672` — RabbitMQ AMQP  
- `15672` — RabbitMQ Management UI → `http://localhost:15672`

---

### 2. Go Detection Server

```bash
cd CUSTOM_LOGGERS/server_side/uls-detection-server

# Build
go build -o uls-server ./cmd/server

# Configure via environment variables (or export them)
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_USER=admin
export POSTGRES_PASS=admin
export POSTGRES_DB=uls_detection

export RABBITMQ_HOST=localhost
export RABBITMQ_PORT=5672
export RABBITMQ_USER=admin
export RABBITMQ_PASS=admin
export RABBITMQ_QUEUE=security_events
export RABBITMQ_FW_QUEUE=firewall_events

export BATCH_SIZE=100
export BATCH_DELAY_MS=1000

# Run
./uls-server
```

On first start the server auto-creates all three database tables (`security_events`, `firewall_events`, `correlation_incidents`) and their indexes.

---

### 3. Windows Agent (Source Side)

Run as **Administrator** on each monitored Windows endpoint:

```powershell
# Deploy Sysmon first (required)
# Download sysmon64.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
sysmon64.exe -accepteula -i sysmonconfig.xml

# Configure agent — set at least these variables at the top of ULS_Agent.ps1:
$RabbitMQServer = "192.168.1.100"   # IP of your detection server
$RabbitMQPort   = 5672
$RabbitMQUser   = "admin"
$RabbitMQPass   = "admin"

# Run the agent (runs indefinitely, polling every 5 seconds)
powershell.exe -ExecutionPolicy Bypass -File ULS_Agent.ps1

# Or install as a Windows service using NSSM:
nssm install ULSAgent powershell.exe -ExecutionPolicy Bypass -File "C:\ULS\ULS_Agent.ps1"
nssm start ULSAgent
```

**Events collected per poll cycle (every 5 seconds):**

| Source | Events |
|---|---|
| `Microsoft-Windows-Sysmon/Operational` | 1, 3, 7, 8, 10, 11, 12, 13, 14, 17, 18, 22, 23 |
| `Security` | 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4732, 4768, 4769, 4776, 4778, 4779, 5140 |
| `System` | 7036, 7045, 104 |
| `Application` | Application errors |

---

### 4. Sophos Firewall Receiver

```bash
cd CUSTOM_LOGGERS/source_side

# Install dependencies
pip install pika

# Run with RabbitMQ forwarding
python sophos_syslog_receiver.py \
  --host 0.0.0.0 \
  --port 5514 \
  --rmq-host 192.168.1.100 \
  --rmq-queue firewall_events \
  --verbose

# Stdout-only mode (no RabbitMQ, for testing)
python sophos_syslog_receiver.py --port 5514
```

**Configure Sophos XG / SFOS:**  
`System → Administration → Notification Settings → Syslog`
- Server IP: `<detection server IP>`  
- Port: `5514`  
- Protocol: `UDP`  
- Format: `Device Standard Format` (key=value) or `CEF`  
- Facility: `LOCAL0`  
- Severity: `Information` and above

Both `Device Standard Format` (key=value) and `CEF` are parsed automatically.

---

## Configuration Reference

All server configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_HOST` | `localhost` | TimescaleDB host |
| `POSTGRES_PORT` | `5432` | TimescaleDB port |
| `POSTGRES_USER` | `postgres` | DB username |
| `POSTGRES_PASS` | `postgres` | DB password |
| `POSTGRES_DB` | `security_logs` | Database name |
| `RABBITMQ_HOST` | `localhost` | RabbitMQ host |
| `RABBITMQ_PORT` | `5672` | RabbitMQ AMQP port |
| `RABBITMQ_USER` | `guest` | RabbitMQ username |
| `RABBITMQ_PASS` | `guest` | RabbitMQ password |
| `RABBITMQ_QUEUE` | `security_events` | Windows event queue name |
| `RABBITMQ_FW_QUEUE` | `firewall_events` | Sophos firewall queue name |
| `BATCH_SIZE` | `100` | Events per DB insert batch |
| `BATCH_DELAY_MS` | `1000` | Flush interval in milliseconds |

---

## Detection Engine

### How Detection Works

Every event from every source flows through the same pipeline:

```
Raw event (JSON)
       │
       ▼
  Parse fields           ← detect log source + event ID
       │
       ▼
  Detect()               ← detector.go dispatches to the matching rule function
       │                    e.g. detectProcessCreation(), detectNetworkConnection(), …
       ▼
  DetectionResult {
    Severity:          "HIGH"
    MitreTechnique:    "T1059.001,T1105"
    DetectionModule:   "Execution"
    EventDetails:      "PowerShell download cradle detected"      ← 5-second alert summary
    AdditionalContext: "File download via PowerShell may indicate malware delivery"
    IsIOA:             true
    ShortSummary:      "[Execution] PowerShell download cradle on WORKSTATION-07 (T1059.001)"
  }
       │
       ▼
  Deduplication          ← suppress duplicates within 5-minute window
       │
       ▼
  Bulk INSERT            ← security_events or firewall_events
```

### IOA vs IOC

| Type | What it is | When it fires | Examples in this system |
|---|---|---|---|
| **IOA** — Indicator of Attack | Behavioural pattern; tool-agnostic | Before compromise confirmed | Encoded PowerShell, LSASS access mask 0x1010, Kerberoasting RC4 ticket, named pipe pattern, DNS-over-TCP |
| **IOC** — Indicator of Compromise | Concrete artifact (hash / IP / domain) | After artifact is known-bad | C2 port match (4444/1337), malicious file path pattern, suspicious service binary location |

> Currently 95% of rules are **IOA-based** — they detect *how* attackers behave, not *which specific tool* they use, making them resistant to tool-swapping evasion.

### Severity Levels

| Level | Meaning | Example Rules |
|---|---|---|
| `INFO` | Observed, nothing suspicious | NTLM auth, network share access |
| `LOW` | Possibly suspicious, low confidence | Single 4625 failed logon, generic PowerShell, RDP session start |
| `MEDIUM` | Likely malicious or high-risk | Scheduled task creation, wscript/cscript execution, Kerberoasting attempt, explicit credential use |
| `HIGH` | Strong indicator of active attack | Encoded PowerShell, MSHTA, suspicious service install in `%TEMP%`, external→internal RDP allowed by firewall |
| `CRITICAL` | Confirmed active attack or post-exploitation | AMSI bypass, LSASS memory dump (Mimikatz pattern), C2 beacon confirmed by both endpoint + firewall, cred dump followed by exfil |

### MITRE ATT&CK Coverage

**85.8% coverage — 97 of 113 techniques across all 14 tactics**

| Tactic | Coverage | Key Techniques Detected |
|---|---|---|
| Execution | ✅ High | T1059.001 PowerShell, T1059.003 CMD, T1059.005 VBS, T1218.005 MSHTA, T1218.010 Regsvr32, T1218.011 Rundll32 |
| Persistence | ✅ High | T1053.005 Scheduled Tasks, T1543.003 Services, T1547.001 Run Keys, T1136.001 User Creation |
| Privilege Escalation | ✅ High | T1055 Process Injection, T1068, T1134 Token Manipulation |
| Defense Evasion | ✅ High | T1562.001 AMSI Bypass, T1218 LOLBins, T1070 Log Clearing |
| Credential Access | ✅ High | T1003.001 LSASS Dump, T1110 Brute Force, T1558.003 Kerberoasting, T1558.004 AS-REP Roasting |
| Discovery | ✅ Medium | T1057, T1082, T1083, T1087, T1135 |
| Lateral Movement | ✅ High | T1021.001 RDP, T1021.002 SMB, T1550.002 Pass-the-Hash |
| Collection | ✅ Medium | T1005, T1039, T1056, T1115 |
| Command & Control | ✅ High | T1071.001, T1071.004 DNS, T1571 Non-Standard Ports |
| Exfiltration | ✅ Medium | T1041, T1048 |

---

## Correlation Engine

The correlation engine (`internal/correlator/`) runs every **30 seconds**, queries both `security_events` and `firewall_events` from the last 10 minutes, and links events sharing the same source IP into confirmed attack sequences.

### 5 Correlation Rules

| Incident Type | What it means | Sources |
|---|---|---|
| `C2_BEACON_CONFIRMED` | Sysmon sees process connecting to C2 port AND Sophos confirms the outbound connection was allowed | Sysmon Event 3 + Firewall ALLOW |
| `BRUTE_FORCE_CONFIRMED` | 5+ Windows logon failures from IP X AND Sophos blocking IP X on same port | Security 4625 ×5 + Firewall DROP |
| `CRED_DUMP_THEN_EXFIL` | LSASS access detected on host X AND >10MB outbound from X's IP within 10 minutes | Sysmon Event 10 + Firewall large transfer |
| `LATERAL_MOVEMENT_CONFIRMED` | Windows records successful network logon from IP A to host B AND Sophos confirms internal SMB/RDP traffic A→B | Security 4624 + Firewall internal allow |
| `FIREWALL_BYPASS_SUSPECTED` | Sophos blocked IP X AND Windows shows successful logon from X shortly after | Firewall DENY + Security 4624 success |

Confirmed incidents are stored in the `correlation_incidents` table with full evidence JSON for forensic replay.

---

## Deduplication

During an active attack the same technique may trigger thousands of identical alerts (e.g. a C2 beacon firing every 100ms). The deduplication engine collapses these into a single DB row with a `duplicate_count` field.

**Fingerprint** (SHA-256 of):

```
agent_host | event_id | mitre_technique | detection_module | image_path | dest_ip | dest_port
```

**Not included in fingerprint:** timestamp, process ID, command line  
→ Obfuscated variants of the same attack still deduplicate correctly.

**Suppression window:** 5 minutes  
**GC interval:** every 10 minutes  
**Max cache size:** 50,000 fingerprints (~8MB RAM)

Expected noise reduction during sustained attacks: **60–90%**

---

## Database Schema

### `security_events` — Windows endpoint telemetry

Contains all events from the PowerShell agent, enriched with detection results.

| Column Group | Key Columns | Description |
|---|---|---|
| Detection | `severity`, `mitre_technique`, `detection_module`, `event_details`, `additional_context` | Alert fields populated by the detection engine |
| Agent | `agent_host`, `timestamp` | Originating hostname and timestamp |
| Sysmon (Level 2) | `image_2`, `commandline_2`, `processguid_2`, `hashes_2`, `destinationip_2`, `destinationport_2`, `targetfilename_2`, `grantedaccess_2`, `calltrace_2` | All Sysmon-specific fields |
| Security log (Level 3) | `logontype_3`, `targetusername_3`, `ipaddress_3`, `ticketencryptiontype_3`, `failurereason_3` | Windows Security log specifics |
| Raw | `eventdata_1` | Full XML blob for unparsed events |

### `firewall_events` — Sophos firewall telemetry

Contains all events from the Sophos syslog receiver, enriched with detection results.

| Column Group | Key Columns | Description |
|---|---|---|
| Detection | `threat_level`, `threat_type`, `mitre_technique`, `event_details` | Firewall detection results |
| Network | `src_ip`, `src_port`, `src_zone_type`, `dst_ip`, `dst_port`, `dst_zone_type` | Full 5-tuple + zone |
| Traffic | `sent_bytes`, `recv_bytes`, `protocol`, `action` | Volume + permit/deny |
| Classification | `log_type`, `log_component`, `log_subtype` | Sophos log category |
| Threat | `message`, `classification` | IDS/IPS/ATP alert text |

### `correlation_incidents` — Cross-source confirmed attack chains

| Column | Description |
|---|---|
| `incident_type` | Attack chain type (see Correlation Engine section) |
| `severity` / `confidence` | HIGH or CRITICAL / MEDIUM or HIGH |
| `affected_host` / `affected_ip` | The compromised machine |
| `mitre_techniques` | Comma-separated ATT&CK IDs from all sources |
| `description` | Human-readable attack narrative |
| `evidence` | JSON array of all linked source events |
| `window_start` / `window_end` | Time range of the attack sequence |

---

## Threat Hunting Queries

Connect to TimescaleDB and run:

```sql
-- Active CRITICAL alerts in the last hour
SELECT timestamp, agent_host, detection_module, mitre_technique, event_details
FROM security_events
WHERE severity = 'CRITICAL'
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;

-- All confirmed attack chains today
SELECT created_at, incident_type, severity, affected_host, affected_ip, description
FROM correlation_incidents
WHERE created_at > NOW() - INTERVAL '24 hours'
ORDER BY severity DESC, created_at DESC;

-- Top attacking IPs (firewall blocked, >10 attempts)
SELECT src_ip, COUNT(*) AS attempts, ARRAY_AGG(DISTINCT dst_port) AS ports_tried
FROM firewall_events
WHERE action IN ('DROP','DENY','REJECT')
  AND received_at > NOW() - INTERVAL '24 hours'
GROUP BY src_ip
HAVING COUNT(*) > 10
ORDER BY attempts DESC;

-- MITRE ATT&CK heatmap — which techniques are firing most
SELECT mitre_technique, detection_module, COUNT(*) AS hits, MAX(severity) AS max_severity
FROM security_events
WHERE mitre_technique != ''
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY mitre_technique, detection_module
ORDER BY hits DESC;

-- Hosts with LSASS access (potential credential theft)
SELECT timestamp, agent_host, image_2, grantedaccess_2, calltrace_2
FROM security_events
WHERE mitre_technique LIKE '%T1003%'
ORDER BY timestamp DESC;

-- Large outbound transfers through firewall
SELECT received_at, src_ip, dst_ip, dst_port, sent_bytes, app_name
FROM firewall_events
WHERE CAST(sent_bytes AS BIGINT) > 10000000
  AND action = 'ALLOW'
ORDER BY CAST(sent_bytes AS BIGINT) DESC;
```

---

## Roadmap

| Priority | Feature | Effort |
|---|---|---|
| 🔴 High | **Webhook alerter** — POST CRITICAL incidents to Slack / Teams / PagerDuty | 1 day |
| 🔴 High | **Grafana dashboard** — severity timeline, MITRE heatmap, top IPs panel | 2 days |
| 🟡 Medium | **IOC feed integration** — VirusTotal / AbuseIPDB lookup for IPs and hashes | 3 days |
| 🟡 Medium | **Temporal brute-force rule** — sliding window counter for N×4625 in T seconds | 2 days |
| 🟡 Medium | **Geo-IP enrichment** — country lookup for firewall src/dst IPs | 1 day |
| 🟢 Lower | **Linux auditd source** — extend agent to ingest `auditd` logs | 1 week |
| 🟢 Lower | **Process ancestry tree** — reconstruct full parent→child chain via ProcessGuid | 1 week |
| 🟢 Lower | **Web threat hunting UI** — query interface over TimescaleDB | 2 weeks |

---

## License

This project is intended for internal security operations and research use.

---

*Built with Go · Python · PostgreSQL/TimescaleDB · RabbitMQ · Sysmon · Sophos XG*
