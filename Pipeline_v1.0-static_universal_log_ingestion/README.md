# Log Analysis Pipeline v1.0

## 🚀 Multi-Source Security Event Correlation Pipeline

The Log Analysis Pipeline is a comprehensive system designed to efficiently ingest, process, analyze, and correlate log data from **multiple security sources**:
- **Windows EDR** (Endpoint Detection & Response)
- **SCADA** (Industrial Control Systems)
- **Firewall** (Network Security Devices)

This pipeline uses **AI-powered correlation** to detect cross-source attack patterns and generate comprehensive attack chain analysis using Large Language Models (LLMs).

---

## 🎯 Key Features

✅ **Multi-Source Ingestion**: Windows CSV, SCADA CSV, Firewall HTTP endpoints  
✅ **Real-time Processing**: RabbitMQ message queue with PostgreSQL storage  
✅ **AI Analysis**: 5-second LLM windows for intelligent event interpretation  
✅ **Cross-Source Correlation**: IP-based and temporal correlation across all sources  
✅ **Attack Chain Detection**: Identifies multi-stage attacks spanning different systems  
✅ **MITRE ATT&CK Mapping**: Automatic technique identification and categorization  
✅ **Scalable Architecture**: Modular design with independent processing components  

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Supported Log Sources](#supported-log-sources)
- [Pipeline Components](#pipeline-components)
- [Multi-Source Correlation](#multi-source-correlation)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Documentation](#documentation)
- [Contributing](#contributing)

---

## 🏗️ Architecture Overview

```
┌─────────────┐    ┌──────────┐    ┌──────────┐
│ Windows CSV │───▶│          │    │          │
│ SCADA CSV   │───▶│ Parsers  │───▶│ RabbitMQ │
│ Firewall    │───▶│ Receiver │    │  Queue   │
│ HTTP POST   │    │          │    │          │
└─────────────┘    └──────────┘    └────┬─────┘
                                         │
                                         ▼
                                  ┌──────────────┐
                                  │ log_processor│
                                  │ (Table Router)│
                                  └──────┬───────┘
                                         │
                        ┌────────────────┴────────────────┐
                        ▼                                 ▼
                ┌───────────────┐              ┌──────────────────┐
                │  logs table   │              │ firewall_logs    │
                │ (Windows/SCADA)│              │ table            │
                └───────┬───────┘              └────────┬─────────┘
                        │                               │
                        └──────────┬────────────────────┘
                                   │ PostgreSQL NOTIFY
                                   ▼
                            ┌──────────────┐
                            │  watcher.py  │
                            │ (5-sec LLM   │
                            │  windows)    │
                            └──────┬───────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │ llm_pass_1 table│
                          │ (All sources)   │
                          └────────┬────────┘
                                   │
                                   ▼
                      ┌────────────────────────┐
                      │ correlation_engine_db  │
                      │ (Cross-source analysis)│
                      └────────────────────────┘
```

The pipeline processes logs through five stages:
1. **Ingestion**: Collect logs from CSV files and HTTP endpoints
2. **Parsing**: Extract structured information and validate
3. **Storage**: Route to appropriate PostgreSQL tables
4. **Analysis**: LLM-powered 5-second window analysis
5. **Correlation**: Multi-source attack chain detection

---

## ⚡ Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- RabbitMQ 3.8+
- Ollama (for LLM analysis)

### 1. Setup Database
```bash
psql -U postgres -d logs_db -f create_firewall_logs_schema.sql
psql -U postgres -d logs_db -f update_logs_trigger.sql
```

### 2. Start Services
```bash
# Terminal 1: Start receiver
python receiver.py

# Terminal 2: Start log processor
python log_processor.py

# Terminal 3: Start watcher
python watcher.py
```

### 3. Test Pipeline
```bash
python test_firewall_integration.py
```

### 4. Send Logs
```bash
# Windows/SCADA logs (automatically monitored CSVs)
# Firewall logs (HTTP POST)
curl -X POST http://172.16.0.144:5000/ingest_firewall \
  -H "Content-Type: application/json" \
  -d '{
    "level": "warning",
    "date": "2024-01-15T14:30:00",
    "host_address": "192.168.1.100",
    "facility": "firewall",
    "inputsource": "pfsense",
    "host_name": "fw-gateway-01",
    "message": "Blocked connection attempt"
  }'
```

### 5. Run Correlation Analysis
```bash
python correlation_engine_db.py
```

---

## 📡 Supported Log Sources

### 1. Windows EDR Logs
**Format**: CSV  
**Columns**: 151 fields including process details, network activity, file operations  
**Parser**: `source-side-log-parser.py`  
**Table**: `logs`  
**Fields**: `process_name`, `command_line`, `source_ip`, `dest_ip`, `username`, etc.

### 2. SCADA Logs
**Format**: CSV  
**Columns**: Industrial control system events  
**Parser**: `source-side-log-parser.py`  
**Table**: `logs`  
**Fields**: System-specific industrial control data

### 3. Firewall Logs (NEW)
**Format**: HTTP POST (JSON)  
**Endpoint**: `/ingest_firewall`  
**Required Fields**:
- `level` - Severity (info/warning/alert/critical)
- `date` - Timestamp
- `host_address` - Firewall IP
- `facility` - Log facility (firewall/utm/ids)
- `inputsource` - Device type (pfsense/fortinet/cisco-asa)
- `host_name` - Device hostname
- `message` - Log message

**Table**: `firewall_logs`  
**Additional Fields**: `source_ip`, `dest_ip`, `port`, `protocol`

---

## 🔧 Pipeline Components

Each module is independently developed to ensure updates in one component have minimal impact on others

---

## Modules

### 1. Data Ingestion Module

- **Purpose:** 
  - Collects log data from multiple sources including files, network streams, and system outputs.
- **Key Features:**
  - Multi-source read support (local files, remote endpoints).
  - Real-time streaming ingestion.
  - Buffering and pre-validation of log data.
- **Components:**
  - Source connectors.
  - Queue management for high throughput.

### 2. Log Parsing Module

- **Purpose:** 
  - Converts raw log entries into a structured format for further analysis.
- **Key Features:**
  - Supports multiple log formats (e.g., JSON, plain text, custom formats).
  - Pattern matching and regular expression-based parsing.
  - Time-stamp normalization and error handling.
- **Components:**
  - Parser engine.
  - Format-specific handlers.

### 3. Analysis Engine

- **Purpose:** 
  - Provides insights by analyzing structured log data.
- **Key Features:**
  - Statistical aggregation and trend analysis.
  - Anomaly detection algorithms.
  - Customizable rule-based processing.
- **Components:**
  - Aggregators for summarization.
  - Machine learning-based anomaly detectors.
  - Comparison and trend modules.

### 4. Alerting System

- **Purpose:** 
  - Monitors the analysis outputs and triggers alerts when critical events or anomalies occur.
- **Key Features:**
  - Threshold-based and predictive alerts.
  - Integration with email, SMS, and third-party messaging systems.
  - Granular alert settings per module or event type.
- **Components:**
  - Alert dispatcher.
  - Notification manager.
  - Alert history and logging.

### 5. Visualization and Reporting

- **Purpose:** 
  - Translates analysis results into interactive dashboards and reports.
- **Key Features:**
  - Real-time dashboard displays.
  - Historical data visualizations.
  - Exportable reports in various formats (PDF, CSV).
- **Components:**
  - Web UI/dashboard framework.
  - Charting libraries and export tools.

### 6. Configuration and Utilities

- **Purpose:** 
  - Manages application settings and provides common utility functions.
- **Key Features:**
  - Centralized configuration management.
  - Logging, error handling, and performance tracking.
  - Helper functions used across modules to standardize operations.
- **Components:**
  - Config file parsers.
  - Shared libraries for common functions.
  - Utility scripts for maintenance and debugging.

---

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/surmount-s4/Pipeline_v1.0.git
   ```
2. **Install Dependencies:**
   Depending on your environment, install necessary dependencies using package managers such as pip, npm, etc.
   ```bash
   cd Pipeline_v1.0
   # For example, if using Python:
   pip install -r requirements.txt
   ```
3. **Configuration:**
   - Copy and modify the configuration file (`config.example.json`) to suit your environment.
   - Ensure that source endpoints and alert settings are updated as required.

---

## Usage

1. **Starting the Pipeline:**
   Launch the log ingestion service and run the modules sequentially or as defined in your orchestration:
   ```bash
   python main.py
   ```
2. **Monitoring:**
   - Check the logs for any errors during the ingestion or processing.
   - Use the integrated dashboard to monitor pipeline performance and alerts.
  
3. **Customizing Modules:**
   - Each module is self-contained; refer to the code comments and module-specific documentation for customizing behavior or adding new log formats.

---

## Contributing

Contributions are welcome!  
- Fork the repository.
- Create a feature branch.
- Test your changes.
- Submit a pull request for review.

Please check out our [CONTRIBUTING.md](CONTRIBUTING.md) for more details on the code of conduct, and the process for submitting pull requests.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

This README provides an overview of the pipeline architecture and details each module's functionality. For deeper insight into each part, consult the inline documentation in the source code.
