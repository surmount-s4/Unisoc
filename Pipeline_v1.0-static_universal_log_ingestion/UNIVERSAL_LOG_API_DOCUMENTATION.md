# Universal Log Ingestion Tool - API Documentation

## Overview
The Universal Log Ingestion Tool provides a backend-only REST API for ingesting logs from ANY firewall or security device. The system automatically detects log formats and creates dynamic parsers.

**Base URL**: `http://localhost:5001`  
**Content-Type**: `application/json`  
**Version**: 1.0

---

## Table of Contents
1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
   - [Health Check](#health-check)
   - [Analyze Format](#analyze-format)
   - [Create Parser](#create-parser)
   - [Test Parser](#test-parser)
   - [Ingest Logs](#ingest-logs)
   - [List Parsers](#list-parsers)
   - [Get Parser Details](#get-parser-details)
   - [Update Parser](#update-parser)
   - [Delete Parser](#delete-parser)
   - [Activate/Deactivate Parser](#activatedeactivate-parser)
   - [Export/Import Parser](#exportimport-parser)
4. [Error Codes](#error-codes)
5. [Field Mappings](#field-mappings)
6. [Integration Examples](#integration-examples)

---

## Quick Start

### Step 1: Analyze Log Format
```bash
curl -X POST http://localhost:5001/analyze_format \
  -H "Content-Type: application/json" \
  -d '{
    "sample_logs": [
      "2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP",
      "2025-10-13 13:15:38,Firewall,Denied,192.168.0.63,10.0.0.1,22,TCP"
    ]
  }'
```

### Step 2: Create Parser
```bash
curl -X POST http://localhost:5001/create_parser \
  -H "Content-Type: application/json" \
  -d '{
    "parser_name": "My Firewall",
    "vendor": "VendorX",
    "mode": "rule-based",
    "format_type": "CSV",
    "parsing_rules": {...},
    "field_mappings": {...}
  }'
```

### Step 3: Ingest Logs
```bash
curl -X POST http://localhost:5001/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "firewall-01",
    "logs": [
      "2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP"
    ]
  }'
```

---

## Authentication
Currently, the API does not require authentication. For production deployment, consider adding:
- API Keys
- OAuth 2.0
- JWT tokens
- IP whitelisting

---

## Endpoints

### Health Check

Check if the API is running.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "service": "Universal Log Receiver",
  "version": "1.0",
  "timestamp": "2025-10-14T13:15:37Z"
}
```

**Status Codes**:
- `200 OK` - Service is healthy

---

### Analyze Format

Automatically detect log format from sample logs.

**Endpoint**: `POST /analyze_format`

**Request Body**:
```json
{
  "sample_logs": [
    "log line 1",
    "log line 2",
    "log line 3"
  ]
}
```

**Response**:
```json
{
  "detected": true,
  "format_type": "CSV",
  "confidence": 1.0,
  "parsing_rules": {
    "delimiter": ",",
    "has_header": false,
    "columns": ["column_1", "column_2", "column_3", "..."],
    "skip_lines": 0,
    "column_count": 7
  },
  "field_mappings": {
    "column_1": "timestamp",
    "column_4": "source_ip",
    "column_5": "dest_ip"
  },
  "timestamp_config": {
    "field": "column_1",
    "format": "%Y-%m-%d %H:%M:%S",
    "timezone": "UTC"
  },
  "sample_parsed": {
    "timestamp": "2025-10-13 13:15:37",
    "source_ip": "192.168.0.62",
    "dest_ip": "162.159.61.3"
  }
}
```

**Supported Format Types**:
- `CSV` - Comma/tab/semicolon/pipe separated values
- `JSON` - JSON objects (one per line)
- `KEY_VALUE` - Key-value pairs (e.g., `key=value`)
- `SYSLOG` - Syslog format (RFC 3164/5424)
- `CEF` - Common Event Format
- `RAW` - Unstructured text (fallback)

**Status Codes**:
- `200 OK` - Format detected
- `400 Bad Request` - Invalid request (empty sample_logs)
- `500 Internal Server Error` - Detection failed

---

### Create Parser

Create and store a new parser profile.

**Endpoint**: `POST /create_parser`

**Request Body**:
```json
{
  "parser_name": "Checkpoint Firewall",
  "vendor": "Checkpoint",
  "description": "Parser for Checkpoint firewall logs",
  "mode": "rule-based",
  "format_type": "CSV",
  "parsing_rules": {
    "delimiter": ",",
    "has_header": false,
    "columns": ["timestamp", "action", "src_ip", "dst_ip", "protocol"]
  },
  "field_mappings": {
    "timestamp": "timestamp",
    "src_ip": "source_ip",
    "dst_ip": "dest_ip",
    "action": "action",
    "protocol": "protocol"
  },
  "timestamp_config": {
    "field": "timestamp",
    "format": "%Y-%m-%d %H:%M:%S",
    "timezone": "UTC"
  },
  "sample_logs": [
    "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP"
  ],
  "source_identifier": "checkpoint-fw-01",
  "log_type": "firewall"
}
```

**Required Fields**:
- `parser_name` - Unique parser name
- `mode` - `rule-based`, `llm-based`, or `hybrid`
- `format_type` - One of: `CSV`, `JSON`, `KEY_VALUE`, `SYSLOG`, `CEF`, `CUSTOM`
- `parsing_rules` - JSONB object with format-specific rules
- `field_mappings` - JSONB object mapping detected fields to standard fields

**Optional Fields**:
- `vendor` - Vendor name (e.g., Sophos, Checkpoint, Fortinet)
- `description` - Human-readable description
- `timestamp_config` - Timestamp parsing configuration
- `validation_rules` - Field validation rules
- `sample_logs` - Array of example logs
- `source_identifier` - Identifier for auto-selection
- `log_type` - Type of logs (e.g., firewall, ids, web-proxy)

**Response**:
```json
{
  "success": true,
  "parser_id": "checkpoint-fw-abc123",
  "message": "Parser 'Checkpoint Firewall' created successfully"
}
```

**Status Codes**:
- `201 Created` - Parser created successfully
- `400 Bad Request` - Missing required fields or parser name exists
- `500 Internal Server Error` - Creation failed

---

### Test Parser

Test a parser with sample logs before deployment (dry-run, no database changes).

**Endpoint**: `POST /test_parser`

**Request Body**:
```json
{
  "parser_id": "checkpoint-fw-abc123",
  "test_logs": [
    "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP",
    "2025-10-13 13:15:38,DENY,192.168.0.63,10.0.0.1,UDP",
    "2025-10-13 13:15:39,ALLOW,192.168.0.64,8.8.8.8,TCP"
  ]
}
```

**Response**:
```json
{
  "success": true,
  "parser_name": "Checkpoint Firewall",
  "parser_id": "checkpoint-fw-abc123",
  "total": 3,
  "success_count": 3,
  "failed_count": 0,
  "success_rate": 1.0,
  "sample_results": [
    {
      "timestamp": "2025-10-13 13:15:37",
      "action": "ALLOW",
      "source_ip": "192.168.0.62",
      "dest_ip": "162.159.61.3",
      "protocol": "TCP",
      "source_type": "csv",
      "raw_log": "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP"
    }
  ],
  "errors": []
}
```

**Status Codes**:
- `200 OK` - Test completed
- `400 Bad Request` - Invalid request
- `404 Not Found` - Parser not found
- `500 Internal Server Error` - Test failed

---

### Ingest Logs

Universal log ingestion with automatic parser routing.

**Endpoint**: `POST /ingest`

**Request Body (with source identifier)**:
```json
{
  "source": "checkpoint-fw-01",
  "logs": [
    "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP",
    "2025-10-13 13:15:38,DENY,192.168.0.63,10.0.0.1,UDP"
  ]
}
```

**Request Body (with vendor)**:
```json
{
  "vendor": "Checkpoint",
  "logs": [
    "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP"
  ]
}
```

**Request Body (auto-detect)**:
```json
{
  "logs": [
    "2025-10-13 13:15:37,ALLOW,192.168.0.62,162.159.61.3,TCP"
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "logs_received": 2,
  "logs_parsed": 2,
  "logs_failed": 0,
  "parser_used": "checkpoint-fw-abc123",
  "parser_name": "Checkpoint Firewall",
  "parse_time_ms": 45
}
```

**Parser Selection Priority**:
1. Exact `source` identifier match
2. `vendor` + auto-detected format match
3. Auto-detected format only
4. Most-used generic parser (fallback)

**Status Codes**:
- `200 OK` - Logs ingested successfully
- `400 Bad Request` - Invalid request
- `404 Not Found` - No suitable parser found
- `503 Service Unavailable` - RabbitMQ connection failed
- `500 Internal Server Error` - Ingestion failed

---

### List Parsers

List all available parsers with optional filters.

**Endpoint**: `GET /parsers`

**Query Parameters**:
- `vendor` - Filter by vendor (e.g., `Sophos`, `Checkpoint`)
- `format_type` - Filter by format (e.g., `CSV`, `JSON`)
- `mode` - Filter by mode (e.g., `rule-based`, `llm-based`)
- `active_only` - Only active parsers (default: `true`)
- `limit` - Max results (default: `100`)

**Examples**:
```bash
GET /parsers
GET /parsers?vendor=Sophos
GET /parsers?format_type=CSV&active_only=true
GET /parsers?limit=10
```

**Response**:
```json
{
  "parsers": [
    {
      "parser_id": "sophos-fw-csv-v1",
      "parser_name": "Sophos Firewall CSV",
      "vendor": "Sophos",
      "format_type": "CSV",
      "mode": "rule-based",
      "active": true,
      "logs_processed": 15234,
      "parse_success_rate": 98.5,
      "avg_parse_time_ms": 12,
      "last_used": "2025-10-14T10:30:00",
      "created_at": "2025-10-01T08:00:00"
    },
    {
      "parser_id": "checkpoint-fw-abc123",
      "parser_name": "Checkpoint Firewall",
      "vendor": "Checkpoint",
      "format_type": "CSV",
      "mode": "rule-based",
      "active": true,
      "logs_processed": 5432,
      "parse_success_rate": 99.2,
      "avg_parse_time_ms": 10,
      "last_used": "2025-10-14T13:15:00",
      "created_at": "2025-10-12T14:30:00"
    }
  ],
  "total": 2
}
```

**Status Codes**:
- `200 OK` - Parsers retrieved
- `500 Internal Server Error` - Query failed

---

### Get Parser Details

Get detailed information about a specific parser.

**Endpoint**: `GET /parsers/<parser_id>`

**Example**:
```bash
GET /parsers/checkpoint-fw-abc123
```

**Response**:
```json
{
  "parser_id": "checkpoint-fw-abc123",
  "parser_name": "Checkpoint Firewall",
  "description": "Parser for Checkpoint firewall logs",
  "vendor": "Checkpoint",
  "format_type": "CSV",
  "mode": "rule-based",
  "log_type": "firewall",
  "parsing_rules": {
    "delimiter": ",",
    "has_header": false,
    "columns": ["timestamp", "action", "src_ip", "dst_ip", "protocol"]
  },
  "field_mappings": {
    "timestamp": "timestamp",
    "src_ip": "source_ip",
    "dst_ip": "dest_ip",
    "action": "action",
    "protocol": "protocol"
  },
  "timestamp_config": {
    "field": "timestamp",
    "format": "%Y-%m-%d %H:%M:%S",
    "timezone": "UTC"
  },
  "validation_rules": {
    "required_fields": ["timestamp", "source_ip", "log"]
  },
  "active": true,
  "version": "1.0",
  "created_at": "2025-10-12T14:30:00",
  "statistics": {
    "logs_processed": 5432,
    "parse_success_rate": 99.2,
    "avg_parse_time_ms": 10,
    "last_used": "2025-10-14T13:15:00",
    "recent_usage": [
      {
        "timestamp": "2025-10-14T13:15:00",
        "logs_count": 100,
        "success_count": 99,
        "failure_count": 1,
        "parse_time_ms": 1000
      }
    ]
  }
}
```

**Status Codes**:
- `200 OK` - Parser retrieved
- `404 Not Found` - Parser not found
- `500 Internal Server Error` - Query failed

---

### Update Parser

Update parser configuration.

**Endpoint**: `PUT /parsers/<parser_id>`

**Request Body**:
```json
{
  "description": "Updated description",
  "parsing_rules": {
    "delimiter": ",",
    "columns": ["new_col_1", "new_col_2"]
  },
  "active": false
}
```

**Allowed Fields**:
- `parser_name`, `description`, `mode`, `format_type`
- `parsing_rules`, `field_mappings`, `timestamp_config`, `validation_rules`
- `sample_logs`, `source_identifier`, `vendor`, `log_type`
- `active`, `version`

**Response**:
```json
{
  "success": true,
  "message": "Parser 'checkpoint-fw-abc123' updated successfully"
}
```

**Status Codes**:
- `200 OK` - Parser updated
- `400 Bad Request` - Invalid fields or parser not found
- `500 Internal Server Error` - Update failed

---

### Delete Parser

Delete a parser from the database.

**Endpoint**: `DELETE /parsers/<parser_id>`

**Example**:
```bash
DELETE /parsers/checkpoint-fw-abc123
```

**Response**:
```json
{
  "success": true,
  "message": "Parser 'checkpoint-fw-abc123' deleted successfully"
}
```

**Status Codes**:
- `200 OK` - Parser deleted
- `404 Not Found` - Parser not found
- `500 Internal Server Error` - Deletion failed

---

### Activate/Deactivate Parser

Activate or deactivate a parser.

**Endpoints**:
- `POST /parsers/<parser_id>/activate`
- `POST /parsers/<parser_id>/deactivate`

**Examples**:
```bash
POST /parsers/checkpoint-fw-abc123/activate
POST /parsers/checkpoint-fw-abc123/deactivate
```

**Response**:
```json
{
  "success": true,
  "message": "Parser 'checkpoint-fw-abc123' activated successfully"
}
```

**Status Codes**:
- `200 OK` - Status changed
- `400 Bad Request` - Parser not found
- `500 Internal Server Error` - Operation failed

---

### Export/Import Parser

Export parser configuration as JSON or import from JSON.

**Export Endpoint**: `GET /parsers/<parser_id>/export`

**Example**:
```bash
GET /parsers/checkpoint-fw-abc123/export
```

**Response**: Full parser configuration JSON (without auto-generated fields)

**Import Endpoint**: `POST /parsers/import`

**Request Body**: Full parser configuration JSON

**Response**:
```json
{
  "success": true,
  "parser_id": "new-parser-id",
  "message": "Parser imported successfully"
}
```

**Status Codes**:
- `200 OK` - Export successful
- `201 Created` - Import successful
- `404 Not Found` - Parser not found (export)
- `400 Bad Request` - Invalid configuration (import)
- `500 Internal Server Error` - Operation failed

---

## Error Codes

| Status Code | Description | Example |
|-------------|-------------|---------|
| `200 OK` | Request successful | - |
| `201 Created` | Resource created | Parser created |
| `400 Bad Request` | Invalid request | Missing required field |
| `404 Not Found` | Resource not found | Parser not found |
| `500 Internal Server Error` | Server error | Database connection failed |
| `503 Service Unavailable` | Service unavailable | RabbitMQ connection failed |

**Error Response Format**:
```json
{
  "error": "Error message description"
}
```

---

## Field Mappings

See `field_mappings.json` for complete standard field taxonomy.

**Standard Fields**:
- `timestamp` - Event timestamp (required)
- `source_ip` - Source IP address
- `dest_ip` - Destination IP address
- `src_port` - Source port
- `dst_port` - Destination port
- `protocol` - Network protocol
- `severity` - Log severity level
- `action` - Action taken (ALLOW/DENY)
- `log` - Log message (required)
- `user` - Username
- `source_system` - Hostname/device name
- `app_name` - Application name

**Auto-Added Fields**:
- `source_type` - Parser format (csv/json/syslog/etc)
- `raw_log` - Original unparsed log
- `parser_id` - Parser ID used
- `parser_name` - Parser name
- `ingested_at` - Ingestion timestamp

---

## Integration Examples

### Python Integration
```python
import requests
import json

# Analyze format
response = requests.post('http://localhost:5001/analyze_format', json={
    'sample_logs': [
        '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP'
    ]
})
detection = response.json()

# Create parser
parser_config = {
    'parser_name': 'My Firewall',
    'vendor': 'VendorX',
    'mode': 'rule-based',
    'format_type': detection['format_type'],
    'parsing_rules': detection['parsing_rules'],
    'field_mappings': detection['field_mappings']
}

response = requests.post('http://localhost:5001/create_parser', json=parser_config)
parser_id = response.json()['parser_id']

# Ingest logs
response = requests.post('http://localhost:5001/ingest', json={
    'source': 'firewall-01',
    'logs': [
        '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP'
    ]
})
print(response.json())
```

### cURL Integration
```bash
# Complete workflow
curl -X POST http://localhost:5001/analyze_format \
  -H "Content-Type: application/json" \
  -d '{"sample_logs":["2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP"]}' \
  | jq '.' > detection.json

curl -X POST http://localhost:5001/create_parser \
  -H "Content-Type: application/json" \
  -d @parser_config.json

curl -X POST http://localhost:5001/ingest \
  -H "Content-Type: application/json" \
  -d '{"source":"firewall-01","logs":["..."]}'
```

### JavaScript (Node.js) Integration
```javascript
const axios = require('axios');

async function ingestLogs() {
    // Analyze format
    const detection = await axios.post('http://localhost:5001/analyze_format', {
        sample_logs: [
            '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP'
        ]
    });
    
    // Create parser
    const parserConfig = {
        parser_name: 'My Firewall',
        vendor: 'VendorX',
        mode: 'rule-based',
        format_type: detection.data.format_type,
        parsing_rules: detection.data.parsing_rules,
        field_mappings: detection.data.field_mappings
    };
    
    const parser = await axios.post('http://localhost:5001/create_parser', parserConfig);
    
    // Ingest logs
    const result = await axios.post('http://localhost:5001/ingest', {
        source: 'firewall-01',
        logs: [
            '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP'
        ]
    });
    
    console.log(result.data);
}

ingestLogs();
```

---

## Production Deployment Checklist

- [ ] Add authentication (API keys, OAuth, JWT)
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limiting
- [ ] Set up monitoring and alerting
- [ ] Configure log rotation
- [ ] Set up database backups
- [ ] Configure load balancer (if needed)
- [ ] Set up firewall rules
- [ ] Enable CORS (if needed for web clients)
- [ ] Configure environment variables for sensitive data
- [ ] Set up health check monitoring
- [ ] Configure auto-restart on failure
- [ ] Set up logging aggregation

---

## Support

For issues or questions:
1. Check this documentation
2. Review `UNIVERSAL_LOG_TOOL_PROGRESS.md`
3. Check code comments in Python files
4. Review `field_mappings.json` for standard fields

**Version**: 1.0  
**Last Updated**: October 14, 2025  
**Status**: Production Ready 🚀
