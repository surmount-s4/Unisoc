# Universal Log Tool - Deployment Guide

**Complete step-by-step deployment instructions for the Universal Log Tool**

---

## 📋 Prerequisites

Before starting, ensure you have:

- ✅ PostgreSQL 12+ installed and running
- ✅ RabbitMQ server installed and running
- ✅ Python 3.8+ installed
- ✅ Git (for version control)
- ✅ Administrator/sudo access

---

## 🚀 Quick Start (5 Steps)

### Step 1: Create Database

```bash
# Run the database creation script
psql -U postgres -f create_universal_logs_database.sql
```

**What it does:**
- Creates new database: `universal_logs_db`
- Enables extensions: uuid-ossp, pg_trgm, btree_gin
- Sets up permissions
- Verifies successful creation

**Expected output:**
```
Database Creation Complete!
SUCCESS: Database "universal_logs_db" created and ready!
```

---

### Step 2: Create Tables

```bash
# Run the schema creation script
psql -U postgres -d universal_logs_db -f create_parser_storage_schema.sql
```

**What it does:**
- Creates `log_parsers` table (stores parser profiles)
- Creates `parser_usage_logs` table (tracks parser statistics)
- Creates `parsed_logs` table (stores ingested logs)
- Creates `correlation_results` table (stores correlation findings)
- Inserts 2 default parsers (Sophos CSV, Generic JSON)
- Creates indexes for performance

**Expected output:**
```
Schema created successfully
Inserted 2 default parsers
```

**Verify tables:**
```bash
psql -U postgres -d universal_logs_db -c "\dt"
```

Should show:
- `log_parsers`
- `parser_usage_logs`
- `parsed_logs`
- `correlation_results`

---

### Step 3: Install Python Dependencies

```bash
# Install required packages
pip install flask psycopg2-binary pika
```

**Packages:**
- `flask` - REST API framework
- `psycopg2-binary` - PostgreSQL adapter
- `pika` - RabbitMQ client

**Verify installation:**
```bash
pip list | findstr /i "flask psycopg2 pika"
```

---

### Step 4: Configure and Start RabbitMQ

**Windows:**
```powershell
# Start RabbitMQ service
net start RabbitMQ

# Enable management plugin (optional, for web UI)
rabbitmq-plugins enable rabbitmq_management

# Verify RabbitMQ is running
rabbitmqctl status
```

**Linux:**
```bash
# Start RabbitMQ service
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server

# Enable management plugin (optional)
sudo rabbitmq-plugins enable rabbitmq_management

# Verify RabbitMQ is running
sudo systemctl status rabbitmq-server
```

**RabbitMQ Management UI:**
- URL: http://localhost:15672
- Default credentials: guest/guest

---

### Step 5: Start Services

**Terminal 1 - API Server:**
```bash
python universal_receiver.py
```

**Expected output:**
```
 * Serving Flask app 'universal_receiver'
 * Running on http://127.0.0.1:5001
 * Press CTRL+C to quit
Universal Receiver API started on port 5001
RabbitMQ connection established
```

**Terminal 2 - Correlation Engine:**
```bash
python universal_correlation_engine.py
```

**Expected output:**
```
Universal Correlation Engine started
Database connection established
RabbitMQ consumer started on queue 'logs'
Correlation analyzers: IP Activity, User Activity, Attack Sequence
```

---

## 🧪 Testing the Pipeline

### Test 1: Health Check

```bash
curl http://localhost:5001/health
```

**Expected:**
```json
{
  "status": "healthy",
  "database": "connected",
  "rabbitmq": "connected",
  "timestamp": "2025-10-14T12:00:00"
}
```

---

### Test 2: Analyze Log Format

**Sample Apache log:**
```bash
curl -X POST http://localhost:5001/analyze_format \
  -H "Content-Type: application/json" \
  -d '{
    "log_samples": [
      "192.168.1.100 - - [14/Oct/2025:12:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
      "10.0.0.50 - admin [14/Oct/2025:12:01:00 +0000] \"POST /login HTTP/1.1\" 401 512"
    ]
  }'
```

**Expected:**
```json
{
  "detected_format": "SYSLOG",
  "confidence": 0.95,
  "sample_count": 2,
  "fields_detected": ["timestamp", "source_ip", "user", "http_method", "url", "status_code"]
}
```

---

### Test 3: Create Parser

```bash
curl -X POST http://localhost:5001/create_parser \
  -H "Content-Type: application/json" \
  -d '{
    "parser_name": "Apache Access Logs",
    "vendor": "Apache",
    "log_source": "web_server",
    "format_type": "SYSLOG",
    "sample_logs": [
      "192.168.1.100 - - [14/Oct/2025:12:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234"
    ],
    "description": "Apache web server access logs"
  }'
```

**Expected:**
```json
{
  "status": "success",
  "parser_id": "apache_web_server_syslog_abc123",
  "message": "Parser created and activated"
}
```

---

### Test 4: Ingest Logs

```bash
curl -X POST http://localhost:5001/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "parser_id": "apache_web_server_syslog_abc123",
    "logs": [
      "192.168.1.100 - - [14/Oct/2025:12:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
      "192.168.1.100 - - [14/Oct/2025:12:00:05 +0000] \"GET /api/orders HTTP/1.1\" 200 2456",
      "192.168.1.100 - - [14/Oct/2025:12:00:10 +0000] \"GET /admin HTTP/1.1\" 403 89"
    ]
  }'
```

**Expected:**
```json
{
  "status": "success",
  "logs_received": 3,
  "logs_parsed": 3,
  "logs_failed": 0,
  "forwarded_to_rabbitmq": true
}
```

---

### Test 5: Verify Correlation

**Wait 60 seconds for correlation window to process**

```bash
# Check database for correlation results
psql -U postgres -d universal_logs_db -c "SELECT * FROM correlation_results ORDER BY detected_at DESC LIMIT 5;"
```

**Expected:** Correlation results showing detected patterns (if any)

---

## 📊 Database Verification

### Check Parser Count

```sql
SELECT COUNT(*) as parser_count FROM log_parsers WHERE active = true;
```

### Check Parsed Logs

```sql
SELECT 
    log_source,
    COUNT(*) as log_count,
    MAX(parsed_at) as latest_log
FROM parsed_logs
GROUP BY log_source
ORDER BY log_count DESC;
```

### Check Correlation Results

```sql
SELECT 
    correlation_type,
    severity,
    COUNT(*) as finding_count
FROM correlation_results
GROUP BY correlation_type, severity
ORDER BY finding_count DESC;
```

---

## 🔧 Configuration Options

### Database Configuration

All three Python files use the same database configuration:

**File:** `universal_receiver.py`, `parser_manager.py`, `universal_correlation_engine.py`

```python
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'universal_logs_db',  # ✅ Updated!
    'user': 'postgres',
    'password': 'postgres'
}
```

**To change database credentials:**
1. Edit the `DB_CONFIG` dictionary in all three Python files
2. Or use environment variables (supported in `universal_correlation_engine.py`):
   ```bash
   export LOGS_DB_NAME=universal_logs_db
   export LOGS_DB_USER=postgres
   export LOGS_DB_PASS=your_password
   export LOGS_DB_HOST=localhost
   export LOGS_DB_PORT=5432
   ```

---

### RabbitMQ Configuration

**File:** `universal_receiver.py`, `universal_correlation_engine.py`

```python
RABBITMQ_HOST = 'localhost'
RABBITMQ_QUEUE = 'logs'
```

**To change RabbitMQ settings:**
1. Edit `RABBITMQ_HOST` if RabbitMQ is on different server
2. Edit `RABBITMQ_QUEUE` if you want different queue name
3. Restart both services after changes

---

## 📁 File Structure

```
Pipeline_v1.0/
├── create_universal_logs_database.sql   ← Database creation script
├── create_parser_storage_schema.sql     ← Table schema script
├── universal_receiver.py                ← REST API (port 5001)
├── universal_correlation_engine.py      ← Correlation engine
├── parser_manager.py                    ← Parser CRUD operations
├── parser_generator.py                  ← Dynamic parser generation
├── format_detector.py                   ← Log format detection
├── field_mappings.json                  ← Standard field taxonomy
├── requirements.txt                     ← Python dependencies
├── README.md                            ← Project overview
├── DEPLOYMENT_GUIDE.md                  ← This file
└── [Documentation files...]
```

---

## 🛠️ Troubleshooting

### Issue 1: Database Connection Failed

**Error:** `psycopg2.OperationalError: could not connect to server`

**Solutions:**
1. Check PostgreSQL is running:
   ```bash
   # Windows
   net start postgresql
   
   # Linux
   sudo systemctl status postgresql
   ```

2. Verify database exists:
   ```bash
   psql -U postgres -l | findstr universal_logs_db
   ```

3. Check credentials in `DB_CONFIG`

---

### Issue 2: RabbitMQ Connection Failed

**Error:** `pika.exceptions.AMQPConnectionError`

**Solutions:**
1. Check RabbitMQ is running:
   ```bash
   # Windows
   net start RabbitMQ
   
   # Linux
   sudo systemctl status rabbitmq-server
   ```

2. Verify RabbitMQ port 5672 is open:
   ```bash
   netstat -an | findstr 5672
   ```

3. Check firewall settings

---

### Issue 3: Port 5001 Already in Use

**Error:** `OSError: [Errno 48] Address already in use`

**Solutions:**
1. Find process using port 5001:
   ```bash
   # Windows
   netstat -ano | findstr :5001
   
   # Linux
   lsof -i :5001
   ```

2. Kill the process or change port in `universal_receiver.py`:
   ```python
   if __name__ == '__main__':
       app.run(host='0.0.0.0', port=5002, debug=True)  # Changed to 5002
   ```

---

### Issue 4: Parser Not Found

**Error:** `{"error": "Parser not found"}`

**Solutions:**
1. List all parsers:
   ```bash
   curl http://localhost:5001/parsers
   ```

2. Use correct `parser_id` from the list

3. Create parser if it doesn't exist (use `/create_parser`)

---

### Issue 5: No Correlation Results

**Possible causes:**
1. Not enough logs ingested (need multiple events)
2. Correlation window hasn't processed yet (wait 60 seconds)
3. No patterns detected (logs don't match correlation rules)

**Check:**
```sql
-- Check if logs are being parsed
SELECT COUNT(*) FROM parsed_logs;

-- Check correlation engine logs
-- (in Terminal 2 where correlation engine is running)
```

---

## 🔐 Production Hardening (Optional)

### 1. Enable Authentication

Add API key authentication to `universal_receiver.py`:

```python
from functools import wraps

API_KEY = "your-secret-key-here"

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key != API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

# Apply to endpoints
@app.route('/ingest', methods=['POST'])
@require_api_key
def ingest_logs():
    # ... existing code
```

---

### 2. Enable HTTPS

Use nginx or Apache as reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

### 3. Configure Logging

Add to `universal_receiver.py`:

```python
import logging

logging.basicConfig(
    filename='universal_receiver.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
```

---

### 4. Set Up Monitoring

Monitor key metrics:
- API request rate
- Parser success rate
- Correlation findings count
- Database size
- RabbitMQ queue depth

Use tools like:
- Prometheus + Grafana
- ELK Stack
- DataDog

---

## 📞 Support

For issues or questions:

1. Check `UNIVERSAL_LOG_API_DOCUMENTATION.md` for API details
2. Check `UNIVERSAL_CORRELATION_ENGINE_DOCS.md` for correlation details
3. Review logs in both terminals
4. Check database tables for data

---

## ✅ Deployment Checklist

- [ ] PostgreSQL installed and running
- [ ] RabbitMQ installed and running
- [ ] Python 3.8+ installed
- [ ] Database created (`create_universal_logs_database.sql`)
- [ ] Tables created (`create_parser_storage_schema.sql`)
- [ ] Python dependencies installed (`pip install flask psycopg2-binary pika`)
- [ ] Database configuration updated in all 3 Python files
- [ ] API server started (`python universal_receiver.py`)
- [ ] Correlation engine started (`python universal_correlation_engine.py`)
- [ ] Health check passed (`curl http://localhost:5001/health`)
- [ ] Test format detection passed
- [ ] Test parser creation passed
- [ ] Test log ingestion passed
- [ ] Correlation results verified

---

## 🎉 Success!

If all tests pass, your Universal Log Tool is ready to process logs!

**Next steps:**
1. Ingest your real log files
2. Monitor correlation results
3. Create custom parsers for your log sources
4. Set up alerts for critical findings

---

**Last Updated:** October 14, 2025  
**Version:** 1.0  
**Author:** Universal Log Tool Team
