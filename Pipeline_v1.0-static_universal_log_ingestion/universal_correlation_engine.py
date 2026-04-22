#!/usr/bin/env python3
"""
universal_correlation_engine.py
================================

Correlation engine designed specifically for the Universal Log Tool pipeline.
This engine works with standardized parsed logs from multiple sources (firewall,
web servers, applications, etc.) to identify:

1. Cross-source event correlation (e.g., network + application events)
2. Time-based anomaly detection
3. IP/User-based activity patterns
4. Security event sequences
5. Multi-source attack chains

Architecture:
- Consumes standardized logs from RabbitMQ (forwarded by universal_receiver.py)
- Uses standard fields (source_ip, dest_ip, user, action, etc.)
- Stores correlation results in PostgreSQL
- Provides REST API for correlation queries

Author: Universal Log Tool Team
Date: October 14, 2025
"""

import json
import os
import sys
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import re

import psycopg2
import psycopg2.extras
import pika

# Configuration
DB_CONFIG = {
    "dbname": os.getenv("LOGS_DB_NAME", "universal_logs_db"),
    "user": os.getenv("LOGS_DB_USER", "postgres"),
    "password": os.getenv("LOGS_DB_PASS", "postgres"),
    "host": os.getenv("LOGS_DB_HOST", "localhost"),
    "port": os.getenv("LOGS_DB_PORT", "5432"),
}

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_QUEUE = os.getenv("RABBITMQ_QUEUE", "logs")

# Correlation window settings
CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "60"))  # 60-second windows
CORRELATION_CHECK_INTERVAL = int(os.getenv("CORRELATION_CHECK_INTERVAL", "10"))  # Check every 10 seconds

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("universal_correlation")


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class StandardizedLog:
    """Standardized log entry from Universal Log Tool"""
    timestamp: datetime
    source_type: str  # firewall, web_server, application, etc.
    source_system: str  # device/server name
    parser_id: str
    
    # Standard fields (from field_mappings.json)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    user: Optional[str] = None
    app_name: Optional[str] = None
    event_id: Optional[str] = None
    category: Optional[str] = None
    url: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    log: Optional[str] = None
    raw_log: Optional[str] = None
    
    # Additional fields
    additional_fields: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Ensure timestamp is datetime object"""
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)


@dataclass
class CorrelationResult:
    """Result of correlation analysis"""
    correlation_id: str
    correlation_type: str  # ip_activity, user_activity, attack_sequence, etc.
    severity: str  # INFO, WARNING, CRITICAL
    title: str
    description: str
    start_time: datetime
    end_time: datetime
    involved_sources: List[str]  # List of source_systems
    involved_ips: List[str]
    involved_users: List[str]
    event_count: int
    events: List[Dict[str, Any]]
    indicators: Dict[str, List[str]]  # IOCs/IOAs
    recommendations: List[str]
    confidence_score: float  # 0.0 to 1.0
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat()
        data['created_at'] = self.created_at.isoformat()
        return data


# =============================================================================
# Database Manager
# =============================================================================

class DatabaseManager:
    """Manages PostgreSQL database operations"""
    
    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.conn = None
        self._init_schema()
    
    def connect(self):
        """Establish database connection"""
        if self.conn is None or self.conn.closed:
            self.conn = psycopg2.connect(**self.db_config)
        return self.conn
    
    def _init_schema(self):
        """Initialize database schema for correlation results"""
        conn = self.connect()
        cur = conn.cursor()
        
        try:
            # Create parsed_logs table (stores standardized logs)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS parsed_logs (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    source_type TEXT NOT NULL,
                    source_system TEXT NOT NULL,
                    parser_id TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    action TEXT,
                    severity TEXT,
                    username TEXT,
                    app_name TEXT,
                    event_id TEXT,
                    category TEXT,
                    url TEXT,
                    http_method TEXT,
                    status_code INTEGER,
                    log TEXT,
                    raw_log TEXT,
                    additional_fields JSONB,
                    ingested_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)
            
            # Create indexes for fast correlation queries
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_timestamp ON parsed_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_source_ip ON parsed_logs(source_ip);
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_dest_ip ON parsed_logs(dest_ip);
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_username ON parsed_logs(username);
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_source_type ON parsed_logs(source_type);
                CREATE INDEX IF NOT EXISTS idx_parsed_logs_source_system ON parsed_logs(source_system);
            """)
            
            # Create correlation_results table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS correlation_results (
                    id BIGSERIAL PRIMARY KEY,
                    correlation_id TEXT UNIQUE NOT NULL,
                    correlation_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    start_time TIMESTAMPTZ NOT NULL,
                    end_time TIMESTAMPTZ NOT NULL,
                    involved_sources TEXT[],
                    involved_ips TEXT[],
                    involved_users TEXT[],
                    event_count INTEGER,
                    events JSONB,
                    indicators JSONB,
                    recommendations TEXT[],
                    confidence_score FLOAT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)
            
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_correlation_results_type ON correlation_results(correlation_type);
                CREATE INDEX IF NOT EXISTS idx_correlation_results_severity ON correlation_results(severity);
                CREATE INDEX IF NOT EXISTS idx_correlation_results_start_time ON correlation_results(start_time);
                CREATE INDEX IF NOT EXISTS idx_correlation_results_created_at ON correlation_results(created_at);
            """)
            
            conn.commit()
            logger.info("Database schema initialized successfully")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error initializing database schema: {e}")
            raise
        finally:
            cur.close()
    
    def insert_parsed_log(self, log: StandardizedLog) -> int:
        """Insert a parsed log into database"""
        conn = self.connect()
        cur = conn.cursor()
        
        try:
            cur.execute("""
                INSERT INTO parsed_logs (
                    timestamp, source_type, source_system, parser_id,
                    source_ip, dest_ip, src_port, dst_port, protocol,
                    action, severity, username, app_name, event_id,
                    category, url, http_method, status_code, log, raw_log,
                    additional_fields
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) RETURNING id;
            """, (
                log.timestamp, log.source_type, log.source_system, log.parser_id,
                log.source_ip, log.dest_ip, log.src_port, log.dst_port, log.protocol,
                log.action, log.severity, log.user, log.app_name, log.event_id,
                log.category, log.url, log.http_method, log.status_code, log.log, log.raw_log,
                json.dumps(log.additional_fields) if log.additional_fields else None
            ))
            
            log_id = cur.fetchone()[0]
            conn.commit()
            return log_id
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting parsed log: {e}")
            raise
        finally:
            cur.close()
    
    def insert_correlation_result(self, result: CorrelationResult):
        """Insert a correlation result into database"""
        conn = self.connect()
        cur = conn.cursor()
        
        try:
            cur.execute("""
                INSERT INTO correlation_results (
                    correlation_id, correlation_type, severity, title, description,
                    start_time, end_time, involved_sources, involved_ips, involved_users,
                    event_count, events, indicators, recommendations, confidence_score
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, (
                result.correlation_id, result.correlation_type, result.severity,
                result.title, result.description, result.start_time, result.end_time,
                result.involved_sources, result.involved_ips, result.involved_users,
                result.event_count, json.dumps(result.events), json.dumps(result.indicators),
                result.recommendations, result.confidence_score
            ))
            
            conn.commit()
            logger.info(f"Correlation result saved: {result.correlation_id}")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting correlation result: {e}")
            raise
        finally:
            cur.close()
    
    def get_logs_in_window(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Retrieve logs within a time window"""
        conn = self.connect()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cur.execute("""
                SELECT * FROM parsed_logs
                WHERE timestamp >= %s AND timestamp <= %s
                ORDER BY timestamp ASC;
            """, (start_time, end_time))
            
            return cur.fetchall()
            
        finally:
            cur.close()
    
    def get_recent_correlations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent correlation results"""
        conn = self.connect()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cur.execute("""
                SELECT * FROM correlation_results
                ORDER BY created_at DESC
                LIMIT %s;
            """, (limit,))
            
            return cur.fetchall()
            
        finally:
            cur.close()


# =============================================================================
# Correlation Analyzers
# =============================================================================

class IPActivityAnalyzer:
    """Analyzes IP-based activity patterns across multiple sources"""
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Analyze IP activity patterns"""
        results = []
        
        # Group logs by source IP
        ip_activities = defaultdict(list)
        for log in logs:
            if log.get('source_ip'):
                ip_activities[log['source_ip']].append(log)
            if log.get('dest_ip'):
                ip_activities[log['dest_ip']].append(log)
        
        # Analyze each IP's activity
        for ip, events in ip_activities.items():
            if len(events) < 5:  # Skip IPs with low activity
                continue
            
            # Check for suspicious patterns
            severity = self._assess_ip_severity(ip, events)
            if severity in ['WARNING', 'CRITICAL']:
                result = self._create_ip_correlation(ip, events, severity)
                results.append(result)
        
        return results
    
    def _assess_ip_severity(self, ip: str, events: List[Dict[str, Any]]) -> str:
        """Assess severity of IP activity"""
        # Count denied/blocked actions
        denied_count = sum(1 for e in events if e.get('action', '').lower() in ['deny', 'block', 'reject'])
        
        # Count unique destination IPs
        unique_dests = len(set(e.get('dest_ip') for e in events if e.get('dest_ip')))
        
        # Count unique ports
        unique_ports = len(set(e.get('dst_port') for e in events if e.get('dst_port')))
        
        # Count different source types
        source_types = len(set(e.get('source_type') for e in events))
        
        # Scoring logic
        if denied_count > 10 or unique_dests > 20 or unique_ports > 50:
            return 'CRITICAL'
        elif denied_count > 5 or unique_dests > 10 or source_types > 2:
            return 'WARNING'
        else:
            return 'INFO'
    
    def _create_ip_correlation(self, ip: str, events: List[Dict[str, Any]], severity: str) -> CorrelationResult:
        """Create correlation result for IP activity"""
        timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        # Extract unique values
        sources = list(set(e.get('source_system') for e in events if e.get('source_system')))
        users = list(set(e.get('username') for e in events if e.get('username')))
        dest_ips = list(set(e.get('dest_ip') for e in events if e.get('dest_ip') and e.get('dest_ip') != ip))
        
        # Count actions
        actions = defaultdict(int)
        for e in events:
            if e.get('action'):
                actions[e['action']] += 1
        
        description = f"IP {ip} generated {len(events)} events across {len(sources)} sources. "
        description += f"Actions: {dict(actions)}. "
        if dest_ips:
            description += f"Contacted {len(dest_ips)} unique destinations."
        
        return CorrelationResult(
            correlation_id=f"ip_{ip.replace('.', '_')}_{int(time.time())}",
            correlation_type="ip_activity",
            severity=severity,
            title=f"Suspicious IP Activity: {ip}",
            description=description,
            start_time=start_time,
            end_time=end_time,
            involved_sources=sources,
            involved_ips=[ip] + dest_ips[:10],  # Limit to 10
            involved_users=users,
            event_count=len(events),
            events=[dict(e) for e in events[:20]],  # Limit to 20 events
            indicators={
                "source_ips": [ip],
                "dest_ips": dest_ips[:10],
                "actions": list(actions.keys())
            },
            recommendations=[
                f"Review IP {ip} activity logs in detail",
                "Check if IP is from expected geographic location",
                "Verify if activity aligns with normal user behavior"
            ],
            confidence_score=0.7 if severity == 'CRITICAL' else 0.5,
            created_at=datetime.now()
        )


class UserActivityAnalyzer:
    """Analyzes user-based activity patterns"""
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Analyze user activity patterns"""
        results = []
        
        # Group logs by username
        user_activities = defaultdict(list)
        for log in logs:
            if log.get('username'):
                user_activities[log['username']].append(log)
        
        # Analyze each user's activity
        for user, events in user_activities.items():
            if len(events) < 3:  # Skip users with low activity
                continue
            
            severity = self._assess_user_severity(user, events)
            if severity in ['WARNING', 'CRITICAL']:
                result = self._create_user_correlation(user, events, severity)
                results.append(result)
        
        return results
    
    def _assess_user_severity(self, user: str, events: List[Dict[str, Any]]) -> str:
        """Assess severity of user activity"""
        # Count failed actions
        failed_count = sum(1 for e in events 
                          if e.get('action', '').lower() in ['deny', 'fail', 'error'] 
                          or e.get('status_code', 0) >= 400)
        
        # Count unique source IPs
        unique_ips = len(set(e.get('source_ip') for e in events if e.get('source_ip')))
        
        # Count different source types
        source_types = len(set(e.get('source_type') for e in events))
        
        if failed_count > 5 or unique_ips > 5:
            return 'CRITICAL'
        elif failed_count > 2 or source_types > 2:
            return 'WARNING'
        else:
            return 'INFO'
    
    def _create_user_correlation(self, user: str, events: List[Dict[str, Any]], severity: str) -> CorrelationResult:
        """Create correlation result for user activity"""
        timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        sources = list(set(e.get('source_system') for e in events if e.get('source_system')))
        ips = list(set(e.get('source_ip') for e in events if e.get('source_ip')))
        
        description = f"User {user} generated {len(events)} events across {len(sources)} sources from {len(ips)} IP(s)."
        
        return CorrelationResult(
            correlation_id=f"user_{user}_{int(time.time())}",
            correlation_type="user_activity",
            severity=severity,
            title=f"Suspicious User Activity: {user}",
            description=description,
            start_time=start_time,
            end_time=end_time,
            involved_sources=sources,
            involved_ips=ips,
            involved_users=[user],
            event_count=len(events),
            events=[dict(e) for e in events[:20]],
            indicators={
                "usernames": [user],
                "source_ips": ips[:10]
            },
            recommendations=[
                f"Review user {user} activity logs",
                "Verify user credentials haven't been compromised",
                "Check if user is logging in from expected locations"
            ],
            confidence_score=0.6 if severity == 'CRITICAL' else 0.4,
            created_at=datetime.now()
        )


class AttackSequenceAnalyzer:
    """Analyzes multi-stage attack patterns across sources"""
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Analyze potential attack sequences"""
        results = []
        
        # Look for common attack patterns:
        # 1. Port scanning followed by connection attempts
        # 2. Failed authentication followed by successful login
        # 3. Web attacks (SQL injection, XSS) followed by data access
        
        # Pattern 1: Port scanning
        scan_results = self._detect_port_scanning(logs)
        results.extend(scan_results)
        
        # Pattern 2: Brute force attacks
        bruteforce_results = self._detect_bruteforce(logs)
        results.extend(bruteforce_results)
        
        return results
    
    def _detect_port_scanning(self, logs: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Detect port scanning activity"""
        results = []
        
        # Group by source IP
        ip_ports = defaultdict(set)
        ip_events = defaultdict(list)
        
        for log in logs:
            src_ip = log.get('source_ip')
            dst_port = log.get('dst_port')
            if src_ip and dst_port:
                ip_ports[src_ip].add(dst_port)
                ip_events[src_ip].append(log)
        
        # Flag IPs accessing many different ports
        for src_ip, ports in ip_ports.items():
            if len(ports) > 20:  # Threshold for port scanning
                events = ip_events[src_ip]
                timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
                
                result = CorrelationResult(
                    correlation_id=f"portscan_{src_ip.replace('.', '_')}_{int(time.time())}",
                    correlation_type="attack_sequence",
                    severity="CRITICAL",
                    title=f"Port Scanning Detected: {src_ip}",
                    description=f"IP {src_ip} attempted to access {len(ports)} different ports, indicating possible port scanning.",
                    start_time=min(timestamps),
                    end_time=max(timestamps),
                    involved_sources=list(set(e.get('source_system') for e in events if e.get('source_system'))),
                    involved_ips=[src_ip],
                    involved_users=[],
                    event_count=len(events),
                    events=[dict(e) for e in events[:20]],
                    indicators={
                        "source_ips": [src_ip],
                        "scanned_ports": sorted(list(ports))[:50],
                        "attack_type": ["port_scanning", "reconnaissance"]
                    },
                    recommendations=[
                        f"Block IP {src_ip} at firewall",
                        "Review all connections from this IP",
                        "Check for successful connections after scan"
                    ],
                    confidence_score=0.9,
                    created_at=datetime.now()
                )
                results.append(result)
        
        return results
    
    def _detect_bruteforce(self, logs: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Detect brute force authentication attempts"""
        results = []
        
        # Group by source IP and username
        auth_attempts = defaultdict(lambda: {'failed': [], 'success': []})
        
        for log in logs:
            src_ip = log.get('source_ip')
            user = log.get('username')
            action = log.get('action', '').lower()
            status = log.get('status_code', 200)
            
            if not (src_ip and user):
                continue
            
            key = f"{src_ip}_{user}"
            
            # Detect failed attempts
            if action in ['deny', 'fail', 'error'] or status >= 400:
                auth_attempts[key]['failed'].append(log)
            elif action in ['allow', 'success'] or status < 300:
                auth_attempts[key]['success'].append(log)
        
        # Flag IPs with many failed attempts
        for key, attempts in auth_attempts.items():
            failed = attempts['failed']
            success = attempts['success']
            
            if len(failed) > 5:  # Threshold for brute force
                src_ip, user = key.split('_', 1)
                all_events = failed + success
                timestamps = [e['timestamp'] for e in all_events if e.get('timestamp')]
                
                severity = "CRITICAL" if success else "WARNING"
                title = f"Brute Force Attack: {src_ip} → {user}"
                if success:
                    title += " (SUCCESSFUL)"
                
                result = CorrelationResult(
                    correlation_id=f"bruteforce_{key}_{int(time.time())}",
                    correlation_type="attack_sequence",
                    severity=severity,
                    title=title,
                    description=f"IP {src_ip} made {len(failed)} failed authentication attempts for user {user}. " +
                               (f"{len(success)} successful login(s) detected." if success else "No successful login."),
                    start_time=min(timestamps),
                    end_time=max(timestamps),
                    involved_sources=list(set(e.get('source_system') for e in all_events if e.get('source_system'))),
                    involved_ips=[src_ip],
                    involved_users=[user],
                    event_count=len(all_events),
                    events=[dict(e) for e in all_events[:20]],
                    indicators={
                        "source_ips": [src_ip],
                        "targeted_users": [user],
                        "attack_type": ["brute_force", "credential_stuffing"],
                        "success": len(success) > 0
                    },
                    recommendations=[
                        f"Block IP {src_ip} immediately" if success else f"Monitor IP {src_ip}",
                        f"Force password reset for user {user}" if success else f"Notify user {user}",
                        "Implement rate limiting on authentication endpoints",
                        "Enable MFA for affected accounts"
                    ],
                    confidence_score=0.95 if success else 0.75,
                    created_at=datetime.now()
                )
                results.append(result)
        
        return results


# =============================================================================
# Correlation Engine
# =============================================================================

class UniversalCorrelationEngine:
    """Main correlation engine for Universal Log Tool"""
    
    def __init__(self):
        self.db = DatabaseManager(DB_CONFIG)
        self.analyzers = [
            IPActivityAnalyzer(),
            UserActivityAnalyzer(),
            AttackSequenceAnalyzer()
        ]
        self.running = False
        logger.info("Universal Correlation Engine initialized")
    
    def consume_from_rabbitmq(self):
        """Consume parsed logs from RabbitMQ"""
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        
        logger.info(f"Listening for logs on RabbitMQ queue: {RABBITMQ_QUEUE}")
        
        def callback(ch, method, properties, body):
            try:
                log_data = json.loads(body)
                
                # Convert to StandardizedLog
                log = StandardizedLog(
                    timestamp=datetime.fromisoformat(log_data.get('timestamp', datetime.now().isoformat())),
                    source_type=log_data.get('source_type', 'unknown'),
                    source_system=log_data.get('source', 'unknown'),
                    parser_id=log_data.get('parser_id', 'unknown'),
                    source_ip=log_data.get('source_ip'),
                    dest_ip=log_data.get('dest_ip'),
                    src_port=log_data.get('src_port'),
                    dst_port=log_data.get('dst_port'),
                    protocol=log_data.get('protocol'),
                    action=log_data.get('action'),
                    severity=log_data.get('severity'),
                    user=log_data.get('user'),
                    app_name=log_data.get('app_name'),
                    event_id=log_data.get('event_id'),
                    category=log_data.get('category'),
                    url=log_data.get('url'),
                    http_method=log_data.get('http_method'),
                    status_code=log_data.get('status_code'),
                    log=log_data.get('log'),
                    raw_log=log_data.get('raw_log'),
                    additional_fields=log_data.get('additional_fields')
                )
                
                # Store in database
                log_id = self.db.insert_parsed_log(log)
                logger.debug(f"Stored parsed log {log_id}")
                
                ch.basic_ack(delivery_tag=method.delivery_tag)
                
            except Exception as e:
                logger.error(f"Error processing log from RabbitMQ: {e}")
                ch.basic_nack(delivery_tag=method.delivery_tag)
        
        channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=callback)
        
        try:
            channel.start_consuming()
        except KeyboardInterrupt:
            channel.stop_consuming()
        finally:
            connection.close()
    
    def run_correlation_analysis(self):
        """Run periodic correlation analysis"""
        logger.info("Starting correlation analysis thread")
        
        while self.running:
            try:
                # Analyze logs from the last correlation window
                end_time = datetime.now()
                start_time = end_time - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
                
                logger.info(f"Analyzing logs from {start_time} to {end_time}")
                
                # Get logs in window
                logs = self.db.get_logs_in_window(start_time, end_time)
                
                if not logs:
                    logger.debug("No logs in current window")
                else:
                    logger.info(f"Analyzing {len(logs)} logs")
                    
                    # Run all analyzers
                    all_results = []
                    for analyzer in self.analyzers:
                        results = analyzer.analyze(logs)
                        all_results.extend(results)
                    
                    # Save correlation results
                    for result in all_results:
                        self.db.insert_correlation_result(result)
                        logger.info(f"Correlation detected: {result.title} (Severity: {result.severity})")
                
                # Sleep until next check
                time.sleep(CORRELATION_CHECK_INTERVAL)
                
            except Exception as e:
                logger.error(f"Error in correlation analysis: {e}")
                time.sleep(CORRELATION_CHECK_INTERVAL)
    
    def start(self):
        """Start the correlation engine"""
        self.running = True
        
        # Start RabbitMQ consumer thread
        consumer_thread = threading.Thread(target=self.consume_from_rabbitmq, daemon=True)
        consumer_thread.start()
        
        # Start correlation analysis thread
        analyzer_thread = threading.Thread(target=self.run_correlation_analysis, daemon=True)
        analyzer_thread.start()
        
        logger.info("Universal Correlation Engine started")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Main entry point"""
    print("=" * 80)
    print("UNIVERSAL CORRELATION ENGINE")
    print("=" * 80)
    print(f"Database: {DB_CONFIG['dbname']}@{DB_CONFIG['host']}")
    print(f"RabbitMQ: {RABBITMQ_HOST} (queue: {RABBITMQ_QUEUE})")
    print(f"Correlation Window: {CORRELATION_WINDOW_SECONDS} seconds")
    print(f"Check Interval: {CORRELATION_CHECK_INTERVAL} seconds")
    print("=" * 80)
    print()
    
    engine = UniversalCorrelationEngine()
    
    print("✅ Correlation engine initialized")
    print("🔄 Starting log consumption and correlation analysis...")
    print("Press Ctrl+C to stop")
    print()
    
    engine.start()


if __name__ == "__main__":
    main()
