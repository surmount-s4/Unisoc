"""
Universal Log Parser Manager
=============================

Database manager for log parser profiles.
Handles CRUD operations, parser selection, and statistics tracking.

Features:
- Create, read, update, delete parsers
- Parser selection by source/vendor/format
- Statistics tracking (logs processed, success rate, parse time)
- Parser activation/deactivation
- Usage logging and analytics

Author: Pipeline v1.0
Date: 2025
"""

import psycopg2
import psycopg2.extras
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import hashlib


class ParserManager:
    """
    Manages log parser profiles in PostgreSQL database.
    Provides CRUD operations and parser selection logic.
    """
    
    def __init__(self, db_config: Dict[str, str]):
        """
        Initialize parser manager with database configuration.
        
        Args:
            db_config: Dictionary with keys: host, port, database, user, password
        """
        self.db_config = db_config
        self.conn = None
        self.cursor = None
        
    def connect(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            return True
        except Exception as e:
            print(f"Database connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
    
    # ==================== CREATE Operations ====================
    
    def create_parser(self, parser_config: Dict[str, Any]) -> Tuple[bool, str, Optional[str]]:
        """
        Create a new parser profile in database.
        
        Args:
            parser_config: Parser configuration dict with keys:
                - parser_name (required): Human-readable name
                - mode (required): 'rule-based', 'llm-based', or 'hybrid'
                - format_type (required): 'CSV', 'JSON', 'KEY_VALUE', 'SYSLOG', 'CEF', 'CUSTOM'
                - parsing_rules (required): JSONB object
                - field_mappings (required): JSONB object
                - timestamp_config (optional): JSONB object
                - validation_rules (optional): JSONB object
                - sample_logs (optional): Array of text
                - source_identifier (optional): Source identifier
                - vendor (optional): Vendor name
                - log_type (optional): Log type
                - description (optional): Description
                - created_by (optional): Creator name
                
        Returns:
            Tuple of (success: bool, message: str, parser_id: Optional[str])
        """
        try:
            # Validate required fields
            required_fields = ['parser_name', 'mode', 'format_type', 'parsing_rules', 'field_mappings']
            for field in required_fields:
                if field not in parser_config:
                    return False, f"Missing required field: {field}", None
            
            # Check if parser name already exists
            if self.parser_exists(parser_config['parser_name']):
                return False, f"Parser with name '{parser_config['parser_name']}' already exists", None
            
            # Generate unique parser_id
            parser_id = self._generate_parser_id(parser_config['parser_name'], parser_config['vendor'])
            
            # Prepare SQL
            sql = """
                INSERT INTO log_parsers (
                    parser_id, parser_name, description, mode, format_type,
                    parsing_rules, field_mappings, timestamp_config, validation_rules,
                    llm_instructions, llm_model, llm_confidence,
                    sample_logs, source_identifier, vendor, log_type,
                    active, version, created_by
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                RETURNING parser_id
            """
            
            # Extract values with defaults
            values = (
                parser_id,
                parser_config['parser_name'],
                parser_config.get('description', ''),
                parser_config['mode'],
                parser_config['format_type'],
                json.dumps(parser_config['parsing_rules']),
                json.dumps(parser_config['field_mappings']),
                json.dumps(parser_config.get('timestamp_config', {})) if parser_config.get('timestamp_config') else None,
                json.dumps(parser_config.get('validation_rules', {})) if parser_config.get('validation_rules') else None,
                parser_config.get('llm_instructions'),
                parser_config.get('llm_model'),
                parser_config.get('llm_confidence'),
                parser_config.get('sample_logs', []),
                parser_config.get('source_identifier'),
                parser_config.get('vendor'),
                parser_config.get('log_type'),
                parser_config.get('active', True),
                parser_config.get('version', '1.0'),
                parser_config.get('created_by')
            )
            
            self.cursor.execute(sql, values)
            self.conn.commit()
            
            return True, f"Parser '{parser_config['parser_name']}' created successfully", parser_id
            
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Failed to create parser: {str(e)}", None
    
    # ==================== READ Operations ====================
    
    def get_parser(self, parser_id: str = None, parser_name: str = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve a parser by ID or name.
        
        Args:
            parser_id: Parser ID
            parser_name: Parser name (used if parser_id is None)
            
        Returns:
            Parser configuration dict or None if not found
        """
        try:
            if parser_id:
                sql = "SELECT * FROM log_parsers WHERE parser_id = %s"
                self.cursor.execute(sql, (parser_id,))
            elif parser_name:
                sql = "SELECT * FROM log_parsers WHERE parser_name = %s"
                self.cursor.execute(sql, (parser_name,))
            else:
                return None
            
            row = self.cursor.fetchone()
            
            if row:
                return dict(row)
            return None
            
        except Exception as e:
            print(f"Failed to get parser: {e}")
            return None
    
    def list_parsers(self, 
                     vendor: str = None,
                     format_type: str = None,
                     mode: str = None,
                     active_only: bool = True,
                     limit: int = 100) -> List[Dict[str, Any]]:
        """
        List parsers with optional filters.
        
        Args:
            vendor: Filter by vendor name
            format_type: Filter by format type
            mode: Filter by mode (rule-based/llm-based/hybrid)
            active_only: Only return active parsers
            limit: Maximum number of results
            
        Returns:
            List of parser configuration dicts
        """
        try:
            # Build query with filters
            sql = "SELECT * FROM log_parsers WHERE 1=1"
            params = []
            
            if vendor:
                sql += " AND vendor = %s"
                params.append(vendor)
            
            if format_type:
                sql += " AND format_type = %s"
                params.append(format_type)
            
            if mode:
                sql += " AND mode = %s"
                params.append(mode)
            
            if active_only:
                sql += " AND active = TRUE"
            
            sql += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            
            self.cursor.execute(sql, params)
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
            
        except Exception as e:
            print(f"Failed to list parsers: {e}")
            return []
    
    def parser_exists(self, parser_name: str) -> bool:
        """
        Check if a parser with given name exists.
        
        Args:
            parser_name: Parser name to check
            
        Returns:
            True if parser exists, False otherwise
        """
        try:
            sql = "SELECT COUNT(*) FROM log_parsers WHERE parser_name = %s"
            self.cursor.execute(sql, (parser_name,))
            count = self.cursor.fetchone()['count']
            return count > 0
        except Exception as e:
            print(f"Failed to check parser existence: {e}")
            return False
    
    # ==================== UPDATE Operations ====================
    
    def update_parser(self, parser_id: str, updates: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Update parser configuration.
        
        Args:
            parser_id: Parser ID to update
            updates: Dictionary of fields to update
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Check if parser exists
            if not self.get_parser(parser_id=parser_id):
                return False, f"Parser with ID '{parser_id}' not found"
            
            # Build UPDATE query
            allowed_fields = [
                'parser_name', 'description', 'mode', 'format_type',
                'parsing_rules', 'field_mappings', 'timestamp_config', 'validation_rules',
                'llm_instructions', 'llm_model', 'llm_confidence',
                'sample_logs', 'source_identifier', 'vendor', 'log_type',
                'active', 'version'
            ]
            
            set_clauses = []
            values = []
            
            for field, value in updates.items():
                if field in allowed_fields:
                    # Convert dicts to JSON for JSONB fields
                    if field in ['parsing_rules', 'field_mappings', 'timestamp_config', 'validation_rules']:
                        if value is not None:
                            value = json.dumps(value)
                    
                    set_clauses.append(f"{field} = %s")
                    values.append(value)
            
            if not set_clauses:
                return False, "No valid fields to update"
            
            sql = f"UPDATE log_parsers SET {', '.join(set_clauses)} WHERE parser_id = %s"
            values.append(parser_id)
            
            self.cursor.execute(sql, values)
            self.conn.commit()
            
            return True, f"Parser '{parser_id}' updated successfully"
            
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Failed to update parser: {str(e)}"
    
    def activate_parser(self, parser_id: str) -> Tuple[bool, str]:
        """
        Activate a parser.
        
        Args:
            parser_id: Parser ID to activate
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        return self.update_parser(parser_id, {'active': True})
    
    def deactivate_parser(self, parser_id: str) -> Tuple[bool, str]:
        """
        Deactivate a parser.
        
        Args:
            parser_id: Parser ID to deactivate
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        return self.update_parser(parser_id, {'active': False})
    
    # ==================== DELETE Operations ====================
    
    def delete_parser(self, parser_id: str) -> Tuple[bool, str]:
        """
        Delete a parser from database.
        
        Args:
            parser_id: Parser ID to delete
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Check if parser exists
            if not self.get_parser(parser_id=parser_id):
                return False, f"Parser with ID '{parser_id}' not found"
            
            sql = "DELETE FROM log_parsers WHERE parser_id = %s"
            self.cursor.execute(sql, (parser_id,))
            self.conn.commit()
            
            return True, f"Parser '{parser_id}' deleted successfully"
            
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Failed to delete parser: {str(e)}"
    
    # ==================== Parser Selection ====================
    
    def select_parser(self, 
                      source_identifier: str = None,
                      vendor: str = None,
                      format_type: str = None) -> Optional[Dict[str, Any]]:
        """
        Select best matching parser based on criteria.
        Selection priority:
        1. Exact source_identifier match
        2. Vendor + format_type match
        3. Format_type only match
        4. Generic fallback parser
        
        Args:
            source_identifier: Source identifier (e.g., device name, IP)
            vendor: Vendor name
            format_type: Log format type
            
        Returns:
            Best matching parser config or None
        """
        try:
            # Priority 1: Exact source_identifier match
            if source_identifier:
                sql = """
                    SELECT * FROM log_parsers 
                    WHERE source_identifier = %s AND active = TRUE
                    ORDER BY logs_processed DESC
                    LIMIT 1
                """
                self.cursor.execute(sql, (source_identifier,))
                row = self.cursor.fetchone()
                if row:
                    return dict(row)
            
            # Priority 2: Vendor + format_type match
            if vendor and format_type:
                sql = """
                    SELECT * FROM log_parsers 
                    WHERE vendor = %s AND format_type = %s AND active = TRUE
                    ORDER BY logs_processed DESC
                    LIMIT 1
                """
                self.cursor.execute(sql, (vendor, format_type))
                row = self.cursor.fetchone()
                if row:
                    return dict(row)
            
            # Priority 3: Format_type only match
            if format_type:
                sql = """
                    SELECT * FROM log_parsers 
                    WHERE format_type = %s AND active = TRUE
                    ORDER BY logs_processed DESC
                    LIMIT 1
                """
                self.cursor.execute(sql, (format_type,))
                row = self.cursor.fetchone()
                if row:
                    return dict(row)
            
            # Priority 4: Generic fallback (most used active parser)
            sql = """
                SELECT * FROM log_parsers 
                WHERE active = TRUE
                ORDER BY logs_processed DESC
                LIMIT 1
            """
            self.cursor.execute(sql)
            row = self.cursor.fetchone()
            if row:
                return dict(row)
            
            return None
            
        except Exception as e:
            print(f"Failed to select parser: {e}")
            return None
    
    # ==================== Statistics Tracking ====================
    
    def update_statistics(self,
                         parser_id: str,
                         logs_count: int,
                         success_count: int,
                         parse_time_ms: int) -> Tuple[bool, str]:
        """
        Update parser statistics after processing logs.
        
        Args:
            parser_id: Parser ID
            logs_count: Total logs processed in this batch
            success_count: Successfully parsed logs
            parse_time_ms: Total parse time in milliseconds
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Calculate new statistics
            failure_count = logs_count - success_count
            success_rate = (success_count / logs_count * 100) if logs_count > 0 else 0.0
            avg_parse_time = parse_time_ms // logs_count if logs_count > 0 else 0
            
            # Update parser statistics
            sql = """
                UPDATE log_parsers
                SET 
                    logs_processed = logs_processed + %s,
                    parse_success_rate = (
                        COALESCE(parse_success_rate * logs_processed, 0) + %s
                    ) / (logs_processed + %s),
                    avg_parse_time_ms = (
                        COALESCE(avg_parse_time_ms * logs_processed, 0) + %s
                    ) / (logs_processed + %s),
                    last_used = NOW()
                WHERE parser_id = %s
            """
            
            self.cursor.execute(sql, (
                logs_count,
                success_rate * logs_count,
                logs_count,
                parse_time_ms,
                logs_count,
                parser_id
            ))
            
            # Log usage in parser_usage_logs
            usage_sql = """
                INSERT INTO parser_usage_logs (
                    parser_id, logs_count, success_count, failure_count, parse_time_ms
                ) VALUES (%s, %s, %s, %s, %s)
            """
            
            self.cursor.execute(usage_sql, (
                parser_id,
                logs_count,
                success_count,
                failure_count,
                parse_time_ms
            ))
            
            self.conn.commit()
            
            return True, f"Statistics updated for parser '{parser_id}'"
            
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Failed to update statistics: {str(e)}"
    
    def get_parser_statistics(self, parser_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed statistics for a parser.
        
        Args:
            parser_id: Parser ID
            
        Returns:
            Statistics dict or None
        """
        try:
            sql = """
                SELECT 
                    parser_id,
                    parser_name,
                    vendor,
                    format_type,
                    logs_processed,
                    parse_success_rate,
                    avg_parse_time_ms,
                    last_used,
                    active
                FROM log_parsers
                WHERE parser_id = %s
            """
            
            self.cursor.execute(sql, (parser_id,))
            row = self.cursor.fetchone()
            
            if row:
                stats = dict(row)
                
                # Get recent usage logs
                usage_sql = """
                    SELECT 
                        timestamp,
                        logs_count,
                        success_count,
                        failure_count,
                        parse_time_ms
                    FROM parser_usage_logs
                    WHERE parser_id = %s
                    ORDER BY timestamp DESC
                    LIMIT 10
                """
                
                self.cursor.execute(usage_sql, (parser_id,))
                usage_rows = self.cursor.fetchall()
                stats['recent_usage'] = [dict(r) for r in usage_rows]
                
                return stats
            
            return None
            
        except Exception as e:
            print(f"Failed to get parser statistics: {e}")
            return None
    
    # ==================== Helper Methods ====================
    
    def _generate_parser_id(self, parser_name: str, vendor: str = None) -> str:
        """
        Generate unique parser ID from name and vendor.
        
        Args:
            parser_name: Parser name
            vendor: Vendor name (optional)
            
        Returns:
            Unique parser ID (e.g., 'sophos-fw-csv-v1-abc123')
        """
        # Create base ID from name and vendor
        base = f"{vendor or 'generic'}-{parser_name}".lower()
        base = base.replace(' ', '-').replace('_', '-')
        
        # Add short hash for uniqueness
        hash_input = f"{parser_name}-{vendor or ''}-{datetime.now().isoformat()}"
        hash_short = hashlib.md5(hash_input.encode()).hexdigest()[:6]
        
        return f"{base}-{hash_short}"
    
    def export_parser(self, parser_id: str, file_path: str) -> Tuple[bool, str]:
        """
        Export parser configuration to JSON file.
        
        Args:
            parser_id: Parser ID to export
            file_path: Output file path
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            parser = self.get_parser(parser_id=parser_id)
            
            if not parser:
                return False, f"Parser '{parser_id}' not found"
            
            # Remove auto-generated fields
            export_data = {k: v for k, v in parser.items() 
                          if k not in ['created_at', 'updated_at', 'logs_processed', 
                                      'parse_success_rate', 'avg_parse_time_ms', 'last_used']}
            
            # Convert datetime objects to strings
            for key, value in export_data.items():
                if isinstance(value, datetime):
                    export_data[key] = value.isoformat()
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True, f"Parser exported to {file_path}"
            
        except Exception as e:
            return False, f"Failed to export parser: {str(e)}"
    
    def import_parser(self, file_path: str) -> Tuple[bool, str, Optional[str]]:
        """
        Import parser configuration from JSON file.
        
        Args:
            file_path: Input file path
            
        Returns:
            Tuple of (success: bool, message: str, parser_id: Optional[str])
        """
        try:
            with open(file_path, 'r') as f:
                parser_config = json.load(f)
            
            # Remove parser_id if exists (will be regenerated)
            if 'parser_id' in parser_config:
                del parser_config['parser_id']
            
            return self.create_parser(parser_config)
            
        except Exception as e:
            return False, f"Failed to import parser: {str(e)}", None


# ==================== CLI Testing ====================

def main():
    """CLI testing interface."""
    print("=" * 70)
    print("Universal Log Parser Manager - Testing Interface")
    print("=" * 70)
    
    # Database configuration
    db_config = {
        'host': 'localhost',
        'port': 5432,
        'database': 'universal_logs_db',
        'user': 'postgres',
        'password': 'postgres'
    }
    
    # Test parser manager
    with ParserManager(db_config) as manager:
        print("\n1. Testing List Parsers")
        print("-" * 70)
        parsers = manager.list_parsers()
        print(f"Found {len(parsers)} parsers:")
        for p in parsers:
            print(f"  - {p['parser_name']} ({p['parser_id']})")
            print(f"    Vendor: {p['vendor']}, Format: {p['format_type']}, Active: {p['active']}")
            print(f"    Processed: {p['logs_processed']}, Success Rate: {p['parse_success_rate']}%")
        
        print("\n2. Testing Get Parser")
        print("-" * 70)
        if parsers:
            parser = manager.get_parser(parser_id=parsers[0]['parser_id'])
            if parser:
                print(f"Retrieved parser: {parser['parser_name']}")
                print(f"  Format: {parser['format_type']}")
                print(f"  Mode: {parser['mode']}")
                print(f"  Parsing Rules: {json.dumps(parser['parsing_rules'], indent=2)[:200]}...")
        
        print("\n3. Testing Create Parser")
        print("-" * 70)
        test_parser = {
            'parser_name': 'Test Checkpoint Firewall',
            'description': 'Test parser for Checkpoint firewall logs',
            'mode': 'rule-based',
            'format_type': 'CSV',
            'parsing_rules': {
                'delimiter': ',',
                'has_header': False,
                'columns': ['timestamp', 'action', 'src_ip', 'dst_ip']
            },
            'field_mappings': {
                'timestamp': 'timestamp',
                'src_ip': 'source_ip',
                'dst_ip': 'dest_ip'
            },
            'vendor': 'Checkpoint',
            'log_type': 'firewall',
            'created_by': 'test_script'
        }
        
        success, message, parser_id = manager.create_parser(test_parser)
        print(f"Create Result: {message}")
        if success:
            print(f"New Parser ID: {parser_id}")
            
            print("\n4. Testing Update Statistics")
            print("-" * 70)
            success, message = manager.update_statistics(
                parser_id=parser_id,
                logs_count=100,
                success_count=95,
                parse_time_ms=1500
            )
            print(f"Update Stats Result: {message}")
            
            print("\n5. Testing Get Statistics")
            print("-" * 70)
            stats = manager.get_parser_statistics(parser_id)
            if stats:
                print(f"Parser: {stats['parser_name']}")
                print(f"  Logs Processed: {stats['logs_processed']}")
                print(f"  Success Rate: {stats['parse_success_rate']:.2f}%")
                print(f"  Avg Parse Time: {stats['avg_parse_time_ms']}ms")
            
            print("\n6. Testing Deactivate Parser")
            print("-" * 70)
            success, message = manager.deactivate_parser(parser_id)
            print(f"Deactivate Result: {message}")
            
            print("\n7. Testing Delete Parser")
            print("-" * 70)
            success, message = manager.delete_parser(parser_id)
            print(f"Delete Result: {message}")
        
        print("\n8. Testing Parser Selection")
        print("-" * 70)
        selected = manager.select_parser(vendor='Sophos', format_type='CSV')
        if selected:
            print(f"Selected Parser: {selected['parser_name']}")
            print(f"  Vendor: {selected['vendor']}, Format: {selected['format_type']}")
    
    print("\n" + "=" * 70)
    print("Testing Complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
