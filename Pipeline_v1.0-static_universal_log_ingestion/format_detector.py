"""
Universal Log Format Detector
==============================

Rule-based automatic detection of log formats:
- CSV (delimiter detection, header detection, column extraction)
- JSON (structure validation, nested field detection)
- Key-Value Pairs (space/= separated formats)
- Syslog (RFC 3164 and RFC 5424)
- CEF (Common Event Format)
- Custom (fallback to raw text)

Author: Pipeline v1.0
Date: 2025
"""

import re
import json
import csv
from io import StringIO
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
from datetime import datetime


class FormatDetector:
    """
    Automatic log format detection using rule-based heuristics.
    Fast, free, and accurate for standard log formats.
    """
    
    def __init__(self, confidence_threshold: float = 0.80):
        """
        Initialize the format detector.
        
        Args:
            confidence_threshold: Minimum confidence (0.0-1.0) to consider detection valid
        """
        self.confidence_threshold = confidence_threshold
        
        # Common timestamp patterns
        self.timestamp_patterns = [
            (r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', '%Y-%m-%d %H:%M:%S'),  # ISO-like
            (r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', '%m/%d/%Y %H:%M:%S'),    # US format
            (r'\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}', '%d-%m-%Y %H:%M:%S'),    # EU format
            (r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', '%b %d %H:%M:%S'),         # Syslog
            (r'\d{10}', 'epoch'),                                                # Unix timestamp
            (r'\d{13}', 'epoch_ms'),                                             # Unix timestamp ms
        ]
        
        # Common IP patterns
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
    def detect(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Main detection method - tries all formats and returns best match.
        
        Args:
            sample_logs: List of log lines (at least 3-5 lines recommended)
            
        Returns:
            Detection result with format, confidence, and parsing rules
        """
        if not sample_logs or len(sample_logs) == 0:
            return self._error_result("No sample logs provided")
        
        # Try each detector in priority order (most specific to least specific)
        # JSON and structured formats first, CSV last (since it's too greedy)
        detectors = [
            ('JSON', self.detect_json),
            ('SYSLOG', self.detect_syslog),
            ('CEF', self.detect_cef),
            ('KEY_VALUE', self.detect_key_value),
            ('CSV', self.detect_csv),  # CSV last - it's too greedy
        ]
        
        results = []
        for format_name, detector_func in detectors:
            try:
                result = detector_func(sample_logs)
                if result['detected']:
                    results.append(result)
            except Exception as e:
                # Skip detectors that fail
                continue
        
        # Filter results that meet confidence threshold
        valid_results = [r for r in results if r['confidence'] >= self.confidence_threshold]
        
        # Return highest confidence result
        if valid_results:
            best_result = max(valid_results, key=lambda x: x['confidence'])
            return best_result
        
        # If no results meet threshold but we have results, return best anyway
        if results:
            best_result = max(results, key=lambda x: x['confidence'])
            best_result['warning'] = f"Confidence {best_result['confidence']:.2%} below threshold {self.confidence_threshold:.2%}"
            return best_result
        
        # Fallback to RAW format
        return self._fallback_result(sample_logs)
    
    def detect_csv(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Detect CSV format with automatic delimiter and header detection.
        
        Returns:
            Format detection result with parsing rules
        """
        # Skip empty or single-line samples
        if len(sample_logs) < 2:
            return {'detected': False, 'format_type': 'CSV', 'confidence': 0.0}
        
        # Detect delimiter (comma, tab, semicolon, pipe)
        delimiter = self._detect_csv_delimiter(sample_logs)
        
        # Require at least 2 delimiters per line (at least 3 columns)
        min_delimiters = min([line.count(delimiter) for line in sample_logs[:5]])
        if min_delimiters < 2:
            return {'detected': False, 'format_type': 'CSV', 'confidence': 0.0}
        
        # Parse with detected delimiter
        try:
            # Parse first 5 lines
            test_lines = sample_logs[:5]
            reader = csv.reader(StringIO('\n'.join(test_lines)), delimiter=delimiter)
            rows = list(reader)
            
            if len(rows) < 2:
                return {'detected': False, 'format_type': 'CSV', 'confidence': 0.0}
            
            # Check if all rows have same column count (strict requirement for CSV)
            col_counts = [len(row) for row in rows]
            if len(set(col_counts)) > 1:  # All rows must have same column count
                return {'detected': False, 'format_type': 'CSV', 'confidence': 0.4}
            
            # Require at least 3 columns for valid CSV
            if col_counts[0] < 3:
                return {'detected': False, 'format_type': 'CSV', 'confidence': 0.3}
            
            # Detect if first row is header
            has_header = self._detect_csv_header(rows)
            
            # Extract column names
            if has_header:
                columns = rows[0]
                data_rows = rows[1:]
            else:
                columns = [f"column_{i+1}" for i in range(len(rows[0]))]
                data_rows = rows
            
            # Calculate confidence based on consistency
            confidence = self._calculate_csv_confidence(data_rows, delimiter)
            
            # Detect timestamp column
            timestamp_info = self._detect_timestamp_column(columns, data_rows)
            
            # Detect IP address columns
            ip_columns = self._detect_ip_columns(columns, data_rows)
            
            return {
                'detected': True,
                'format_type': 'CSV',
                'confidence': confidence,
                'parsing_rules': {
                    'delimiter': delimiter,
                    'has_header': has_header,
                    'columns': columns,
                    'skip_lines': 0,
                    'column_count': len(columns)
                },
                'field_mappings': self._generate_csv_field_mappings(
                    columns, timestamp_info, ip_columns
                ),
                'timestamp_config': timestamp_info,
                'sample_parsed': data_rows[0] if data_rows else []
            }
            
        except Exception as e:
            return {'detected': False, 'format_type': 'CSV', 'confidence': 0.0, 'error': str(e)}
    
    def detect_json(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Detect JSON format (single-line JSON objects or arrays).
        
        Returns:
            Format detection result with parsing rules
        """
        valid_jsons = 0
        sample_structure = None
        all_keys = set()
        
        for log_line in sample_logs[:10]:  # Test first 10 lines
            try:
                parsed = json.loads(log_line.strip())
                valid_jsons += 1
                
                # Extract keys
                if isinstance(parsed, dict):
                    all_keys.update(parsed.keys())
                    if sample_structure is None:
                        sample_structure = parsed
                        
            except json.JSONDecodeError:
                continue
        
        if valid_jsons == 0:
            return {'detected': False, 'format_type': 'JSON', 'confidence': 0.0}
        
        confidence = valid_jsons / min(len(sample_logs), 10)
        
        if confidence < self.confidence_threshold:
            return {'detected': False, 'format_type': 'JSON', 'confidence': confidence}
        
        # Analyze structure
        nested = self._is_nested_json(sample_structure) if sample_structure else False
        
        # Detect common field names
        field_mappings = self._generate_json_field_mappings(list(all_keys))
        
        # Detect timestamp field
        timestamp_field = self._detect_json_timestamp_field(sample_structure)
        
        return {
            'detected': True,
            'format_type': 'JSON',
            'confidence': confidence,
            'parsing_rules': {
                'nested_fields': nested,
                'flatten': nested,
                'all_keys': list(all_keys)
            },
            'field_mappings': field_mappings,
            'timestamp_config': timestamp_field,
            'sample_parsed': sample_structure
        }
    
    def detect_syslog(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Detect Syslog format (RFC 3164 or RFC 5424).
        
        Returns:
            Format detection result with parsing rules
        """
        # RFC 3164: <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MESSAGE
        rfc3164_pattern = r'^<\d{1,3}>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'
        
        # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        rfc5424_pattern = r'^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        
        matches_3164 = 0
        matches_5424 = 0
        
        for log_line in sample_logs[:10]:
            if re.match(rfc3164_pattern, log_line):
                matches_3164 += 1
            if re.match(rfc5424_pattern, log_line):
                matches_5424 += 1
        
        total_samples = min(len(sample_logs), 10)
        
        if matches_5424 > 0:
            confidence = matches_5424 / total_samples
            rfc_version = 'RFC5424'
        elif matches_3164 > 0:
            confidence = matches_3164 / total_samples
            rfc_version = 'RFC3164'
        else:
            return {'detected': False, 'format_type': 'SYSLOG', 'confidence': 0.0}
        
        if confidence < self.confidence_threshold:
            return {'detected': False, 'format_type': 'SYSLOG', 'confidence': confidence}
        
        return {
            'detected': True,
            'format_type': 'SYSLOG',
            'confidence': confidence,
            'parsing_rules': {
                'rfc_version': rfc_version,
                'components': ['priority', 'timestamp', 'hostname', 'app_name', 'message']
            },
            'field_mappings': {
                'timestamp': 'timestamp',
                'hostname': 'source_system',
                'app_name': 'app_name',
                'message': 'log'
            },
            'sample_parsed': sample_logs[0] if sample_logs else ''
        }
    
    def detect_cef(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Detect CEF (Common Event Format) logs.
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        
        Returns:
            Format detection result with parsing rules
        """
        cef_pattern = r'^CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|'
        
        matches = 0
        for log_line in sample_logs[:10]:
            if re.match(cef_pattern, log_line):
                matches += 1
        
        if matches == 0:
            return {'detected': False, 'format_type': 'CEF', 'confidence': 0.0}
        
        confidence = matches / min(len(sample_logs), 10)
        
        if confidence < self.confidence_threshold:
            return {'detected': False, 'format_type': 'CEF', 'confidence': confidence}
        
        return {
            'detected': True,
            'format_type': 'CEF',
            'confidence': confidence,
            'parsing_rules': {
                'header_separator': '|',
                'extension_separator': ' ',
                'components': [
                    'version', 'device_vendor', 'device_product', 'device_version',
                    'signature_id', 'name', 'severity', 'extension'
                ]
            },
            'field_mappings': {
                'name': 'log',
                'severity': 'severity',
                'device_vendor': 'source_system'
            },
            'sample_parsed': sample_logs[0] if sample_logs else ''
        }
    
    def detect_key_value(self, sample_logs: List[str]) -> Dict[str, Any]:
        """
        Detect key-value pair format (e.g., key1=value1 key2=value2).
        
        Returns:
            Format detection result with parsing rules
        """
        # Common key-value patterns
        kv_patterns = [
            (r'(\w+)=([^\s]+)', '=', ' '),      # key=value separated by space
            (r'(\w+):([^\s]+)', ':', ' '),      # key:value separated by space
            (r'(\w+)="([^"]*)"', '=', ' '),     # key="value with spaces"
        ]
        
        best_pattern = None
        best_matches = 0
        
        for pattern, separator, delimiter in kv_patterns:
            matches = 0
            for log_line in sample_logs[:10]:
                pairs = re.findall(pattern, log_line)
                if len(pairs) >= 3:  # At least 3 key-value pairs
                    matches += 1
            
            if matches > best_matches:
                best_matches = matches
                best_pattern = (pattern, separator, delimiter)
        
        if best_matches == 0:
            return {'detected': False, 'format_type': 'KEY_VALUE', 'confidence': 0.0}
        
        confidence = best_matches / min(len(sample_logs), 10)
        
        if confidence < self.confidence_threshold:
            return {'detected': False, 'format_type': 'KEY_VALUE', 'confidence': confidence}
        
        # Extract sample keys
        pattern, separator, delimiter = best_pattern
        sample_keys = set()
        for log_line in sample_logs[:5]:
            pairs = re.findall(pattern, log_line)
            sample_keys.update([key for key, _ in pairs])
        
        # Generate field mappings
        field_mappings = self._generate_kv_field_mappings(list(sample_keys))
        
        return {
            'detected': True,
            'format_type': 'KEY_VALUE',
            'confidence': confidence,
            'parsing_rules': {
                'pair_delimiter': delimiter,
                'key_value_separator': separator,
                'quote_char': '"',
                'sample_keys': list(sample_keys)
            },
            'field_mappings': field_mappings,
            'sample_parsed': sample_logs[0] if sample_logs else ''
        }
    
    # ==================== Helper Methods ====================
    
    def _detect_csv_delimiter(self, sample_logs: List[str]) -> str:
        """Detect CSV delimiter by counting occurrences."""
        delimiters = [',', '\t', ';', '|']
        delimiter_counts = {d: 0 for d in delimiters}
        
        for log_line in sample_logs[:5]:
            for delimiter in delimiters:
                delimiter_counts[delimiter] += log_line.count(delimiter)
        
        # Return most common delimiter
        return max(delimiter_counts, key=delimiter_counts.get)
    
    def _detect_csv_header(self, rows: List[List[str]]) -> bool:
        """Detect if first row is a header by checking data types."""
        if len(rows) < 2:
            return False
        
        first_row = rows[0]
        second_row = rows[1]
        
        # If first row has no numbers but second row does, likely header
        first_has_numbers = any(self._is_numeric(cell) for cell in first_row)
        second_has_numbers = any(self._is_numeric(cell) for cell in second_row)
        
        return not first_has_numbers and second_has_numbers
    
    def _calculate_csv_confidence(self, data_rows: List[List[str]], delimiter: str) -> float:
        """Calculate confidence based on CSV consistency."""
        if not data_rows:
            return 0.0
        
        # Check column count consistency
        col_counts = [len(row) for row in data_rows]
        most_common_count = Counter(col_counts).most_common(1)[0][1]
        consistency_ratio = most_common_count / len(data_rows)
        
        # Bonus for common delimiters
        delimiter_bonus = 0.1 if delimiter in [',', '\t'] else 0.0
        
        return min(consistency_ratio + delimiter_bonus, 1.0)
    
    def _detect_timestamp_column(self, columns: List[str], data_rows: List[List[str]]) -> Optional[Dict]:
        """Detect which column contains timestamps."""
        for col_idx, col_name in enumerate(columns):
            # Check if column name suggests timestamp
            if any(kw in col_name.lower() for kw in ['time', 'date', 'timestamp', 'when']):
                # Verify with data
                sample_value = data_rows[0][col_idx] if data_rows and len(data_rows[0]) > col_idx else ''
                timestamp_format = self._detect_timestamp_format(sample_value)
                if timestamp_format:
                    return {
                        'field': col_name,
                        'format': timestamp_format,
                        'timezone': 'UTC'
                    }
        return None
    
    def _detect_timestamp_format(self, value: str) -> Optional[str]:
        """Detect timestamp format from value."""
        for pattern, fmt in self.timestamp_patterns:
            if re.search(pattern, value):
                return fmt
        return None
    
    def _detect_ip_columns(self, columns: List[str], data_rows: List[List[str]]) -> List[str]:
        """Detect columns containing IP addresses."""
        ip_columns = []
        for col_idx, col_name in enumerate(columns):
            if any(kw in col_name.lower() for kw in ['ip', 'addr', 'host']):
                # Verify with data
                sample_value = data_rows[0][col_idx] if data_rows and len(data_rows[0]) > col_idx else ''
                if re.match(self.ip_pattern, sample_value):
                    ip_columns.append(col_name)
        return ip_columns
    
    def _generate_csv_field_mappings(self, columns: List[str], 
                                     timestamp_info: Optional[Dict],
                                     ip_columns: List[str]) -> Dict[str, str]:
        """Generate field mappings for CSV based on column names."""
        mappings = {}
        
        # Common field name patterns
        field_patterns = {
            'source_ip': ['src ip', 'source ip', 'src_ip', 'source_ip', 'srcip', 'sourceip'],
            'dest_ip': ['dst ip', 'dest ip', 'dst_ip', 'dest_ip', 'dstip', 'destip', 'destination ip'],
            'src_port': ['src port', 'source port', 'src_port', 'source_port', 'srcport'],
            'dst_port': ['dst port', 'dest port', 'dst_port', 'dest_port', 'dstport'],
            'protocol': ['protocol', 'proto'],
            'severity': ['severity', 'level', 'priority', 'action'],
            'log': ['message', 'msg', 'log', 'description', 'event'],
            'user': ['user', 'username', 'account']
        }
        
        for col in columns:
            col_lower = col.lower()
            
            # Check timestamp
            if timestamp_info and col == timestamp_info['field']:
                mappings[col] = 'timestamp'
                continue
            
            # Check field patterns
            for target_field, patterns in field_patterns.items():
                if any(pattern in col_lower for pattern in patterns):
                    mappings[col] = target_field
                    break
        
        return mappings
    
    def _generate_json_field_mappings(self, keys: List[str]) -> Dict[str, str]:
        """Generate field mappings for JSON based on key names."""
        mappings = {}
        
        field_patterns = {
            'timestamp': ['timestamp', 'time', 'date', '@timestamp', 'eventTime'],
            'source_ip': ['src_ip', 'source_ip', 'srcIP', 'sourceIP', 'clientIP'],
            'dest_ip': ['dst_ip', 'dest_ip', 'dstIP', 'destIP', 'serverIP'],
            'severity': ['severity', 'level', 'priority', 'logLevel'],
            'log': ['message', 'msg', 'log', 'event', 'description'],
            'user': ['user', 'username', 'account', 'userId']
        }
        
        for key in keys:
            key_lower = key.lower()
            for target_field, patterns in field_patterns.items():
                if key_lower in patterns or any(p in key_lower for p in patterns):
                    mappings[key] = target_field
                    break
        
        return mappings
    
    def _generate_kv_field_mappings(self, keys: List[str]) -> Dict[str, str]:
        """Generate field mappings for key-value format."""
        # Reuse JSON mapping logic
        return self._generate_json_field_mappings(keys)
    
    def _detect_json_timestamp_field(self, sample: Optional[Dict]) -> Optional[Dict]:
        """Detect timestamp field in JSON."""
        if not sample:
            return None
        
        for key, value in sample.items():
            if any(kw in key.lower() for kw in ['time', 'date', 'timestamp']):
                timestamp_format = self._detect_timestamp_format(str(value))
                if timestamp_format:
                    return {
                        'field': key,
                        'format': timestamp_format,
                        'timezone': 'UTC'
                    }
        return None
    
    def _is_nested_json(self, obj: Any) -> bool:
        """Check if JSON has nested objects."""
        if isinstance(obj, dict):
            return any(isinstance(v, (dict, list)) for v in obj.values())
        return False
    
    def _is_numeric(self, value: str) -> bool:
        """Check if string value is numeric."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def _error_result(self, error: str) -> Dict[str, Any]:
        """Return error result."""
        return {
            'detected': False,
            'format_type': 'UNKNOWN',
            'confidence': 0.0,
            'error': error
        }
    
    def _fallback_result(self, sample_logs: List[str]) -> Dict[str, Any]:
        """Fallback to raw text format."""
        return {
            'detected': True,
            'format_type': 'RAW',
            'confidence': 0.5,
            'parsing_rules': {
                'store_as': 'raw_text',
                'line_based': True
            },
            'field_mappings': {
                'raw_line': 'log'
            },
            'sample_parsed': sample_logs[0] if sample_logs else '',
            'note': 'No standard format detected, storing as raw text'
        }


# ==================== CLI Testing ====================

def main():
    """CLI testing interface."""
    import sys
    
    print("=" * 70)
    print("Universal Log Format Detector - Testing Interface")
    print("=" * 70)
    
    # Test samples
    test_samples = {
        'CSV': [
            '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP',
            '2025-10-13 13:15:38,Firewall,Denied,192.168.0.63,10.0.0.1,22,TCP',
            '2025-10-13 13:15:39,Firewall,Allowed,192.168.0.64,8.8.8.8,53,UDP',
        ],
        'JSON': [
            '{"timestamp":"2025-10-13T13:15:37Z","src_ip":"192.168.0.62","dst_ip":"162.159.61.3","action":"Allowed"}',
            '{"timestamp":"2025-10-13T13:15:38Z","src_ip":"192.168.0.63","dst_ip":"10.0.0.1","action":"Denied"}',
        ],
        'SYSLOG': [
            '<134>Oct 13 13:15:37 firewall kernel: DROP IN=eth0 OUT= SRC=192.168.0.62 DST=162.159.61.3',
            '<134>Oct 13 13:15:38 firewall kernel: ACCEPT IN=eth0 OUT= SRC=192.168.0.63 DST=10.0.0.1',
        ],
        'KEY_VALUE': [
            'time=2025-10-13T13:15:37 src_ip=192.168.0.62 dst_ip=162.159.61.3 action=Allowed protocol=TCP',
            'time=2025-10-13T13:15:38 src_ip=192.168.0.63 dst_ip=10.0.0.1 action=Denied protocol=TCP',
        ]
    }
    
    detector = FormatDetector(confidence_threshold=0.80)
    
    for format_name, samples in test_samples.items():
        print(f"\n{'='*70}")
        print(f"Testing {format_name} Format")
        print(f"{'='*70}")
        print(f"Sample: {samples[0][:80]}...")
        
        result = detector.detect(samples)
        
        print(f"\nDetected: {result['detected']}")
        print(f"Format: {result['format_type']}")
        print(f"Confidence: {result['confidence']:.2%}")
        
        if result['detected']:
            print(f"\nParsing Rules:")
            print(json.dumps(result['parsing_rules'], indent=2))
            
            print(f"\nField Mappings:")
            print(json.dumps(result['field_mappings'], indent=2))


if __name__ == '__main__':
    main()
