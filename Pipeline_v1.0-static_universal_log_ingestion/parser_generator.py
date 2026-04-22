"""
Universal Log Parser Generator
================================

Generates executable parsers from format detection results.
Converts format_detector output into dynamic parsing functions.

Supported Formats:
- CSV (with custom delimiters and field mappings)
- JSON (with nested object flattening)
- Key-Value Pairs (various delimiters and separators)
- Syslog (RFC 3164 and RFC 5424)
- CEF (Common Event Format)
- RAW (fallback for unknown formats)

Author: Pipeline v1.0
Date: 2025
"""

import re
import json
import csv
from io import StringIO
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime


class ParserGenerator:
    """
    Generates dynamic log parsers from format detection results.
    Each parser is a callable function that converts raw logs to structured data.
    """
    
    def __init__(self):
        """Initialize the parser generator."""
        self.parser_templates = {
            'CSV': self._generate_csv_parser,
            'JSON': self._generate_json_parser,
            'KEY_VALUE': self._generate_key_value_parser,
            'SYSLOG': self._generate_syslog_parser,
            'CEF': self._generate_cef_parser,
            'RAW': self._generate_raw_parser,
        }
    
    def generate(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a parser from format detection result.
        
        Args:
            detection_result: Output from FormatDetector.detect()
            
        Returns:
            Parser configuration with executable parsing function
        """
        format_type = detection_result.get('format_type', 'RAW')
        
        if format_type not in self.parser_templates:
            format_type = 'RAW'
        
        # Get template generator
        generator_func = self.parser_templates[format_type]
        
        # Generate parser
        parser_config = generator_func(detection_result)
        
        # Add metadata
        parser_config['format_type'] = format_type
        parser_config['detection_confidence'] = detection_result.get('confidence', 0.0)
        parser_config['generated_at'] = datetime.now().isoformat()
        
        return parser_config
    
    def _generate_csv_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate CSV parser."""
        parsing_rules = detection_result['parsing_rules']
        field_mappings = detection_result.get('field_mappings', {})
        timestamp_config = detection_result.get('timestamp_config')
        
        delimiter = parsing_rules['delimiter']
        has_header = parsing_rules['has_header']
        columns = parsing_rules['columns']
        skip_lines = parsing_rules.get('skip_lines', 0)
        
        def parse_csv_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Parse a single CSV log line."""
            try:
                # Skip empty lines
                if not log_line or log_line.strip() == '':
                    return None
                
                # Parse CSV
                reader = csv.reader(StringIO(log_line), delimiter=delimiter)
                row = next(reader)
                
                # Check column count
                if len(row) != len(columns):
                    return {
                        'error': 'Column count mismatch',
                        'expected': len(columns),
                        'actual': len(row),
                        'raw_log': log_line
                    }
                
                # Map to field names
                parsed = {}
                for col_name, value in zip(columns, row):
                    # Apply field mapping if exists
                    target_field = field_mappings.get(col_name, col_name)
                    parsed[target_field] = value.strip() if value else None
                
                # Parse timestamp if configured
                if timestamp_config:
                    timestamp_field = field_mappings.get(
                        timestamp_config['field'], 
                        timestamp_config['field']
                    )
                    if timestamp_field in parsed:
                        parsed['timestamp'] = self._parse_timestamp(
                            parsed[timestamp_field],
                            timestamp_config['format']
                        )
                
                # Add source type
                parsed['source_type'] = 'csv'
                parsed['raw_log'] = log_line
                
                return parsed
                
            except Exception as e:
                return {
                    'error': str(e),
                    'raw_log': log_line,
                    'source_type': 'csv'
                }
        
        return {
            'parser_func': parse_csv_log,
            'parsing_rules': parsing_rules,
            'field_mappings': field_mappings,
            'timestamp_config': timestamp_config,
            'parser_type': 'CSV'
        }
    
    def _generate_json_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JSON parser."""
        parsing_rules = detection_result['parsing_rules']
        field_mappings = detection_result.get('field_mappings', {})
        timestamp_config = detection_result.get('timestamp_config')
        
        should_flatten = parsing_rules.get('flatten', False)
        
        def parse_json_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Parse a single JSON log line."""
            try:
                # Skip empty lines
                if not log_line or log_line.strip() == '':
                    return None
                
                # Parse JSON
                parsed = json.loads(log_line.strip())
                
                # Flatten nested objects if configured
                if should_flatten and isinstance(parsed, dict):
                    parsed = self._flatten_dict(parsed)
                
                # Apply field mappings
                mapped = {}
                for key, value in parsed.items():
                    target_field = field_mappings.get(key, key)
                    mapped[target_field] = value
                
                # Parse timestamp if configured
                if timestamp_config:
                    timestamp_field = field_mappings.get(
                        timestamp_config['field'],
                        timestamp_config['field']
                    )
                    if timestamp_field in mapped:
                        mapped['timestamp'] = self._parse_timestamp(
                            str(mapped[timestamp_field]),
                            timestamp_config['format']
                        )
                
                # Add source type
                mapped['source_type'] = 'json'
                mapped['raw_log'] = log_line
                
                return mapped
                
            except json.JSONDecodeError as e:
                return {
                    'error': f'JSON parse error: {str(e)}',
                    'raw_log': log_line,
                    'source_type': 'json'
                }
            except Exception as e:
                return {
                    'error': str(e),
                    'raw_log': log_line,
                    'source_type': 'json'
                }
        
        return {
            'parser_func': parse_json_log,
            'parsing_rules': parsing_rules,
            'field_mappings': field_mappings,
            'timestamp_config': timestamp_config,
            'parser_type': 'JSON'
        }
    
    def _generate_key_value_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate key-value parser."""
        parsing_rules = detection_result['parsing_rules']
        field_mappings = detection_result.get('field_mappings', {})
        timestamp_config = detection_result.get('timestamp_config')
        
        pair_delimiter = parsing_rules['pair_delimiter']
        kv_separator = parsing_rules['key_value_separator']
        quote_char = parsing_rules.get('quote_char', '"')
        
        def parse_kv_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Parse a single key-value log line."""
            try:
                # Skip empty lines
                if not log_line or log_line.strip() == '':
                    return None
                
                parsed = {}
                
                # Handle quoted values: key="value with spaces" key2=value2
                pattern = rf'(\w+){re.escape(kv_separator)}({re.escape(quote_char)}[^{re.escape(quote_char)}]*{re.escape(quote_char)}|[^{re.escape(pair_delimiter)}]+)'
                
                matches = re.findall(pattern, log_line)
                
                for key, value in matches:
                    # Remove quotes
                    value = value.strip(quote_char).strip()
                    
                    # Apply field mapping
                    target_field = field_mappings.get(key, key)
                    parsed[target_field] = value
                
                # Parse timestamp if configured
                if timestamp_config:
                    timestamp_field = field_mappings.get(
                        timestamp_config['field'],
                        timestamp_config['field']
                    )
                    if timestamp_field in parsed:
                        parsed['timestamp'] = self._parse_timestamp(
                            parsed[timestamp_field],
                            timestamp_config['format']
                        )
                
                # Add source type
                parsed['source_type'] = 'key_value'
                parsed['raw_log'] = log_line
                
                return parsed if parsed else None
                
            except Exception as e:
                return {
                    'error': str(e),
                    'raw_log': log_line,
                    'source_type': 'key_value'
                }
        
        return {
            'parser_func': parse_kv_log,
            'parsing_rules': parsing_rules,
            'field_mappings': field_mappings,
            'timestamp_config': timestamp_config,
            'parser_type': 'KEY_VALUE'
        }
    
    def _generate_syslog_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate syslog parser."""
        parsing_rules = detection_result['parsing_rules']
        field_mappings = detection_result.get('field_mappings', {})
        
        rfc_version = parsing_rules.get('rfc_version', 'RFC3164')
        
        def parse_syslog_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Parse a single syslog log line."""
            try:
                # Skip empty lines
                if not log_line or log_line.strip() == '':
                    return None
                
                parsed = {}
                
                if rfc_version == 'RFC3164':
                    # <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MESSAGE
                    pattern = r'^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)$'
                    match = re.match(pattern, log_line)
                    
                    if match:
                        priority, timestamp, hostname, app_name, message = match.groups()
                        parsed['priority'] = int(priority)
                        parsed['timestamp'] = timestamp
                        parsed['source_system'] = hostname
                        parsed['app_name'] = app_name
                        parsed['log'] = message
                        
                elif rfc_version == 'RFC5424':
                    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
                    pattern = r'^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$'
                    match = re.match(pattern, log_line)
                    
                    if match:
                        priority, version, timestamp, hostname, app_name, procid, msgid, structured_data, message = match.groups()
                        parsed['priority'] = int(priority)
                        parsed['version'] = int(version)
                        parsed['timestamp'] = timestamp
                        parsed['source_system'] = hostname
                        parsed['app_name'] = app_name
                        parsed['process_id'] = procid
                        parsed['message_id'] = msgid
                        parsed['structured_data'] = structured_data
                        parsed['log'] = message
                
                # Apply field mappings
                mapped = {}
                for key, value in parsed.items():
                    target_field = field_mappings.get(key, key)
                    mapped[target_field] = value
                
                # Add source type
                mapped['source_type'] = 'syslog'
                mapped['raw_log'] = log_line
                
                return mapped if mapped else {
                    'error': 'Failed to parse syslog format',
                    'raw_log': log_line,
                    'source_type': 'syslog'
                }
                
            except Exception as e:
                return {
                    'error': str(e),
                    'raw_log': log_line,
                    'source_type': 'syslog'
                }
        
        return {
            'parser_func': parse_syslog_log,
            'parsing_rules': parsing_rules,
            'field_mappings': field_mappings,
            'parser_type': 'SYSLOG'
        }
    
    def _generate_cef_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate CEF parser."""
        parsing_rules = detection_result['parsing_rules']
        field_mappings = detection_result.get('field_mappings', {})
        
        def parse_cef_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Parse a single CEF log line."""
            try:
                # Skip empty lines
                if not log_line or log_line.strip() == '':
                    return None
                
                # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
                pattern = r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
                match = re.match(pattern, log_line)
                
                if not match:
                    return {
                        'error': 'Failed to parse CEF format',
                        'raw_log': log_line,
                        'source_type': 'cef'
                    }
                
                version, vendor, product, device_version, signature_id, name, severity, extension = match.groups()
                
                parsed = {
                    'cef_version': int(version),
                    'device_vendor': vendor,
                    'device_product': product,
                    'device_version': device_version,
                    'signature_id': signature_id,
                    'name': name,
                    'severity': severity,
                    'extension': extension
                }
                
                # Parse extension fields (key=value pairs)
                if extension:
                    ext_pattern = r'(\w+)=([^\s]+)'
                    ext_matches = re.findall(ext_pattern, extension)
                    for key, value in ext_matches:
                        parsed[f'ext_{key}'] = value
                
                # Apply field mappings
                mapped = {}
                for key, value in parsed.items():
                    target_field = field_mappings.get(key, key)
                    mapped[target_field] = value
                
                # Add source type
                mapped['source_type'] = 'cef'
                mapped['raw_log'] = log_line
                
                return mapped
                
            except Exception as e:
                return {
                    'error': str(e),
                    'raw_log': log_line,
                    'source_type': 'cef'
                }
        
        return {
            'parser_func': parse_cef_log,
            'parsing_rules': parsing_rules,
            'field_mappings': field_mappings,
            'parser_type': 'CEF'
        }
    
    def _generate_raw_parser(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate raw text parser (fallback)."""
        
        def parse_raw_log(log_line: str) -> Optional[Dict[str, Any]]:
            """Store log as raw text."""
            if not log_line or log_line.strip() == '':
                return None
            
            return {
                'log': log_line.strip(),
                'raw_log': log_line,
                'source_type': 'raw',
                'timestamp': datetime.now().isoformat()
            }
        
        return {
            'parser_func': parse_raw_log,
            'parsing_rules': {'store_as': 'raw_text'},
            'field_mappings': {'raw_line': 'log'},
            'parser_type': 'RAW'
        }
    
    # ==================== Helper Methods ====================
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _parse_timestamp(self, value: str, fmt: str) -> str:
        """Parse timestamp to ISO format."""
        try:
            if fmt == 'epoch':
                dt = datetime.fromtimestamp(int(value))
            elif fmt == 'epoch_ms':
                dt = datetime.fromtimestamp(int(value) / 1000)
            else:
                dt = datetime.strptime(value, fmt)
            
            return dt.isoformat()
        except:
            # Return original value if parsing fails
            return value
    
    def test_parser(self, parser_config: Dict[str, Any], test_logs: List[str]) -> Dict[str, Any]:
        """
        Test a generated parser with sample logs.
        
        Args:
            parser_config: Generated parser configuration
            test_logs: List of test log lines
            
        Returns:
            Test results with success/failure counts and samples
        """
        parser_func = parser_config['parser_func']
        
        results = {
            'total': len(test_logs),
            'success': 0,
            'failed': 0,
            'sample_results': [],
            'errors': []
        }
        
        for log_line in test_logs:
            try:
                parsed = parser_func(log_line)
                
                if parsed and 'error' not in parsed:
                    results['success'] += 1
                    if len(results['sample_results']) < 3:
                        results['sample_results'].append(parsed)
                else:
                    results['failed'] += 1
                    if parsed and 'error' in parsed:
                        results['errors'].append(parsed['error'])
                        
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(str(e))
        
        results['success_rate'] = results['success'] / results['total'] if results['total'] > 0 else 0.0
        
        return results


# ==================== CLI Testing ====================

def main():
    """CLI testing interface."""
    from format_detector import FormatDetector
    
    print("=" * 70)
    print("Universal Log Parser Generator - Testing Interface")
    print("=" * 70)
    
    # Test samples
    test_samples = {
        'CSV': [
            '2025-10-13 13:15:37,Firewall,Allowed,192.168.0.62,162.159.61.3,443,TCP',
            '2025-10-13 13:15:38,Firewall,Denied,192.168.0.63,10.0.0.1,22,TCP',
        ],
        'JSON': [
            '{"timestamp":"2025-10-13T13:15:37Z","src_ip":"192.168.0.62","dst_ip":"162.159.61.3","action":"Allowed"}',
            '{"timestamp":"2025-10-13T13:15:38Z","src_ip":"192.168.0.63","dst_ip":"10.0.0.1","action":"Denied"}',
        ],
        'KEY_VALUE': [
            'time=2025-10-13T13:15:37 src_ip=192.168.0.62 dst_ip=162.159.61.3 action=Allowed protocol=TCP',
            'time=2025-10-13T13:15:38 src_ip=192.168.0.63 dst_ip=10.0.0.1 action=Denied protocol=TCP',
        ]
    }
    
    detector = FormatDetector()
    generator = ParserGenerator()
    
    for format_name, samples in test_samples.items():
        print(f"\n{'='*70}")
        print(f"Testing {format_name} Format")
        print(f"{'='*70}")
        
        # Detect format
        detection = detector.detect(samples)
        print(f"\nDetected: {detection['format_type']} (confidence: {detection['confidence']:.2%})")
        
        # Generate parser
        parser_config = generator.generate(detection)
        print(f"Parser Type: {parser_config['parser_type']}")
        
        # Test parser
        test_results = generator.test_parser(parser_config, samples)
        print(f"\nTest Results:")
        print(f"  Total: {test_results['total']}")
        print(f"  Success: {test_results['success']}")
        print(f"  Failed: {test_results['failed']}")
        print(f"  Success Rate: {test_results['success_rate']:.2%}")
        
        if test_results['sample_results']:
            print(f"\nSample Parsed Log:")
            print(json.dumps(test_results['sample_results'][0], indent=2))


if __name__ == '__main__':
    main()
