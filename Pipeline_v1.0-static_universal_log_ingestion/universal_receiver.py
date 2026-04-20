"""
Universal Log Receiver - REST API
===================================

Backend-only REST API for universal log ingestion.
Supports ANY log format through automatic detection and dynamic parsing.

Endpoints:
- POST /analyze_format - Detect log format from samples
- POST /create_parser - Create and store new parser
- POST /test_parser - Test parser with sample logs
- POST /ingest - Universal log ingestion with parser routing
- GET /parsers - List all available parsers
- GET /parsers/<parser_id> - Get specific parser details
- PUT /parsers/<parser_id> - Update parser configuration
- DELETE /parsers/<parser_id> - Delete parser

Author: Pipeline v1.0
Date: 2025
"""

from flask import Flask, request, jsonify
import json
import pika
import time
from typing import Dict, List, Any
from datetime import datetime

# Import our custom modules
from format_detector import FormatDetector
from parser_generator import ParserGenerator
from parser_manager import ParserManager

# ==================== Configuration ====================

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'universal_logs_db',
    'user': 'postgres',
    'password': 'postgres'
}

# RabbitMQ configuration
RABBITMQ_HOST = 'localhost'
RABBITMQ_QUEUE = 'logs'

# Format detector with 80% confidence threshold
format_detector = FormatDetector(confidence_threshold=0.80)

# Parser generator
parser_generator = ParserGenerator()

# ==================== Helper Functions ====================

def get_rabbitmq_connection():
    """Establish RabbitMQ connection."""
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST)
        )
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        return connection, channel
    except Exception as e:
        print(f"RabbitMQ connection failed: {e}")
        return None, None

def send_to_rabbitmq(channel, message: Dict) -> bool:
    """Send message to RabbitMQ queue."""
    try:
        channel.basic_publish(
            exchange='',
            routing_key=RABBITMQ_QUEUE,
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=2,  # Make message persistent
            )
        )
        return True
    except Exception as e:
        print(f"Failed to send to RabbitMQ: {e}")
        return False

def validate_request_json(required_fields: List[str]) -> tuple:
    """
    Validate that request contains required JSON fields.
    
    Returns:
        Tuple of (valid: bool, data: dict or error_response: tuple)
    """
    if not request.is_json:
        return False, (jsonify({'error': 'Request must be JSON'}), 400)
    
    data = request.get_json()
    
    for field in required_fields:
        if field not in data:
            return False, (jsonify({'error': f'Missing required field: {field}'}), 400)
    
    return True, data

# ==================== API Endpoints ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Universal Log Receiver',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/analyze_format', methods=['POST'])
def analyze_format():
    """
    Analyze log format from sample logs.
    
    Request Body:
    {
        "sample_logs": ["log line 1", "log line 2", ...]
    }
    
    Response:
    {
        "detected": true,
        "format_type": "CSV",
        "confidence": 1.0,
        "parsing_rules": {...},
        "field_mappings": {...},
        "timestamp_config": {...},
        "sample_parsed": {...}
    }
    """
    try:
        # Validate request
        valid, result = validate_request_json(['sample_logs'])
        if not valid:
            return result
        
        data = result
        sample_logs = data['sample_logs']
        
        # Validate sample logs
        if not isinstance(sample_logs, list) or len(sample_logs) == 0:
            return jsonify({
                'error': 'sample_logs must be a non-empty array'
            }), 400
        
        # Detect format
        detection_result = format_detector.detect(sample_logs)
        
        # Return result
        return jsonify({
            'detected': detection_result.get('detected', False),
            'format_type': detection_result.get('format_type'),
            'confidence': detection_result.get('confidence', 0.0),
            'parsing_rules': detection_result.get('parsing_rules', {}),
            'field_mappings': detection_result.get('field_mappings', {}),
            'timestamp_config': detection_result.get('timestamp_config'),
            'sample_parsed': detection_result.get('sample_parsed'),
            'warning': detection_result.get('warning'),
            'note': detection_result.get('note')
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Format analysis failed: {str(e)}'
        }), 500

@app.route('/create_parser', methods=['POST'])
def create_parser():
    """
    Create and store a new parser profile.
    
    Request Body:
    {
        "parser_name": "Checkpoint Firewall",
        "vendor": "Checkpoint",
        "description": "Parser for Checkpoint firewall logs",
        "mode": "rule-based",
        "format_type": "CSV",
        "parsing_rules": {...},
        "field_mappings": {...},
        "timestamp_config": {...},
        "sample_logs": [...],
        "source_identifier": "checkpoint-fw-01"
    }
    
    Response:
    {
        "success": true,
        "parser_id": "checkpoint-fw-abc123",
        "message": "Parser created successfully"
    }
    """
    try:
        # Validate request
        valid, result = validate_request_json(['parser_name', 'mode', 'format_type', 'parsing_rules', 'field_mappings'])
        if not valid:
            return result
        
        parser_config = result
        
        # Create parser in database
        with ParserManager(DB_CONFIG) as manager:
            success, message, parser_id = manager.create_parser(parser_config)
            
            if success:
                return jsonify({
                    'success': True,
                    'parser_id': parser_id,
                    'message': message
                }), 201
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        
    except Exception as e:
        return jsonify({
            'error': f'Parser creation failed: {str(e)}'
        }), 500

@app.route('/test_parser', methods=['POST'])
def test_parser():
    """
    Test a parser with sample logs (dry-run, no database changes).
    
    Request Body:
    {
        "parser_id": "checkpoint-fw-abc123",
        "test_logs": ["log line 1", "log line 2", ...]
    }
    
    Response:
    {
        "success": true,
        "parser_name": "Checkpoint Firewall",
        "total": 100,
        "success_count": 95,
        "failed_count": 5,
        "success_rate": 0.95,
        "sample_results": [...],
        "errors": [...]
    }
    """
    try:
        # Validate request
        valid, result = validate_request_json(['parser_id', 'test_logs'])
        if not valid:
            return result
        
        data = result
        parser_id = data['parser_id']
        test_logs = data['test_logs']
        
        if not isinstance(test_logs, list) or len(test_logs) == 0:
            return jsonify({
                'error': 'test_logs must be a non-empty array'
            }), 400
        
        # Get parser from database
        with ParserManager(DB_CONFIG) as manager:
            parser = manager.get_parser(parser_id=parser_id)
            
            if not parser:
                return jsonify({
                    'error': f'Parser with ID {parser_id} not found'
                }), 404
            
            # Generate parser function from stored config
            detection_result = {
                'format_type': parser['format_type'],
                'parsing_rules': parser['parsing_rules'],
                'field_mappings': parser['field_mappings'],
                'timestamp_config': parser['timestamp_config'],
                'confidence': 1.0
            }
            
            parser_config = parser_generator.generate(detection_result)
            
            # Test parser
            test_results = parser_generator.test_parser(parser_config, test_logs)
            
            return jsonify({
                'success': True,
                'parser_name': parser['parser_name'],
                'parser_id': parser_id,
                'total': test_results['total'],
                'success_count': test_results['success'],
                'failed_count': test_results['failed'],
                'success_rate': test_results['success_rate'],
                'sample_results': test_results['sample_results'],
                'errors': test_results.get('errors', [])
            }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Parser testing failed: {str(e)}'
        }), 500

@app.route('/ingest', methods=['POST'])
def ingest_logs():
    """
    Universal log ingestion with automatic parser routing.
    
    Request Body:
    {
        "source": "checkpoint-fw-01",
        "vendor": "Checkpoint",
        "logs": ["log line 1", "log line 2", ...]
    }
    
    OR auto-detect format:
    {
        "logs": ["log line 1", "log line 2", ...]
    }
    
    Response:
    {
        "status": "success",
        "logs_received": 100,
        "logs_parsed": 95,
        "logs_failed": 5,
        "parser_used": "checkpoint-fw-abc123",
        "parse_time_ms": 1234
    }
    """
    try:
        # Validate request
        valid, result = validate_request_json(['logs'])
        if not valid:
            return result
        
        data = result
        logs = data['logs']
        source = data.get('source')
        vendor = data.get('vendor')
        
        if not isinstance(logs, list) or len(logs) == 0:
            return jsonify({
                'error': 'logs must be a non-empty array'
            }), 400
        
        start_time = time.time()
        
        # Select parser
        with ParserManager(DB_CONFIG) as manager:
            # Try to find existing parser
            parser = None
            
            if source:
                parser = manager.select_parser(source_identifier=source)
            
            if not parser and vendor:
                # Detect format from first few logs
                detection = format_detector.detect(logs[:5])
                parser = manager.select_parser(vendor=vendor, format_type=detection['format_type'])
            
            if not parser:
                # Auto-detect format and use generic parser
                detection = format_detector.detect(logs[:5])
                parser = manager.select_parser(format_type=detection['format_type'])
            
            if not parser:
                return jsonify({
                    'error': 'No suitable parser found. Please create a parser first.'
                }), 404
            
            # Generate parser function
            detection_result = {
                'format_type': parser['format_type'],
                'parsing_rules': parser['parsing_rules'],
                'field_mappings': parser['field_mappings'],
                'timestamp_config': parser['timestamp_config'],
                'confidence': 1.0
            }
            
            parser_config = parser_generator.generate(detection_result)
            parser_func = parser_config['parser_func']
            
            # Parse logs and send to RabbitMQ
            connection, channel = get_rabbitmq_connection()
            
            if not connection or not channel:
                return jsonify({
                    'error': 'Failed to connect to RabbitMQ'
                }), 503
            
            success_count = 0
            failed_count = 0
            
            try:
                for log_line in logs:
                    parsed = parser_func(log_line)
                    
                    if parsed and 'error' not in parsed:
                        # Add metadata
                        parsed['parser_id'] = parser['parser_id']
                        parsed['parser_name'] = parser['parser_name']
                        parsed['ingested_at'] = datetime.now().isoformat()
                        
                        # Send to RabbitMQ
                        if send_to_rabbitmq(channel, parsed):
                            success_count += 1
                        else:
                            failed_count += 1
                    else:
                        failed_count += 1
                
            finally:
                connection.close()
            
            # Calculate parse time
            parse_time_ms = int((time.time() - start_time) * 1000)
            
            # Update parser statistics
            manager.update_statistics(
                parser_id=parser['parser_id'],
                logs_count=len(logs),
                success_count=success_count,
                parse_time_ms=parse_time_ms
            )
            
            return jsonify({
                'status': 'success' if success_count > 0 else 'failed',
                'logs_received': len(logs),
                'logs_parsed': success_count,
                'logs_failed': failed_count,
                'parser_used': parser['parser_id'],
                'parser_name': parser['parser_name'],
                'parse_time_ms': parse_time_ms
            }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Log ingestion failed: {str(e)}'
        }), 500

@app.route('/parsers', methods=['GET'])
def list_parsers():
    """
    List all available parsers with optional filters.
    
    Query Parameters:
    - vendor: Filter by vendor
    - format_type: Filter by format type
    - mode: Filter by mode (rule-based/llm-based/hybrid)
    - active_only: Only active parsers (default: true)
    - limit: Max results (default: 100)
    
    Response:
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
                "last_used": "2025-10-14T10:30:00"
            }
        ],
        "total": 5
    }
    """
    try:
        # Get query parameters
        vendor = request.args.get('vendor')
        format_type = request.args.get('format_type')
        mode = request.args.get('mode')
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        limit = int(request.args.get('limit', 100))
        
        # Get parsers from database
        with ParserManager(DB_CONFIG) as manager:
            parsers = manager.list_parsers(
                vendor=vendor,
                format_type=format_type,
                mode=mode,
                active_only=active_only,
                limit=limit
            )
            
            # Format response
            parser_list = []
            for p in parsers:
                parser_list.append({
                    'parser_id': p['parser_id'],
                    'parser_name': p['parser_name'],
                    'vendor': p['vendor'],
                    'format_type': p['format_type'],
                    'mode': p['mode'],
                    'active': p['active'],
                    'logs_processed': p['logs_processed'],
                    'parse_success_rate': float(p['parse_success_rate']) if p['parse_success_rate'] else 0.0,
                    'avg_parse_time_ms': p['avg_parse_time_ms'],
                    'last_used': p['last_used'].isoformat() if p['last_used'] else None,
                    'created_at': p['created_at'].isoformat() if p['created_at'] else None
                })
            
            return jsonify({
                'parsers': parser_list,
                'total': len(parser_list)
            }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to list parsers: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>', methods=['GET'])
def get_parser_details(parser_id: str):
    """
    Get detailed information about a specific parser.
    
    Response:
    {
        "parser_id": "sophos-fw-csv-v1",
        "parser_name": "Sophos Firewall CSV",
        "description": "...",
        "vendor": "Sophos",
        "format_type": "CSV",
        "mode": "rule-based",
        "parsing_rules": {...},
        "field_mappings": {...},
        "statistics": {
            "logs_processed": 15234,
            "parse_success_rate": 98.5,
            "avg_parse_time_ms": 12,
            "last_used": "2025-10-14T10:30:00",
            "recent_usage": [...]
        }
    }
    """
    try:
        with ParserManager(DB_CONFIG) as manager:
            parser = manager.get_parser(parser_id=parser_id)
            
            if not parser:
                return jsonify({
                    'error': f'Parser with ID {parser_id} not found'
                }), 404
            
            # Get statistics
            stats = manager.get_parser_statistics(parser_id)
            
            return jsonify({
                'parser_id': parser['parser_id'],
                'parser_name': parser['parser_name'],
                'description': parser['description'],
                'vendor': parser['vendor'],
                'format_type': parser['format_type'],
                'mode': parser['mode'],
                'log_type': parser['log_type'],
                'parsing_rules': parser['parsing_rules'],
                'field_mappings': parser['field_mappings'],
                'timestamp_config': parser['timestamp_config'],
                'validation_rules': parser['validation_rules'],
                'active': parser['active'],
                'version': parser['version'],
                'created_at': parser['created_at'].isoformat() if parser['created_at'] else None,
                'statistics': stats
            }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to get parser details: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>', methods=['PUT'])
def update_parser(parser_id: str):
    """
    Update parser configuration.
    
    Request Body:
    {
        "description": "Updated description",
        "parsing_rules": {...},
        "field_mappings": {...},
        "active": true
    }
    
    Response:
    {
        "success": true,
        "message": "Parser updated successfully"
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        updates = request.get_json()
        
        with ParserManager(DB_CONFIG) as manager:
            success, message = manager.update_parser(parser_id, updates)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': message
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        
    except Exception as e:
        return jsonify({
            'error': f'Parser update failed: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>', methods=['DELETE'])
def delete_parser(parser_id: str):
    """
    Delete a parser.
    
    Response:
    {
        "success": true,
        "message": "Parser deleted successfully"
    }
    """
    try:
        with ParserManager(DB_CONFIG) as manager:
            success, message = manager.delete_parser(parser_id)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': message
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 404
        
    except Exception as e:
        return jsonify({
            'error': f'Parser deletion failed: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>/activate', methods=['POST'])
def activate_parser(parser_id: str):
    """Activate a parser."""
    try:
        with ParserManager(DB_CONFIG) as manager:
            success, message = manager.activate_parser(parser_id)
            
            return jsonify({
                'success': success,
                'message': message
            }), 200 if success else 400
        
    except Exception as e:
        return jsonify({
            'error': f'Parser activation failed: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>/deactivate', methods=['POST'])
def deactivate_parser(parser_id: str):
    """Deactivate a parser."""
    try:
        with ParserManager(DB_CONFIG) as manager:
            success, message = manager.deactivate_parser(parser_id)
            
            return jsonify({
                'success': success,
                'message': message
            }), 200 if success else 400
        
    except Exception as e:
        return jsonify({
            'error': f'Parser deactivation failed: {str(e)}'
        }), 500

@app.route('/parsers/<parser_id>/export', methods=['GET'])
def export_parser(parser_id: str):
    """
    Export parser configuration as JSON.
    
    Response:
    {
        "parser_id": "sophos-fw-csv-v1",
        "parser_name": "Sophos Firewall CSV",
        "format_type": "CSV",
        ...
    }
    """
    try:
        with ParserManager(DB_CONFIG) as manager:
            parser = manager.get_parser(parser_id=parser_id)
            
            if not parser:
                return jsonify({
                    'error': f'Parser with ID {parser_id} not found'
                }), 404
            
            # Remove auto-generated fields
            export_data = {k: v for k, v in parser.items() 
                          if k not in ['created_at', 'updated_at', 'logs_processed', 
                                      'parse_success_rate', 'avg_parse_time_ms', 'last_used']}
            
            # Convert datetime objects to strings
            for key, value in export_data.items():
                if isinstance(value, datetime):
                    export_data[key] = value.isoformat()
            
            return jsonify(export_data), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Parser export failed: {str(e)}'
        }), 500

@app.route('/parsers/import', methods=['POST'])
def import_parser():
    """
    Import parser configuration from JSON.
    
    Request Body: Parser configuration JSON
    
    Response:
    {
        "success": true,
        "parser_id": "new-parser-id",
        "message": "Parser imported successfully"
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        parser_config = request.get_json()
        
        # Remove parser_id if exists (will be regenerated)
        if 'parser_id' in parser_config:
            del parser_config['parser_id']
        
        with ParserManager(DB_CONFIG) as manager:
            success, message, parser_id = manager.create_parser(parser_config)
            
            if success:
                return jsonify({
                    'success': True,
                    'parser_id': parser_id,
                    'message': message
                }), 201
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        
    except Exception as e:
        return jsonify({
            'error': f'Parser import failed: {str(e)}'
        }), 500

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== Main Entry Point ====================

if __name__ == '__main__':
    print("=" * 70)
    print("Universal Log Receiver - REST API Server")
    print("=" * 70)
    print("\nAvailable Endpoints:")
    print("  POST   /analyze_format      - Detect log format")
    print("  POST   /create_parser       - Create new parser")
    print("  POST   /test_parser         - Test parser with samples")
    print("  POST   /ingest              - Ingest logs")
    print("  GET    /parsers             - List all parsers")
    print("  GET    /parsers/<id>        - Get parser details")
    print("  PUT    /parsers/<id>        - Update parser")
    print("  DELETE /parsers/<id>        - Delete parser")
    print("  POST   /parsers/<id>/activate   - Activate parser")
    print("  POST   /parsers/<id>/deactivate - Deactivate parser")
    print("  GET    /parsers/<id>/export - Export parser config")
    print("  POST   /parsers/import      - Import parser config")
    print("  GET    /health              - Health check")
    print("\n" + "=" * 70)
    print("Starting server on http://localhost:5001")
    print("=" * 70 + "\n")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5001, debug=True)
