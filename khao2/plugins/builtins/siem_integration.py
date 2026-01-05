"""SIEM integration plugin for security event logging and alerting."""
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from khao2.plugins import (
    IntegrationPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class SIEMEvent:
    """Represents a security event for SIEM systems."""
    event_id: str
    timestamp: float
    event_type: str
    severity: str
    source: str
    message: str
    details: Dict[str, Any]
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "details": self.details,
            "tags": self.tags
        }


class SIEMIntegrationPlugin(IntegrationPlugin):
    """Integration with SIEM systems for security event logging and alerting."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.event_buffer: List[SIEMEvent] = []
        self.buffer_size = 100
        self.api_client = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="siem_integration",
            version="1.0.0",
            description="SIEM integration for security event logging and compliance",
            author="Khao2 Community",
            plugin_type="integration",
            entry_point="khao2.plugins.builtins.siem_integration.SIEMIntegrationPlugin",
            config_schema={
                "enabled": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable SIEM event logging"
                },
                "siem_type": {
                    "type": "string",
                    "enum": ["splunk", "elasticsearch", "syslog", "file"],
                    "default": "file",
                    "description": "Type of SIEM system to integrate with"
                },
                "endpoint": {
                    "type": "string",
                    "description": "SIEM system endpoint URL"
                },
                "api_key": {
                    "type": "string",
                    "description": "API key for SIEM authentication"
                },
                "log_file": {
                    "type": "string",
                    "default": "~/.khao2/siem_events.log",
                    "description": "Log file path for file-based logging"
                },
                "batch_size": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of events to batch before sending"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the SIEM integration."""
        self.api_client = context.services.get('api_client')

        # Load configuration
        plugin_config = context.config.get('siem_integration', {})
        self.config = {
            'enabled': plugin_config.get('enabled', True),
            'siem_type': plugin_config.get('siem_type', 'file'),
            'endpoint': plugin_config.get('endpoint'),
            'api_key': plugin_config.get('api_key'),
            'log_file': plugin_config.get('log_file', '~/.khao2/siem_events.log'),
            'batch_size': plugin_config.get('batch_size', 10)
        }

        # Expand log file path
        self.config['log_file'] = str(Path(self.config['log_file']).expanduser())

        # Ensure log directory exists
        log_path = Path(self.config['log_file'])
        log_path.parent.mkdir(parents=True, exist_ok=True)

    def cleanup(self) -> None:
        """Clean up and flush any remaining events."""
        self._flush_events()

    def integrate(self, data: Any, **kwargs) -> Any:
        """Main integration method for SIEM operations."""
        operation = kwargs.get('operation', 'unknown')

        if operation == 'log_event':
            return self.log_security_event(data, **kwargs)
        elif operation == 'log_scan_result':
            return self.log_scan_result(data, **kwargs)
        elif operation == 'log_anomaly':
            return self.log_anomaly(data, **kwargs)
        elif operation == 'get_events':
            return self.get_events(**kwargs)
        elif operation == 'flush_events':
            return self._flush_events()
        else:
            raise PluginError(f"Unknown operation: {operation}")

    def log_security_event(self, event_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Log a security event to SIEM."""
        if not self.config.get('enabled'):
            return {"status": "disabled"}

        # Create SIEM event
        event = SIEMEvent(
            event_id=self._generate_event_id(),
            timestamp=time.time(),
            event_type=event_data.get('event_type', 'unknown'),
            severity=event_data.get('severity', 'info'),
            source=event_data.get('source', 'khao2'),
            message=event_data.get('message', ''),
            details=event_data.get('details', {}),
            tags=event_data.get('tags', [])
        )

        # Add to buffer
        self.event_buffer.append(event)

        # Flush if buffer is full
        if len(self.event_buffer) >= self.config.get('batch_size', 10):
            self._flush_events()

        return {
            "status": "logged",
            "event_id": event.event_id
        }

    def log_scan_result(self, scan_result: Any, **kwargs) -> Dict[str, Any]:
        """Log scan results as security events."""
        if hasattr(scan_result, 'static_ai') and scan_result.static_ai:
            ai = scan_result.static_ai

            # Log suspicious scans
            if ai.possibility_of_steganography > 50:
                event_data = {
                    "event_type": "steganography_detected",
                    "severity": "high" if ai.possibility_of_steganography > 80 else "medium",
                    "source": "khao2_scan",
                    "message": f"Steganography detected in scan {getattr(scan_result, 'imageid', 'unknown')}",
                    "details": {
                        "scan_id": getattr(scan_result, 'imageid', 'unknown'),
                        "confidence": ai.confidence,
                        "possibility": ai.possibility_of_steganography,
                        "verdict": ai.verdict,
                        "anomalies_count": len(ai.anomalies) if ai.anomalies else 0
                    },
                    "tags": ["steganography", "scan", "security"]
                }
                return self.log_security_event(event_data)

        return {"status": "no_event_logged"}

    def log_anomaly(self, anomaly_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Log anomaly detection as security event."""
        severity_map = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical"
        }

        event_data = {
            "event_type": "anomaly_detected",
            "severity": severity_map.get(anomaly_data.get('severity', 'medium'), 'medium'),
            "source": "khao2_anomaly",
            "message": anomaly_data.get('description', 'Anomaly detected'),
            "details": anomaly_data,
            "tags": ["anomaly", "security", anomaly_data.get('type', 'unknown')]
        }

        return self.log_security_event(event_data)

    def get_events(self, limit: int = 100, **kwargs) -> List[Dict[str, Any]]:
        """Get recent SIEM events."""
        events = self.event_buffer[-limit:] if limit > 0 else self.event_buffer
        return [event.to_dict() for event in events]

    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        import uuid
        return f"evt_{uuid.uuid4().hex[:12]}"

    def _flush_events(self) -> Dict[str, Any]:
        """Flush buffered events to SIEM system."""
        if not self.event_buffer:
            return {"status": "no_events"}

        siem_type = self.config.get('siem_type', 'file')

        try:
            if siem_type == 'file':
                return self._send_to_file(self.event_buffer)
            elif siem_type == 'splunk':
                return self._send_to_splunk(self.event_buffer)
            elif siem_type == 'elasticsearch':
                return self._send_to_elasticsearch(self.event_buffer)
            elif siem_type == 'syslog':
                return self._send_to_syslog(self.event_buffer)
            else:
                return {"status": "error", "message": f"Unsupported SIEM type: {siem_type}"}

        except Exception as e:
            return {"status": "error", "message": str(e)}
        # Clear buffer only after successful send
        self.event_buffer.clear()

    def _send_to_file(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send events to log file."""
        log_file = Path(self.config['log_file'])

        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event.to_dict()) + '\n')

            return {
                "status": "success",
                "events_sent": len(events),
                "destination": str(log_file)
            }

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _send_to_splunk(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send events to Splunk HTTP Event Collector."""
        import requests

        endpoint = self.config.get('endpoint')
        api_key = self.config.get('api_key')

        if not endpoint or not api_key:
            return {"status": "error", "message": "Splunk endpoint and API key required"}

        headers = {
            'Authorization': f'Splunk {api_key}',
            'Content-Type': 'application/json'
        }

        try:
            # Send events in batch
            events_data = [event.to_dict() for event in events]
            response = requests.post(
                endpoint,
                headers=headers,
                json=events_data,
                timeout=30
            )

            if response.status_code == 200:
                return {
                    "status": "success",
                    "events_sent": len(events),
                    "destination": "splunk"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Splunk API error: {response.status_code}",
                    "response": response.text
                }

        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}

    def _send_to_elasticsearch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send events to Elasticsearch."""
        import requests

        endpoint = self.config.get('endpoint')
        api_key = self.config.get('api_key')

        if not endpoint:
            return {"status": "error", "message": "Elasticsearch endpoint required"}

        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'ApiKey {api_key}'

        try:
            # Send events individually (bulk API would be better for production)
            sent_count = 0
            for event in events:
                index_url = f"{endpoint}/khao2-events-{_get_date_suffix()}/_doc"
                response = requests.post(
                    index_url,
                    headers=headers,
                    json=event.to_dict(),
                    timeout=10
                )

                if response.status_code in [200, 201]:
                    sent_count += 1

            return {
                "status": "success",
                "events_sent": sent_count,
                "total_events": len(events),
                "destination": "elasticsearch"
            }

        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}

    def _send_to_syslog(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send events to syslog."""
        import logging
        import logging.handlers

        syslog_address = self.config.get('endpoint', '/dev/log')

        try:
            # Configure syslog handler
            logger = logging.getLogger('khao2_siem')
            logger.setLevel(logging.INFO)

            # Remove existing handlers
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)

            # Add syslog handler
            if isinstance(syslog_address, str) and syslog_address.startswith('/'):
                # Unix socket
                handler = logging.handlers.SysLogHandler(address=syslog_address)
            else:
                # TCP/UDP
                host, port = syslog_address.rsplit(':', 1) if ':' in syslog_address else (syslog_address, 514)
                handler = logging.handlers.SysLogHandler(address=(host, int(port)))

            formatter = logging.Formatter('KHAO2: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            # Send events
            sent_count = 0
            for event in events:
                try:
                    logger.info(json.dumps(event.to_dict()))
                    sent_count += 1
                except Exception:
                    continue

            return {
                "status": "success",
                "events_sent": sent_count,
                "total_events": len(events),
                "destination": "syslog"
            }

        except Exception as e:
            return {"status": "error", "message": str(e)}


def _get_date_suffix() -> str:
    """Get date suffix for Elasticsearch index."""
    from datetime import datetime
    return datetime.now().strftime("%Y.%m.%d")


# Plugin metadata for discovery
PLUGIN_METADATA = SIEMIntegrationPlugin().metadata