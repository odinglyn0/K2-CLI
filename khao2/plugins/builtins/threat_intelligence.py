"""Threat intelligence aggregator plugin for integrating multiple threat feeds."""
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
from khao2.plugins import (
    ProcessorPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class ThreatIndicator:
    """Represents a threat indicator from intelligence feeds."""
    indicator_type: str  # 'ip', 'domain', 'hash', 'url', etc.
    value: str
    confidence: float  # 0.0 to 1.0
    severity: str  # 'low', 'medium', 'high', 'critical'
    sources: List[str]
    first_seen: float
    last_seen: float
    tags: List[str]
    context: Dict[str, Any] = None

    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class ThreatAssessment:
    """Assessment of a file or entity against threat intelligence."""
    target: str
    target_type: str
    indicators_found: List[ThreatIndicator]
    risk_score: float  # 0.0 to 1.0
    assessment: str  # 'clean', 'suspicious', 'malicious'
    recommendations: List[str]
    assessed_at: float


class ThreatIntelligencePlugin(ProcessorPlugin):
    """Plugin for aggregating and analyzing threat intelligence from multiple sources."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.feeds: Dict[str, Dict[str, Any]] = {}
        self.cache: Dict[str, Any] = {}
        self.indicators: Dict[str, List[ThreatIndicator]] = {}

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="threat_intelligence",
            version="1.0.0",
            description="Aggregate threat intelligence from multiple feeds for enhanced detection",
            author="Khao2 Community",
            plugin_type="processor",
            entry_point="khao2.plugins.builtins.threat_intelligence.ThreatIntelligencePlugin",
            config_schema={
                "enabled_feeds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["abuseipdb", "virustotal", "openphish", "malware_bazaar"],
                    "description": "List of threat intelligence feeds to query"
                },
                "cache_ttl": {
                    "type": "integer",
                    "default": 3600,
                    "description": "Cache time-to-live in seconds"
                },
                "risk_thresholds": {
                    "type": "object",
                    "properties": {
                        "low": {"type": "number", "default": 0.3},
                        "medium": {"type": "number", "default": 0.6},
                        "high": {"type": "number", "default": 0.8}
                    },
                    "default": {"low": 0.3, "medium": 0.6, "high": 0.8},
                    "description": "Risk score thresholds for severity levels"
                },
                "api_keys": {
                    "type": "object",
                    "default": {},
                    "description": "API keys for premium feeds"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the threat intelligence aggregator."""
        # Load configuration
        plugin_config = context.config.get('threat_intelligence', {})
        self.config = {
            'enabled_feeds': plugin_config.get('enabled_feeds', ['abuseipdb', 'virustotal', 'openphish', 'malware_bazaar']),
            'cache_ttl': plugin_config.get('cache_ttl', 3600),
            'risk_thresholds': plugin_config.get('risk_thresholds', {'low': 0.3, 'medium': 0.6, 'high': 0.8}),
            'api_keys': plugin_config.get('api_keys', {})
        }

        # Initialize feeds
        self._initialize_feeds()

        # Load cached indicators
        self._load_cache()

    def cleanup(self) -> None:
        """Clean up resources and save cache."""
        self._save_cache()

    def process(self, items: List[Any], **kwargs) -> List[Any]:
        """Process inputs through threat intelligence analysis."""
        results = []
        
        for data in items:
            if isinstance(data, dict):
                if 'file_path' in data:
                    target = data['file_path']
                    target_type = 'file'
                elif 'url' in data:
                    target = data['url']
                    target_type = 'url'
                elif 'ip' in data:
                    target = data['ip']
                    target_type = 'ip'
                elif 'domain' in data:
                    target = data['domain']
                    target_type = 'domain'
                else:
                    raise PluginError("No recognizable target in input data")
            elif isinstance(data, str):
                # Try to determine type from string
                target = data
                target_type = self._infer_target_type(data)
            else:
                raise PluginError("Invalid input: expected file path, URL, IP, or domain")

            # Perform threat assessment
            assessment = self._assess_threat(target, target_type)

            results.append({
                'threat_assessment': assessment,
                'indicators': assessment.indicators_found,
                'risk_score': assessment.risk_score,
                'assessment': assessment.assessment
            })
        
        return results

    def _initialize_feeds(self) -> None:
        """Initialize threat intelligence feeds."""
        self.feeds = {
            'abuseipdb': {
                'name': 'AbuseIPDB',
                'type': 'ip',
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'api_key_required': True,
                'rate_limit': 1000,  # per day
                'parser': self._parse_abuseipdb
            },
            'virustotal': {
                'name': 'VirusTotal',
                'type': 'multi',
                'url': 'https://www.virustotal.com/api/v3/',
                'api_key_required': True,
                'rate_limit': 500,  # per day for free tier
                'parser': self._parse_virustotal
            },
            'openphish': {
                'name': 'OpenPhish',
                'type': 'url',
                'url': 'https://openphish.com/feed.txt',
                'api_key_required': False,
                'rate_limit': None,
                'parser': self._parse_openphish
            },
            'malware_bazaar': {
                'name': 'Malware Bazaar',
                'type': 'hash',
                'url': 'https://mb-api.abuse.ch/api/v1/',
                'api_key_required': False,
                'rate_limit': None,
                'parser': self._parse_malware_bazaar
            },
            'phishtank': {
                'name': 'PhishTank',
                'type': 'url',
                'url': 'http://data.phishtank.com/data/online-valid.json',
                'api_key_required': False,
                'rate_limit': None,
                'parser': self._parse_phishtank
            }
        }

    def _infer_target_type(self, target: str) -> str:
        """Infer the type of target from the string."""
        # Check if it's an IP address
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass

        # Check if it's a URL
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return 'url'

        # Check if it's a hash
        if len(target) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in target):
            return 'hash'

        # Check if it's a domain (basic check)
        if '.' in target and len(target.split('.')) >= 2:
            return 'domain'

        # Default to file path
        return 'file'

    def _assess_threat(self, target: str, target_type: str) -> ThreatAssessment:
        """Assess threat level of target."""
        indicators = []
        total_score = 0.0
        source_count = 0

        # Query enabled feeds
        for feed_name in self.config['enabled_feeds']:
            if feed_name in self.feeds:
                feed = self.feeds[feed_name]
                if self._feed_supports_type(feed, target_type):
                    try:
                        feed_indicators = self._query_feed(feed_name, target, target_type)
                        indicators.extend(feed_indicators)
                        source_count += 1
                    except Exception as e:
                        # Log error but continue with other feeds
                        import logging
                        logging.warning(f"Error querying {feed_name}: {e}")

        # Calculate risk score
        if indicators:
            # Weight by confidence and recency
            current_time = time.time()
            for indicator in indicators:
                age_days = (current_time - indicator.last_seen) / (24 * 3600)
                age_weight = max(0.1, 1.0 - (age_days / 365))  # Decay over year
                total_score += indicator.confidence * age_weight

            risk_score = min(1.0, total_score / len(indicators))
        else:
            risk_score = 0.0

        # Determine assessment
        thresholds = self.config['risk_thresholds']
        if risk_score >= thresholds['high']:
            assessment = 'malicious'
        elif risk_score >= thresholds['medium']:
            assessment = 'suspicious'
        else:
            assessment = 'clean'

        # Generate recommendations
        recommendations = self._generate_recommendations(assessment, indicators)

        return ThreatAssessment(
            target=target,
            target_type=target_type,
            indicators_found=indicators,
            risk_score=risk_score,
            assessment=assessment,
            recommendations=recommendations,
            assessed_at=time.time()
        )

    def _feed_supports_type(self, feed: Dict[str, Any], target_type: str) -> bool:
        """Check if feed supports the target type."""
        feed_type = feed['type']
        return feed_type == 'multi' or feed_type == target_type

    def _query_feed(self, feed_name: str, target: str, target_type: str) -> List[ThreatIndicator]:
        """Query a specific threat intelligence feed."""
        # Check cache first
        cache_key = f"{feed_name}:{target}"
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            if time.time() - cached_data['timestamp'] < self.config['cache_ttl']:
                return cached_data['indicators']

        feed = self.feeds[feed_name]
        indicators = []

        try:
            if feed_name == 'abuseipdb':
                indicators = self._query_abuseipdb(target)
            elif feed_name == 'virustotal':
                indicators = self._query_virustotal(target, target_type)
            elif feed_name == 'openphish':
                indicators = self._query_openphish(target)
            elif feed_name == 'malware_bazaar':
                indicators = self._query_malware_bazaar(target)
            elif feed_name == 'phishtank':
                indicators = self._query_phishtank(target)

            # Cache results
            self.cache[cache_key] = {
                'indicators': indicators,
                'timestamp': time.time()
            }

        except Exception as e:
            import logging
            logging.warning(f"Error querying {feed_name}: {e}")

        return indicators

    def _query_abuseipdb(self, target: str) -> List[ThreatIndicator]:
        """Query AbuseIPDB for IP reputation."""
        api_key = self.config['api_keys'].get('abuseipdb')
        if not api_key:
            return []

        # This would make actual API call in real implementation
        # For demo, return mock data
        return [
            ThreatIndicator(
                indicator_type='ip',
                value=target,
                confidence=0.8,
                severity='high',
                sources=['AbuseIPDB'],
                first_seen=time.time() - (30 * 24 * 3600),  # 30 days ago
                last_seen=time.time() - (1 * 24 * 3600),    # 1 day ago
                tags=['malware', 'botnet'],
                context={'abuse_score': 85, 'reports': 12}
            )
        ]

    def _query_virustotal(self, target: str, target_type: str) -> List[ThreatIndicator]:
        """Query VirusTotal for threat intelligence."""
        api_key = self.config['api_keys'].get('virustotal')
        if not api_key:
            return []

        # Mock implementation
        if target_type == 'hash':
            return [
                ThreatIndicator(
                    indicator_type='hash',
                    value=target,
                    confidence=0.9,
                    severity='critical',
                    sources=['VirusTotal'],
                    first_seen=time.time() - (60 * 24 * 3600),
                    last_seen=time.time() - (2 * 24 * 3600),
                    tags=['trojan', 'ransomware'],
                    context={'positives': 45, 'total': 70}
                )
            ]
        return []

    def _query_openphish(self, target: str) -> List[ThreatIndicator]:
        """Query OpenPhish for phishing URLs."""
        # Mock implementation - would download feed
        if 'phish' in target.lower():
            return [
                ThreatIndicator(
                    indicator_type='url',
                    value=target,
                    confidence=0.95,
                    severity='high',
                    sources=['OpenPhish'],
                    first_seen=time.time() - (7 * 24 * 3600),
                    last_seen=time.time() - (1 * 24 * 3600),
                    tags=['phishing', 'credential_theft'],
                    context={'feed_date': time.strftime('%Y-%m-%d')}
                )
            ]
        return []

    def _query_malware_bazaar(self, target: str) -> List[ThreatIndicator]:
        """Query Malware Bazaar for malware samples."""
        # Mock implementation
        if len(target) == 64:  # SHA256 hash
            return [
                ThreatIndicator(
                    indicator_type='hash',
                    value=target,
                    confidence=0.85,
                    severity='high',
                    sources=['Malware Bazaar'],
                    first_seen=time.time() - (14 * 24 * 3600),
                    last_seen=time.time() - (3 * 24 * 3600),
                    tags=['malware', 'trojan'],
                    context={'signature': 'Trojan.Generic', 'size': 245760}
                )
            ]
        return []

    def _query_phishtank(self, target: str) -> List[ThreatIndicator]:
        """Query PhishTank for phishing sites."""
        # Mock implementation
        if 'bank' in target.lower() and 'login' in target.lower():
            return [
                ThreatIndicator(
                    indicator_type='url',
                    value=target,
                    confidence=0.9,
                    severity='high',
                    sources=['PhishTank'],
                    first_seen=time.time() - (10 * 24 * 3600),
                    last_seen=time.time() - (1 * 24 * 3600),
                    tags=['phishing', 'banking'],
                    context={'verified': True, 'submission_time': time.strftime('%Y-%m-%d')}
                )
            ]
        return []

    def _generate_recommendations(self, assessment: str, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate security recommendations based on assessment."""
        recommendations = []

        if assessment == 'malicious':
            recommendations.extend([
                "Immediately isolate the affected system",
                "Scan all systems for similar indicators",
                "Change all passwords and security credentials",
                "Contact security incident response team",
                "Preserve evidence for forensic analysis"
            ])
        elif assessment == 'suspicious':
            recommendations.extend([
                "Monitor the target closely for suspicious activity",
                "Consider additional scanning with specialized tools",
                "Review access logs and recent activity",
                "Implement additional security controls if needed"
            ])

        # Add specific recommendations based on indicator types
        indicator_types = set(ind.indicator_type for ind in indicators)
        if 'ip' in indicator_types:
            recommendations.append("Block the IP address in firewall rules")
        if 'domain' in indicator_types:
            recommendations.append("Add domain to DNS blacklist")
        if 'hash' in indicator_types:
            recommendations.append("Quarantine files with matching hashes")

        return recommendations

    def _load_cache(self) -> None:
        """Load cached threat intelligence data."""
        cache_file = Path.home() / '.khao2' / 'threat_intelligence_cache.json'
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}

    def _save_cache(self) -> None:
        """Save threat intelligence cache."""
        cache_dir = Path.home() / '.khao2'
        cache_dir.mkdir(exist_ok=True)
        cache_file = cache_dir / 'threat_intelligence_cache.json'

        try:
            with open(cache_file, 'w') as f:
                json.dump(self.cache, f, default=str)
        except:
            pass

    # Parser methods for different feeds (would be implemented for real API calls)
    def _parse_abuseipdb(self, response: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse AbuseIPDB API response."""
        return []

    def _parse_virustotal(self, response: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse VirusTotal API response."""
        return []

    def _parse_openphish(self, response: str) -> List[ThreatIndicator]:
        """Parse OpenPhish feed."""
        return []

    def _parse_malware_bazaar(self, response: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse Malware Bazaar API response."""
        return []

    def _parse_phishtank(self, response: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse PhishTank API response."""
        return []


# Plugin metadata for discovery
PLUGIN_METADATA = ThreatIntelligencePlugin().metadata