"""VirusTotal integration plugin for enhanced threat intelligence."""
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from khao2.plugins import (
    IntegrationPlugin, PluginMetadata, PluginContext,
    PluginError
)


class VirusTotalIntegrationPlugin(IntegrationPlugin):
    """Integration with VirusTotal for threat intelligence and reputation analysis."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.api_key: Optional[str] = None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # VT allows 4 requests per minute for free tier

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="virustotal_integration",
            version="1.0.0",
            description="VirusTotal integration for file reputation and threat intelligence",
            author="Khao2 Community",
            plugin_type="integration",
            entry_point="khao2.plugins.builtins.virustotal_integration.VirusTotalIntegrationPlugin",
            config_schema={
                "api_key": {
                    "type": "string",
                    "description": "VirusTotal API key (optional, increases rate limits)"
                },
                "enable_file_scans": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable file scanning through VirusTotal"
                },
                "enable_reputation_check": {
                    "type": "boolean",
                    "default": True,
                    "description": "Check file reputation scores"
                },
                "cache_results": {
                    "type": "boolean",
                    "default": True,
                    "description": "Cache VirusTotal results locally"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the VirusTotal integration."""
        # Load configuration
        plugin_config = context.config.get('virustotal_integration', {})
        self.config = {
            'api_key': plugin_config.get('api_key'),
            'enable_file_scans': plugin_config.get('enable_file_scans', True),
            'enable_reputation_check': plugin_config.get('enable_reputation_check', True),
            'cache_results': plugin_config.get('cache_results', True)
        }

        self.api_key = self.config.get('api_key')

        # Initialize cache if enabled
        if self.config.get('cache_results'):
            self._init_cache()

    def cleanup(self) -> None:
        """Clean up resources."""
        if hasattr(self, '_cache') and self.config.get('cache_results'):
            self._save_cache()

    def integrate(self, data: Any, **kwargs) -> Any:
        """Main integration method for VirusTotal operations."""
        operation = kwargs.get('operation', 'unknown')

        if operation == 'check_file':
            return self.check_file_reputation(data, **kwargs)
        elif operation == 'scan_file':
            return self.scan_file(data, **kwargs)
        elif operation == 'get_report':
            return self.get_scan_report(data, **kwargs)
        elif operation == 'analyze_scan_results':
            return self.analyze_scan_results(data, **kwargs)
        else:
            raise PluginError(f"Unknown operation: {operation}")

    def check_file_reputation(self, file_path: Path, **kwargs) -> Dict[str, Any]:
        """Check file reputation using hash lookup."""
        if not isinstance(file_path, Path):
            file_path = Path(file_path)

        if not file_path.exists():
            raise PluginError(f"File does not exist: {file_path}")

        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)

        # Check cache first
        if self.config.get('cache_results'):
            cached_result = self._get_cached_result(file_hash)
            if cached_result:
                return cached_result

        # Query VirusTotal
        result = self._query_file_hash(file_hash)

        # Cache result
        if self.config.get('cache_results'):
            self._cache_result(file_hash, result)

        return result

    def scan_file(self, file_path: Path, **kwargs) -> Dict[str, Any]:
        """Submit file for scanning to VirusTotal."""
        if not self.config.get('enable_file_scans'):
            raise PluginError("File scanning is disabled")

        if not isinstance(file_path, Path):
            file_path = Path(file_path)

        if not file_path.exists():
            raise PluginError(f"File does not exist: {file_path}")

        # Check file size (VT free tier limit is 32MB)
        file_size = file_path.stat().st_size
        if file_size > 32 * 1024 * 1024:  # 32MB
            raise PluginError("File too large for VirusTotal free tier (max 32MB)")

        # Submit file for scanning
        result = self._submit_file_for_scan(file_path)

        return result

    def get_scan_report(self, scan_id: str, **kwargs) -> Dict[str, Any]:
        """Get scan report by analysis ID."""
        return self._get_analysis_report(scan_id)

    def analyze_scan_results(self, vt_result: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Analyze VirusTotal results in context of steganography detection."""
        analysis = {
            "threat_assessment": "unknown",
            "risk_level": "low",
            "insights": [],
            "recommendations": []
        }

        if not isinstance(vt_result, dict):
            return analysis

        # Extract detection statistics
        data = vt_result.get('data', {})
        attributes = data.get('attributes', {})

        malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        suspicious_count = attributes.get('last_analysis_stats', {}).get('suspicious', 0)
        total_engines = attributes.get('last_analysis_stats', {}).get('total', 0)

        # Assess threat level
        if malicious_count > 0:
            analysis["threat_assessment"] = "malicious"
            analysis["risk_level"] = "high" if malicious_count > 5 else "medium"
            analysis["insights"].append(f"Detected as malicious by {malicious_count}/{total_engines} engines")
        elif suspicious_count > 0:
            analysis["threat_assessment"] = "suspicious"
            analysis["risk_level"] = "medium"
            analysis["insights"].append(f"Flagged as suspicious by {suspicious_count}/{total_engines} engines")
        else:
            analysis["threat_assessment"] = "clean"
            analysis["risk_level"] = "low"
            analysis["insights"].append(f"No threats detected by {total_engines} engines")

        # Generate recommendations
        if analysis["risk_level"] in ["high", "medium"]:
            analysis["recommendations"].append("File shows malicious indicators - handle with caution")
            analysis["recommendations"].append("Consider isolating file and performing deeper analysis")

        # Check for steganography-related insights
        file_type = attributes.get('type_description', '').lower()
        if 'image' in file_type:
            analysis["insights"].append("Image file - steganography analysis recommended")
            if malicious_count > 0:
                analysis["recommendations"].append("Malicious image file may contain embedded malware")

        return analysis

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _query_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal for file hash information."""
        import requests

        url = f"{self.base_url}/files/{file_hash}"
        headers = {'Accept': 'application/json'}

        if self.api_key:
            headers['x-apikey'] = self.api_key

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {
                    "data": None,
                    "status": "not_found",
                    "message": "File not found in VirusTotal database"
                }
            else:
                return {
                    "error": f"API request failed: {response.status_code}",
                    "status": "error"
                }

        except requests.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "status": "error"
            }

    def _submit_file_for_scan(self, file_path: Path) -> Dict[str, Any]:
        """Submit file to VirusTotal for scanning."""
        import requests

        url = f"{self.base_url}/files"
        headers = {'Accept': 'application/json'}

        if self.api_key:
            headers['x-apikey'] = self.api_key

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = requests.post(url, headers=headers, files=files, timeout=60)

            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                return {
                    "status": "submitted",
                    "analysis_id": analysis_id,
                    "message": "File submitted for scanning"
                }
            else:
                return {
                    "status": "error",
                    "error": f"Submission failed: {response.status_code}",
                    "details": response.text
                }

        except requests.RequestException as e:
            return {
                "status": "error",
                "error": f"Network error: {str(e)}"
            }

    def _get_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis report by ID."""
        import requests

        url = f"{self.base_url}/analyses/{analysis_id}"
        headers = {'Accept': 'application/json'}

        if self.api_key:
            headers['x-apikey'] = self.api_key

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"Failed to get report: {response.status_code}",
                    "status": "error"
                }

        except requests.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "status": "error"
            }

    def _init_cache(self) -> None:
        """Initialize result cache."""
        cache_dir = Path.home() / ".khao2" / "vt_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = cache_dir / "vt_results.json"

        try:
            import json
            if self._cache_file.exists():
                with open(self._cache_file, 'r') as f:
                    self._cache = json.load(f)
            else:
                self._cache = {}
        except (json.JSONDecodeError, OSError, ValueError):
            self._cache = {}

    def _get_cached_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired."""
        if not hasattr(self, '_cache'):
            return None

        cached = self._cache.get(file_hash)
        if not cached:
            return None

        # Check if cache is expired (24 hours)
        cache_time = cached.get('cached_at', 0)
        if time.time() - cache_time > 24 * 60 * 60:
            return None

        return cached.get('result')

    def _cache_result(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Cache a result."""
        if not hasattr(self, '_cache'):
            return

        self._cache[file_hash] = {
            'result': result,
            'cached_at': time.time()
        }

    def _save_cache(self) -> None:
        """Save cache to disk."""
        if not hasattr(self, '_cache'):
            return

        try:
            import json
            with open(self._cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except (OSError, TypeError):
            pass  # Fail silently


# Plugin metadata for discovery
PLUGIN_METADATA = VirusTotalIntegrationPlugin().metadata