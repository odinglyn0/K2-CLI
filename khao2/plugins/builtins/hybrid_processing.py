"""Hybrid processing plugin for cloud-local analysis with intelligent routing."""
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from khao2.plugins import (
    ProcessorPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class CacheEntry:
    """Represents a cached scan result."""
    file_hash: str
    file_path: str
    scan_result: Dict[str, Any]
    cached_at: float
    expires_at: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() > self.expires_at


@dataclass
class LocalDetectorResult:
    """Result from local detection analysis."""
    file_path: str
    entropy: float
    file_size_score: float
    strings_found: int
    has_suspicious_patterns: bool
    confidence: float
    detected_anomalies: List[Dict[str, Any]]
    analysis_time: float


@dataclass
class HybridConfig:
    """Configuration for hybrid processing."""
    enable_caching: bool = True
    cache_ttl_hours: int = 24
    enable_local_analysis: bool = True
    local_threshold_confidence: float = 0.8
    cost_optimization: bool = True
    low_credits_threshold: int = 5
    cache_dir: Optional[Path] = None


class HybridProcessingPlugin(ProcessorPlugin):
    """Plugin for hybrid cloud-local processing with intelligent routing."""

    def __init__(self):
        self.config: HybridConfig = HybridConfig()
        self.cache: Dict[str, CacheEntry] = {}
        self.api_client = None
        self.scan_service = None
        self.quota_service = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="hybrid_processing",
            version="1.0.0",
            description="Intelligent hybrid cloud-local processing with caching",
            author="Khao2 Team",
            plugin_type="processor",
            entry_point="khao2.plugins.builtins.hybrid_processing.HybridProcessingPlugin",
            config_schema={
                "enable_caching": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable result caching"
                },
                "cache_ttl_hours": {
                    "type": "integer",
                    "default": 24,
                    "description": "Cache TTL in hours"
                },
                "enable_local_analysis": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable local pre-analysis"
                },
                "local_threshold_confidence": {
                    "type": "number",
                    "default": 0.8,
                    "description": "Confidence threshold for local-only results"
                },
                "cost_optimization": {
                    "type": "boolean",
                    "default": True,
                    "description": "Optimize for cost by using local analysis when possible"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the hybrid processor."""
        self.api_client = context.services.get('api_client')
        self.scan_service = context.services.get('scan_service')
        self.quota_service = context.services.get('quota_service')

        # Load configuration
        plugin_config = context.config.get('hybrid_processing', {})
        cache_dir = plugin_config.get('cache_dir')
        if cache_dir:
            cache_dir = Path(cache_dir)
        else:
            cache_dir = Path.home() / ".khao2" / "cache"

        self.config = HybridConfig(
            enable_caching=plugin_config.get('enable_caching', True),
            cache_ttl_hours=plugin_config.get('cache_ttl_hours', 24),
            enable_local_analysis=plugin_config.get('enable_local_analysis', True),
            local_threshold_confidence=plugin_config.get('local_threshold_confidence', 0.8),
            cost_optimization=plugin_config.get('cost_optimization', True),
            low_credits_threshold=plugin_config.get('low_credits_threshold', 5),
            cache_dir=cache_dir
        )

        # Initialize cache directory
        if self.config.enable_caching:
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_cache()

    def cleanup(self) -> None:
        """Clean up and save cache."""
        if self.config.enable_caching:
            self._save_cache()

    def process(self, items: List[Any], **kwargs) -> List[Any]:
        """Process items with hybrid cloud-local intelligence."""
        if not isinstance(items, list):
            raise PluginError("Hybrid processor expects a list of items")

        results = []

        for item in items:
            try:
                result = self._process_single_item(item, **kwargs)
                results.append(result)
            except Exception as e:
                results.append({
                    "item": item,
                    "error": str(e),
                    "processed": False
                })

        return results

    def _process_single_item(self, item: Any, **kwargs) -> Dict[str, Any]:
        """Process a single item with hybrid intelligence."""
        if isinstance(item, (str, Path)):
            file_path = Path(item)
        else:
            raise PluginError(f"Unsupported item type: {type(item)}")

        if not file_path.exists():
            raise PluginError(f"File does not exist: {file_path}")

        # Check cache first
        if self.config.enable_caching:
            cached_result = self._get_cached_result(file_path)
            if cached_result:
                return {
                    "file_path": str(file_path),
                    "result": cached_result,
                    "source": "cache",
                    "processed": True
                }

        # Perform local analysis if enabled
        local_result = None
        if self.config.enable_local_analysis:
            local_result = self._perform_local_analysis(file_path)

        # Decide processing strategy
        strategy = self._determine_processing_strategy(file_path, local_result)

        if strategy == "local_only":
            # High confidence from local analysis, skip cloud
            return {
                "file_path": str(file_path),
                "result": local_result,
                "source": "local",
                "processed": True
            }

        elif strategy == "cloud_with_fallback":
            # Try cloud first, fallback to local if credits low
            try:
                cloud_result = self._perform_cloud_analysis(file_path)
                result = {
                    "file_path": str(file_path),
                    "result": cloud_result,
                    "source": "cloud",
                    "processed": True
                }
            except Exception as e:
                if local_result and self.config.cost_optimization:
                    result = {
                        "file_path": str(file_path),
                        "result": local_result,
                        "source": "local_fallback",
                        "cloud_error": str(e),
                        "processed": True
                    }
                else:
                    raise

        else:  # cloud_only
            cloud_result = self._perform_cloud_analysis(file_path)
            result = {
                "file_path": str(file_path),
                "result": cloud_result,
                "source": "cloud",
                "processed": True
            }

        # Cache the result
        if self.config.enable_caching and 'result' in result:
            self._cache_result(file_path, result['result'])

        return result

    def _perform_local_analysis(self, file_path: Path) -> LocalDetectorResult:
        """Perform local steganalysis on a file."""
        start_time = time.time()

        # Calculate basic file statistics
        file_size = file_path.stat().st_size
        entropy = self._calculate_entropy(file_path)
        size_score = min(file_size / 1000000, 1.0)  # Normalize to 0-1

        # Extract strings (simple implementation)
        strings_found = self._extract_strings(file_path)

        # Simple anomaly detection
        anomalies = []
        confidence = 0.0

        # Check for perfect lag correlation (suspicious for 1x1 images)
        if file_size < 1000:  # Very small files
            anomalies.append({
                "id": "small_file",
                "explanation": "Very small file size may indicate trivial steganography",
                "confidence": 0.3
            })
            confidence += 0.3

        # High entropy in small files
        if entropy > 0.8 and file_size < 10000:
            anomalies.append({
                "id": "high_entropy_small_file",
                "explanation": "High entropy in small file may indicate hidden data",
                "confidence": 0.6
            })
            confidence += 0.6

        # Many strings in small files
        if strings_found > 10 and file_size < 50000:
            anomalies.append({
                "id": "many_strings",
                "explanation": "Unexpected number of strings in small file",
                "confidence": 0.4
            })
            confidence += 0.4

        # Suspicious patterns
        has_suspicious = len(anomalies) > 0

        analysis_time = time.time() - start_time

        return LocalDetectorResult(
            file_path=str(file_path),
            entropy=entropy,
            file_size_score=size_score,
            strings_found=strings_found,
            has_suspicious_patterns=has_suspicious,
            confidence=min(confidence, 1.0),
            detected_anomalies=anomalies,
            analysis_time=analysis_time
        )

    def _perform_cloud_analysis(self, file_path: Path) -> Dict[str, Any]:
        """Perform cloud analysis via API."""
        if not self.scan_service:
            raise PluginError("Scan service not available")

        scan_id = self.scan_service.upload_and_scan(str(file_path))
        result = self.scan_service.get_scan_result(scan_id)

        return {
            "scan_id": scan_id,
            "scan_result": result
        }

    def _determine_processing_strategy(self, file_path: Path,
                                    local_result: Optional[LocalDetectorResult]) -> str:
        """Determine the best processing strategy."""
        if not self.config.cost_optimization:
            return "cloud_only"

        # Check credits if quota service available
        if self.quota_service:
            try:
                can_scan, message = self.quota_service.check_can_scan()
                if not can_scan:
                    # No credits, use local only
                    return "local_only"
            except Exception:
                pass

        # Use local confidence to decide
        if local_result and local_result.confidence >= self.config.local_threshold_confidence:
            return "local_only"

        # Default to cloud with fallback
        return "cloud_with_fallback"

    def _calculate_entropy(self, file_path: Path) -> float:
        """Calculate file entropy."""
        import math
        
        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        entropy = 0.0
        for i in range(256):
            p = data.count(i) / len(data)
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy / 8.0  # Normalize to 0-1

    def _extract_strings(self, file_path: Path) -> int:
        """Extract printable strings from file."""
        strings = []
        with open(file_path, 'rb') as f:
            data = f.read()

        current_string = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(''.join(current_string))
                current_string = []

        # Don't forget the last string
        if len(current_string) >= 4:
            strings.append(''.join(current_string))

        return len(strings)

    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_cached_result(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Get cached result for file if available and not expired."""
        if not self.config.enable_caching:
            return None

        file_hash = self._get_file_hash(file_path)
        entry = self.cache.get(file_hash)

        if entry and not entry.is_expired():
            return entry.scan_result

        # Remove expired entry
        if entry and entry.is_expired():
            del self.cache[file_hash]

        return None

    def _cache_result(self, file_path: Path, result: Dict[str, Any]) -> None:
        """Cache a scan result."""
        if not self.config.enable_caching:
            return

        file_hash = self._get_file_hash(file_path)
        expires_at = time.time() + (self.config.cache_ttl_hours * 3600)

        entry = CacheEntry(
            file_hash=file_hash,
            file_path=str(file_path),
            scan_result=result,
            cached_at=time.time(),
            expires_at=expires_at
        )

        self.cache[file_hash] = entry

    def _load_cache(self) -> None:
        \"\"\"Load cache from disk.\"\"\"
        if not self.config.enable_caching:
            return

        cache_file = self.config.cache_dir / "scan_cache.json"
        if cache_file.exists():
            try:
                import json
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                    # Reconstruct CacheEntry objects from dicts
                    self.cache = {
                        k: CacheEntry(**v) for k, v in cache_data.items()
                    }

                # Remove expired entries
                expired = [k for k, v in self.cache.items() if v.is_expired()]
                for k in expired:
                    del self.cache[k]

            except Exception:
                # If cache is corrupted, start fresh
                self.cache = {}

    def _save_cache(self) -> None:
        \"\"\"Save cache to disk.\"\"\"
        if not self.config.enable_caching:
            return

        cache_file = self.config.cache_dir / "scan_cache.json"
        try:
            import json
            with open(cache_file, 'w') as f:
                # Convert CacheEntry objects to dicts for JSON serialization
                cache_data = {
                    k: {
                        'file_hash': v.file_hash,
                        'file_path': v.file_path,
                        'scan_result': v.scan_result,
                        'cached_at': v.cached_at,
                        'expires_at': v.expires_at,
                        'metadata': v.metadata
                    } for k, v in self.cache.items()
                }
                json.dump(cache_data, f, default=str)
        except Exception:
            pass  # Fail silently for cache saves


# Plugin metadata for discovery
PLUGIN_METADATA = HybridProcessingPlugin().metadata