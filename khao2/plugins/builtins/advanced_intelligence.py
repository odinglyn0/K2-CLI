"""Advanced intelligence plugin for pattern recognition and continuous learning."""
import json
import statistics
import time
from collections import defaultdict, Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from khao2.plugins import (
    AnalyzerPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class Pattern:
    """Represents a detected pattern in scan results."""
    pattern_id: str
    pattern_type: str  # 'anomaly', 'technique', 'file_type'
    description: str
    confidence: float
    occurrences: int
    first_seen: float
    last_seen: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ThreatIndicator:
    """Represents a threat indicator learned from scans."""
    indicator_id: str
    indicator_type: str  # 'file_hash', 'pattern', 'behavior'
    value: str
    confidence: float
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    first_seen: float
    last_seen: float
    occurrences: int
    context: Dict[str, Any] = None

    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class LearningConfig:
    """Configuration for the learning system."""
    enable_pattern_learning: bool = True
    enable_threat_detection: bool = True
    enable_feedback_learning: bool = True
    min_occurrences_for_pattern: int = 3
    false_positive_threshold: float = 0.7
    learning_data_dir: Optional[Path] = None
    max_patterns: int = 1000
    pattern_decay_days: int = 30


class AdvancedIntelligencePlugin(AnalyzerPlugin):
    """Plugin for advanced pattern recognition and continuous learning."""

    def __init__(self):
        self.config: LearningConfig = LearningConfig()
        self.patterns: Dict[str, Pattern] = {}
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.feedback_history: List[Dict[str, Any]] = []
        self.scan_history: List[Dict[str, Any]] = []
        self.api_client = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="advanced_intelligence",
            version="1.0.0",
            description="Pattern recognition and continuous learning system",
            author="Khao2 Team",
            plugin_type="analyzer",
            entry_point="khao2.plugins.builtins.advanced_intelligence.AdvancedIntelligencePlugin",
            config_schema={
                "enable_pattern_learning": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable automatic pattern learning"
                },
                "enable_threat_detection": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable threat indicator detection"
                },
                "min_occurrences_for_pattern": {
                    "type": "integer",
                    "default": 3,
                    "description": "Minimum occurrences to establish a pattern"
                },
                "false_positive_threshold": {
                    "type": "number",
                    "default": 0.7,
                    "description": "Confidence threshold for false positive detection"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the intelligence plugin."""
        self.api_client = context.services.get('api_client')

        # Load configuration
        plugin_config = context.config.get('advanced_intelligence', {})
        learning_dir = plugin_config.get('learning_data_dir')
        if learning_dir:
            learning_dir = Path(learning_dir)
        else:
            learning_dir = Path.home() / ".khao2" / "intelligence"

        self.config = LearningConfig(
            enable_pattern_learning=plugin_config.get('enable_pattern_learning', True),
            enable_threat_detection=plugin_config.get('enable_threat_detection', True),
            enable_feedback_learning=plugin_config.get('enable_feedback_learning', True),
            min_occurrences_for_pattern=plugin_config.get('min_occurrences_for_pattern', 3),
            false_positive_threshold=plugin_config.get('false_positive_threshold', 0.7),
            learning_data_dir=learning_dir,
            max_patterns=plugin_config.get('max_patterns', 1000),
            pattern_decay_days=plugin_config.get('pattern_decay_days', 30)
        )

        # Initialize data directory
        self.config.learning_data_dir.mkdir(parents=True, exist_ok=True)
        self._load_learning_data()

    def cleanup(self) -> None:
        """Clean up and save learning data."""
        self._save_learning_data()

    def analyze(self, scan_result: Any, **kwargs) -> Dict[str, Any]:
        """Analyze scan results and learn patterns."""
        analysis_result = {
            "patterns_detected": [],
            "threat_indicators": [],
            "insights": [],
            "recommendations": []
        }

        # Extract features from scan result
        features = self._extract_features(scan_result)

        # Learn from this scan
        if self.config.enable_pattern_learning:
            new_patterns = self._learn_patterns(features)
            analysis_result["patterns_detected"] = new_patterns

        # Detect threats
        if self.config.enable_threat_detection:
            threats = self._detect_threats(features)
            analysis_result["threat_indicators"] = threats

        # Generate insights
        insights = self._generate_insights(features, scan_result)
        analysis_result["insights"] = insights

        # Generate recommendations
        recommendations = self._generate_recommendations(features, scan_result)
        analysis_result["recommendations"] = recommendations

        # Store scan for future learning
        self._store_scan_result(scan_result, features)

        return analysis_result

    def record_feedback(self, scan_id: str, is_false_positive: bool,
                       user_feedback: str = "", **kwargs) -> None:
        """Record user feedback for learning."""
        if not self.config.enable_feedback_learning:
            return

        feedback = {
            "scan_id": scan_id,
            "is_false_positive": is_false_positive,
            "user_feedback": user_feedback,
            "timestamp": time.time(),
            "metadata": kwargs
        }

        self.feedback_history.append(feedback)
        self._learn_from_feedback(feedback)

    def get_patterns(self, pattern_type: Optional[str] = None) -> List[Pattern]:
        """Get learned patterns."""
        if pattern_type:
            return [p for p in self.patterns.values() if p.pattern_type == pattern_type]
        return list(self.patterns.values())

    def get_threat_indicators(self, risk_level: Optional[str] = None) -> List[ThreatIndicator]:
        """Get threat indicators."""
        if risk_level:
            return [t for t in self.threat_indicators.values() if t.risk_level == risk_level]
        return list(self.threat_indicators.values())

    def _extract_features(self, scan_result: Any) -> Dict[str, Any]:
        """Extract features from scan result for analysis."""
        features = {
            "file_size": 0,
            "entropy": 0.0,
            "anomalies_count": 0,
            "anomaly_types": [],
            "techniques_detected": [],
            "confidence_scores": [],
            "file_format": "unknown",
            "has_hidden_data": False,
            "processing_time": 0
        }

        # Extract from scan result object
        if hasattr(scan_result, 'file_meta'):
            if scan_result.file_meta:
                features["file_size"] = (scan_result.file_meta.width * scan_result.file_meta.height
                                       if scan_result.file_meta.width and scan_result.file_meta.height else 0)
                features["file_format"] = scan_result.file_meta.format

        if hasattr(scan_result, 'static_ai') and scan_result.static_ai:
            ai = scan_result.static_ai
            features["has_hidden_data"] = ai.possibility_of_steganography > 50
            features["confidence_scores"] = [ai.confidence] if ai.confidence else []

            if ai.anomalies:
                features["anomalies_count"] = len(ai.anomalies)
                features["anomaly_types"] = [a.id for a in ai.anomalies]

        if hasattr(scan_result, 'elapsed_time'):
            features["processing_time"] = scan_result.elapsed_time

        return features

    def _learn_patterns(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Learn patterns from features."""
        detected_patterns = []

        # Pattern: Small files with high anomaly counts
        if (features.get("file_size", 0) < 10000 and
            features.get("anomalies_count", 0) > 2):
            pattern_key = "small_file_high_anomalies"
            self._update_pattern(pattern_key, "anomaly",
                               "Small files with multiple anomalies", 0.8)
            detected_patterns.append({
                "pattern_id": pattern_key,
                "description": "Small files with multiple anomalies detected"
            })

        # Pattern: Consistent anomaly types
        anomaly_types = features.get("anomaly_types", [])
        if anomaly_types:
            for anomaly_type in anomaly_types:
                pattern_key = f"anomaly_type_{anomaly_type}"
                self._update_pattern(pattern_key, "anomaly",
                                   f"Recurring anomaly type: {anomaly_type}", 0.6)
                detected_patterns.append({
                    "pattern_id": pattern_key,
                    "description": f"Detected recurring anomaly: {anomaly_type}"
                })

        # Pattern: Processing time anomalies
        proc_time = features.get("processing_time", 0)
        if proc_time > 300000:  # 5 minutes
            pattern_key = "long_processing_time"
            self._update_pattern(pattern_key, "performance",
                               "Unusually long processing times", 0.7)
            detected_patterns.append({
                "pattern_id": pattern_key,
                "description": "Detected unusually long processing time"
            })

        return detected_patterns

    def _detect_threats(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential threats based on learned patterns."""
        threats = []

        # Check for known threat patterns
        anomaly_types = set(features.get("anomaly_types", []))
        anomalies_count = features.get("anomalies_count", 0)

        # High-risk: Multiple anomalies in small files
        if anomalies_count >= 3 and features.get("file_size", 0) < 50000:
            threats.append({
                "indicator_id": "high_risk_small_file",
                "type": "pattern",
                "risk_level": "high",
                "description": "Multiple anomalies in small file - high steganography risk"
            })

        # Medium-risk: Known suspicious anomaly types
        suspicious_anomalies = {"high_entropy_small_file", "perfect_lag_1x1"}
        if anomaly_types & suspicious_anomalies:
            threats.append({
                "indicator_id": "suspicious_anomalies",
                "type": "pattern",
                "risk_level": "medium",
                "description": "Known suspicious anomaly patterns detected"
            })

        return threats

    def _generate_insights(self, features: Dict[str, Any], scan_result: Any) -> List[Dict[str, Any]]:
        """Generate insights from analysis."""
        insights = []

        # Insight: Processing efficiency
        proc_time = features.get("processing_time", 0)
        if proc_time > 0:
            avg_time = self._calculate_average_processing_time()
            if avg_time > 0:
                ratio = proc_time / avg_time
                if ratio > 2:
                    insights.append({
                        "type": "performance",
                        "title": "Slow Processing Detected",
                        "description": f"This scan took {ratio:.1f}x longer than average",
                        "severity": "medium"
                    })

        # Insight: Anomaly patterns
        anomalies_count = features.get("anomalies_count", 0)
        avg_anomalies = self._calculate_average_anomalies()
        if avg_anomalies > 0 and anomalies_count > avg_anomalies * 2:
            insights.append({
                "type": "anomaly",
                "title": "High Anomaly Count",
                "description": f"Detected {anomalies_count} anomalies, {anomalies_count/avg_anomalies:.1f}x above average",
                "severity": "high"
            })

        return insights

    def _generate_recommendations(self, features: Dict[str, Any], scan_result: Any) -> List[Dict[str, Any]]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Recommendation: Further analysis for suspicious files
        if features.get("anomalies_count", 0) > 2:
            recommendations.append({
                "action": "deep_analysis",
                "description": "Consider running additional forensic tools (binwalk, exiftool, zsteg)",
                "priority": "high"
            })

        # Recommendation: Batch processing for similar files
        similar_files = self._find_similar_files(features)
        if len(similar_files) > 3:
            recommendations.append({
                "action": "batch_process",
                "description": f"Found {len(similar_files)} similar files that could be processed in batch",
                "priority": "medium"
            })

        return recommendations

    def _update_pattern(self, pattern_id: str, pattern_type: str,
                       description: str, confidence: float) -> None:
        """Update or create a pattern."""
        current_time = time.time()

        if pattern_id in self.patterns:
            pattern = self.patterns[pattern_id]
            pattern.occurrences += 1
            pattern.last_seen = current_time
            pattern.confidence = (pattern.confidence + confidence) / 2  # Average
        else:
            pattern = Pattern(
                pattern_id=pattern_id,
                pattern_type=pattern_type,
                description=description,
                confidence=confidence,
                occurrences=1,
                first_seen=current_time,
                last_seen=current_time
            )

        self.patterns[pattern_id] = pattern

        # Limit number of patterns
        if len(self.patterns) > self.config.max_patterns:
            # Remove oldest patterns
            sorted_patterns = sorted(self.patterns.items(),
                                   key=lambda x: x[1].last_seen)
            to_remove = len(self.patterns) - self.config.max_patterns
            for i in range(to_remove):
                del self.patterns[sorted_patterns[i][0]]

    def _learn_from_feedback(self, feedback: Dict[str, Any]) -> None:
        """Learn from user feedback."""
        # Adjust pattern confidence based on feedback
        scan_id = feedback["scan_id"]
        is_fp = feedback["is_false_positive"]

        # Find the scan in history
        scan_data = None
        for scan in self.scan_history:
            if scan.get("scan_id") == scan_id:
                scan_data = scan
                break

        if scan_data:
            features = scan_data.get("features", {})

            # Adjust confidence for patterns that were detected
            anomaly_types = features.get("anomaly_types", [])
            for anomaly_type in anomaly_types:
                pattern_key = f"anomaly_type_{anomaly_type}"
                if pattern_key in self.patterns:
                    pattern = self.patterns[pattern_key]
                    if is_fp:
                        # Reduce confidence for false positives
                        pattern.confidence *= 0.9
                    else:
                        # Increase confidence for true positives
                        pattern.confidence = min(1.0, pattern.confidence * 1.1)

    def _store_scan_result(self, scan_result: Any, features: Dict[str, Any]) -> None:
        """Store scan result for future learning."""
        scan_data = {
            "scan_id": getattr(scan_result, 'imageid', 'unknown'),
            "timestamp": time.time(),
            "features": features,
            "result_summary": {
                "has_hidden_data": features.get("has_hidden_data", False),
                "anomalies_count": features.get("anomalies_count", 0),
                "confidence": features.get("confidence_scores", [0])[0] if features.get("confidence_scores") else 0
            }
        }

        self.scan_history.append(scan_data)

        # Limit history size
        if len(self.scan_history) > 1000:
            self.scan_history = self.scan_history[-1000:]

    def _calculate_average_processing_time(self) -> float:
        """Calculate average processing time from history."""
        if not self.scan_history:
            return 0.0

        times = [s["features"].get("processing_time", 0) for s in self.scan_history
                if s["features"].get("processing_time", 0) > 0]
        return statistics.mean(times) if times else 0.0

    def _calculate_average_anomalies(self) -> float:
        """Calculate average anomalies count from history."""
        if not self.scan_history:
            return 0.0

        counts = [s["features"].get("anomalies_count", 0) for s in self.scan_history]
        return statistics.mean(counts) if counts else 0.0

    def _find_similar_files(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find files with similar features."""
        similar = []
        target_size = features.get("file_size", 0)
        target_anomalies = features.get("anomaly_types", [])

        for scan in self.scan_history:
            scan_features = scan.get("features", {})
            size_diff = abs(scan_features.get("file_size", 0) - target_size)
            anomaly_overlap = len(set(scan_features.get("anomaly_types", [])) &
                                set(target_anomalies))

            if size_diff < 10000 and anomaly_overlap > 0:  # Similar size and anomalies
                similar.append(scan)

        return similar

    def _load_learning_data(self) -> None:
        """Load learning data from disk."""
        data_dir = self.config.learning_data_dir

        # Load patterns
        patterns_file = data_dir / "patterns.json"
        if patterns_file.exists():
            with open(patterns_file, 'r') as f:
                patterns_data = json.load(f)
                for p_dict in patterns_data.values():
                    pattern = Pattern(**p_dict)
                    self.patterns[pattern.pattern_id] = pattern

        # Load threat indicators
        threats_file = data_dir / "threats.json"
        if threats_file.exists():
            with open(threats_file, 'r') as f:
                threats_data = json.load(f)
                for t_dict in threats_data.values():
                    threat = ThreatIndicator(**t_dict)
                    self.threat_indicators[threat.indicator_id] = threat

        # Load feedback history
        feedback_file = data_dir / "feedback.json"
        if feedback_file.exists():
            with open(feedback_file, 'r') as f:
                self.feedback_history = json.load(f)

        # Load scan history
        scans_file = data_dir / "scans.json"
        if scans_file.exists():
            with open(scans_file, 'r') as f:
                self.scan_history = json.load(f)

    def _save_learning_data(self) -> None:
        """Save learning data to disk."""
        data_dir = self.config.learning_data_dir

        # Save patterns
        patterns_file = data_dir / "patterns.json"
        with open(patterns_file, 'w') as f:
            json.dump(
                {p_id: {
                    "pattern_id": p.pattern_id,
                    "pattern_type": p.pattern_type,
                    "description": p.description,
                    "confidence": p.confidence,
                    "occurrences": p.occurrences,
                    "first_seen": p.first_seen,
                    "last_seen": p.last_seen,
                    "metadata": p.metadata
                } for p_id, p in self.patterns.items()},
                f, indent=2
            )

        # Save threat indicators
        threats_file = data_dir / "threats.json"
        with open(threats_file, 'w') as f:
            json.dump(
                {t_id: {
                    "indicator_id": t.indicator_id,
                    "indicator_type": t.indicator_type,
                    "value": t.value,
                    "confidence": t.confidence,
                    "risk_level": t.risk_level,
                    "first_seen": t.first_seen,
                    "last_seen": t.last_seen,
                    "occurrences": t.occurrences,
                    "context": t.context
                } for t_id, t in self.threat_indicators.items()},
                f, indent=2
            )

        # Save feedback history
        feedback_file = data_dir / "feedback.json"
        with open(feedback_file, 'w') as f:
            json.dump(self.feedback_history, f, indent=2)

        # Save scan history
        scans_file = data_dir / "scans.json"
        with open(scans_file, 'w') as f:
            json.dump(self.scan_history, f, indent=2)


# Plugin metadata for discovery
PLUGIN_METADATA = AdvancedIntelligencePlugin().metadata