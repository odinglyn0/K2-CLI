"""Custom LSB detector plugin demonstrating detector plugin extensibility."""
import os
from pathlib import Path
from typing import Any, Dict, List
from khao2.plugins import (
    DetectorPlugin, PluginMetadata, PluginContext,
    PluginError
)


class LSBDetectorPlugin(DetectorPlugin):
    """Custom detector for Least Significant Bit steganography."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.api_client = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="lsb_detector",
            version="1.0.0",
            description="Advanced LSB steganography detection with statistical analysis",
            author="Khao2 Community",
            plugin_type="detector",
            entry_point="khao2.plugins.builtins.lsb_detector.LSBDetectorPlugin",
            config_schema={
                "sensitivity": {
                    "type": "number",
                    "default": 0.7,
                    "description": "Detection sensitivity threshold (0.0-1.0)"
                },
                "analyze_planes": {
                    "type": "boolean",
                    "default": True,
                    "description": "Analyze individual color planes"
                },
                "check_metadata": {
                    "type": "boolean",
                    "default": True,
                    "description": "Check for steganography in metadata"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the LSB detector."""
        self.api_client = context.services.get('api_client')

        # Load configuration
        plugin_config = context.config.get('lsb_detector', {})
        self.config = {
            'sensitivity': plugin_config.get('sensitivity', 0.7),
            'analyze_planes': plugin_config.get('analyze_planes', True),
            'check_metadata': plugin_config.get('check_metadata', True)
        }

    def cleanup(self) -> None:
        """Clean up resources."""
        pass

    def detect(self, image_path: Path, **kwargs) -> Dict[str, Any]:
        """Perform LSB steganography detection."""
        if not image_path.exists():
            raise PluginError(f"Image file does not exist: {image_path}")

        # Basic file validation
        if not self._is_supported_format(image_path):
            return {
                "detected": False,
                "confidence": 0.0,
                "method": "lsb",
                "reason": "Unsupported file format for LSB analysis"
            }

        try:
            # Perform LSB analysis
            analysis_result = self._analyze_lsb(image_path)

            # Calculate overall confidence
            confidence = self._calculate_confidence(analysis_result)

            # Determine if steganography is detected
            detected = confidence >= self.config['sensitivity']

            result = {
                "detected": detected,
                "confidence": confidence,
                "method": "lsb",
                "analysis": analysis_result,
                "recommendations": self._generate_recommendations(analysis_result, detected)
            }

            return result

        except Exception as e:
            return {
                "detected": False,
                "confidence": 0.0,
                "method": "lsb",
                "error": f"LSB analysis failed: {str(e)}"
            }

    def _is_supported_format(self, image_path: Path) -> bool:
        """Check if the image format is supported for LSB analysis."""
        supported_extensions = {'.png', '.bmp', '.tiff', '.tif'}
        return image_path.suffix.lower() in supported_extensions

    def _analyze_lsb(self, image_path: Path) -> Dict[str, Any]:
        """Perform detailed LSB analysis."""
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            raise PluginError("PIL and numpy required for LSB analysis")

        image = Image.open(image_path)
        img_array = np.array(image)

        analysis = {
            "file_info": {
                "size": image.size,
                "mode": image.mode,
                "format": image.format
            },
            "lsb_analysis": {},
            "statistical_tests": {},
            "anomalies": []
        }

        # Analyze LSB patterns
        if len(img_array.shape) == 3:  # RGB/RGBA image
            for channel in range(min(3, img_array.shape[2])):  # RGB channels
                channel_name = ['R', 'G', 'B'][channel]
                channel_data = img_array[:, :, channel]

                lsb_analysis = self._analyze_channel_lsb(channel_data)
                analysis["lsb_analysis"][channel_name] = lsb_analysis

                # Check for anomalies
                anomalies = self._detect_lsb_anomalies(channel_data, lsb_analysis)
                analysis["anomalies"].extend(anomalies)

        # Statistical tests
        analysis["statistical_tests"] = self._run_statistical_tests(img_array)

        return analysis

    def _analyze_channel_lsb(self, channel_data: np.ndarray) -> Dict[str, Any]:
        """Analyze LSB patterns in a single channel."""
        # Extract LSB plane
        lsb_plane = channel_data & 1

        # Calculate statistics
        lsb_ratio = np.mean(lsb_plane)
        lsb_variance = np.var(lsb_plane)

        # Check for patterns that might indicate steganography
        # Look for unusual LSB distributions
        hist, _ = np.histogram(lsb_plane.flatten(), bins=2, range=(0, 1))
        hist_ratio = hist[1] / hist[0] if hist[0] > 0 else float('inf')

        # Calculate entropy of LSB plane
        from scipy.stats import entropy
        lsb_entropy = entropy(hist / np.sum(hist)) if np.sum(hist) > 0 else 0

        return {
            "lsb_ratio": float(lsb_ratio),
            "lsb_variance": float(lsb_variance),
            "histogram_ratio": float(hist_ratio),
            "lsb_entropy": float(lsb_entropy),
            "total_pixels": int(channel_data.size)
        }

    def _detect_lsb_anomalies(self, channel_data: np.ndarray, lsb_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in LSB patterns."""
        anomalies = []

        lsb_ratio = lsb_analysis["lsb_ratio"]
        lsb_entropy = lsb_analysis["lsb_entropy"]

        # Check for suspicious LSB ratios (should be ~0.5 for natural images)
        if abs(lsb_ratio - 0.5) > 0.1:
            anomalies.append({
                "type": "lsb_ratio_anomaly",
                "severity": "medium",
                "description": f"Unusual LSB ratio: {lsb_ratio:.3f} (expected ~0.5)",
                "confidence": min(abs(lsb_ratio - 0.5) * 2, 1.0)
            })

        # Check for low entropy (might indicate embedded data)
        if lsb_entropy < 0.9:
            anomalies.append({
                "type": "low_lsb_entropy",
                "severity": "high",
                "description": f"Low LSB entropy: {lsb_entropy:.3f} (possible embedded data)",
                "confidence": 1.0 - lsb_entropy
            })

        return anomalies

    def _run_statistical_tests(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Run statistical tests for steganography detection."""
        tests = {}

        # Chi-square test for LSB uniformity
        if len(img_array.shape) >= 3:
            lsb_plane = img_array[:, :, 0] & 1  # Red channel LSB
            observed = np.bincount(lsb_plane.flatten(), minlength=2)
            expected = np.full(2, lsb_plane.size / 2)

            # Simple chi-square calculation
            chi_square = np.sum((observed - expected) ** 2 / expected) if np.all(expected > 0) else 0
            tests["lsb_chi_square"] = float(chi_square)

        return tests

    def _calculate_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall confidence score."""
        confidence = 0.0
        weights = []

        # Weight anomalies by severity
        anomalies = analysis_result.get("anomalies", [])
        for anomaly in anomalies:
            severity_weight = {"low": 0.3, "medium": 0.6, "high": 1.0}.get(
                anomaly.get("severity", "medium"), 0.5
            )
            confidence += anomaly.get("confidence", 0.0) * severity_weight
            weights.append(severity_weight)

        # Factor in statistical tests
        stat_tests = analysis_result.get("statistical_tests", {})
        chi_square = stat_tests.get("lsb_chi_square", 0)
        if chi_square > 10:  # Significant deviation
            confidence += 0.3
            weights.append(0.3)

        # Normalize confidence
        if weights:
            confidence = confidence / len(weights)

        return min(confidence, 1.0)

    def _generate_recommendations(self, analysis_result: Dict[str, Any], detected: bool) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if detected:
            recommendations.append("LSB steganography detected - recommend further analysis with specialized tools")
            recommendations.append("Consider extracting and analyzing the LSB plane manually")

        anomalies = analysis_result.get("anomalies", [])
        if any(a.get("type") == "low_lsb_entropy" for a in anomalies):
            recommendations.append("Low LSB entropy suggests possible data embedding")
            recommendations.append("Try frequency domain analysis (DCT) for additional confirmation")

        if not detected and len(anomalies) > 0:
            recommendations.append("Some LSB anomalies detected but below confidence threshold")
            recommendations.append("Consider re-analysis with adjusted sensitivity settings")

        return recommendations


# Plugin metadata for discovery
PLUGIN_METADATA = LSBDetectorPlugin().metadata