"""Compliance checker plugin for validating files against regulatory standards."""
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from khao2.plugins import (
    ProcessorPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    standard: str
    version: str
    passed: bool
    violations: List[str]
    recommendations: List[str]
    score: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    file_path: Path
    file_hash: str
    checks_performed: List[ComplianceResult]
    overall_score: float
    critical_violations: int
    generated_at: float


class ComplianceCheckerPlugin(ProcessorPlugin):
    """Plugin for checking files against various compliance standards."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.standards: Dict[str, Dict[str, Any]] = {}

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="compliance_checker",
            version="1.0.0",
            description="Validate files against regulatory compliance standards",
            author="Khao2 Community",
            plugin_type="processor",
            entry_point="khao2.plugins.builtins.compliance_checker.ComplianceCheckerPlugin",
            config_schema={
                "enabled_standards": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["gdpr", "hipaa", "pci_dss", "sox"],
                    "description": "List of compliance standards to check"
                },
                "strict_mode": {
                    "type": "boolean",
                    "default": False,
                    "description": "Fail on any violation in strict mode"
                },
                "custom_rules": {
                    "type": "object",
                    "default": {},
                    "description": "Custom compliance rules"
                },
                "report_format": {
                    "type": "string",
                    "enum": ["json", "xml", "html"],
                    "default": "json",
                    "description": "Format for compliance reports"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the compliance checker."""
        # Load configuration
        plugin_config = context.config.get('compliance_checker', {})
        self.config = {
            'enabled_standards': plugin_config.get('enabled_standards', ['gdpr', 'hipaa', 'pci_dss', 'sox']),
            'strict_mode': plugin_config.get('strict_mode', False),
            'custom_rules': plugin_config.get('custom_rules', {}),
            'report_format': plugin_config.get('report_format', 'json')
        }

        # Load compliance standards
        self._load_standards()

    def cleanup(self) -> None:
        """Clean up resources."""
        pass

    def process(self, items: List[Any], **kwargs) -> List[Any]:
        """Process files through compliance checks."""
        results = []
        
        for data in items:
            if isinstance(data, dict) and 'file_path' in data:
                file_path = Path(data['file_path'])
            elif isinstance(data, str):
                file_path = Path(data)
            else:
                raise PluginError("Invalid input: expected file path")

            if not file_path.exists():
                raise PluginError(f"File not found: {file_path}")

            # Perform compliance checks
            check_results = self._check_compliance(file_path)

            # Generate report
            report = self._generate_report(file_path, check_results)

            results.append({
                'compliance_report': report,
                'results': check_results,
                'passed': all(r.passed for r in check_results) if not self.config['strict_mode'] else report.critical_violations == 0
            })
        
        return results

    def _load_standards(self) -> None:
        """Load compliance standards definitions."""
        self.standards = {
            'gdpr': {
                'name': 'General Data Protection Regulation',
                'version': '2018',
                'rules': {
                    'personal_data_detection': self._check_gdpr_personal_data,
                    'data_minimization': self._check_gdpr_data_minimization,
                    'consent_mechanism': self._check_gdpr_consent,
                    'data_portability': self._check_gdpr_portability
                }
            },
            'hipaa': {
                'name': 'Health Insurance Portability and Accountability Act',
                'version': '1996',
                'rules': {
                    'phi_detection': self._check_hipaa_phi,
                    'encryption': self._check_hipaa_encryption,
                    'access_controls': self._check_hipaa_access,
                    'audit_trail': self._check_hipaa_audit
                }
            },
            'pci_dss': {
                'name': 'Payment Card Industry Data Security Standard',
                'version': '4.0',
                'rules': {
                    'card_data_detection': self._check_pci_card_data,
                    'encryption': self._check_pci_encryption,
                    'access_control': self._check_pci_access,
                    'vulnerability_scanning': self._check_pci_scanning
                }
            },
            'sox': {
                'name': 'Sarbanes-Oxley Act',
                'version': '2002',
                'rules': {
                    'financial_data_integrity': self._check_sox_financial_data,
                    'internal_controls': self._check_sox_controls,
                    'audit_trail': self._check_sox_audit,
                    'documentation': self._check_sox_documentation
                }
            }
        }

    def _check_compliance(self, file_path: Path) -> List[ComplianceResult]:
        """Run all enabled compliance checks."""
        results = []

        # Calculate file hash for integrity
        file_hash = self._calculate_file_hash(file_path)

        # Read file content (safely)
        content = self._read_file_content(file_path)

        for standard_name in self.config['enabled_standards']:
            if standard_name in self.standards:
                standard = self.standards[standard_name]
                result = self._check_standard(standard, content, file_path, file_hash)
                results.append(result)

        return results

    def _check_standard(self, standard: Dict[str, Any], content: str,
                       file_path: Path, file_hash: str) -> ComplianceResult:
        """Check a specific compliance standard."""
        violations = []
        recommendations = []
        score = 1.0

        for rule_name, rule_func in standard['rules'].items():
            try:
                rule_result = rule_func(content, file_path, file_hash)
                if not rule_result['passed']:
                    violations.extend(rule_result['violations'])
                    recommendations.extend(rule_result['recommendations'])
                    score -= rule_result.get('penalty', 0.1)
            except Exception as e:
                import logging
                logging.warning(f"Error checking {rule_name}: {e}")
                violations.append(f"Error checking {rule_name}: {str(e)}")
                score -= 0.05

        score = max(0.0, min(1.0, score))

        return ComplianceResult(
            standard=standard['name'],
            version=standard['version'],
            passed=len(violations) == 0,
            violations=violations,
            recommendations=recommendations,
            score=score,
            metadata={
                'rules_checked': len(standard['rules']),
                'file_hash': file_hash
            }
        )

    def _read_file_content(self, file_path: Path) -> str:
        """Safely read file content for analysis."""
        try:
            # Only read text files, limit size
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                return "[FILE_TOO_LARGE_FOR_CONTENT_ANALYSIS]"

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return "[BINARY_OR_UNREADABLE_FILE]"

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # GDPR Compliance Checks
    def _check_gdpr_personal_data(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check for personal data under GDPR."""
        violations = []
        recommendations = []

        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        if emails:
            violations.append(f"Found {len(emails)} email addresses")
            recommendations.append("Consider pseudonymizing or encrypting email addresses")

        # Phone number pattern (basic)
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        phones = re.findall(phone_pattern, content)
        if phones:
            violations.append(f"Found {len(phones)} phone numbers")
            recommendations.append("Phone numbers should be encrypted or masked")

        # IP address pattern
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        if ips:
            violations.append(f"Found {len(ips)} IP addresses")
            recommendations.append("IP addresses may constitute personal data")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': len(violations) * 0.1
        }

    def _check_gdpr_data_minimization(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check data minimization principle."""
        violations = []
        recommendations = []

        # Check file size (rough heuristic)
        file_size = file_path.stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB
            violations.append("File size suggests potential data over-collection")
            recommendations.append("Consider data minimization and purpose limitation")

        # Check for excessive data fields (heuristic based on content patterns)
        data_indicators = ['name', 'address', 'ssn', 'dob', 'salary']
        found_indicators = [ind for ind in data_indicators if ind.lower() in content.lower()]
        if len(found_indicators) > 3:
            violations.append("Multiple personal data types detected")
            recommendations.append("Ensure data collection is limited to what's necessary")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': len(violations) * 0.05
        }

    def _check_gdpr_consent(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check for consent mechanisms."""
        violations = []
        recommendations = []

        # Look for consent-related keywords
        consent_keywords = ['consent', 'agreement', 'permission', 'opt-in', 'opt-out']
        found_keywords = [kw for kw in consent_keywords if kw in content.lower()]

        if not found_keywords:
            violations.append("No consent mechanism documentation found")
            recommendations.append("Document consent mechanisms and legal basis")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.2 if violations else 0
        }

    def _check_gdpr_portability(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check data portability requirements."""
        violations = []
        recommendations = []

        # Check file format for portability
        extension = file_path.suffix.lower()
        portable_formats = ['.json', '.xml', '.csv', '.txt']

        if extension not in portable_formats:
            violations.append(f"File format ({extension}) may not be easily portable")
            recommendations.append("Consider using structured, machine-readable formats")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.1 if violations else 0
        }

    # HIPAA Compliance Checks
    def _check_hipaa_phi(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check for Protected Health Information (PHI)."""
        violations = []
        recommendations = []

        # PHI indicators
        phi_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            (r'\b\d{10}\b', 'Medical Record Number'),
            (r'\b[A-Z]{2}\d{6}\b', 'Health Plan ID'),
        ]

        for pattern, phi_type in phi_patterns:
            matches = re.findall(pattern, content)
            if matches:
                violations.append(f"Found {len(matches)} instances of {phi_type}")
                recommendations.append(f"PHI ({phi_type}) must be encrypted or de-identified")

        # Health-related keywords
        health_keywords = ['diagnosis', 'treatment', 'medication', 'medical', 'health']
        found_health = [kw for kw in health_keywords if kw in content.lower()]
        if found_health:
            violations.append("Health-related content detected")
            recommendations.append("Ensure PHI is properly protected")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': len(violations) * 0.15
        }

    def _check_hipaa_encryption(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check encryption requirements."""
        violations = []
        recommendations = []

        # This is a basic check - in reality, you'd need to analyze the file itself
        # For now, we'll check for encryption indicators in metadata/filename
        filename = file_path.name.lower()
        if not any(enc in filename for enc in ['encrypted', 'enc', 'aes', 'pgp']):
            violations.append("No encryption indicators found")
            recommendations.append("PHI must be encrypted at rest and in transit")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.2 if violations else 0
        }

    def _check_hipaa_access(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check access control requirements."""
        violations = []
        recommendations = []

        # Look for access control documentation
        access_keywords = ['access control', 'authorization', 'authentication', 'role-based']
        found_access = [kw for kw in access_keywords if kw in content.lower()]

        if not found_access:
            violations.append("No access control documentation found")
            recommendations.append("Implement role-based access controls for PHI")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.15 if violations else 0
        }

    def _check_hipaa_audit(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check audit trail requirements."""
        violations = []
        recommendations = []

        # Look for audit-related content
        audit_keywords = ['audit', 'log', 'trail', 'tracking', 'monitoring']
        found_audit = [kw for kw in audit_keywords if kw in content.lower()]

        if not found_audit:
            violations.append("No audit trail documentation found")
            recommendations.append("Maintain audit logs for all PHI access")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.1 if violations else 0
        }

    # PCI DSS Compliance Checks
    def _check_pci_card_data(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check for payment card data."""
        violations = []
        recommendations = []

        # Credit card number patterns (basic validation)
        cc_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 16 digits
            r'\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b',  # 15 digits (Amex)
        ]

        total_cards = 0
        for pattern in cc_patterns:
            matches = re.findall(pattern, content)
            total_cards += len(matches)

        if total_cards > 0:
            violations.append(f"Found {total_cards} potential card numbers")
            recommendations.append("Card data must never be stored unencrypted")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': total_cards * 0.2
        }

    def _check_pci_encryption(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check PCI encryption requirements."""
        violations = []
        recommendations = []

        # Check for encryption indicators
        filename = file_path.name.lower()
        if not any(enc in filename for enc in ['encrypted', 'enc', 'tokenized']):
            violations.append("No encryption indicators found for card data")
            recommendations.append("Card data must be encrypted using strong cryptography")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.25 if violations else 0
        }

    def _check_pci_access(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check PCI access control requirements."""
        violations = []
        recommendations = []

        # Look for access control documentation
        access_keywords = ['access control', 'least privilege', 'need to know']
        found_access = [kw for kw in access_keywords if kw in content.lower()]

        if not found_access:
            violations.append("No access control documentation found")
            recommendations.append("Implement principle of least privilege for card data")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.15 if violations else 0
        }

    def _check_pci_scanning(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check vulnerability scanning requirements."""
        violations = []
        recommendations = []

        # Look for scanning documentation
        scan_keywords = ['vulnerability scan', 'penetration test', 'security assessment']
        found_scan = [kw for kw in scan_keywords if kw in content.lower()]

        if not found_scan:
            violations.append("No vulnerability scanning documentation found")
            recommendations.append("Perform regular vulnerability scans and penetration testing")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.1 if violations else 0
        }

    # SOX Compliance Checks
    def _check_sox_financial_data(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check financial data integrity."""
        violations = []
        recommendations = []

        # Financial keywords
        financial_keywords = ['revenue', 'profit', 'loss', 'assets', 'liabilities', 'equity']
        found_financial = [kw for kw in financial_keywords if kw in content.lower()]

        if found_financial:
            violations.append("Financial data detected")
            recommendations.append("Ensure financial data accuracy and prevent unauthorized changes")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': len(found_financial) * 0.1
        }

    def _check_sox_controls(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check internal controls."""
        violations = []
        recommendations = []

        # Look for control documentation
        control_keywords = ['internal control', 'segregation of duties', 'approval process']
        found_controls = [kw for kw in control_keywords if kw in content.lower()]

        if not found_controls:
            violations.append("No internal controls documentation found")
            recommendations.append("Document and test internal controls over financial reporting")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.15 if violations else 0
        }

    def _check_sox_audit(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check SOX audit requirements."""
        violations = []
        recommendations = []

        # Look for audit documentation
        audit_keywords = ['audit committee', 'external audit', 'internal audit']
        found_audit = [kw for kw in audit_keywords if kw in content.lower()]

        if not found_audit:
            violations.append("No audit documentation found")
            recommendations.append("Maintain proper audit trails for financial transactions")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.1 if violations else 0
        }

    def _check_sox_documentation(self, content: str, file_path: Path, file_hash: str) -> Dict[str, Any]:
        """Check documentation requirements."""
        violations = []
        recommendations = []

        # Check file metadata for documentation
        if not content.strip():
            violations.append("Empty or undocumented file")
            recommendations.append("Maintain proper documentation for all financial processes")

        return {
            'passed': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'penalty': 0.05 if violations else 0
        }

    def _generate_report(self, file_path: Path, results: List[ComplianceResult]) -> ComplianceReport:
        """Generate comprehensive compliance report."""
        import time

        file_hash = self._calculate_file_hash(file_path)

        # Calculate overall score
        if results:
            overall_score = sum(r.score for r in results) / len(results)
        else:
            overall_score = 1.0

        # Count critical violations
        critical_violations = sum(1 for r in results if not r.passed)

        return ComplianceReport(
            file_path=file_path,
            file_hash=file_hash,
            checks_performed=results,
            overall_score=overall_score,
            critical_violations=critical_violations,
            generated_at=time.time()
        )


# Plugin metadata for discovery
PLUGIN_METADATA = ComplianceCheckerPlugin().metadata