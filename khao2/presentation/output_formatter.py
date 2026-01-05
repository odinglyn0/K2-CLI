"""Output formatting for CLI commands with JSON and human-readable support."""
import json
from khao2.core.models import (
    QuotaInfo, ScanList, UsageData, AuditLogs, ScanResult, QueueStatus
)
from khao2.utils.formatters import format_number


class OutputFormatter:
    """Handles formatting of output in JSON or human-readable format."""

    def __init__(self, json_mode: bool = False):
        """
        Initialize the output formatter.
        
        Args:
            json_mode: If True, output JSON format. If False, human-readable format.
        """
        self.json_mode = json_mode

    def format_quota(self, quota: QuotaInfo) -> str:
        """
        Format quota information for display.
        
        Args:
            quota: QuotaInfo object containing quota data.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps(quota.to_dict(), indent=2)
        
        lines = [
            "QUOTA INFORMATION",
            "━" * 40,
            f"Tier: {quota.tier.upper()}",
            f"Monthly Limit: {quota.monthly_limit}",
            f"Used: {quota.used}",
            f"Remaining: {quota.remaining}",
            f"Period End: {quota.period_end}",
            "━" * 40,
        ]
        return "\n".join(lines)

    def format_queue_status(self, queue_status: QueueStatus) -> str:
        """
        Format queue status information for display.
        
        Args:
            queue_status: QueueStatus object containing queue data.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps({
                'queued': queue_status.queued,
                'processing': queue_status.processing
            }, indent=2)
        
        lines = [
            "QUEUE STATUS",
            "━" * 40,
            f"Queued: {queue_status.queued}",
            f"Processing: {queue_status.processing}",
            "━" * 40,
        ]
        return "\n".join(lines)

    def format_scan_list(self, scan_list: ScanList) -> str:
        """
        Format scan list for display.
        
        Args:
            scan_list: ScanList object containing paginated scans.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps(scan_list.to_dict(), indent=2)
        
        lines = [
            "SCAN HISTORY",
            "━" * 80,
            f"{'IMAGE ID':<40} {'SIZE':<12} {'TYPE':<12} {'SUBMITTED'}",
            "─" * 80,
        ]
        
        for scan in scan_list.scans:
            size_str = format_number(scan.file_size)
            lines.append(
                f"{scan.image_id:<40} {size_str:<12} {scan.scan_type:<12} {scan.submitted_at}"
            )
        
        lines.append("─" * 80)
        lines.append(f"Showing {len(scan_list.scans)} scans (offset: {scan_list.offset}, limit: {scan_list.limit})")
        
        return "\n".join(lines)


    def format_usage(self, usage: UsageData) -> str:
        """
        Format usage data for display.
        
        Args:
            usage: UsageData object containing usage periods.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps(usage.to_dict(), indent=2)
        
        lines = [
            "USAGE ANALYTICS",
            "━" * 70,
            f"{'PERIOD START':<20} {'PERIOD END':<20} {'SCANS':<10} {'BYTES PROCESSED'}",
            "─" * 70,
        ]
        
        for period in usage.usage:
            bytes_str = format_number(period.total_bytes_processed)
            lines.append(
                f"{period.period_start:<20} {period.period_end:<20} {period.total_scans:<10} {bytes_str}"
            )
        
        lines.append("─" * 70)
        
        # Summary
        total_scans = sum(p.total_scans for p in usage.usage)
        total_bytes = sum(p.total_bytes_processed for p in usage.usage)
        lines.append(f"Total: {total_scans} scans, {format_number(total_bytes)} bytes processed")
        
        return "\n".join(lines)

    def format_audit_logs(self, audit_logs: AuditLogs) -> str:
        """
        Format audit logs for display.
        
        Args:
            audit_logs: AuditLogs object containing paginated log entries.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps(audit_logs.to_dict(), indent=2)
        
        lines = [
            "AUDIT LOGS",
            "━" * 100,
            f"{'ACTION':<15} {'RESOURCE TYPE':<15} {'RESOURCE ID':<30} {'IP ADDRESS':<18} {'TIMESTAMP'}",
            "─" * 100,
        ]
        
        for entry in audit_logs.logs:
            # Truncate resource_id if too long
            resource_id = entry.resource_id[:28] + ".." if len(entry.resource_id) > 30 else entry.resource_id
            lines.append(
                f"{entry.action:<15} {entry.resource_type:<15} {resource_id:<30} {entry.ip_address:<18} {entry.created_at}"
            )
        
        lines.append("─" * 100)
        lines.append(f"Showing {len(audit_logs.logs)} entries (offset: {audit_logs.offset}, limit: {audit_logs.limit})")
        
        return "\n".join(lines)

    def format_scan_result(self, result: ScanResult) -> str:
        """
        Format scan result for display.
        
        Args:
            result: ScanResult object containing scan data.
            
        Returns:
            Formatted string (JSON or human-readable).
        """
        if self.json_mode:
            return json.dumps(self._scan_result_to_dict(result), indent=2)
        
        return self._format_scan_result_human(result)

    def _scan_result_to_dict(self, result: ScanResult) -> dict:
        """Convert ScanResult to dictionary for JSON serialization."""
        data = {
            'status': result.status,
            'metadata': {
                'imageid': result.metadata.imageid,
                'userid': result.metadata.userid,
                'filesize': result.metadata.filesize,
                'scantype': result.metadata.scantype,
                'useragent': result.metadata.useragent,
                'ipaddress': result.metadata.ipaddress,
                'submittedat': result.metadata.submittedat,
            },
            'completedEngines': result.completed_engines,
            'failedEngines': result.failed_engines,
            'totalEngines': result.total_engines,
            'elapsedTime': result.elapsed_time,
            'usedFlops': result.used_flops,
        }
        
        # Include queue fields when status is "queued"
        if result.status == 'queued':
            if result.queue_depth is not None:
                data['queueDepth'] = result.queue_depth
            if result.queued_at:
                data['queuedAt'] = result.queued_at
            if result.queue_time is not None:
                data['queueTime'] = result.queue_time
        
        if result.file_name:
            data['fileName'] = result.file_name
        
        if result.file_hashes:
            data['fileHashes'] = {
                'ssdeep': result.file_hashes.ssdeep,
                'sha512': result.file_hashes.sha512,
                'sha256': result.file_hashes.sha256,
                'md5': result.file_hashes.md5,
            }
        
        if result.file_meta:
            data['fileMeta'] = {
                'width': result.file_meta.width,
                'height': result.file_meta.height,
                'format': result.file_meta.format,
                'mode': result.file_meta.mode,
            }
        
        if result.static_ai:
            data['staticAi'] = {
                'verdict': result.static_ai.verdict,
                'possibility_of_steganography': result.static_ai.possibility_of_steganography,
                'confidence': result.static_ai.confidence,
                'most_possible_medium': result.static_ai.most_possible_medium,
                'most_possible_vector': result.static_ai.most_possible_vector,
                'most_possible_vector_cardinals': result.static_ai.most_possible_vector_cardinals,
                'anomalies': [
                    {
                        'id': a.id,
                        'explanation': a.explanation,
                        'confidence': a.confidence,
                        'anomaly_value': a.anomaly_value,
                    }
                    for a in result.static_ai.anomalies
                ],
            }
        
        if result.firm_scan:
            data['firmScan'] = result.firm_scan
        
        if result.found_strings:
            data['foundStrings'] = result.found_strings
        
        if result.static_bounce:
            data['staticBounce'] = result.static_bounce
        
        return data


    def _format_scan_result_human(self, result: ScanResult) -> str:
        """Format scan result in human-readable format."""
        lines = []
        
        if result.status == 'completed' and result.static_ai:
            lines.extend(self._format_completed_scan(result))
        else:
            lines.extend(self._format_pending_scan(result))
        
        return "\n".join(lines)

    def _format_pending_scan(self, result: ScanResult) -> list:
        """Format a pending/in-progress scan."""
        lines = [
            "SCAN STATUS",
            "━" * 62,
            f"Status: {result.status.upper()}",
            f"Image ID: {result.metadata.imageid}",
            f"User ID: {result.metadata.userid}",
            f"File Size: {result.metadata.filesize} bytes",
            f"Scan Type: {result.metadata.scantype}",
            f"Submitted: {result.metadata.submittedat}",
            "",
        ]
        
        # Show queue information when status is "queued"
        if result.status == 'queued':
            lines.append("QUEUE STATUS")
            if result.queue_depth is not None:
                lines.append(f"├─ Position in Queue: {result.queue_depth}")
            if result.queued_at:
                lines.append(f"├─ Queued At: {result.queued_at}")
            if result.queue_time is not None:
                queue_time_sec = result.queue_time / 1000
                lines.append(f"└─ Estimated Wait: {queue_time_sec:.1f}s")
        else:
            lines.append("PROGRESS")
            lines.append(f"├─ Engines Completed: {result.completed_engines}/{result.total_engines}")
            lines.append(f"├─ Engines Failed: {result.failed_engines}")
            lines.append(f"└─ Elapsed Time: {result.elapsed_time}ms")
        
        lines.append("━" * 62)
        return lines

    def _format_completed_scan(self, result: ScanResult) -> list:
        """Format a completed scan with full details."""
        lines = [
            "SCAN RESULT",
            "━" * 62,
            f"Status: {result.status.upper()}",
            f"Verdict: {result.static_ai.verdict}",
            f"Possibility of Steganography: {result.static_ai.possibility_of_steganography}%",
            f"Confidence: {result.static_ai.confidence}%",
            "",
            "METADATA",
            f"├─ Image ID: {result.metadata.imageid}",
            f"├─ User ID: {result.metadata.userid}",
            f"├─ File Size: {result.metadata.filesize} bytes",
            f"├─ Scan Type: {result.metadata.scantype}",
            f"└─ Submitted: {result.metadata.submittedat}",
        ]
        
        if result.file_name:
            lines.append(f"File Name: {result.file_name}")
        
        if result.file_meta:
            lines.extend([
                "",
                "FILE INFO",
                f"├─ Dimensions: {result.file_meta.width}x{result.file_meta.height}",
                f"├─ Format: {result.file_meta.format}",
                f"└─ Mode: {result.file_meta.mode}",
            ])
        
        if result.file_hashes:
            lines.extend([
                "",
                "FILE HASHES",
                f"├─ SSDEEP: {result.file_hashes.ssdeep}",
                f"├─ SHA512: {result.file_hashes.sha512}",
                f"├─ SHA256: {result.file_hashes.sha256}",
                f"└─ MD5: {result.file_hashes.md5}",
            ])
        
        lines.extend([
            "",
            "ENGINE STATS",
            f"├─ Completed: {result.completed_engines}/{result.total_engines}",
            f"├─ Failed: {result.failed_engines}",
            f"├─ Elapsed Time: {result.elapsed_time}ms",
            f"└─ Used FLOPs: {format_number(result.used_flops)}",
        ])
        
        if result.static_ai.anomalies:
            lines.extend([
                "",
                f"ANOMALIES DETECTED: {len(result.static_ai.anomalies)}",
            ])
            for anomaly in result.static_ai.anomalies:
                lines.append(f"├─ #{anomaly.id}: {anomaly.explanation}")
                lines.append(f"│  Confidence: {anomaly.confidence}% | Value: {anomaly.anomaly_value}")
        
        lines.extend([
            "",
            "ANALYSIS",
            f"├─ Medium: {result.static_ai.most_possible_medium}",
            f"├─ Vector: {result.static_ai.most_possible_vector}",
            f"└─ Technique: {result.static_ai.most_possible_vector_cardinals}",
            "━" * 62,
        ])
        
        return lines
