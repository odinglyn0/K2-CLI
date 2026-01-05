"""Domain models for scan data."""
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class ScanMetadata:
    imageid: str
    userid: str
    filesize: int
    scantype: str
    useragent: str
    ipaddress: str
    submittedat: str


@dataclass
class FileHashes:
    ssdeep: str
    sha512: str
    sha256: str
    md5: str


@dataclass
class FileMeta:
    width: int
    height: int
    format: str
    mode: str


@dataclass
class Anomaly:
    id: str
    explanation: str
    confidence: int
    anomaly_value: float


@dataclass
class FxReason:
    """Reason for a potential false positive/negative."""
    reason: str
    likelyhood: int


@dataclass
class StaticAI:
    verdict: str
    possibility_of_steganography: int
    confidence: int
    most_possible_medium: str
    most_possible_vector: str
    most_possible_vector_cardinals: str
    anomalies: List[Anomaly]
    r_for_a_fx: List[FxReason]  # Renamed from legit_reasons_for_a_false_x
    r_next_steps: str  # Renamed from reccomended_next_steps


@dataclass
class QueueStatus:
    """Global queue status information."""
    queued: int
    processing: int

    @classmethod
    def from_api_response(cls, data: dict) -> 'QueueStatus':
        """Create QueueStatus from API response."""
        return cls(
            queued=data.get('queued', 0),
            processing=data.get('processing', 0)
        )


@dataclass
class ScanResult:
    status: str
    metadata: ScanMetadata
    completed_engines: int
    failed_engines: int
    total_engines: int
    elapsed_time: int
    used_flops: int
    file_hashes: Optional[FileHashes] = None
    file_meta: Optional[FileMeta] = None
    file_name: Optional[str] = None
    static_ai: Optional[StaticAI] = None
    firm_scan: Optional[Dict[str, Any]] = None
    found_strings: Optional[Dict[str, Any]] = None
    static_bounce: Optional[Dict[str, Any]] = None
    # Queue-related fields (when status is "queued")
    queue_depth: Optional[int] = None
    queued_at: Optional[str] = None
    queue_time: Optional[int] = None

    @classmethod
    def from_api_response(cls, data: dict) -> 'ScanResult':
        """Create ScanResult from API response."""
        metadata_dict = data.get('metadata', {})
        metadata = ScanMetadata(
            imageid=metadata_dict.get('imageid', 'N/A'),
            userid=metadata_dict.get('userid', 'N/A'),
            filesize=metadata_dict.get('filesize', 0),
            scantype=metadata_dict.get('scantype', 'N/A'),
            useragent=metadata_dict.get('useragent', 'N/A'),
            ipaddress=metadata_dict.get('ipaddress', 'N/A'),
            submittedat=metadata_dict.get('submittedat', 'N/A')
        )

        file_hashes = None
        if 'fileHashes' in data:
            hashes = data['fileHashes']
            file_hashes = FileHashes(
                ssdeep=hashes.get('ssdeep', 'N/A'),
                sha512=hashes.get('sha512', 'N/A'),
                sha256=hashes.get('sha256', 'N/A'),
                md5=hashes.get('md5', 'N/A')
            )

        file_meta = None
        if 'fileMeta' in data:
            meta = data['fileMeta']
            file_meta = FileMeta(
                width=meta.get('width', 0),
                height=meta.get('height', 0),
                format=meta.get('format', 'N/A'),
                mode=meta.get('mode', 'N/A')
            )

        static_ai = None
        if 'staticAi' in data:
            ai = data['staticAi']
            anomalies = [
                Anomaly(
                    id=a.get('id', 'N/A'),
                    explanation=a.get('explanation', 'N/A'),
                    confidence=a.get('confidence', 0),
                    anomaly_value=a.get('anomaly_value', 0)
                )
                for a in ai.get('anomalies', [])
            ]
            # Parse rForAFX (renamed from legit_reasons_for_a_false_x)
            fx_reasons = [
                FxReason(
                    reason=r.get('reason', ''),
                    likelyhood=r.get('likelyhood', 0)
                )
                for r in ai.get('rForAFX', [])
            ]
            static_ai = StaticAI(
                verdict=ai.get('verdict', 'UNKNOWN'),
                possibility_of_steganography=ai.get('possibility_of_steganography', 0),
                confidence=ai.get('confidence', 0),
                most_possible_medium=ai.get('most_possible_medium', 'N/A'),
                most_possible_vector=ai.get('most_possible_vector', 'N/A'),
                most_possible_vector_cardinals=ai.get('most_possible_vector_cardinals', 'N/A'),
                anomalies=anomalies,
                r_for_a_fx=fx_reasons,
                r_next_steps=ai.get('rNextSteps', '')
            )

        return cls(
            status=data.get('status', 'unknown'),
            metadata=metadata,
            completed_engines=data.get('completedEngines', 0),
            failed_engines=data.get('failedEngines', 0),
            total_engines=data.get('totalEngines', 339),
            elapsed_time=data.get('elapsedTime', 0),
            used_flops=data.get('usedFlops', 0),
            file_hashes=file_hashes,
            file_meta=file_meta,
            file_name=data.get('fileName'),
            static_ai=static_ai,
            firm_scan=data.get('firmScan'),
            found_strings=data.get('foundStrings'),
            static_bounce=data.get('staticBounce'),
            queue_depth=data.get('queueDepth'),
            queued_at=data.get('queuedAt'),
            queue_time=data.get('queueTime')
        )


@dataclass
class QuotaInfo:
    """User quota information."""
    monthly_limit: int
    used: int
    remaining: int
    period_end: str
    tier: str

    @classmethod
    def from_api_response(cls, data: dict) -> 'QuotaInfo':
        """Create QuotaInfo from API response."""
        return cls(
            monthly_limit=data.get('monthlyLimit', 0),
            used=data.get('used', 0),
            remaining=data.get('remaining', 0),
            period_end=data.get('periodEnd', ''),
            tier=data.get('tier', 'free')
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'monthlyLimit': self.monthly_limit,
            'used': self.used,
            'remaining': self.remaining,
            'periodEnd': self.period_end,
            'tier': self.tier
        }


@dataclass
class ScanListItem:
    """Individual scan item in scan list."""
    image_id: str
    file_size: int
    scan_type: str
    submitted_at: str

    @classmethod
    def from_api_response(cls, data: dict) -> 'ScanListItem':
        """Create ScanListItem from API response."""
        return cls(
            image_id=data.get('imageid', ''),
            file_size=data.get('filesize', 0),
            scan_type=data.get('scantype', 'standard'),
            submitted_at=data.get('submittedat', '')
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'imageid': self.image_id,
            'filesize': self.file_size,
            'scantype': self.scan_type,
            'submittedat': self.submitted_at
        }


@dataclass
class ScanList:
    """Paginated list of scans."""
    scans: List[ScanListItem]
    limit: int
    offset: int

    @classmethod
    def from_api_response(cls, data: dict) -> 'ScanList':
        """Create ScanList from API response."""
        scans = [ScanListItem.from_api_response(s) for s in data.get('scans', [])]
        return cls(
            scans=scans,
            limit=data.get('limit', 50),
            offset=data.get('offset', 0)
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'scans': [s.to_dict() for s in self.scans],
            'limit': self.limit,
            'offset': self.offset
        }


@dataclass
class UsagePeriod:
    """Usage data for a specific period."""
    period_start: str
    period_end: str
    total_scans: int
    total_bytes_processed: int

    @classmethod
    def from_api_response(cls, data: dict) -> 'UsagePeriod':
        """Create UsagePeriod from API response."""
        return cls(
            period_start=data.get('periodStart', ''),
            period_end=data.get('periodEnd', ''),
            total_scans=data.get('totalScans', 0),
            total_bytes_processed=data.get('totalBytesProcessed', 0)
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'periodStart': self.period_start,
            'periodEnd': self.period_end,
            'totalScans': self.total_scans,
            'totalBytesProcessed': self.total_bytes_processed
        }


@dataclass
class UsageData:
    """Collection of usage periods."""
    usage: List[UsagePeriod]

    @classmethod
    def from_api_response(cls, data: dict) -> 'UsageData':
        """Create UsageData from API response."""
        periods = [UsagePeriod.from_api_response(p) for p in data.get('usage', [])]
        return cls(usage=periods)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'usage': [p.to_dict() for p in self.usage]
        }


@dataclass
class AuditLogEntry:
    """Individual audit log entry."""
    action: str
    resource_type: str
    resource_id: str
    metadata: Dict[str, Any]
    ip_address: str
    created_at: str

    @classmethod
    def from_api_response(cls, data: dict) -> 'AuditLogEntry':
        """Create AuditLogEntry from API response."""
        return cls(
            action=data.get('action', ''),
            resource_type=data.get('resourcetype', ''),
            resource_id=data.get('resourceid', ''),
            metadata=data.get('metadata', {}),
            ip_address=data.get('ipaddress', ''),
            created_at=data.get('createdat', '')
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'action': self.action,
            'resourcetype': self.resource_type,
            'resourceid': self.resource_id,
            'metadata': self.metadata,
            'ipaddress': self.ip_address,
            'createdat': self.created_at
        }


@dataclass
class AuditLogs:
    """Paginated list of audit log entries."""
    logs: List[AuditLogEntry]
    limit: int
    offset: int

    @classmethod
    def from_api_response(cls, data: dict) -> 'AuditLogs':
        """Create AuditLogs from API response."""
        logs = [AuditLogEntry.from_api_response(e) for e in data.get('logs', [])]
        return cls(
            logs=logs,
            limit=data.get('limit', 50),
            offset=data.get('offset', 0)
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'logs': [e.to_dict() for e in self.logs],
            'limit': self.limit,
            'offset': self.offset
        }
