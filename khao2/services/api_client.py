"""API client for communicating with the Khao2 backend."""
import locale
import platform
import requests
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from khao2.core.exceptions import (
    APIError, ConfigurationError, ValidationError,
    InsufficientCreditsError, UploadExpiredError
)
from khao2.core.models import QuotaInfo, ScanList, UsageData, AuditLogs, QueueStatus


def get_cli_version() -> str:
    """Get CLI version from package metadata."""
    try:
        from importlib.metadata import version
        return version('khao2')
    except Exception:
        return '1.0.0'


def get_user_agent() -> str:
    """Build User-Agent string with OS and language info."""
    os_name = platform.system()
    try:
        lang, _ = locale.getdefaultlocale()
        lang = lang.lower().replace('_', '-') if lang else 'en-us'
    except Exception:
        lang = 'en-us'
    return f"Khao2-CLI ({os_name}; {lang})"


class APIClient:
    """Handles all HTTP communication with the Khao2 API."""

    CONTENT_TYPE_MAP = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.webp': 'image/webp'
    }

    def __init__(self, endpoint: str, token: str, debug: bool = False):
        self.endpoint = endpoint
        self.token = token
        self.debug = debug
        self._validate_config()

    def _validate_config(self):
        """Validate API configuration."""
        if not self.endpoint:
            raise ConfigurationError(
                "API endpoint not configured. Use 'k2 endpoint set <url>' first."
            )
        if not self.token:
            raise ConfigurationError(
                "API token not configured. Use 'k2 token set <token>' first."
            )
        if not (self.endpoint.startswith('http://') or self.endpoint.startswith('https://')):
            raise ValidationError(
                f"Invalid endpoint URL: {self.endpoint}. Must start with http:// or https://"
            )

    def _get_base_url(self) -> str:
        """Extract base URL from endpoint."""
        if self.endpoint.endswith('/upload') or self.endpoint.endswith('/images'):
            return self.endpoint.rsplit('/', 1)[0]
        return self.endpoint

    def _get_content_type(self, image_path: Path) -> str:
        """Determine content type from file extension."""
        ext = image_path.suffix.lower()
        return self.CONTENT_TYPE_MAP.get(ext, 'application/octet-stream')

    def _request_upload_url(self, filename: str, content_type: str) -> Dict[str, Any]:
        """Step 1: Request a presigned upload URL from the API."""
        url = f"{self.endpoint.rstrip('/')}/createscan"

        if self.debug:
            print(f"[DEBUG] Step 1 - Requesting upload URL: {url}")

        headers = {
            'Content-Type': 'application/json',
            'apiKey': self.token,
            'User-Agent': get_user_agent()
        }
        payload = {
            'filename': filename,
            'contentType': content_type
        }

        try:
            response = requests.post(url, json=payload, headers=headers)

            if response.status_code == 403:
                raise InsufficientCreditsError("No credits remaining. Please add credits to continue.")

            if response.status_code not in (200, 201):
                raise APIError(f"Failed to get upload URL: {response.status_code} - {response.text}")

            data = response.json()
            if data.get('m') != 'Ack':
                raise APIError(f"Unexpected response from createscan: {data}")

            if self.debug:
                print(f"[DEBUG] Got upload URL for scan ID: {data.get('id')}")

            return data
        except requests.RequestException as e:
            raise APIError(f"Network error requesting upload URL: {str(e)}")

    def _upload_to_s3(
        self,
        upload_url: str,
        file_data: bytes,
        content_type: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> None:
        """Step 2: Upload file directly to S3 using presigned URL."""
        if self.debug:
            print(f"[DEBUG] Step 2 - Uploading to S3: {upload_url[:80]}...")

        headers = {'Content-Type': content_type}

        try:
            response = requests.put(upload_url, data=file_data, headers=headers)

            if response.status_code == 403:
                raise UploadExpiredError(
                    "Upload URL expired. Please retry the upload to get a new URL."
                )

            if response.status_code not in (200, 201):
                raise APIError(f"S3 upload failed: {response.status_code} - {response.text}")

            if self.debug:
                print(f"[DEBUG] S3 upload complete")

        except requests.RequestException as e:
            raise APIError(f"Network error during S3 upload: {str(e)}")

    def _initiate_scan(self, image_id: str, s3_key: str, scan_type: str = "standard") -> Dict[str, Any]:
        """Step 3: Initiate the scan after file is uploaded to S3."""
        url = f"{self.endpoint.rstrip('/')}/initiatescan"

        if self.debug:
            print(f"[DEBUG] Step 3 - Initiating scan: {url}")

        headers = {
            'Content-Type': 'application/json',
            'apiKey': self.token,
            'X-Scan-Type': scan_type,
            'X-CLI-Version': get_cli_version(),
            'User-Agent': get_user_agent()
        }
        payload = {
            'imageId': image_id,
            's3Key': s3_key
        }

        try:
            response = requests.post(url, json=payload, headers=headers)

            if response.status_code == 404:
                raise APIError("File not found in S3. The upload may have failed.")

            # Accept both 201 (legacy) and 202 (queued) responses
            if response.status_code not in (200, 201, 202):
                raise APIError(f"Failed to initiate scan: {response.status_code} - {response.text}")

            data = response.json()
            # Accept both "Ack" (legacy) and "Queued" (new) messages
            if data.get('m') not in ('Ack', 'Queued'):
                raise APIError(f"Unexpected response from initiatescan: {data}")

            if self.debug:
                if data.get('m') == 'Queued':
                    print(f"[DEBUG] Scan queued at position: {data.get('position', 'unknown')}")
                else:
                    print(f"[DEBUG] Scan initiated successfully")

            return data
        except requests.RequestException as e:
            raise APIError(f"Network error initiating scan: {str(e)}")

    def upload_image(
        self,
        image_path: str,
        scan_type: str = "standard",
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Upload an image for scanning using the 3-step flow.
        
        Steps:
        1. Request presigned upload URL from API
        2. Upload file directly to S3
        3. Initiate the scan
        
        Args:
            image_path: Path to the image file
            scan_type: Type of scan to perform (default: "standard")
            progress_callback: Optional callback for upload progress (bytes_sent, total_bytes)
            
        Returns:
            Dict with scan 'id' and acknowledgment
        """
        image_file = Path(image_path)
        if not image_file.exists():
            raise ValidationError(f"Image file not found: {image_path}")

        content_type = self._get_content_type(image_file)

        if self.debug:
            print(f"[DEBUG] Starting 3-step upload for: {image_file.name}")
            print(f"[DEBUG] Content-Type: {content_type}")

        # Read file data once
        with open(image_file, 'rb') as f:
            file_data = f.read()

        # Step 1: Get presigned upload URL
        upload_info = self._request_upload_url(image_file.name, content_type)
        image_id = upload_info['id']
        upload_url = upload_info['uploadUrl']
        s3_key = upload_info['s3Key']

        # Step 2: Upload to S3
        self._upload_to_s3(upload_url, file_data, content_type, progress_callback)

        # Step 3: Initiate scan
        result = self._initiate_scan(image_id, s3_key, scan_type)

        return result

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status of a scan."""
        base_url = self._get_base_url()
        status_url = f"{base_url}/scans/{scan_id}"

        if self.debug:
            print(f"[DEBUG] Status endpoint: {status_url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            response = requests.get(status_url, headers=headers)

            # Handle errored status (HTTP 503)
            if response.status_code == 503:
                data = response.json()
                if data.get('status') == 'errored':
                    return data
                raise APIError(
                    f"Service unavailable: {response.status_code} - {response.text}"
                )

            if response.status_code != 200:
                raise APIError(
                    f"Failed to get scan status: {response.status_code} - {response.text}"
                )

            return response.json()
        except requests.RequestException as e:
            raise APIError(f"Network error while fetching status: {str(e)}")

    def get_quota(self) -> QuotaInfo:
        """
        GET /quota - Retrieve user quota information.
        
        Returns:
            QuotaInfo with monthly_limit, used, remaining, period_end, tier
        """
        base_url = self._get_base_url()
        url = f"{base_url}/quota"

        if self.debug:
            print(f"[DEBUG] Quota endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            response = requests.get(url, headers=headers)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to get quota: {response.status_code} - {response.text}"
                )

            return QuotaInfo.from_api_response(response.json())
        except requests.RequestException as e:
            raise APIError(f"Network error while fetching quota: {str(e)}")

    def list_scans(self, limit: int = 50, offset: int = 0) -> ScanList:
        """
        GET /scans - List user's scans with pagination.
        
        Args:
            limit: Maximum number of results (max 100)
            offset: Number of results to skip
            
        Returns:
            ScanList with scans, limit, offset
        """
        base_url = self._get_base_url()
        url = f"{base_url}/scans"

        if self.debug:
            print(f"[DEBUG] List scans endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            params = {'limit': min(limit, 100), 'offset': offset}
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to list scans: {response.status_code} - {response.text}"
                )

            return ScanList.from_api_response(response.json())
        except requests.RequestException as e:
            raise APIError(f"Network error while listing scans: {str(e)}")

    def abort_scan(self, scan_id: str) -> bool:
        """
        POST /scans/{id}/abort - Abort a running scan.
        
        Args:
            scan_id: ID of the scan to abort
            
        Returns:
            True if abort succeeded
        """
        base_url = self._get_base_url()
        url = f"{base_url}/scans/{scan_id}/abort"

        if self.debug:
            print(f"[DEBUG] Abort scan endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            response = requests.post(url, headers=headers)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code == 404:
                raise APIError(f"Scan not found: {scan_id}")

            if response.status_code == 400:
                raise APIError("Scan is not in a running state.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to abort scan: {response.status_code} - {response.text}"
                )

            return True
        except requests.RequestException as e:
            raise APIError(f"Network error while aborting scan: {str(e)}")

    def delete_scan(self, scan_id: str) -> bool:
        """
        DELETE /scans/{id} - Delete a completed scan.
        
        Args:
            scan_id: ID of the scan to delete
            
        Returns:
            True if delete succeeded
        """
        base_url = self._get_base_url()
        url = f"{base_url}/scans/{scan_id}"

        if self.debug:
            print(f"[DEBUG] Delete scan endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            response = requests.delete(url, headers=headers)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code == 404:
                raise APIError(f"Scan not found: {scan_id}")

            if response.status_code == 400:
                raise APIError("Cannot delete scan. Scan must be completed first.")

            if response.status_code not in (200, 204):
                raise APIError(
                    f"Failed to delete scan: {response.status_code} - {response.text}"
                )

            return True
        except requests.RequestException as e:
            raise APIError(f"Network error while deleting scan: {str(e)}")

    def get_usage(self, start: Optional[str] = None, end: Optional[str] = None) -> UsageData:
        """
        GET /usage - Get usage analytics.
        
        Args:
            start: Start date filter (optional)
            end: End date filter (optional)
            
        Returns:
            UsageData with usage periods
        """
        base_url = self._get_base_url()
        url = f"{base_url}/usage"

        if self.debug:
            print(f"[DEBUG] Usage endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            params = {}
            if start:
                params['start'] = start
            if end:
                params['end'] = end

            response = requests.get(url, headers=headers, params=params if params else None)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to get usage: {response.status_code} - {response.text}"
                )

            return UsageData.from_api_response(response.json())
        except requests.RequestException as e:
            raise APIError(f"Network error while fetching usage: {str(e)}")

    def get_audit_logs(self, limit: int = 50, offset: int = 0) -> AuditLogs:
        """
        GET /audit - Get audit log entries.
        
        Args:
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            AuditLogs with log entries, limit, offset
        """
        base_url = self._get_base_url()
        url = f"{base_url}/audit"

        if self.debug:
            print(f"[DEBUG] Audit logs endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            params = {'limit': limit, 'offset': offset}
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to get audit logs: {response.status_code} - {response.text}"
                )

            return AuditLogs.from_api_response(response.json())
        except requests.RequestException as e:
            raise APIError(f"Network error while fetching audit logs: {str(e)}")

    def get_queue_status(self) -> QueueStatus:
        """
        GET /queue/status - Get current queue state.
        
        Returns:
            QueueStatus with queued and processing counts
        """
        base_url = self._get_base_url()
        url = f"{base_url}/queue/status"

        if self.debug:
            print(f"[DEBUG] Queue status endpoint: {url}")

        try:
            headers = {'apiKey': self.token, 'User-Agent': get_user_agent()}
            response = requests.get(url, headers=headers)

            if response.status_code == 401:
                raise APIError("Invalid API key. Please verify your token.")

            if response.status_code != 200:
                raise APIError(
                    f"Failed to get queue status: {response.status_code} - {response.text}"
                )

            return QueueStatus.from_api_response(response.json())
        except requests.RequestException as e:
            raise APIError(f"Network error while fetching queue status: {str(e)}")
