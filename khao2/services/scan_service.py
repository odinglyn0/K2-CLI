"""Service for managing scan operations."""
import time
from typing import Callable, Optional, Tuple
from khao2.services.api_client import APIClient
from khao2.core.models import ScanResult, ScanList, QueueStatus
from khao2.core.exceptions import APIError


class ScanService:
    """Handles scan lifecycle operations."""

    def __init__(self, api_client: APIClient):
        self.api_client = api_client

    def upload_and_scan(self, image_path: str) -> Tuple[str, Optional[int]]:
        """
        Upload an image and return the scan ID and queue position.
        
        Returns:
            Tuple of (scan_id, queue_position) where queue_position is None if not queued
        """
        result = self.api_client.upload_image(image_path)
        scan_id = result.get('id')
        queue_position = result.get('position')  # New field from 202 response
        return scan_id, queue_position

    def get_scan_result(self, scan_id: str) -> ScanResult:
        """Get scan result by ID."""
        data = self.api_client.get_scan_status(scan_id)
        return ScanResult.from_api_response(data)

    def get_queue_status(self) -> QueueStatus:
        """Get global queue status."""
        return self.api_client.get_queue_status()

    def poll_scan_status(
        self,
        scan_id: str,
        callback: Callable[[ScanResult], None],
        poll_interval: int = 2,
        error_retry_interval: int = 5
    ) -> Optional[ScanResult]:
        """
        Poll scan status until completion.
        
        Args:
            scan_id: The scan ID to monitor
            callback: Function to call with each status update
            poll_interval: Seconds between polls
            error_retry_interval: Seconds to wait after errors
            
        Returns:
            Final ScanResult or None if interrupted
            
        Status flow: queued → pending → running → classifying → completed
                                                              ↘ errored
        """
        while True:
            try:
                result = self.get_scan_result(scan_id)
                callback(result)

                if result.status in ['completed', 'failed', 'error', 'errored']:
                    return result

                time.sleep(poll_interval)
            except KeyboardInterrupt:
                print("\n\nScan monitoring stopped by user.")
                return None
            except APIError as e:
                print(f"\nError polling status: {str(e)}")
                time.sleep(error_retry_interval)

    def poll_scan_status_with_keybinds(
        self,
        scan_id: str,
        callback: Callable[[ScanResult, str, str], None],
        keybind_handler,
        loading_animation,
        poll_interval: float = 0.5,
        error_retry_interval: int = 5
    ) -> Optional[ScanResult]:
        """
        Poll scan status with keybind handling and animation.
        
        Args:
            scan_id: The scan ID to monitor
            callback: Function to call with (result, animation_frame, keybind_hints)
            keybind_handler: KeybindHandler instance for keyboard input
            loading_animation: LoadingAnimation instance for animation frames
            poll_interval: Seconds between polls (shorter for responsive keybinds)
            error_retry_interval: Seconds to wait after errors
            
        Returns:
            Final ScanResult or None if interrupted/aborted
        """
        last_poll_time = 0
        api_poll_interval = 2  # Actual API polling interval
        
        while True:
            try:
                # Check for keyboard input
                should_exit, should_abort = keybind_handler.check_input()
                
                if should_exit:
                    if should_abort:
                        print("\n\nAbort request sent...")
                        try:
                            self.abort_scan(scan_id)
                            print("Scan aborted successfully.")
                        except Exception as e:
                            print(f"Failed to abort scan: {e}")
                    else:
                        print("\n\nExiting client (scan continues on server)...")
                    return None
                
                current_time = time.time()
                
                # Only poll API at the specified interval
                if current_time - last_poll_time >= api_poll_interval:
                    result = self.get_scan_result(scan_id)
                    last_poll_time = current_time
                    
                    if result.status in ['completed', 'failed', 'error', 'errored']:
                        # Final display without animation
                        callback(result, None, None)
                        return result
                else:
                    # Use cached result if available
                    result = getattr(self, '_last_result', None)
                    if result is None:
                        result = self.get_scan_result(scan_id)
                        last_poll_time = current_time
                
                self._last_result = result
                
                # Get animation frame and keybind hints
                animation_frame = loading_animation.get_frame()
                keybind_hints = keybind_handler.get_keybind_hints()
                
                callback(result, animation_frame, keybind_hints)
                
                time.sleep(poll_interval)
                
            except KeyboardInterrupt:
                keybind_handler.handle_interrupt()
                if keybind_handler.abort_requested:
                    print("\n\nHard abort - sending abort request...")
                    try:
                        self.abort_scan(scan_id)
                        print("Scan aborted successfully.")
                    except Exception as e:
                        print(f"Failed to abort scan: {e}")
                else:
                    print("\n\nScan monitoring stopped by user.")
                return None
            except APIError as e:
                print(f"\nError polling status: {str(e)}")
                time.sleep(error_retry_interval)

    def list_scans(self, limit: int = 50, offset: int = 0) -> ScanList:
        """
        List user's scans with pagination.
        
        Args:
            limit: Maximum number of results (max 100)
            offset: Number of results to skip
            
        Returns:
            ScanList with scans, limit, offset
        """
        return self.api_client.list_scans(limit=limit, offset=offset)

    def abort_scan(self, scan_id: str) -> bool:
        """
        Abort a running scan.
        
        Args:
            scan_id: ID of the scan to abort
            
        Returns:
            True if abort succeeded
        """
        return self.api_client.abort_scan(scan_id)

    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a completed scan.
        
        Args:
            scan_id: ID of the scan to delete
            
        Returns:
            True if delete succeeded
        """
        return self.api_client.delete_scan(scan_id)
