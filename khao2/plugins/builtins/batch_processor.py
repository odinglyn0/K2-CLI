"""Batch processing plugin for intelligent multi-image analysis."""
import asyncio
import concurrent.futures
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from khao2.plugins import (
    ProcessorPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class BatchJob:
    """Represents a batch processing job."""
    job_id: str
    items: List[Path]
    status: str = "pending"
    results: List[Dict[str, Any]] = None
    errors: List[str] = None
    created_at: float = None
    completed_at: Optional[float] = None

    def __post_init__(self):
        if self.results is None:
            self.results = []
        if self.errors is None:
            self.errors = []
        if self.created_at is None:
            self.created_at = time.time()


@dataclass
class BatchConfig:
    """Configuration for batch processing."""
    max_concurrent: int = 3
    retry_attempts: int = 2
    retry_delay: float = 1.0
    progress_callback: Optional[Callable] = None
    error_callback: Optional[Callable] = None


class BatchProcessorPlugin(ProcessorPlugin):
    """Plugin for intelligent batch processing of images."""

    def __init__(self):
        self.jobs: Dict[str, BatchJob] = {}
        self.config: BatchConfig = BatchConfig()
        self.api_client = None
        self.scan_service = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="batch_processor",
            version="1.0.0",
            description="Intelligent batch processing for multiple images",
            author="Khao2 Team",
            plugin_type="processor",
            entry_point="khao2.plugins.builtins.batch_processor.BatchProcessorPlugin",
            config_schema={
                "max_concurrent": {
                    "type": "integer",
                    "default": 3,
                    "description": "Maximum concurrent scans"
                },
                "retry_attempts": {
                    "type": "integer",
                    "default": 2,
                    "description": "Number of retry attempts for failed scans"
                },
                "retry_delay": {
                    "type": "number",
                    "default": 1.0,
                    "description": "Delay between retry attempts in seconds"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the batch processor with services."""
        self.api_client = context.services.get('api_client')
        self.scan_service = context.services.get('scan_service')

        # Load configuration
        plugin_config = context.config.get('batch_processor', {})
        self.config = BatchConfig(
            max_concurrent=plugin_config.get('max_concurrent', 3),
            retry_attempts=plugin_config.get('retry_attempts', 2),
            retry_delay=plugin_config.get('retry_delay', 1.0)
        )

    def cleanup(self) -> None:
        """Clean up resources."""
        # Cancel any running jobs
        for job in self.jobs.values():
            if job.status == "running":
                job.status = "cancelled"

    def process(self, items: List[Any], **kwargs) -> List[Any]:
        """Process a batch of image paths."""
        if not isinstance(items, list) or not all(isinstance(item, (str, Path)) for item in items):
            raise PluginError("Batch processor expects a list of file paths")

        image_paths = [Path(item) for item in items]

        # Validate all paths exist and are images
        valid_paths = []
        for path in image_paths:
            if not path.exists():
                raise PluginError(f"File does not exist: {path}")
            if not self._is_image_file(path):
                raise PluginError(f"Not an image file: {path}")
            valid_paths.append(path)

        # Create batch job
        job_id = self._generate_job_id()
        job = BatchJob(job_id=job_id, items=valid_paths)
        self.jobs[job_id] = job

        # Process the batch
        try:
            results = self._process_batch(job, **kwargs)
            job.status = "completed"
            job.completed_at = time.time()
            return results
        except Exception as e:
            job.status = "failed"
            job.errors.append(str(e))
            job.completed_at = time.time()
            raise PluginError(f"Batch processing failed: {e}") from e

    def get_job_status(self, job_id: str) -> Optional[BatchJob]:
        """Get the status of a batch job."""
        return self.jobs.get(job_id)

    def list_jobs(self) -> List[BatchJob]:
        """List all batch jobs."""
        return list(self.jobs.values())

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job."""
        job = self.jobs.get(job_id)
        if job and job.status == "running":
            job.status = "cancelled"
            return True
        return False

    def _process_batch(self, job: BatchJob, **kwargs) -> List[Dict[str, Any]]:
        """Process a batch job with concurrency control."""
        if not self.scan_service:
            raise PluginError("Scan service not available")

        results = []
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def process_item(path: Path) -> Dict[str, Any]:
            async with semaphore:
                return await self._process_single_item(path, **kwargs)

        async def run_batch():
            tasks = [process_item(path) for path in job.items]
            completed_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(completed_results):
                if isinstance(result, Exception):
                    error_msg = f"Failed to process {job.items[i]}: {result}"
                    job.errors.append(error_msg)
                    results.append({"path": str(job.items[i]), "error": str(result)})
                else:
                    results.append(result)

        # Run the batch processing
        asyncio.run(run_batch())
        return results

    async def _process_single_item(self, path: Path, **kwargs) -> Dict[str, Any]:
        """Process a single item with retry logic."""
        last_error = None

        for attempt in range(self.config.retry_attempts + 1):
            try:
                # Upload and scan
                scan_id = self.scan_service.upload_and_scan(str(path))

                # Get result (simplified - in real implementation would handle polling)
                result = self.scan_service.get_scan_result(scan_id)

                return {
                    "path": str(path),
                    "scan_id": scan_id,
                    "result": result,
                    "attempts": attempt + 1
                }

            except Exception as e:
                last_error = e
                if attempt < self.config.retry_attempts:
                    await asyncio.sleep(self.config.retry_delay)
                continue

        # All attempts failed
        raise last_error

    def _is_image_file(self, path: Path) -> bool:
        """Check if a file is an image based on extension."""
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
        return path.suffix.lower() in image_extensions

    def _generate_job_id(self) -> str:
        """Generate a unique job ID."""
        import uuid
        return f"batch_{uuid.uuid4().hex[:8]}"


# Plugin metadata for discovery
PLUGIN_METADATA = PluginMetadata(
    name="batch_processor",
    version="1.0.0",
    description="Intelligent batch processing with concurrency and smart routing",
    author="Khao2 Team",
    plugin_type="processor",
    entry_point="khao2.plugins.builtins.batch_processor.BatchProcessorPlugin",
    config_schema={
        "max_concurrent": {
            "type": "integer",
            "default": 5,
            "description": "Maximum number of concurrent scans"
        },
        "retry_attempts": {
            "type": "integer",
            "default": 3,
            "description": "Number of retry attempts for failed scans"
        },
        "retry_delay": {
            "type": "number",
            "default": 1.0,
            "description": "Delay between retry attempts in seconds"
        }
    }
)