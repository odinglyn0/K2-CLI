"""Plugin system for Khao2 CLI extensibility."""
import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Type, Union, runtime_checkable
from khao2.core.exceptions import Khao2Error


class PluginError(Khao2Error):
    """Base exception for plugin-related errors."""
    pass


class PluginLoadError(PluginError):
    """Exception raised when a plugin fails to load."""
    pass


class PluginValidationError(PluginError):
    """Exception raised when a plugin fails validation."""
    pass


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    entry_point: str
    dependencies: List[str] = None
    config_schema: Dict[str, Any] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.config_schema is None:
            self.config_schema = {}


class PluginContext:
    """Context passed to plugins during execution."""

    def __init__(self, config: Dict[str, Any], services: Dict[str, Any]):
        self.config = config
        self.services = services


@runtime_checkable
class Plugin(Protocol):
    """Protocol for all plugins."""

    @property
    def metadata(self) -> PluginMetadata:
        """Plugin metadata."""
        ...

    def initialize(self, context: PluginContext) -> None:
        """Initialize the plugin with context."""
        ...

    def cleanup(self) -> None:
        """Clean up plugin resources."""
        ...


@runtime_checkable
class DetectorPlugin(Plugin, Protocol):
    """Protocol for detection plugins."""

    def detect(self, image_path: Path, **kwargs) -> Dict[str, Any]:
        """Perform detection on an image."""
        ...


@runtime_checkable
class ProcessorPlugin(Plugin, Protocol):
    """Protocol for processing plugins."""

    def process(self, items: List[Any], **kwargs) -> List[Any]:
        """Process a batch of items."""
        ...


@runtime_checkable
class ExporterPlugin(Plugin, Protocol):
    """Protocol for export plugins."""

    def export(self, data: Any, output_path: Path, **kwargs) -> None:
        """Export data to a file."""
        ...


@runtime_checkable
class AnalyzerPlugin(Plugin, Protocol):
    """Protocol for analysis plugins."""

    def analyze(self, scan_result: Any, **kwargs) -> Dict[str, Any]:
        """Perform additional analysis on scan results."""
        ...


@runtime_checkable
class IntegrationPlugin(Plugin, Protocol):
    """Protocol for integration plugins."""

    def integrate(self, data: Any, **kwargs) -> Any:
        """Integrate with external systems."""
        ...


class PluginManager:
    """Manages plugin discovery, loading, and execution."""

    def __init__(self, plugin_dirs: Optional[List[Path]] = None):
        self.plugin_dirs = plugin_dirs or [
            Path(__file__).parent / "builtins",
            Path.home() / ".khao2" / "plugins"
        ]
        self._loaded_plugins: Dict[str, Plugin] = {}
        self._plugin_types: Dict[str, Type[Plugin]] = {
            'detector': DetectorPlugin,
            'processor': ProcessorPlugin,
            'exporter': ExporterPlugin,
            'analyzer': AnalyzerPlugin,
            'integration': IntegrationPlugin,
        }

    def discover_plugins(self) -> Dict[str, PluginMetadata]:
        """Discover available plugins."""
        plugins = {}

        # Discover built-in plugins
        builtin_dir = Path(__file__).parent / "builtins"
        if builtin_dir.exists():
            for plugin_file in builtin_dir.glob("*.py"):
                if plugin_file.name.startswith('_'):
                    continue
                try:
                    metadata = self._load_plugin_metadata_from_file(plugin_file)
                    if metadata:
                        plugins[metadata.name] = metadata
                except Exception as e:
                    import logging
                    logging.warning(f"Failed to load plugin from {plugin_file}: {e}")
                    continue

        # Discover user plugins
        for plugin_dir in self.plugin_dirs[1:]:
            if plugin_dir.exists():
                for plugin_file in plugin_dir.glob("*.py"):
                    try:
                        metadata = self._load_plugin_metadata_from_file(plugin_file)
                        if metadata:
                            plugins[metadata.name] = metadata
                    except Exception as e:
                        import logging
                        logging.warning(f"Failed to load plugin from {plugin_file}: {e}")
                        continue

        return plugins

    def load_plugin(self, name: str, context: PluginContext) -> Plugin:
        """Load a plugin by name."""
        if name in self._loaded_plugins:
            return self._loaded_plugins[name]

        plugins = self.discover_plugins()
        if name not in plugins:
            raise PluginLoadError(f"Plugin '{name}' not found")

        metadata = plugins[name]
        plugin_class = self._load_plugin_class(metadata)
        plugin_instance = plugin_class()

        # Validate plugin
        self._validate_plugin(plugin_instance, metadata)

        # Initialize plugin
        plugin_instance.initialize(context)
        self._loaded_plugins[name] = plugin_instance

        return plugin_instance

    def unload_plugin(self, name: str) -> None:
        """Unload a plugin."""
        if name in self._loaded_plugins:
            plugin = self._loaded_plugins[name]
            plugin.cleanup()
            del self._loaded_plugins[name]

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a loaded plugin by name."""
        return self._loaded_plugins.get(name)

    def list_loaded_plugins(self) -> List[str]:
        """List names of loaded plugins."""
        return list(self._loaded_plugins.keys())

    def _load_plugin_metadata_from_file(self, file_path: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from a Python file."""
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Look for PLUGIN_METADATA
        if hasattr(module, 'PLUGIN_METADATA'):
            return module.PLUGIN_METADATA

        return None

    def _load_plugin_class(self, metadata: PluginMetadata) -> Type[Plugin]:
        """Load plugin class from metadata."""
        module_name, class_name = metadata.entry_point.rsplit('.', 1)
        module = importlib.import_module(module_name)
        plugin_class = getattr(module, class_name)
        return plugin_class

    def _validate_plugin(self, plugin: Plugin, metadata: PluginMetadata) -> None:
        """Validate that a plugin implements the correct interface."""
        plugin_type = metadata.plugin_type
        if plugin_type not in self._plugin_types:
            raise PluginValidationError(f"Unknown plugin type: {plugin_type}")

        expected_protocol = self._plugin_types[plugin_type]
        if not isinstance(plugin, expected_protocol):
            raise PluginValidationError(
                f"Plugin {metadata.name} does not implement {plugin_type} protocol"
            )

    def execute_detector(self, name: str, image_path: Path, **kwargs) -> Dict[str, Any]:
        """Execute a detector plugin."""
        plugin = self.get_plugin(name)
        if not plugin or not isinstance(plugin, DetectorPlugin):
            raise PluginError(f"Plugin '{name}' is not a detector plugin")

        return plugin.detect(image_path, **kwargs)

    def execute_processor(self, name: str, items: List[Any], **kwargs) -> List[Any]:
        """Execute a processor plugin."""
        plugin = self.get_plugin(name)
        if not plugin or not isinstance(plugin, ProcessorPlugin):
            raise PluginError(f"Plugin '{name}' is not a processor plugin")

        return plugin.process(items, **kwargs)

    def execute_exporter(self, name: str, data: Any, output_path: Path, **kwargs) -> None:
        """Execute an exporter plugin."""
        plugin = self.get_plugin(name)
        if not plugin or not isinstance(plugin, ExporterPlugin):
            raise PluginError(f"Plugin '{name}' is not an exporter plugin")

        plugin.export(data, output_path, **kwargs)

    def execute_analyzer(self, name: str, scan_result: Any, **kwargs) -> Dict[str, Any]:
        """Execute an analyzer plugin."""
        plugin = self.get_plugin(name)
        if not plugin or not isinstance(plugin, AnalyzerPlugin):
            raise PluginError(f"Plugin '{name}' is not an analyzer plugin")

        return plugin.analyze(scan_result, **kwargs)

    def execute_integration(self, name: str, data: Any, **kwargs) -> Any:
        """Execute an integration plugin."""
        plugin = self.get_plugin(name)
        if not plugin or not isinstance(plugin, IntegrationPlugin):
            raise PluginError(f"Plugin '{name}' is not an integration plugin")

        return plugin.integrate(data, **kwargs)