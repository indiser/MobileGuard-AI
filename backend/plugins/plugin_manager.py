"""
plugin_manager.py
-----------------
Asynchronous, fault-tolerant execution engine for custom threat detectors.
Enforces hard timeouts to prevent rogue plugins from hanging the pipeline.
"""

import os
import importlib
import inspect
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from pathlib import Path
from typing import List

from backend.plugins.plugin_base import PluginBase, PluginFinding

logger = logging.getLogger(__name__)

class PluginManager:
    def __init__(self, plugin_dir: str = "backend/plugins/custom_detectors", timeout_sec: int = 5):
        self.plugin_dir = Path(plugin_dir)
        self.timeout_sec = timeout_sec
        self.plugins: List[PluginBase] = []
        self._load_plugins()

    def _load_plugins(self):
        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory {self.plugin_dir} does not exist.")
            return

        for file_path in self.plugin_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue

            # Convert path to python module notation (e.g., backend.plugins.custom_detectors.detector)
            module_parts = list(file_path.parts)
            module_parts[-1] = file_path.stem
            module_name = ".".join(module_parts)

            try:
                module = importlib.import_module(module_name)
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    # Strictly check inheritance and ensure we don't instantiate the ABC itself
                    if issubclass(obj, PluginBase) and obj is not PluginBase:
                        plugin_instance = obj()
                        self.plugins.append(plugin_instance)
                        logger.info(f"[PLUGIN READY] {plugin_instance.metadata.name} v{plugin_instance.metadata.version}")
            except Exception as e:
                logger.error(f"[PLUGIN CRASH] Failed to load {file_path.name}: {e}")

    def run_plugins(self, static_features, dynamic_features) -> List[PluginFinding]:
        """
        Executes all loaded plugins concurrently.
        Any plugin that exceeds `self.timeout_sec` is abandoned.
        """
        if not self.plugins:
            return []

        all_findings: List[PluginFinding] = []
        
        with ThreadPoolExecutor(max_workers=min(10, len(self.plugins))) as executor:
            # Map futures to plugin names for error reporting
            future_to_plugin = {
                executor.submit(plugin.analyze, static_features, dynamic_features): plugin.metadata.name
                for plugin in self.plugins
            }

            for future in as_completed(future_to_plugin, timeout=self.timeout_sec + 2):
                plugin_name = future_to_plugin[future]
                try:
                    # Enforce the hard timeout per plugin
                    findings = future.result(timeout=self.timeout_sec)
                    if findings:
                        all_findings.extend(findings)
                except TimeoutError:
                    logger.error(f"[PLUGIN TIMEOUT] {plugin_name} exceeded {self.timeout_sec}s limit. Terminated.")
                except Exception as e:
                    logger.error(f"[PLUGIN FAILURE] {plugin_name} threw an exception: {e}")

        return all_findings