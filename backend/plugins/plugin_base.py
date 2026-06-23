"""
plugin_base.py
--------------
Defines the strict data contracts and abstract base class for all custom threat detectors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class PluginFinding:
    finding: str
    severity: str              # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float          # 0.0 - 100.0
    evidence: List[str]
    mitre_techniques: List[str] = field(default_factory=list)

@dataclass
class PluginMetadata:
    name: str
    author: str
    version: str
    description: str

class PluginBase(ABC):
    """
    Abstract base class for all MobileGuard AI custom detectors.
    Must be pure and stateless during the analyze() call.
    """
    
    # Plugins must override this metadata
    metadata = PluginMetadata(
        name="BasePlugin",
        author="Unknown",
        version="0.0.0",
        description="Uninitialized plugin."
    )

    @abstractmethod
    def analyze(
        self,
        static_features,
        dynamic_features
    ) -> List[PluginFinding]:
        """
        Executes the detection logic. 
        Must complete within the PluginManager's hard timeout limit.
        """
        pass