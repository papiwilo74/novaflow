"""
NovaFlow NDR - Machine Learning Model Registry & Versioning
Control de ciclo de vida, linaje y versionado de modelos de detección de anomalías.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ModelVersion:
    version: str  # e.g. "v1.0.0"
    algorithm: str  # "IsolationForest", "OnlineZScore"
    trained_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "ACTIVE"  # "ACTIVE", "CANDIDATE", "ARCHIVED"
    metrics: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    sample_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "trained_at": self.trained_at.isoformat(),
            "status": self.status,
            "metrics": self.metrics,
            "parameters": self.parameters,
            "sample_count": self.sample_count,
        }


class ModelRegistry:
    """Registro en memoria de versiones de modelos de ciberseguridad."""

    def __init__(self):
        self._versions: Dict[str, ModelVersion] = {}
        self.active_version_id: Optional[str] = None

        # Registrar versión base inicial v1.0.0
        self.register_version(
            ModelVersion(
                version="v1.0.0",
                algorithm="IsolationForest + RobustBaseline",
                status="ACTIVE",
                parameters={"contamination": 0.05, "n_estimators": 100},
                metrics={"accuracy_baseline": 0.96},
                sample_count=5000,
            )
        )

    def register_version(self, model_ver: ModelVersion):
        self._versions[model_ver.version] = model_ver
        if model_ver.status == "ACTIVE":
            self.active_version_id = model_ver.version

    def get_active_model(self) -> Optional[ModelVersion]:
        if self.active_version_id:
            return self._versions.get(self.active_version_id)
        return None

    def list_versions(self) -> List[Dict[str, Any]]:
        return [v.to_dict() for v in self._versions.values()]


model_registry = ModelRegistry()
