"""
NovaFlow NDR x OmniBreach - Purple Team Contract Schema v1.0
Contrato formal estructurado para correlación de campañas ofensivas (Red Team),
telemetría L3/L4/L7 y validación experimental defensiva (Blue Team).
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, List, Optional


class CampaignPhase(str, Enum):
    RECON = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class PurpleTeamEvent:
    """
    Contrato formal para un evento ofensivo individual emitido por OmniBreach.
    """
    vector_id: str
    vector_name: str
    phase: str
    mitre_technique: str
    mitre_tactic: str
    target_ip: str
    target_port: int
    attacker_ip: str
    expected_detector: str
    campaign_id: str = field(default_factory=lambda: f"camp_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{str(uuid.uuid4())[:8]}")
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol: int = 6  # 6=TCP, 17=UDP, 1=ICMP
    expected_severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    started_at: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    ended_at: Optional[float] = None
    payload_metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PurpleTeamEvent":
        clean_data = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**clean_data)


@dataclass
class PurpleTeamCampaign:
    """
    Representa una campaña ofensiva completa que agrupa múltiples vectores de ataque.
    """
    campaign_id: str
    name: str
    source_tool: str = "OmniBreach v3.0"
    target_env: str = "local-lab"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    events: List[PurpleTeamEvent] = field(default_factory=list)
    schema_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "source_tool": self.source_tool,
            "target_env": self.target_env,
            "created_at": self.created_at,
            "events_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "schema_version": self.schema_version,
        }


@dataclass
class VectorEvaluationResult:
    """
    Resultado de la evaluación empírica de un vector de ataque frente a NovaFlow NDR.
    """
    campaign_id: str
    vector_id: str
    vector_name: str
    mitre_technique: str
    expected_detector: str
    expected_severity: str
    detected: bool
    detected_alert_id: Optional[str] = None
    detected_category: Optional[str] = None
    detected_severity: Optional[str] = None
    severity_matched: bool = False
    detector_matched: bool = False
    mitre_matched: bool = False
    mttd_ms: Optional[float] = None
    alert_title: Optional[str] = None
    alert_confidence: Optional[float] = None
    cef_syslog_emitted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PurpleBenchmarkMetrics:
    """
    Conjunto formal de métricas cuantitativas calculadas empíricamente.
    Ninguna métrica es asumida a priori; todas provienen de mediciones de tiempo y precisión.
    """
    benchmark_id: str = field(default_factory=lambda: f"bench_{str(uuid.uuid4())[:8]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    campaign_id: str = ""
    total_vectors_tested: int = 0
    true_positives: int = 0      # TP: Vectores ofensivos detectados
    false_negatives: int = 0     # FN: Vectores ofensivos que eludieron la detección
    false_positives: int = 0     # FP: Alertas disparadas sobre tráfico benigno de fondo
    true_negatives: int = 0      # TN: Flujos benignos procesados sin generar falsa alarma
    total_background_flows: int = 0
    total_flows_processed: int = 0
    precision: float = 0.0       # TP / (TP + FP)
    recall: float = 0.0          # TP / (TP + FN)
    f1_score: float = 0.0        # 2 * (Precision * Recall) / (Precision + Recall)
    severity_accuracy: float = 0.0 # Porcentaje de TP donde detected_severity == expected_severity
    mean_mttd_ms: float = 0.0    # Mean Time to Detect (promedio)
    min_mttd_ms: float = 0.0     # Mínimo MTTD
    max_mttd_ms: float = 0.0     # Máximo MTTD
    duration_seconds: float = 0.0
    throughput_fps: float = 0.0  # Flujos por segundo procesados
    vector_results: List[VectorEvaluationResult] = field(default_factory=list)
    schema_version: str = "1.0.0"

    def calculate_derived_metrics(self):
        """Calcula de forma exacta y matemática las tasas de desempeño."""
        # Precisión
        denom_prec = self.true_positives + self.false_positives
        self.precision = round(self.true_positives / denom_prec, 4) if denom_prec > 0 else 0.0

        # Recall (Sensibilidad)
        denom_rec = self.true_positives + self.false_negatives
        self.recall = round(self.true_positives / denom_rec, 4) if denom_rec > 0 else 0.0

        # F1-Score
        if (self.precision + self.recall) > 0:
            self.f1_score = round(2 * (self.precision * self.recall) / (self.precision + self.recall), 4)
        else:
            self.f1_score = 0.0

        # Exactitud de severidad
        sev_matches = sum(1 for v in self.vector_results if v.severity_matched)
        self.severity_accuracy = round(sev_matches / self.total_vectors_tested, 4) if self.total_vectors_tested > 0 else 0.0

        # MTTD estadísticas
        latencies = [v.mttd_ms for v in self.vector_results if v.mttd_ms is not None]
        if latencies:
            self.mean_mttd_ms = round(sum(latencies) / len(latencies), 3)
            self.min_mttd_ms = round(min(latencies), 3)
            self.max_mttd_ms = round(max(latencies), 3)
        else:
            self.mean_mttd_ms = 0.0
            self.min_mttd_ms = 0.0
            self.max_mttd_ms = 0.0

        # Throughput
        if self.duration_seconds > 0:
            self.throughput_fps = round(self.total_flows_processed / self.duration_seconds, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "timestamp": self.timestamp,
            "campaign_id": self.campaign_id,
            "total_vectors_tested": self.total_vectors_tested,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "total_background_flows": self.total_background_flows,
            "total_flows_processed": self.total_flows_processed,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "severity_accuracy": self.severity_accuracy,
            "mttd_ms": {
                "mean": self.mean_mttd_ms,
                "min": self.min_mttd_ms,
                "max": self.max_mttd_ms,
            },
            "performance": {
                "duration_seconds": round(self.duration_seconds, 4),
                "throughput_fps": self.throughput_fps,
            },
            "vector_results": [v.to_dict() for v in self.vector_results],
            "schema_version": self.schema_version,
        }
