"""
NovaFlow NDR - Machine Learning Anomaly Detection (Isolation Forest)
Modelo no supervisado para detectar desviaciones estadísticas del comportamiento basal de red.
"""

import logging
import math
from typing import Any, Dict, List, Optional

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.ml.explainability import explainer
from detector.ml.model_registry import model_registry
from detector.ml.online_learner import online_learner

logger = logging.getLogger("NovaFlow.ML")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class NetworkIsolationForestDetector:
    """
    Detector de anomalías multivariable basado en Isolation Forest (Scikit-Learn)
    con motor analítico estadístico robusto de contingencia (IQR/Z-Score) si scikit-learn
    se encuentra en proceso de inicialización.
    """

    FEATURE_NAMES = [
        "packets",
        "bytes",
        "bytes_per_packet",
        "src_port",
        "dst_port",
        "protocol",
        "tcp_flags",
    ]

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.is_trained = False
        self._model: Optional[Any] = None

        # Límites basales estadísticos de respaldo
        self._baseline_stats: Dict[str, Dict[str, float]] = {}

    @classmethod
    def extract_features(cls, flow: NetFlowRecord) -> List[float]:
        """Extrae vector de características numéricas normalizadas del flujo."""
        bytes_per_pkt = flow.bytes / max(1, flow.packets)
        return [
            float(flow.packets),
            float(flow.bytes),
            float(bytes_per_pkt),
            float(flow.src_port),
            float(flow.dst_port),
            float(flow.protocol),
            float(flow.tcp_flags),
        ]

    def train_baseline(self, normal_flows: List[NetFlowRecord]):
        """Entrena el modelo no supervisado con tráfico considerado legítimo/basal."""
        if not normal_flows:
            return

        features = [self.extract_features(f) for f in normal_flows]

        # Calcular medias y desviaciones estándar para baseline estadístico
        num_features = len(self.FEATURE_NAMES)
        for idx, feat_name in enumerate(self.FEATURE_NAMES):
            vals = [row[idx] for row in features]
            mean = sum(vals) / len(vals)
            variance = sum((x - mean) ** 2 for x in vals) / len(vals)
            std = math.sqrt(variance) if variance > 0 else 1.0
            self._baseline_stats[feat_name] = {"mean": mean, "std": std, "max": max(vals)}

        if SKLEARN_AVAILABLE:
            try:
                X = np.array(features)
                self._model = IsolationForest(
                    contamination=self.contamination,
                    n_estimators=self.n_estimators,
                    random_state=42,
                )
                self._model.fit(X)
                logger.info(
                    f"Modelo Isolation Forest entrenado exitosamente con {len(normal_flows)} flujos basales."
                )
            except Exception as e:
                logger.warning(f"Error entrenando Scikit-Learn Isolation Forest: {e}")

        self.is_trained = True

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """Evalúa si un flujo individual se desvía anómalamente del comportamiento basal."""
        if not self.is_trained:
            return None

        feat_vector = self.extract_features(flow)
        is_anomaly = False
        anomaly_score = 0.0
        reason = ""

        if SKLEARN_AVAILABLE and self._model is not None:
            try:
                X = np.array([feat_vector])
                prediction = self._model.predict(X)[0]  # -1 para anomalía, 1 para normal
                # Decision function: negativo indica anomalía
                score = float(self._model.decision_function(X)[0])

                if prediction == -1:
                    is_anomaly = True
                    # Convertir score a probabilidad de confianza (0.75 - 0.99)
                    confidence = min(0.99, max(0.75, 0.5 - score))
                    anomaly_score = round(score, 4)
                    reason = f"Decision Function score = {anomaly_score}"
            except Exception as e:
                logger.debug(f"Error evaluando con sklearn: {e}")

        if not is_anomaly and self._baseline_stats:
            # Fallback estadístico multivariable (Z-score extremo > 4 sigma)
            bytes_stat = self._baseline_stats.get("bytes", {})
            pkts_stat = self._baseline_stats.get("packets", {})

            if bytes_stat and pkts_stat:
                z_bytes = (flow.bytes - bytes_stat["mean"]) / max(1.0, bytes_stat["std"])
                z_pkts = (flow.packets - pkts_stat["mean"]) / max(1.0, pkts_stat["std"])

                if z_bytes > 5.0 or (z_pkts > 4.0 and flow.tcp_flags == 0x02):
                    is_anomaly = True
                    confidence = 0.85
                    reason = f"Z-score volumétrico anómalo (Z_bytes={z_bytes:.1f}, Z_pkts={z_pkts:.1f})"

        if is_anomaly:
            # Calcular atribución de características (similar a SHAP values)
            explanation = explainer.explain_anomaly(
                feature_names=self.FEATURE_NAMES,
                current_values=feat_vector,
                baseline_stats=self._baseline_stats,
            )

            active_ver = model_registry.get_active_model()
            version_str = active_ver.version if active_ver else "v1.0.0"

            return SecurityAlert(
                severity=AlertSeverity.HIGH if flow.bytes > 5_000_000 else AlertSeverity.MEDIUM,
                category=AlertCategory.ANOMALY_ML,
                title=f"Anomalía de Comportamiento Detectada por Machine Learning (Isolation Forest)",
                description=(
                    f"El flujo de red {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                    f"(Proto: {flow.protocol}, Bytes: {flow.bytes:,}, Pkts: {flow.packets:,}) "
                    f"se desvía del espacio dimensional basal. {explanation['human_explanation']}"
                ),
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                confidence=confidence,
                metrics={
                    "anomaly_score": anomaly_score,
                    "model_version": version_str,
                    "primary_feature": explanation["primary_feature"],
                    "feature_attributions": explanation["feature_attributions"],
                    "standardized_deviations_sigma": explanation["standardized_deviations_sigma"],
                    "features": dict(zip(self.FEATURE_NAMES, feat_vector)),
                    "detection_model": "IsolationForest + Explainability",
                },
            )

        # Si el flujo es normal, actualizar aprendizaje incremental online
        feat_dict = dict(zip(self.FEATURE_NAMES, feat_vector))
        online_learner.update_with_flow(feat_dict)
        return None
