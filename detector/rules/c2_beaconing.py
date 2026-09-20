"""
NovaFlow NDR - C2 Beaconing & Jitter Detection Engine
Detecta balizamiento sigiloso de Command & Control (Cobalt Strike, Sliver, Mythic, Empire)
mediante el análisis matemático de intervalos entre llegadas (Inter-Arrival Time - IAT)
y Coeficiente de Variación (CV), sin depender de listas de reputación de IPs.
"""

import ipaddress
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class C2BeaconingDetector:
    """
    Detector de balizamiento C2 basado en entropía y dispersión de tiempos entre llegadas (IAT).
    
    Matemática de Detección:
      - IAT: Δt_i = t_i - t_{i-1}
      - Media (μ): promedio del intervalo de sueño (sleep time)
      - Desviación estándar (σ)
      - Coeficiente de Variación (CV): CV = σ / μ
      - Tráfico humano/web: CV >= 1.0 (caótico e impredecible)
      - Malware C2 automatizado (con sleep jitter <= 30%): CV <= 0.35
    """

    def __init__(
        self,
        cv_threshold: float = 0.35,
        min_samples: int = 5,
        min_interval_sec: float = 2.0,
        max_interval_sec: float = 300.0,
        window_seconds: float = 600.0,
        alert_cooldown_seconds: float = 180.0,
    ):
        self.cv_threshold = cv_threshold
        self.min_samples = min_samples
        self.min_interval_sec = min_interval_sec
        self.max_interval_sec = max_interval_sec
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # Estructura: (src_ip, dst_ip, dst_port) -> List[float (timestamps_sec)]
        self._connection_history: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
        # Cooldown: (src_ip, dst_ip, dst_port) -> float (last_alert_time)
        self._last_alerted: Dict[Tuple[str, str, int], float] = {}

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """
        Evalúa si un flujo individual forma parte de una secuencia de balizamiento periódico.
        """
        # Filtrar flujos con datos masivos (las balizas C2 son de control, no descargas grandes)
        if flow.bytes > 500_000:
            return None

        # Priorizar conexiones hacia el exterior o entre segmentos
        # (src interno a dst externo o cross-host)
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port

        # Ignorar multicast o broadcast
        if dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip == "255.255.255.255":
            return None

        key = (src_ip, dst_ip, dst_port)
        flow_ts = flow.timestamp.timestamp() if hasattr(flow.timestamp, "timestamp") else datetime.now(timezone.utc).timestamp()

        # Registrar timestamp
        timestamps = self._connection_history[key]
        timestamps.append(flow_ts)

        # Podar timestamps fuera de la ventana deslizante
        cutoff = flow_ts - self.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

        # Requiere un mínimo de conexiones para significancia estadística
        if len(timestamps) < self.min_samples:
            return None

        # Verificar cooldown para no saturar con alertas repetidas
        last_alert = self._last_alerted.get(key, 0.0)
        if flow_ts - last_alert < self.alert_cooldown_seconds:
            return None

        # Calcular intervalos entre llegadas (Inter-Arrival Times)
        intervals: List[float] = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta > 0.05:  # Descartar conexiones instantáneas simultáneas del mismo burst
                intervals.append(delta)

        if len(intervals) < (self.min_samples - 1):
            return None

        # 1. Media de intervalos (μ)
        n = len(intervals)
        mean_iat = sum(intervals) / n

        # Filtrar por rango de periodicidad típico de C2 (entre 2s y 300s)
        if mean_iat < self.min_interval_sec or mean_iat > self.max_interval_sec:
            return None

        # 2. Varianza y Desviación estándar (σ)
        variance = sum((x - mean_iat) ** 2 for x in intervals) / (n - 1) if n > 1 else 0.0
        std_dev = math.sqrt(variance)

        # 3. Coeficiente de Variación (CV = σ / μ)
        cv = std_dev / mean_iat if mean_iat > 0 else 1.0

        # Criterio: Regularidad matemática (CV <= cv_threshold)
        if cv <= self.cv_threshold:
            # Calcular porcentaje de Jitter
            min_iat = min(intervals)
            max_iat = max(intervals)
            jitter_pct = ((max_iat - min_iat) / mean_iat * 100.0) if mean_iat > 0 else 0.0

            # Calibrar severidad y confianza
            is_external = not self._is_private_ip(dst_ip)
            severity = AlertSeverity.CRITICAL if is_external and dst_port not in (80, 443) else AlertSeverity.HIGH
            confidence = round(min(0.98, max(0.85, 1.0 - cv)), 2)

            self._last_alerted[key] = flow_ts

            return SecurityAlert(
                severity=severity,
                category=AlertCategory.C2_BEACONING,
                title=f"Balizamiento C2 Sigiloso Detectado: {src_ip} -> {dst_ip}:{dst_port}",
                description=(
                    f"El host interno {src_ip} mantiene conexiones salientes altamente periódicas hacia {dst_ip}:{dst_port}. "
                    f"Intervalo medio de baliza: {mean_iat:.1f}s, Jitter estimado: {jitter_pct:.1f}%, Coeficiente de Variación: {cv:.3f}. "
                    "Patrón característico de implantes C2 (Cobalt Strike, Sliver, Mythic) evadiendo detección basada en firmas."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=flow.protocol,
                confidence=confidence,
                metrics={
                    "beacon_interval_seconds": round(mean_iat, 2),
                    "jitter_percentage": round(jitter_pct, 1),
                    "std_deviation_seconds": round(std_dev, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "observed_connections": len(timestamps),
                    "target_is_external": is_external,
                },
            )

        return None
