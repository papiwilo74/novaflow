"""
NovaFlow NDR - Heuristic Rule: Bandwidth Exfiltration Detector
Detecta transferencias de datos anormalmente masivas hacia direcciones públicas exteriores.
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Dict, Optional, Set

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_internal_ip(ip_str: str) -> bool:
    """Determina si una dirección IPv4 pertenece a redes internas privadas (RFC 1918)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


class BandwidthExfiltrationDetector:
    """
    Supervisa flujos salientes desde hosts internos hacia el exterior.
    Dispara alertas ante anomalías volumétricas en un solo flujo o acumuladas en ventana.
    """

    def __init__(
        self,
        single_flow_threshold_bytes: int = 20_000_000,  # 20 Megabytes
        window_threshold_bytes: int = 50_000_000,       # 50 Megabytes
        window_seconds: float = 60.0,
        alert_cooldown_seconds: float = 45.0,
        trusted_destinations: Optional[Set[str]] = None,
        biflow_stitcher: Optional[object] = None,
        host_profiler: Optional[object] = None,
    ):
        self.single_flow_threshold = single_flow_threshold_bytes
        self.window_threshold = window_threshold_bytes
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.trusted_destinations = set(trusted_destinations or [])
        self.biflow_stitcher = biflow_stitcher
        self.host_profiler = host_profiler

        # (src_ip, dst_ip) -> deque of (timestamp, bytes)
        self._history: Dict[tuple, deque] = defaultdict(deque)
        self._last_alert: Dict[tuple, float] = {}

    def add_trusted_destination(self, ip: str):
        """Añade un destino corporativo o cloud backup a la lista de confianza."""
        self.trusted_destinations.add(ip)

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        # Descartar si el destino está en la lista de confianza corporativa
        if flow.dst_ip in self.trusted_destinations:
            return None

        # Solo evaluar tráfico saliente (Origen interno -> Destino público/externo)
        src_is_internal = is_internal_ip(flow.src_ip)
        dst_is_internal = is_internal_ip(flow.dst_ip)

        if not src_is_internal or dst_is_internal:
            return None

        now = time.time()
        pair_key = (flow.src_ip, flow.dst_ip)
        history = self._history[pair_key]

        # Limpiar ventana
        while history and (now - history[0][0]) > self.window_seconds:
            history.popleft()

        history.append((now, flow.bytes))
        cumulative_bytes = sum(item[1] for item in history)

        is_massive_single = flow.bytes >= self.single_flow_threshold
        is_massive_window = cumulative_bytes >= self.window_threshold

        # 0. Verificación estadística de comportamiento mediante Z-Score de Welford
        is_statistical_anomaly = False
        z_score_val = 0.0
        host_role_val = "WORKSTATION"
        if self.host_profiler and hasattr(self.host_profiler, "get_host_profile"):
            prof = self.host_profiler.get_host_profile(flow.src_ip)
            host_role_val = prof.get("role", "WORKSTATION")
            acc = getattr(self.host_profiler, "_accumulators", {}).get(flow.src_ip)
            if acc and acc.count >= 10:
                z_score_val = acc.calculate_z_score(flow.bytes)
                # Si se desvía más de 3.5 sigmas respecto al comportamiento habitual y transfiere al menos 1 MB
                if z_score_val >= 3.5 and flow.bytes >= 1_000_000:
                    is_statistical_anomaly = True

        if is_massive_single or is_massive_window or is_statistical_anomaly:
            # 1. Validación Bi-Flow: si disponemos del ensamblador, descartar descargas benignas
            biflow_ratio = None
            if self.biflow_stitcher and hasattr(self.biflow_stitcher, "get_session"):
                session = self.biflow_stitcher.get_session(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
                if session and session.bytes_received > 0:
                    biflow_ratio = session.bytes_ratio
                    # Si el host recibió significativamente más de lo que envió (ratio < 0.2), es una descarga legítima
                    if biflow_ratio < 0.2:
                        return None

            last_alert = self._last_alert.get(pair_key, 0)
            if (now - last_alert) >= self.alert_cooldown_seconds:
                self._last_alert[pair_key] = now

                volume_mb = max(flow.bytes, cumulative_bytes) / (1024 * 1024)
                severity = (
                    AlertSeverity.CRITICAL
                    if volume_mb >= 50.0
                    else AlertSeverity.HIGH
                )

                # Cálculo dinámico de confianza: base 0.86 + volumen + puerto sensible no estándar + Z-score bonus
                vol_bonus = min(0.08, (volume_mb - 20.0) * 0.003) if volume_mb >= 20.0 else 0.0
                port_bonus = 0.04 if flow.dst_port not in (80, 443, 8080) else 0.0
                ratio_bonus = 0.04 if (biflow_ratio is not None and biflow_ratio > 20.0) else 0.0
                z_bonus = 0.05 if is_statistical_anomaly else 0.0
                confidence = round(min(0.99, 0.86 + vol_bonus + port_bonus + ratio_bonus + z_bonus), 2)

                is_pure_statistical = is_statistical_anomaly and not (is_massive_single or is_massive_window)
                title = (
                    f"Exfiltración Anómala por Desviación de Comportamiento (Z={z_score_val:.1f}σ): {flow.src_ip} -> {flow.dst_ip}"
                    if is_pure_statistical
                    else f"Posible Exfiltración Masiva de Datos: {flow.src_ip} -> {flow.dst_ip}"
                )

                return SecurityAlert(
                    severity=severity,
                    category=AlertCategory.EXFILTRATION,
                    title=title,
                    description=(
                        f"El host interno {flow.src_ip} ({host_role_val}) ha transferido {volume_mb:.2f} MB hacia "
                        f"la IP externa {flow.dst_ip}:{flow.dst_port}. "
                        f"Flujo: {flow.bytes / (1024*1024):.2f} MB en {flow.packets:,} paquetes. "
                        + (f"Desviación estadística Z={z_score_val:.1f}σ sobre línea base de Welford." if is_statistical_anomaly else "")
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=confidence,
                    metrics={
                        "bytes_transferred": max(flow.bytes, cumulative_bytes),
                        "megabytes": round(volume_mb, 2),
                        "packets": flow.packets,
                        "is_non_standard_port": flow.dst_port not in (80, 443, 8080),
                        "window_seconds": self.window_seconds,
                        "welford_z_score": z_score_val,
                        "host_role": host_role_val,
                    },
                )

        return None
