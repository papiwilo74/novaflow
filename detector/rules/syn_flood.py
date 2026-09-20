"""
NovaFlow NDR - Heuristic Rule: SYN Flood DoS/DDoS Detector
Detecta saturaciones de denegación de servicio por avalancha de paquetes TCP SYN.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Optional

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class SynFloodDetector:
    """
    Rastrea el volumen de flujos SYN entrantes dirigidos a un destino específico (IP/Puerto).
    Identifica anomalías por spoofing masivo de IPs y agotamiento de recursos del kernel.
    """

    def __init__(
        self,
        syn_count_threshold: int = 30,
        window_seconds: float = 5.0,
        alert_cooldown_seconds: float = 20.0,
    ):
        self.syn_count_threshold = syn_count_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # (dst_ip, dst_port) -> deque of (timestamp, src_ip, packets)
        self._target_history: Dict[tuple, deque] = defaultdict(deque)
        self._last_alert: Dict[tuple, float] = {}

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        # Solo flujos TCP (6) con flag SYN (0x02) y paquetes pequeños típicos de handshake
        if flow.protocol != 6:
            return None

        is_pure_syn = (flow.tcp_flags & 0x02) and not (flow.tcp_flags & 0x10)  # SYN sin ACK
        if not is_pure_syn or flow.packets > 4:
            return None

        now = time.time()
        target_key = (flow.dst_ip, flow.dst_port)
        history = self._target_history[target_key]

        # Limpiar ventana
        while history and (now - history[0][0]) > self.window_seconds:
            history.popleft()

        history.append((now, flow.src_ip, flow.packets))

        total_syn_flows = len(history)
        distinct_sources = len({item[1] for item in history})

        if total_syn_flows >= self.syn_count_threshold:
            last_alert = self._last_alert.get(target_key, 0)
            if (now - last_alert) >= self.alert_cooldown_seconds:
                self._last_alert[target_key] = now

                severity = (
                    AlertSeverity.CRITICAL
                    if total_syn_flows >= 60
                    else AlertSeverity.HIGH
                )
                rate = total_syn_flows / max(0.5, self.window_seconds)

                # Cálculo dinámico de confianza: base 0.88 + intensidad de ráfaga + factor spoofing
                volume_bonus = min(0.06, (total_syn_flows - self.syn_count_threshold) * 0.002)
                spoofing_bonus = min(0.05, (distinct_sources / max(1, total_syn_flows)) * 0.05)
                confidence = round(min(0.99, 0.88 + volume_bonus + spoofing_bonus), 2)

                return SecurityAlert(
                    severity=severity,
                    category=AlertCategory.SYN_FLOOD,
                    title=f"Ataque DoS SYN Flood contra {flow.dst_ip}:{flow.dst_port}",
                    description=(
                        f"Se registraron {total_syn_flows} intentos de conexión SYN hacia el servicio "
                        f"{flow.dst_ip}:{flow.dst_port} en {self.window_seconds}s provenientes de "
                        f"{distinct_sources} direcciones IP de origen distintas (patrón de IP Spoofing). "
                        f"Intensidad: {rate:.1f} SYN flows/segundo."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=confidence,
                    metrics={
                        "syn_flows_in_window": total_syn_flows,
                        "distinct_sources": distinct_sources,
                        "rate_syn_per_sec": round(rate, 2),
                        "window_seconds": self.window_seconds,
                    },
                )

        return None
