"""
NovaFlow NDR - Heuristic Rule: Port Scan Detector
Detecta barridos de puertos verticales u horizontales mediante ventanas deslizantes.
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class PortScanDetector:
    """
    Rastrea intentos de conexión por IP origen en una ventana temporal deslizante.
    Identifica patrones de sondeo rápido con paquetes SYN o intentos a puertos cerrados.
    """

    def __init__(
        self,
        port_threshold: int = 15,
        window_seconds: float = 10.0,
        alert_cooldown_seconds: float = 30.0,
    ):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # src_ip -> deque of (timestamp, dst_ip, dst_port, tcp_flags)
        self._history: Dict[str, deque] = defaultdict(deque)
        # src_ip -> last_alert_time
        self._last_alert: Dict[str, float] = {}

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        # Filtrar solo TCP (protocolo 6)
        if flow.protocol != 6:
            return None

        # Detectar patrones de sondeo / escaneo activo:
        # 1. SYN scan: SYN activado (0x02), típicamente sin ACK (no 0x10) o pocos paquetes
        # 2. FIN scan: solo flag FIN (0x01)
        # 3. NULL scan: sin flags (0x00)
        # 4. Xmas scan: FIN + PSH + URG (0x29)
        # Se descartan flujos con muchos paquetes (> 4) porque corresponden a transferencias o sesiones establecidas
        if flow.packets > 4:
            return None

        is_syn_scan = bool(flow.tcp_flags & 0x02)
        is_fin_scan = (flow.tcp_flags == 0x01)
        is_null_scan = (flow.tcp_flags == 0x00)
        is_xmas_scan = ((flow.tcp_flags & 0x29) == 0x29)

        if not (is_syn_scan or is_fin_scan or is_null_scan or is_xmas_scan):
            return None

        scan_type = "SYN" if is_syn_scan else ("FIN" if is_fin_scan else ("NULL" if is_null_scan else "XMAS"))

        now = time.time()
        history = self._history[flow.src_ip]

        # Limpiar registros fuera de la ventana deslizante
        while history and (now - history[0][0]) > self.window_seconds:
            history.popleft()

        history.append((now, flow.dst_ip, flow.dst_port, flow.tcp_flags, scan_type))

        # Contar puertos únicos tocados por este host
        unique_ports = {item[2] for item in history}
        unique_targets = {item[1] for item in history}

        if len(unique_ports) >= self.port_threshold:
            last_alert = self._last_alert.get(flow.src_ip, 0)
            if (now - last_alert) >= self.alert_cooldown_seconds:
                self._last_alert[flow.src_ip] = now

                severity = (
                    AlertSeverity.HIGH
                    if len(unique_ports) >= 30
                    else AlertSeverity.MEDIUM
                )
                rate = len(unique_ports) / max(0.5, self.window_seconds)

                # Cálculo dinámico y calibrado de confianza estadística
                # Base 0.85 + volumen de puertos + dispersión de objetivos
                port_bonus = min(0.09, (len(unique_ports) / 50.0) * 0.09)
                dispersion_bonus = min(0.04, (len(unique_targets) - 1) * 0.01)
                stealth_bonus = 0.02 if scan_type in ("FIN", "NULL", "XMAS") else 0.0
                confidence = round(min(0.99, 0.85 + port_bonus + dispersion_bonus + stealth_bonus), 2)

                return SecurityAlert(
                    severity=severity,
                    category=AlertCategory.PORT_SCAN,
                    title=f"Barrido de Puertos ({scan_type}) detectado desde {flow.src_ip}",
                    description=(
                        f"El host {flow.src_ip} ha sondeado {len(unique_ports)} puertos diferentes "
                        f"en {len(unique_targets)} objetivos en una ventana de {self.window_seconds}s. "
                        f"Tasa estimada: {rate:.1f} puertos/segundo mediante técnica de escaneo {scan_type} (Flags: 0x{flow.tcp_flags:02x})."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=confidence,
                    metrics={
                        "unique_ports_scanned": len(unique_ports),
                        "unique_targets": len(unique_targets),
                        "ports_sample": sorted(list(unique_ports))[:10],
                        "scan_rate_pps": round(rate, 2),
                        "scan_type": scan_type,
                    },
                )

        return None
