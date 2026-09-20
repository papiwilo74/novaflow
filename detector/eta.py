"""
NovaFlow NDR - Encrypted Traffic Analysis (ETA) & SPLT Profiler
Inspección de flujos TLS/HTTPS sin descifrado de payload mediante perfilado SPLT
(Sequence of Packet Lengths and Times) para detectar canales C2 y exfiltración encubierta.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord
from detector.biflow import BiFlowStitcher
from detector.models import AlertCategory, AlertSeverity, SecurityAlert

logger = logging.getLogger("NovaFlow.ETA")


class EncryptedTrafficAnalyzer:
    """
    Analizador de Tráfico Cifrado (ETA) basado en el estándar Cisco ETA.
    Evalúa la forma estadística del transporte (SPLT):
    - Tamaño promedio de paquete (Bytes/Pkt)
    - Asimetría de transferencia de carga útil
    - Patrón de baliza C2 interactiva vs descarga/subida de contenido
    """

    TLS_PORTS = {443, 8443, 9443}

    def __init__(self, biflow_stitcher: Optional[BiFlowStitcher] = None):
        self.biflow_stitcher = biflow_stitcher
        # Historial de flujos por par (src_ip, dst_ip, dst_port)
        self.flow_history: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
        self.max_history_per_pair = 20

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.20.")
            or ip.startswith("172.21.")
            or ip.startswith("172.22.")
            or ip.startswith("172.23.")
            or ip.startswith("172.24.")
            or ip.startswith("172.25.")
            or ip.startswith("172.26.")
            or ip.startswith("172.27.")
            or ip.startswith("172.28.")
            or ip.startswith("172.29.")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
            or ip.startswith("127.")
        )

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """
        Inspecciona un flujo individual en busca de patrones de TLS anómalo.
        """
        # Solo evaluar TCP
        if flow.protocol != 6:
            return None

        # Verificar si involucra puertos TLS o puertos anómalos salientes
        is_tls_port = flow.dst_port in self.TLS_PORTS or flow.src_port in self.TLS_PORTS
        if not is_tls_port:
            return None

        # Ignorar tráfico puramente interno si ambos son privados y no es exfiltración
        src_private = self._is_private_ip(flow.src_ip)
        dst_private = self._is_private_ip(flow.dst_ip)
        if src_private and dst_private:
            return None

        # Calcular métricas SPLT
        packets = max(1, flow.packets)
        avg_pkt_size = flow.bytes / packets

        pair_key = (flow.src_ip, flow.dst_ip, flow.dst_port)
        history = self.flow_history[pair_key]
        history.append({
            "bytes": flow.bytes,
            "packets": flow.packets,
            "avg_pkt_size": avg_pkt_size,
            "timestamp": flow.timestamp,
        })
        if len(history) > self.max_history_per_pair:
            history.pop(0)

        # 1. Detección de Exfiltración Cifrada Masiva sobre TLS (Encrypted Data Staging / Exfiltration)
        # Flujo saliente desde host interno con tamaño de paquete saturando MTU (~1100-1500 bytes)
        # y volumen masivo (>= 5 MB) con asimetría de subida
        if src_private and not dst_private and flow.bytes >= 5_000_000 and avg_pkt_size >= 1150:
            is_upload_heavy = True
            if self.biflow_stitcher:
                biflow = self.biflow_stitcher.get_biflow(flow)
                if biflow and biflow.is_bidirectional:
                    # Si la sesión bi-flow muestra que la subida es > 85% del total
                    is_upload_heavy = biflow.bytes_ratio >= 0.85

            if is_upload_heavy:
                mb_transferred = round(flow.bytes / (1024 * 1024), 2)
                return SecurityAlert(
                    category=AlertCategory.ANOMALOUS_TLS,
                    severity=AlertSeverity.HIGH,
                    title=f"Exfiltración Cifrada Masiva (ETA): {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}",
                    description=(
                        f"Se identificó un túnel de exfiltración TLS saliente hacia {flow.dst_ip}:{flow.dst_port}. "
                        f"Patrón SPLT saturado: {mb_transferred} MB en {flow.packets:,} paquetes "
                        f"(promedio MTU: {int(avg_pkt_size)} bytes/pkt)."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=0.91,
                    timestamp=flow.timestamp,
                    metrics={
                        "technique": "SPLT_ENCRYPTED_EXFILTRATION",
                        "avg_packet_size": round(avg_pkt_size, 1),
                        "total_bytes": flow.bytes,
                        "packets": flow.packets,
                        "mb_transferred": mb_transferred,
                    },
                )

        # 2. Detección de Canal C2 Furtivo Cifrado (Cobalt Strike / Sliver HTTPS Beaconing)
        # Flujos repetidos con paquetes pequeños y uniformes (150-450 bytes),
        # conteo moderado de paquetes (5 a 50) y repetición recurrente hacia IP externa
        if src_private and not dst_private and 5 <= flow.packets <= 50 and 120 <= avg_pkt_size <= 480:
            # Evaluar si hay repetición en el historial reciente (>= 3 ráfagas consistentes)
            if len(history) >= 3:
                similar_bursts = sum(
                    1 for h in history if 100 <= h["avg_pkt_size"] <= 500 and 4 <= h["packets"] <= 60
                )
                if similar_bursts >= 3:
                    return SecurityAlert(
                        category=AlertCategory.ANOMALOUS_TLS,
                        severity=AlertSeverity.HIGH,
                        title=f"Canal C2 Cifrado Anómalo (ETA Beaconing): {flow.src_ip} -> {flow.dst_ip}",
                        description=(
                            f"Tráfico periódico HTTPS/TLS anómalo detectado hacia {flow.dst_ip}:{flow.dst_port}. "
                            f"Firma SPLT compatible con baliza C2 cifrada: {similar_bursts} ráfagas uniformes "
                            f"(tamaño medio {int(avg_pkt_size)} bytes/pkt)."
                        ),
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        confidence=0.88,
                        timestamp=flow.timestamp,
                        metrics={
                            "technique": "SPLT_ENCRYPTED_C2_BEACON",
                            "avg_packet_size": round(avg_pkt_size, 1),
                            "consistent_bursts": similar_bursts,
                            "packets": flow.packets,
                            "bytes": flow.bytes,
                        },
                    )

        return None
