"""
NovaFlow NDR - Heuristic Rule: Lateral Movement & Internal Pivoting Detector (T1021)
Detecta propagación horizontal inter-workstations en puertos administrativos (SMB, RPC, RDP, WinRM, SSH).
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Puertos administrativos críticos comúnmente abusados para movimiento lateral y ransomware
ADMIN_PORTS: Dict[int, str] = {
    445: "SMB / Windows Shares (PsExec / Pass-the-Hash)",
    139: "NetBIOS Session Service",
    135: "Microsoft RPC / DCOM (WMI Execution)",
    3389: "Remote Desktop Protocol (RDP)",
    5985: "Windows Remote Management (WinRM HTTP)",
    5986: "Windows Remote Management (WinRM HTTPS)",
    22: "SSH Remote Administration",
}


def is_internal_ip(ip_str: str) -> bool:
    """Determina si una dirección IPv4 pertenece a redes privadas (RFC 1918)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


class LateralMovementDetector:
    """
    Supervisa comunicaciones internas de host a host (RFC 1918 -> RFC 1918).
    Identifica anomalías de topología cuando un endpoint de usuario inicia conexiones
    hacia múltiples hosts internos en puertos de administración remota (Internal Fan-out).
    """

    def __init__(
        self,
        target_threshold: int = 3,
        window_seconds: float = 30.0,
        alert_cooldown_seconds: float = 45.0,
        whitelisted_sources: Optional[Set[str]] = None,
        host_profiler: Optional[object] = None,
    ):
        self.target_threshold = target_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.whitelisted_sources = set(whitelisted_sources or [])
        self.host_profiler = host_profiler

        # src_ip -> deque of (timestamp, dst_ip, dst_port, protocol, bytes, packets)
        self._history: Dict[str, deque] = defaultdict(deque)
        # src_ip -> last_alert_timestamp
        self._last_alert: Dict[str, float] = {}

    def add_whitelist_source(self, ip: str):
        """Añade una IP de administración autorizada (bastion, scanner de vulnerabilidades, DC)."""
        self.whitelisted_sources.add(ip)

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """
        Evalúa si un flujo representa una técnica de movimiento lateral o propagación interna.
        """
        # 1. Descartar orígenes en lista blanca o activos clasificados como gestión legítima
        if flow.src_ip in self.whitelisted_sources:
            return None

        if self.host_profiler and hasattr(self.host_profiler, "classifier"):
            role = self.host_profiler.classifier.get_role(flow.src_ip)
            # Las estaciones de gestión (SCCM, Ansible, Bastion) y Domain Controllers tienen tráfico legítimo multi-host
            if role in ("ADMIN_MANAGEMENT", "INFRASTRUCTURE_DC"):
                return None

        # 2. Solo tráfico estrictamente interno (RFC 1918 a RFC 1918)
        if not (is_internal_ip(flow.src_ip) and is_internal_ip(flow.dst_ip)):
            return None

        # 3. Descartar loopback / tráfico hacia sí mismo
        if flow.src_ip == flow.dst_ip:
            return None

        # 4. Verificar si el puerto destino corresponde a un protocolo administrativo supervisado
        if flow.dst_port not in ADMIN_PORTS:
            return None

        now = time.time()
        history = self._history[flow.src_ip]

        # Limpiar registros fuera de la ventana deslizante
        while history and (now - history[0][0]) > self.window_seconds:
            history.popleft()

        # Registrar evento actual
        history.append((now, flow.dst_ip, flow.dst_port, flow.protocol, flow.bytes, flow.packets))

        # Calcular destinos únicos alcanzados en la ventana
        unique_targets = {item[1] for item in history}

        if len(unique_targets) >= self.target_threshold:
            last_alert = self._last_alert.get(flow.src_ip, 0)
            if (now - last_alert) >= self.alert_cooldown_seconds:
                self._last_alert[flow.src_ip] = now

                target_count = len(unique_targets)
                targeted_ports = sorted(list({item[2] for item in history}))
                port_names = [ADMIN_PORTS.get(p, f"Port {p}") for p in targeted_ports]
                total_bytes = sum(item[4] for item in history)
                total_packets = sum(item[5] for item in history)

                # Severidad según cardinalidad de propagación y criticidad de puertos
                has_smb = 445 in targeted_ports
                has_rdp = 3389 in targeted_ports
                if target_count >= 6 or (has_smb and has_rdp):
                    severity = AlertSeverity.CRITICAL
                elif target_count >= 4 or has_smb:
                    severity = AlertSeverity.HIGH
                else:
                    severity = AlertSeverity.MEDIUM

                # Cálculo de confianza adaptativo
                fanout_bonus = min(0.08, (target_count - self.target_threshold) * 0.02)
                port_bonus = 0.03 if has_smb else 0.0
                confidence = round(min(0.99, 0.88 + fanout_bonus + port_bonus), 2)

                return SecurityAlert(
                    severity=severity,
                    category=AlertCategory.LATERAL_MOVEMENT,
                    title=f"Movimiento Lateral L4 Detectado (Fan-out a {target_count} hosts): {flow.src_ip}",
                    description=(
                        f"El host interno {flow.src_ip} ha iniciado conexiones simultáneas hacia {target_count} endpoints "
                        f"internos distintos a través de servicios administrativos ({', '.join(port_names)}) en una "
                        f"ventana de {self.window_seconds:.0f}s. Patrón concordante con propagación automatizada de malware, "
                        "ransomware o ataque con herramientas tipo PsExec / Pass-the-Hash (MITRE ATT&CK T1021)."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=confidence,
                    metrics={
                        "unique_targets_count": target_count,
                        "targets": sorted(list(unique_targets))[:15],
                        "targeted_ports": targeted_ports,
                        "window_seconds": self.window_seconds,
                        "total_bytes_window": total_bytes,
                        "total_packets_window": total_packets,
                        "primary_service": ADMIN_PORTS.get(flow.dst_port, "Unknown Admin Service"),
                    },
                )

        return None
