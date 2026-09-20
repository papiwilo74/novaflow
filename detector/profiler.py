"""
NovaFlow NDR - Asset Profiling & Dynamic Behavioral Baseline Engine
Calcula líneas base estadísticas gaussianas continuas mediante el Algoritmo de Welford en O(1) de memoria,
clasifica automáticamente los roles de los activos (DC, DNS, Admin, Server, Workstation)
y detecta anomalías de comportamiento mediante Z-Score dinámico por host.
"""

import ipaddress
import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from collector.parser import NetFlowRecord

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_internal_ip(ip_str: str) -> bool:
    """Verifica si una dirección IPv4 pertenece a redes privadas RFC 1918."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


class AssetRole(str, Enum):
    WORKSTATION = "WORKSTATION"
    INFRASTRUCTURE_DC = "INFRASTRUCTURE_DC"
    INFRASTRUCTURE_DNS = "INFRASTRUCTURE_DNS"
    ADMIN_MANAGEMENT = "ADMIN_MANAGEMENT"
    INTERNAL_SERVER = "INTERNAL_SERVER"


@dataclass
class HostWelfordAccumulator:
    """
    Implementación online del Algoritmo de Welford (1962).
    Calcula la media y varianza muestral continua en un solo paso numérico estable sin almacenar datos.
    """
    count: int = 0
    mean_bytes: float = 0.0
    m2_bytes: float = 0.0  # Suma de cuadrados de diferencias respecto a la media
    mean_packets: float = 0.0
    m2_packets: float = 0.0

    def update(self, bytes_val: float, packets_val: float = 0.0):
        """Actualiza la media y la suma de cuadrados en O(1) con una nueva muestra."""
        self.count += 1
        k = self.count

        # Welford para bytes
        delta_b = bytes_val - self.mean_bytes
        self.mean_bytes += delta_b / k
        delta_b2 = bytes_val - self.mean_bytes
        self.m2_bytes += delta_b * delta_b2

        # Welford para paquetes
        if packets_val > 0:
            delta_p = packets_val - self.mean_packets
            self.mean_packets += delta_p / k
            delta_p2 = packets_val - self.mean_packets
            self.m2_packets += delta_p * delta_p2

    @property
    def variance_bytes(self) -> float:
        """Varianza muestral s^2."""
        if self.count < 2:
            return 0.0
        return self.m2_bytes / (self.count - 1)

    @property
    def stdev_bytes(self) -> float:
        """Desviación estándar muestral s = sqrt(s^2)."""
        return math.sqrt(self.variance_bytes)

    def calculate_z_score(self, bytes_val: float) -> float:
        """
        Calcula el Z-score de una nueva observación frente al historial acumulado:
          Z = (x - mean) / stdev
        Si la desviación estándar es 0 o hay menos de 5 muestras, retorna 0.0.
        """
        if self.count < 5 or self.stdev_bytes <= 1e-4:
            return 0.0
        return round((bytes_val - self.mean_bytes) / self.stdev_bytes, 2)


@dataclass
class HostDeviationResult:
    """Resultado del cotejo estadístico de un flujo frente a la línea base del host."""
    host_ip: str
    role: AssetRole
    z_score: float
    is_statistically_anomalous: bool
    samples_count: int
    mean_bytes: float
    stdev_bytes: float
    observed_bytes: int


class AssetRoleClassifier:
    """
    Clasifica de manera autónoma los roles de red de cada host observando el tráfico L4 entrante y saliente.
    """

    def __init__(self):
        # host -> set of incoming client IPs per port
        self._inbound_clients_by_port: Dict[str, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))
        # host -> set of outbound target IPs on admin ports
        self._admin_outbound_targets: Dict[str, Set[str]] = defaultdict(set)
        # host -> AssetRole cache
        self._roles: Dict[str, AssetRole] = {}

    def observe_flow(self, flow: NetFlowRecord):
        """Registra el flujo para inferir el rol del host."""
        src = flow.src_ip
        dst = flow.dst_ip
        dpt = flow.dst_port

        # Observar servidor de destino (tráfico entrante)
        if is_internal_ip(dst):
            self._inbound_clients_by_port[dst][dpt].add(src)

        # Observar tráfico de gestión administrativa saliente (445, 135, 5985, 22)
        if is_internal_ip(src) and is_internal_ip(dst) and dpt in (445, 135, 5985, 22):
            self._admin_outbound_targets[src].add(dst)

        # Re-evaluar rol de dst
        self._evaluate_role(dst)
        # Re-evaluar rol de src
        self._evaluate_role(src)

    def _evaluate_role(self, ip: str):
        if not is_internal_ip(ip):
            return

        inbound_ports = self._inbound_clients_by_port.get(ip, {})
        dns_clients = len(inbound_ports.get(53, set()))
        smb_clients = len(inbound_ports.get(445, set()))
        krb_clients = len(inbound_ports.get(88, set()))
        ldap_clients = len(inbound_ports.get(389, set()))
        web_clients = len(inbound_ports.get(80, set())) + len(inbound_ports.get(443, set()))
        db_clients = len(inbound_ports.get(3306, set())) + len(inbound_ports.get(5432, set()))

        admin_targets = len(self._admin_outbound_targets.get(ip, set()))

        # 1. Domain Controller (Kerberos 88, LDAP 389 o SMB 445 servido a múltiples hosts)
        if krb_clients >= 3 or ldap_clients >= 3 or (smb_clients >= 5 and (krb_clients > 0 or ldap_clients > 0)):
            self._roles[ip] = AssetRole.INFRASTRUCTURE_DC
            return

        # 2. DNS Server (Puerto 53 entrante desde múltiples hosts)
        if dns_clients >= 4:
            self._roles[ip] = AssetRole.INFRASTRUCTURE_DNS
            return

        # 3. Estación de Gestión / Despliegue de Parches (SCCM, Ansible, Bastion)
        # Inicia conexiones administrativas salientes hacia 5 o más hosts de forma consistente
        if admin_targets >= 5 and smb_clients < 2:
            self._roles[ip] = AssetRole.ADMIN_MANAGEMENT
            return

        # 4. Servidor Web o Base de Datos Interna
        if web_clients >= 4 or db_clients >= 3:
            self._roles[ip] = AssetRole.INTERNAL_SERVER
            return

        # 5. Por defecto: Estación de trabajo estándar
        if ip not in self._roles:
            self._roles[ip] = AssetRole.WORKSTATION

    def get_role(self, ip: str) -> AssetRole:
        """Retorna el rol inferido para el activo o WORKSTATION si es desconocido."""
        return self._roles.get(ip, AssetRole.WORKSTATION)


class DynamicBaselineProfiler:
    """
    Orquestador central de perfiles de host y cálculo continuo de línea base gaussiana.
    """

    def __init__(self, anomaly_z_threshold: float = 3.5, min_samples_for_baseline: int = 10):
        self.anomaly_z_threshold = anomaly_z_threshold
        self.min_samples_for_baseline = min_samples_for_baseline

        # host_ip -> HostWelfordAccumulator
        self._accumulators: Dict[str, HostWelfordAccumulator] = defaultdict(HostWelfordAccumulator)
        self.classifier = AssetRoleClassifier()

    def ingest_flow(self, flow: NetFlowRecord) -> HostDeviationResult:
        """
        Ingesta un flujo, actualiza el perfil del activo y calcula la desviación (Z-Score)
        del host de origen respecto a su línea base histórica.
        """
        self.classifier.observe_flow(flow)

        src = flow.src_ip
        acc = self._accumulators[src]

        # Calcular Z-score antes de incorporar la muestra actual
        z_score = acc.calculate_z_score(flow.bytes)
        samples = acc.count
        mean_b = acc.mean_bytes
        stdev_b = acc.stdev_bytes

        # Actualizar acumulador Welford
        acc.update(flow.bytes, flow.packets)

        role = self.classifier.get_role(src)
        is_anomalous = (samples >= self.min_samples_for_baseline) and (z_score >= self.anomaly_z_threshold)

        return HostDeviationResult(
            host_ip=src,
            role=role,
            z_score=z_score,
            is_statistically_anomalous=is_anomalous,
            samples_count=samples,
            mean_bytes=round(mean_b, 1),
            stdev_bytes=round(stdev_b, 1),
            observed_bytes=flow.bytes,
        )

    def get_host_profile(self, ip: str) -> Dict[str, Any]:
        """Retorna el perfil estadístico y rol del host."""
        acc = self._accumulators.get(ip)
        role = self.classifier.get_role(ip)
        if not acc:
            return {
                "ip": ip,
                "role": role.value,
                "samples": 0,
                "mean_bytes": 0.0,
                "stdev_bytes": 0.0,
            }

        return {
            "ip": ip,
            "role": role.value,
            "samples": acc.count,
            "mean_bytes": round(acc.mean_bytes, 1),
            "stdev_bytes": round(acc.stdev_bytes, 1),
        }
