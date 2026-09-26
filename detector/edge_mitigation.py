"""
NovaFlow NDR - BGP Flowspec (RFC 5575 / RFC 8955) & Cloud-Native Zero-Trust Engine
Generador de políticas de mitigación de borde en routers troncales (Cisco IOS-XR, Juniper Junos,
ExaBGP) y manifiestos de microsegmentación Zero-Trust para Kubernetes CNI (Cilium y Calico).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from detector.models import AlertCategory, SecurityAlert


class BGPFlowspecAction(str, Enum):
    DROP_TRAFFIC = "DROP_TRAFFIC"
    RATE_LIMIT = "RATE_LIMIT"
    REDIRECT_VRF = "REDIRECT_VRF"
    DSCP_MARKING = "DSCP_MARKING"


@dataclass
class BGPFlowspecRule:
    """Regla de filtrado y acción conforme a la especificación RFC 5575."""

    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    src_prefix: Optional[str] = None
    dst_prefix: Optional[str] = None
    protocol: Optional[int] = None       # 6=TCP, 17=UDP, 1=ICMP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None      # e.g., "SYN", "ACK"
    action: BGPFlowspecAction = BGPFlowspecAction.DROP_TRAFFIC
    rate_bytes_sec: int = 0              # 0 para descarte total (blackholing)
    redirect_vrf: Optional[str] = None   # Nombre de VRF para análisis/sandbox
    dscp_mark: Optional[int] = None      # DSCP value (0-63)

    def to_exabgp(self) -> str:
        """Sintaxis de inyección para el demonio ExaBGP / BGP SDN Controller."""
        match_parts = []
        if self.src_prefix:
            src_str = self.src_prefix if "/" in self.src_prefix else f"{self.src_prefix}/32"
            match_parts.append(f"source {src_str};")
        if self.dst_prefix:
            dst_str = self.dst_prefix if "/" in self.dst_prefix else f"{self.dst_prefix}/32"
            match_parts.append(f"destination {dst_str};")
        if self.protocol == 6:
            match_parts.append("protocol tcp;")
        elif self.protocol == 17:
            match_parts.append("protocol udp;")
        elif self.protocol == 1:
            match_parts.append("protocol icmp;")

        if self.dst_port:
            match_parts.append(f"destination-port ={self.dst_port};")
        if self.src_port:
            match_parts.append(f"source-port ={self.src_port};")
        if self.tcp_flags:
            match_parts.append(f"tcp-flags {self.tcp_flags.lower()};")

        match_block = " ".join(match_parts)

        if self.action == BGPFlowspecAction.DROP_TRAFFIC or (self.action == BGPFlowspecAction.RATE_LIMIT and self.rate_bytes_sec == 0):
            action_block = "rate-limit 0;"
        elif self.action == BGPFlowspecAction.RATE_LIMIT:
            action_block = f"rate-limit {self.rate_bytes_sec};"
        elif self.action == BGPFlowspecAction.REDIRECT_VRF:
            action_block = f"redirect 65000:{self.redirect_vrf or 'SANDBOX'};"
        elif self.action == BGPFlowspecAction.DSCP_MARKING:
            action_block = f"mark {self.dscp_mark or 0};"
        else:
            action_block = "rate-limit 0;"

        return f"announce flow route {{ match {{ {match_block} }} then {{ {action_block} }} }}"

    def to_juniper_junos(self) -> str:
        """Sintaxis de configuración para Junos OS (Juniper Networks)."""
        name = f"FS_NOVA_{self.rule_id[:8]}"
        cmds = [f"set routing-options flow route {name} match"]
        if self.src_prefix:
            cmds.append(f"source {self.src_prefix}/32" if "/" not in self.src_prefix else f"source {self.src_prefix}")
        if self.dst_prefix:
            cmds.append(f"destination {self.dst_prefix}/32" if "/" not in self.dst_prefix else f"destination {self.dst_prefix}")
        if self.protocol == 6:
            cmds.append("protocol tcp")
        elif self.protocol == 17:
            cmds.append("protocol udp")
        if self.dst_port:
            cmds.append(f"destination-port {self.dst_port}")

        match_line = " ".join(cmds)
        then_line = f"set routing-options flow route {name} then discard"
        if self.action == BGPFlowspecAction.REDIRECT_VRF:
            then_line = f"set routing-options flow route {name} then routing-instance {self.redirect_vrf or 'SANDBOX'}"

        return f"{match_line}\n{then_line}"

    def to_cisco_iosxr(self) -> str:
        """Sintaxis de configuración modular para Cisco IOS-XR."""
        class_name = f"CLASS_FS_{self.rule_id[:8]}"
        policy_name = "POLICY_NOVAFLOW_FLOWSPEC"
        proto_str = "tcp" if self.protocol == 6 else ("udp" if self.protocol == 17 else "ipv4")

        lines = [
            f"class-map type traffic match-all {class_name}",
        ]
        if self.dst_prefix:
            lines.append(f" match destination-address ipv4 {self.dst_prefix}/32" if "/" not in self.dst_prefix else f" match destination-address ipv4 {self.dst_prefix}")
        if self.src_prefix:
            lines.append(f" match source-address ipv4 {self.src_prefix}/32" if "/" not in self.src_prefix else f" match source-address ipv4 {self.src_prefix}")
        if self.dst_port:
            lines.append(f" match destination-port {self.dst_port}")
        lines.append("end-class-map")

        lines.append(f"policy-map type pbr {policy_name}")
        lines.append(f" class {class_name}")
        if self.action == BGPFlowspecAction.DROP_TRAFFIC:
            lines.append("  drop")
        elif self.action == BGPFlowspecAction.RATE_LIMIT:
            lines.append(f"  police rate {self.rate_bytes_sec} bps")
        elif self.action == BGPFlowspecAction.REDIRECT_VRF:
            lines.append(f"  redirect vrf {self.redirect_vrf or 'SANDBOX'}")
        lines.append("end-policy-map")

        return "\n".join(lines)


class BGPFlowspecGenerator:
    """Motor generador de reglas BGP Flowspec a partir de incidentes de seguridad."""

    @classmethod
    def generate_from_alert(
        cls,
        alert: SecurityAlert,
        action: BGPFlowspecAction = BGPFlowspecAction.DROP_TRAFFIC,
        redirect_vrf: Optional[str] = None,
    ) -> BGPFlowspecRule:
        """Formula la regla BGP Flowspec óptima para contener la amenaza en el borde de la red."""
        # Si es un ataque DoS volumétrico, filtrar tráfico dirigido al objetivo en el puerto atacado
        if alert.category == AlertCategory.SYN_FLOOD:
            return BGPFlowspecRule(
                src_prefix=None,
                dst_prefix=alert.dst_ip,
                protocol=6,
                dst_port=alert.dst_port or 80,
                tcp_flags="SYN",
                action=action,
                rate_bytes_sec=0,
                redirect_vrf=redirect_vrf,
            )

        # Si es C2 o exfiltración, aislar bidireccionalmente la IP hostil externa
        if alert.category in (AlertCategory.MALICIOUS_C2, AlertCategory.C2_BEACONING, AlertCategory.EXFILTRATION):
            return BGPFlowspecRule(
                src_prefix=None,
                dst_prefix=alert.dst_ip,
                protocol=alert.protocol or 6,
                dst_port=alert.dst_port if alert.dst_port > 0 else None,
                action=action,
                rate_bytes_sec=0,
                redirect_vrf=redirect_vrf,
            )

        # Por defecto aislar el tráfico del atacante
        return BGPFlowspecRule(
            src_prefix=alert.src_ip,
            dst_prefix=alert.dst_ip if alert.dst_ip != "0.0.0.0" else None,
            protocol=alert.protocol or 6,
            dst_port=alert.dst_port if alert.dst_port > 0 else None,
            action=action,
            rate_bytes_sec=0,
            redirect_vrf=redirect_vrf,
        )


class CloudNativeZeroTrustGenerator:
    """Generador de políticas de microsegmentación Zero-Trust para clústeres Kubernetes."""

    @classmethod
    def generate_cilium_quarantine_policy(
        cls,
        target_ip: str,
        namespace: str = "production",
        incident_id: str = "INC-001",
    ) -> str:
        """Genera un manifiesto CiliumNetworkPolicy para aislamiento quirúrgico de Pods."""
        return f"""apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "novaflow-quarantine-{incident_id[:8].lower()}"
  namespace: "{namespace}"
  labels:
    app.kubernetes.io/managed-by: novaflow-ndr
    security.novaflow.io/action: quarantine
spec:
  endpointSelector:
    matchLabels:
      io.kubernetes.pod.ip: "{target_ip}"
  ingress:
    # Bloquear todo el tráfico entrante excepto sondas de liveness y recolección forense
    - fromEndpoints:
        - matchLabels:
            app: novaflow-forensics-agent
  egress:
    # Bloquear todo el tráfico saliente (previene C2 y exfiltración Este-Oeste)
    - toEntities:
        - none
"""

    @classmethod
    def generate_k8s_network_policy(
        cls,
        pod_label_key: str = "app",
        pod_label_val: str = "compromised-workload",
        namespace: str = "production",
    ) -> str:
        """Genera una NetworkPolicy estándar de Kubernetes para aislamiento total (Default-Deny)."""
        return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "novaflow-isolate-{pod_label_val}"
  namespace: "{namespace}"
spec:
  podSelector:
    matchLabels:
      {pod_label_key}: "{pod_label_val}"
  policyTypes:
  - Ingress
  - Egress
  # Sin reglas de ingress ni egress -> Aislamiento absoluto (Drop All)
"""
