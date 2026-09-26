"""
NovaFlow NDR - Active Directory & Identity Threat Detection Rule
Identifica técnicas de ataque de identidad sin agentes en la red corporativa:
Kerberoasting, AS-REP Roasting, DCSync (drsuapi) y ejecución remota vía PsExec (svcctl).
"""

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from collector.l7_parsers import DCERPCMessage, KerberosMessage
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class ActiveDirectoryThreatDetector:
    """Regla analítica para detección de intrusiones en Directorio Activo (L7)."""

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        # src_ip -> list of (timestamp, spn)
        self._tgs_rc4_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

    def evaluate_kerberos(
        self,
        msg: KerberosMessage,
        src_ip: str,
        kdc_ip: str,
    ) -> Optional[SecurityAlert]:
        """Evalúa un mensaje de autenticación Kerberos."""
        now = time.time()

        # 1. Detección de AS-REP Roasting (AS-REQ sin preautenticación)
        if msg.msg_name == "AS-REQ" and not msg.has_preauth:
            return SecurityAlert(
                severity=AlertSeverity.HIGH,
                category=AlertCategory.IDENTITY_ATTACK,
                title=f"Posible Ataque AS-REP Roasting: Solicitud sin Pre-Autenticación desde {src_ip}",
                description=(
                    f"El host {src_ip} emitió una solicitud de ticket inicial AS-REQ hacia el KDC "
                    f"{kdc_ip}:88 sin incluir la marca de tiempo cifrada obligatoria (PA-ENC-TIMESTAMP). "
                    f"Técnica utilizada comúnmente para capturar hashes AS-REP y crackear contraseñas offline."
                ),
                src_ip=src_ip,
                dst_ip=kdc_ip,
                dst_port=88,
                protocol=17,
                confidence=0.88,
                metrics={
                    "technique": "AS-REP Roasting",
                    "has_preauth": False,
                    "mitre": "T1558.004",
                },
            )

        # 2. Detección de Kerberoasting (TGS-REQ con solicitud de cifrado débil RC4)
        if msg.msg_name == "TGS-REQ" and msg.is_rc4_requested:
            spn_target = "/".join(msg.sname) if msg.sname else "ServiceAccount"
            self._tgs_rc4_history[src_ip].append((now, spn_target))

            # Poda temporal
            cutoff = now - self.window_seconds
            self._tgs_rc4_history[src_ip] = [
                e for e in self._tgs_rc4_history[src_ip] if e[0] >= cutoff
            ]

            recent = self._tgs_rc4_history[src_ip]
            unique_spns = set(e[1] for e in recent)

            # Si solicita RC4 para cuentas de servicio específicas (o ráfaga >= 2 SPNs)
            if len(unique_spns) >= 2 or ("MSSQLSvc" in spn_target) or len(recent) >= 3:
                return SecurityAlert(
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.IDENTITY_ATTACK,
                    title=f"Ataque Kerberoasting Detectado: Solicitud TGS (RC4) desde {src_ip}",
                    description=(
                        f"El host interno {src_ip} solicitó tickets de servicio TGS hacia {kdc_ip}:88 "
                        f"forzando el tipo de cifrado vulnerable RC4-HMAC (etype 0x17) sobre {len(unique_spns)} "
                        f"cuentas de servicio ({', '.join(list(unique_spns)[:3])}). Patrón típico de Rubeus/Impacket."
                    ),
                    src_ip=src_ip,
                    dst_ip=kdc_ip,
                    dst_port=88,
                    protocol=6,
                    confidence=0.96,
                    metrics={
                        "technique": "Kerberoasting",
                        "cipher_requested": "RC4-HMAC (0x17)",
                        "targeted_spns": list(unique_spns),
                        "tgs_requests_count": len(recent),
                        "mitre": "T1558.003",
                    },
                )

        return None

    def evaluate_dcerpc(
        self,
        msg: DCERPCMessage,
        src_ip: str,
        target_ip: str,
        port: int = 445,
    ) -> Optional[SecurityAlert]:
        """Evalúa una transacción DCE-RPC / SMB buscando explotación de interfaces críticas."""
        if not msg.interface_name:
            return None

        # 1. Ataque DCSync (Replicación no autorizada de credenciales NTDS vía DRSUAPI)
        if msg.interface_name == "drsuapi":
            return SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.IDENTITY_ATTACK,
                title=f"Ataque DCSync Detectado: Invocación de DRSUAPI desde {src_ip} hacia {target_ip}",
                description=(
                    f"El host {src_ip} intentó enlazar (Bind) la interfaz de replicación de Directorio Activo "
                    f"DRSUAPI (UUID: {msg.interface_uuid}) contra el servidor {target_ip}:{port}. "
                    f"Esta técnica es utilizada por Mimikatz / Impacket para extraer la base de datos ntds.dit."
                ),
                src_ip=src_ip,
                dst_ip=target_ip,
                dst_port=port,
                protocol=6,
                confidence=0.98,
                metrics={
                    "interface": "drsuapi",
                    "uuid": msg.interface_uuid,
                    "technique": "DCSync",
                    "mitre": "T1003.006",
                },
            )

        # 2. Ejecución Remota de Servicios (PsExec / Lateral Movement vía svcctl)
        if msg.interface_name == "svcctl":
            return SecurityAlert(
                severity=AlertSeverity.HIGH,
                category=AlertCategory.LATERAL_MOVEMENT,
                title=f"Movimiento Lateral MSRPC (PsExec/svcctl): {src_ip} -> {target_ip}",
                description=(
                    f"Se detectó la conexión a la interfaz Service Control Manager (svcctl) "
                    f"desde {src_ip} hacia {target_ip}:{port}. Patrón característico de ejecución remota "
                    f"y creación de servicios maliciosos (PsExec / Impacket psexec)."
                ),
                src_ip=src_ip,
                dst_ip=target_ip,
                dst_port=port,
                protocol=6,
                confidence=0.92,
                metrics={
                    "interface": "svcctl",
                    "uuid": msg.interface_uuid,
                    "technique": "Service Execution",
                    "mitre": "T1021.002",
                },
            )

        return None
