"""
NovaFlow NDR - JA4 & Encrypted Traffic Analytics (ETA) Detection Rule
Evalúa metadatos criptográficos TLS y secuencias SPLT para identificar canales C2
ocultos y herramientas adversarias sin descifrado de carga útil (Privacy-Preserving).
"""

from typing import Any, Dict, Optional

from collector.parser import NetFlowRecord
from collector.tls_parser import TLSClientHello
from detector.ja4 import JA4Fingerprint, SPLTProfile
from detector.ja4_database import JA4Database
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class JA4ThreatDetector:
    """Regla analítica para detección de amenazas TLS mediante huellas JA4/JA3 y perfiles SPLT."""

    def __init__(self, db: Optional[JA4Database] = None):
        self.db = db or JA4Database()

    def evaluate_tls_hello(
        self,
        hello: TLSClientHello,
        src_ip: str = "10.0.0.1",
        dst_ip: str = "198.51.100.1",
        dst_port: int = 443,
        protocol: str = "TCP",
    ) -> Optional[SecurityAlert]:
        """Analiza un objeto TLSClientHello directamente capturado del cable."""
        ja4_hash = JA4Fingerprint.calculate_ja4(hello, protocol=protocol)
        ja3_hash, _ = JA4Fingerprint.calculate_ja3(hello)

        threat_meta = self.db.is_known_malicious(ja4_hash, ja3_hash)
        if threat_meta:
            family = threat_meta.get("family", "Malicious TLS")
            tool = threat_meta.get("tool", "Unknown Implant")
            sev_str = threat_meta.get("severity", "CRITICAL")
            severity = AlertSeverity.CRITICAL if sev_str == "CRITICAL" else AlertSeverity.HIGH

            return SecurityAlert(
                severity=severity,
                category=AlertCategory.MALICIOUS_C2,
                title=f"Detección Criptográfica JA4 ({family}): {tool}",
                description=(
                    f"Sesión TLS cifrada iniciada desde {src_ip} hacia {dst_ip}:{dst_port} "
                    f"coincide con la firma de malware/C2 '{family}' (Herramienta: {tool}). "
                    f"Huella JA4 calculada: {ja4_hash} | JA3: {ja3_hash}."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=6,
                confidence=0.96,
                metrics={
                    "ja4": ja4_hash,
                    "ja3": ja3_hash,
                    "family": family,
                    "tool": tool,
                    "sni": hello.sni,
                    "alpn": hello.alpn,
                    "detection_method": "JA4_FINGERPRINT_MATCH",
                },
            )

        return None

    def evaluate_splt_profile(
        self,
        splt: SPLTProfile,
        src_ip: str,
        dst_ip: str,
        dst_port: int = 443,
        ja4_hash: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        """Evalúa el perfil SPLT de una sesión para identificar balizamiento C2 cifrado."""
        if not splt.is_beacon_pattern():
            return None

        # Si coincide con un navegador legítimo conocido en navegación regular, descartar falso positivo
        if ja4_hash and self.db.is_legitimate_baseline(ja4_hash):
            return None

        entropy = splt.calculate_entropy()

        return SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.C2_BEACONING,
            title=f"Canal C2 Cifrado Detectado mediante Análisis SPLT (ETA): {dst_ip}:{dst_port}",
            description=(
                f"La sesión cifrada entre {src_ip} y {dst_ip}:{dst_port} presenta un patrón "
                f"altamente uniforme de paquetes de consulta (baja varianza en tamaño) característico "
                f"de balizamiento C2 periódico. Entropía de longitud calculada: {entropy:.4f}."
            ),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=6,
            confidence=0.89,
            metrics={
                "detection_method": "SPLT_BEACON_CADENCE",
                "entropy": entropy,
                "client_bytes": splt.client_bytes,
                "server_bytes": splt.server_bytes,
                "packets_evaluated": len(splt.packet_sequence),
                "ja4": ja4_hash,
            },
        )
