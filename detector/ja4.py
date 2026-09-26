"""
NovaFlow NDR - JA4 & JA3 Cryptographic Fingerprinting & SPLT Engine
Generador canónico de huellas criptográficas JA4 (FoxIO standard) y JA3 retrocompatible,
junto con perfiles SPLT (Sequence of Packet Lengths and Times) para Encrypted Traffic Analytics (ETA).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple
from collector.tls_parser import TLSClientHello


class JA4Fingerprint:
    """Calculador y contenedor de huellas TLS canónicas JA4 y JA3."""

    @classmethod
    def calculate_ja4(cls, hello: TLSClientHello, protocol: str = "TCP") -> str:
        """
        Genera la huella canónica JA4 según la especificación formal de FoxIO:
        Formato: [JA4_a]_[JA4_b]_[JA4_c]
        Ejemplo: t13d1516h2_8daaf6152771_e562703ab855
        """
        # 1. JA4_a: Protocolo + Versión + SNI + CiphersCount + ExtsCount + ALPN
        proto_char = "t" if protocol.upper() == "TCP" else "q"

        # Versión TLS
        eff_ver = hello.effective_version
        if eff_ver == 0x0304:
            ver_str = "13"
        elif eff_ver == 0x0303:
            ver_str = "12"
        elif eff_ver == 0x0302:
            ver_str = "11"
        elif eff_ver == 0x0301:
            ver_str = "10"
        elif eff_ver == 0x0300:
            ver_str = "s3"
        else:
            ver_str = "00"

        # Presencia de SNI (d=domain, i=ip/none)
        sni_char = "d" if (hello.sni and not cls._is_ip_address(hello.sni)) else "i"

        # Contadores de Ciphers y Extensiones (limitados a 99)
        ciphers_count = min(len(hello.cipher_suites), 99)
        ciphers_str = f"{ciphers_count:02d}"

        exts_count = min(len(hello.extensions), 99)
        exts_str = f"{exts_count:02d}"

        # ALPN: primer y último carácter del primer protocolo negociado
        alpn_str = "00"
        if hello.alpn and len(hello.alpn) >= 1:
            if len(hello.alpn) == 1:
                alpn_str = hello.alpn[0] + hello.alpn[0]
            else:
                alpn_str = hello.alpn[0] + hello.alpn[-1]

        ja4_a = f"{proto_char}{ver_str}{sni_char}{ciphers_str}{exts_str}{alpn_str}"

        # 2. JA4_b: Hash truncado a 12 caracteres de Cipher Suites ordenados alfanuméricamente
        if hello.cipher_suites:
            sorted_ciphers = sorted(f"{c:04x}" for c in hello.cipher_suites)
            raw_b = ",".join(sorted_ciphers)
            ja4_b = hashlib.sha256(raw_b.encode("utf-8")).hexdigest()[:12]
        else:
            ja4_b = "000000000000"

        # 3. JA4_c: Hash truncado a 12 caracteres de Extensiones ordenadas + Signature Algorithms
        if hello.extensions:
            # Excluir extensiones SNI (0x0000) y ALPN (0x0010) del hash según spec JA4
            filtered_exts = [e for e in hello.extensions if e not in (0x0000, 0x0010)]
            sorted_exts = sorted(f"{e:04x}" for e in filtered_exts)
            raw_c = ",".join(sorted_exts)

            if hello.signature_algorithms:
                sig_str = ",".join(f"{s:04x}" for s in hello.signature_algorithms)
                raw_c += f"_{sig_str}"

            ja4_c = hashlib.sha256(raw_c.encode("utf-8")).hexdigest()[:12]
        else:
            ja4_c = "000000000000"

        return f"{ja4_a}_{ja4_b}_{ja4_c}"

    @classmethod
    def calculate_ja3(cls, hello: TLSClientHello) -> Tuple[str, str]:
        """
        Genera la huella clásica JA3 y su cadena fuente cruda.
        Retorna (ja3_hash_md5, raw_ja3_string).
        """
        # Formato canónico JA3: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
        ver = str(hello.client_version)
        ciphers = "-".join(str(c) for c in hello.cipher_suites)
        exts = "-".join(str(e) for e in hello.extensions)
        groups = "-".join(str(g) for g in hello.supported_groups)
        points = "-".join(str(p) for p in hello.ec_point_formats)

        raw_ja3 = f"{ver},{ciphers},{exts},{groups},{points}"
        ja3_hash = hashlib.md5(raw_ja3.encode("utf-8")).hexdigest()
        return ja3_hash, raw_ja3

    @staticmethod
    def _is_ip_address(val: str) -> bool:
        """Determina si un host es una dirección IP numérica o un nombre de dominio."""
        parts = val.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
        return ":" in val


class SPLTProfile:
    """
    Perfil SPLT (Sequence of Packet Lengths and Times) para análisis de tráfico cifrado (ETA).
    Captura los primeros N paquetes de una sesión para clasificar el canal sin descifrado.
    """

    def __init__(self, max_packets: int = 30):
        self.max_packets = max_packets
        # Lista de tuplas: (longitud_bytes_con_signo, delta_ms_desde_anterior)
        # Signo positivo: Cliente -> Servidor. Signo negativo: Servidor -> Cliente.
        self.packet_sequence: List[Tuple[int, float]] = []
        self.last_timestamp: Optional[float] = None
        self.client_bytes: int = 0
        self.server_bytes: int = 0

    def add_packet(self, length: int, direction: str, timestamp: float):
        """Registra un paquete en la secuencia."""
        if len(self.packet_sequence) >= self.max_packets:
            return

        signed_len = length if direction.upper() in ("OUT", "CLIENT", "C2S") else -length
        if signed_len > 0:
            self.client_bytes += length
        else:
            self.server_bytes += length

        delta_ms = 0.0
        if self.last_timestamp is not None:
            delta_ms = max(0.0, (timestamp - self.last_timestamp) * 1000.0)
        self.last_timestamp = timestamp

        self.packet_sequence.append((signed_len, round(delta_ms, 2)))

    def calculate_entropy(self) -> float:
        """Calcula la entropía de Shannon sobre las longitudes absolutas de los paquetes."""
        if not self.packet_sequence:
            return 0.0
        lengths = [abs(p[0]) for p in self.packet_sequence]
        total = sum(lengths)
        if total == 0:
            return 0.0

        entropy = 0.0
        for l in lengths:
            p = l / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def is_beacon_pattern(self) -> bool:
        """
        Determina heurísticamente si la secuencia exhibe un patrón regular de balizamiento C2:
        - Paquetes de longitud casi idéntica en ráfagas de consulta de tamaño reducido (<600 bytes)
        - Baja varianza en el tamaño de las peticiones iniciales.
        """
        if len(self.packet_sequence) < 4:
            return False

        client_lens = [abs(p[0]) for p in self.packet_sequence if p[0] > 0]
        if len(client_lens) < 3:
            return False

        avg_len = sum(client_lens) / len(client_lens)
        if avg_len > 800:
            return False

        variance = sum((l - avg_len) ** 2 for l in client_lens) / len(client_lens)
        # Una varianza baja en tamaños pequeños sugiere balizas programadas
        return variance < 150.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets_recorded": len(self.packet_sequence),
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "length_entropy": self.calculate_entropy(),
            "beacon_pattern_detected": self.is_beacon_pattern(),
            "sequence": self.packet_sequence[:15],  # Muestra inicial
        }
