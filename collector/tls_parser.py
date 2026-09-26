"""
NovaFlow NDR - TLS ClientHello Binary Parser & Wire Data Extractor
Decodifica registros TLS en el cable (Wire Data) para análisis de tráfico cifrado (ETA)
sin requerir descifrado SSL ni inspección invasiva (Privacy-Preserving Inspection).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Set, Tuple


# Valores GREASE definidos en el RFC 8701 (Generate Random Extensions And Sustain Extensibility)
GREASE_VALUES: Set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def is_grease(val: int) -> bool:
    """Verifica si un valor numérico de 16 bits corresponde a una reserva GREASE."""
    return val in GREASE_VALUES


class TLSClientHello:
    """Estructura normalizada de metadatos extraídos de un mensaje TLS ClientHello."""

    def __init__(
        self,
        record_version: int,
        client_version: int,
        cipher_suites: List[int],
        extensions: List[int],
        sni: Optional[str] = None,
        alpn: Optional[str] = None,
        supported_groups: Optional[List[int]] = None,
        signature_algorithms: Optional[List[int]] = None,
        ec_point_formats: Optional[List[int]] = None,
        supported_versions: Optional[List[int]] = None,
    ):
        self.record_version = record_version
        self.client_version = client_version
        # Filtrar GREASE para generación determinista de huellas
        self.cipher_suites = [c for c in cipher_suites if not is_grease(c)]
        self.extensions = [e for e in extensions if not is_grease(e)]
        self.sni = sni
        self.alpn = alpn
        self.supported_groups = [g for g in (supported_groups or []) if not is_grease(g)]
        self.signature_algorithms = [s for s in (signature_algorithms or []) if not is_grease(s)]
        self.ec_point_formats = ec_point_formats or []
        self.supported_versions = [v for v in (supported_versions or []) if not is_grease(v)]

    @property
    def effective_version(self) -> int:
        """Determina la versión TLS efectiva negociada considerando extensiones."""
        if self.supported_versions:
            # TLS 1.3 se declara prioritariamente en la extensión supported_versions (0x002b)
            if 0x0304 in self.supported_versions:
                return 0x0304
            if 0x0303 in self.supported_versions:
                return 0x0303
        return self.client_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_version": f"0x{self.record_version:04x}",
            "client_version": f"0x{self.client_version:04x}",
            "effective_version": f"0x{self.effective_version:04x}",
            "sni": self.sni,
            "alpn": self.alpn,
            "ciphers_count": len(self.cipher_suites),
            "extensions_count": len(self.extensions),
            "ciphers": [f"0x{c:04x}" for c in self.cipher_suites],
            "extensions": [f"0x{e:04x}" for e in self.extensions],
            "supported_groups": [f"0x{g:04x}" for g in self.supported_groups],
            "signature_algorithms": [f"0x{s:04x}" for s in self.signature_algorithms],
        }


class TLSParser:
    """
    Parser binario zero-copy para registros TLS Handshake.
    Capaz de operar sobre paquetes TCP crudos o volcados de red.
    """

    TLS_RECORD_HANDSHAKE = 0x16
    TLS_HANDSHAKE_CLIENT_HELLO = 0x01

    @classmethod
    def parse_client_hello(cls, data: bytes) -> Optional[TLSClientHello]:
        """
        Analiza un buffer de bytes en busca de un registro TLS ClientHello.
        Retorna la instancia TLSClientHello o None si el payload no es TLS válido.
        """
        if len(data) < 44:  # Tamaño mínimo para un ClientHello básico
            return None

        # Verificar si comienza con cabecera de registro TLS
        content_type = data[0]
        if content_type != cls.TLS_RECORD_HANDSHAKE:
            return None

        record_version = struct.unpack("!H", data[1:3])[0]
        record_len = struct.unpack("!H", data[3:5])[0]

        if len(data) < 5 + min(record_len, 40):
            return None

        offset = 5
        # Verificar tipo de Handshake
        handshake_type = data[offset]
        if handshake_type != cls.TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        # handshake_len = struct.unpack("!I", b"\x00" + data[offset+1:offset+4])[0]
        offset += 4

        if offset + 34 > len(data):
            return None

        client_version = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= len(data):
            return None
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Cipher Suites
        if offset + 2 > len(data):
            return None
        ciphers_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2

        if offset + ciphers_len > len(data):
            return None

        cipher_suites: List[int] = []
        for i in range(0, ciphers_len, 2):
            if offset + i + 2 <= len(data):
                cipher = struct.unpack("!H", data[offset+i:offset+i+2])[0]
                cipher_suites.append(cipher)
        offset += ciphers_len

        # Compression Methods
        if offset >= len(data):
            return None
        compression_len = data[offset]
        offset += 1 + compression_len

        # Extensions
        extensions: List[int] = []
        sni: Optional[str] = None
        alpn: Optional[str] = None
        supported_groups: List[int] = []
        signature_algorithms: List[int] = []
        ec_point_formats: List[int] = []
        supported_versions: List[int] = []

        if offset + 2 <= len(data):
            extensions_total_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            ext_end = min(len(data), offset + extensions_total_len)

            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", data[offset:offset+2])[0]
                ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
                offset += 4

                if offset + ext_len > len(data):
                    break

                ext_data = data[offset:offset+ext_len]
                extensions.append(ext_type)

                # Decodificar extensiones críticas para fingerprinting
                if ext_type == 0x0000:  # Server Name Indication (SNI)
                    sni = cls._parse_sni(ext_data)
                elif ext_type == 0x0010:  # ALPN
                    alpn = cls._parse_alpn(ext_data)
                elif ext_type == 0x000A:  # Supported Groups
                    supported_groups = cls._parse_uint16_list(ext_data)
                elif ext_type == 0x000D:  # Signature Algorithms
                    signature_algorithms = cls._parse_uint16_list(ext_data)
                elif ext_type == 0x000B:  # EC Point Formats
                    ec_point_formats = [int(b) for b in ext_data[1:]] if len(ext_data) > 1 else []
                elif ext_type == 0x002B:  # Supported Versions
                    supported_versions = cls._parse_supported_versions(ext_data)

                offset += ext_len

        return TLSClientHello(
            record_version=record_version,
            client_version=client_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            sni=sni,
            alpn=alpn,
            supported_groups=supported_groups,
            signature_algorithms=signature_algorithms,
            ec_point_formats=ec_point_formats,
            supported_versions=supported_versions,
        )

    @classmethod
    def _parse_sni(cls, data: bytes) -> Optional[str]:
        """Extrae el nombre de host del bloque SNI."""
        if len(data) < 5:
            return None
        try:
            # sni_list_len = struct.unpack("!H", data[0:2])[0]
            name_type = data[2]
            if name_type == 0x00:  # host_name
                name_len = struct.unpack("!H", data[3:5])[0]
                if 5 + name_len <= len(data):
                    return data[5:5+name_len].decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    @classmethod
    def _parse_alpn(cls, data: bytes) -> Optional[str]:
        """Extrae el primer protocolo negociado en la extensión ALPN."""
        if len(data) < 3:
            return None
        try:
            # alpn_list_len = struct.unpack("!H", data[0:2])[0]
            proto_len = data[2]
            if 3 + proto_len <= len(data):
                return data[3:3+proto_len].decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    @classmethod
    def _parse_uint16_list(cls, data: bytes) -> List[int]:
        """Parsea una lista de enteros de 16 bits precedida por su longitud."""
        if len(data) < 2:
            return []
        try:
            list_len = struct.unpack("!H", data[0:2])[0]
            items = []
            for i in range(2, min(len(data), 2 + list_len), 2):
                if i + 2 <= len(data):
                    val = struct.unpack("!H", data[i:i+2])[0]
                    items.append(val)
            return items
        except Exception:
            return []

    @classmethod
    def _parse_supported_versions(cls, data: bytes) -> List[int]:
        """Extrae versiones soportadas (RFC 8446 con longitud uint8 en ClientHello)."""
        if len(data) < 3:
            return []
        try:
            list_len = data[0]
            items = []
            for i in range(1, min(len(data), 1 + list_len), 2):
                if i + 2 <= len(data):
                    val = struct.unpack("!H", data[i:i+2])[0]
                    items.append(val)
            if items:
                return items
        except Exception:
            pass
        return cls._parse_uint16_list(data)

