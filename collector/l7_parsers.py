"""
NovaFlow NDR - Layer 7 Identity & Active Directory Protocol Parsers
Decodificadores binarios en Python puro para Kerberos v5 (RFC 4120) y DCE-RPC (MSRPC).
Permite la inspección profunda de autenticación e invocaciones RPC críticas sin agentes.
"""

from __future__ import annotations

import struct
import uuid
from typing import Any, Dict, List, Optional, Tuple


# UUIDs de interfaces DCE-RPC de alto riesgo en Active Directory
KNOWN_RPC_INTERFACES: Dict[str, Dict[str, str]] = {
    "367abb81-9844-35f1-ad32-98f038001003": {
        "name": "svcctl",
        "description": "Service Control Manager (Creación y ejecución remota de servicios / PsExec)",
        "risk": "HIGH",
        "mitre_technique": "T1021.002",
    },
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": {
        "name": "drsuapi",
        "description": "Directory Replication Service (Replicación DCSync / Extracción de hashes ntds.dit)",
        "risk": "CRITICAL",
        "mitre_technique": "T1003.006",
    },
    "12345778-1234-abcd-ef00-0123456789ac": {
        "name": "samr",
        "description": "Security Account Manager Remote (Enumeración de usuarios y grupos locales)",
        "risk": "MEDIUM",
        "mitre_technique": "T1087.002",
    },
    "12345778-1234-abcd-ef00-0123456789ab": {
        "name": "lsarpc",
        "description": "Local Security Authority RPC (Consulta de directivas de seguridad y dominios)",
        "risk": "MEDIUM",
        "mitre_technique": "T1087.002",
    },
}


class ASN1Reader:
    """Lector ligero de secuencias binarias ASN.1 DER (Tag-Length-Value)."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def has_more(self) -> bool:
        return self.offset < len(self.data)

    def read_tlv(self) -> Optional[Tuple[int, bytes]]:
        """Lee el siguiente elemento ASN.1 Tag-Length-Value."""
        if self.offset >= len(self.data):
            return None

        tag = self.data[self.offset]
        self.offset += 1

        if self.offset >= len(self.data):
            return None

        length_byte = self.data[self.offset]
        self.offset += 1

        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            if self.offset + num_len_bytes > len(self.data):
                return None
            length = int.from_bytes(self.data[self.offset:self.offset + num_len_bytes], "big")
            self.offset += num_len_bytes
        else:
            length = length_byte

        if self.offset + length > len(self.data):
            return None

        val = self.data[self.offset:self.offset + length]
        self.offset += length
        return tag, val


class KerberosMessage:
    """Estructura de metadatos de un paquete Kerberos decodificado."""

    def __init__(
        self,
        msg_type: int,
        msg_name: str,
        has_preauth: bool = False,
        etypes: Optional[List[int]] = None,
        sname: Optional[List[str]] = None,
        realm: Optional[str] = None,
    ):
        self.msg_type = msg_type
        self.msg_name = msg_name
        self.has_preauth = has_preauth
        self.etypes = etypes or []
        self.sname = sname or []
        self.realm = realm

    @property
    def is_rc4_requested(self) -> bool:
        """Determina si la solicitud exige cifrado débil RC4-HMAC (etype 23 / 0x17)."""
        return 0x17 in self.etypes or 23 in self.etypes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_type": self.msg_type,
            "msg_name": self.msg_name,
            "has_preauth": self.has_preauth,
            "etypes": [f"0x{e:02x}" for e in self.etypes],
            "is_rc4_requested": self.is_rc4_requested,
            "sname": "/".join(self.sname) if self.sname else None,
            "realm": self.realm,
        }


class KerberosParser:
    """Parser binario para mensajes Kerberos v5 (puerto 88 TCP/UDP)."""

    MSG_TYPES = {
        0x6A: (10, "AS-REQ"),
        0x6B: (11, "AS-REP"),
        0x6C: (12, "TGS-REQ"),
        0x6D: (13, "TGS-REP"),
        0x6E: (14, "AP-REQ"),
        0x7E: (30, "KRB-ERROR"),
    }

    @classmethod
    def parse_payload(cls, data: bytes) -> Optional[KerberosMessage]:
        """Analiza un payload de red en busca de un mensaje Kerberos válido."""
        if len(data) < 6:
            return None

        # Si viene encapsulado sobre TCP, los primeros 4 bytes son la longitud
        payload = data
        if len(data) > 4:
            possible_tcp_len = struct.unpack("!I", data[:4])[0]
            if possible_tcp_len == len(data) - 4:
                payload = data[4:]

        if not payload:
            return None

        first_tag = payload[0]
        if first_tag not in cls.MSG_TYPES:
            return None

        msg_type_id, msg_name = cls.MSG_TYPES[first_tag]

        # Analizar campos TLV internos
        reader = ASN1Reader(payload)
        tlv = reader.read_tlv()
        if not tlv:
            return None

        body_data = tlv[1]
        has_preauth = False
        etypes: List[int] = []
        sname: List[str] = []
        realm = None

        # Búsqueda heurística en el cuerpo ASN.1
        # PA-ENC-TIMESTAMP (padata-type 2)
        if b"\x02\x01\x02" in body_data or b"\xa1\x03\x02\x01\x02" in body_data:
            has_preauth = True

        # Extracción de etypes solicitados
        # RC4-HMAC es 0x17 (23 dec), AES256 es 0x12 (18 dec), AES128 es 0x11 (17 dec)
        if b"\x02\x01\x17" in body_data:
            etypes.append(0x17)
        if b"\x02\x01\x12" in body_data:
            etypes.append(0x12)
        if b"\x02\x01\x11" in body_data:
            etypes.append(0x11)

        # Extracción de nombres SPN textuales comunes (ej. MSSQLSvc, HTTP, CIFS, krbtgt)
        common_spns = ["MSSQLSvc", "HTTP", "CIFS", "HOST", "krbtgt", "WSMAN", "TERMSRV"]
        for spn in common_spns:
            spn_b = spn.encode("utf-8")
            if spn_b in body_data:
                sname.append(spn)

        return KerberosMessage(
            msg_type=msg_type_id,
            msg_name=msg_name,
            has_preauth=has_preauth,
            etypes=etypes,
            sname=sname,
            realm=realm,
        )

    parse = parse_payload


class DCERPCMessage:
    """Estructura de metadatos de un paquete DCE-RPC decodificado."""

    def __init__(
        self,
        ptype: int,
        call_id: int,
        interface_uuid: Optional[str] = None,
        interface_name: Optional[str] = None,
        risk_level: str = "LOW",
    ):
        self.ptype = ptype
        self.call_id = call_id
        self.interface_uuid = interface_uuid
        self.interface_name = interface_name
        self.risk_level = risk_level

    @property
    def is_bind(self) -> bool:
        return self.ptype == 11  # Bind

    @property
    def is_request(self) -> bool:
        return self.ptype == 0   # Request

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ptype": self.ptype,
            "call_id": self.call_id,
            "interface_uuid": self.interface_uuid,
            "interface_name": self.interface_name,
            "risk_level": self.risk_level,
        }


class DCERPCParser:
    """Parser binario para tramas DCE-RPC versión 5.0 (puertos 135 y 445 SMB)."""

    RPC_PTYPE_REQUEST = 0
    RPC_PTYPE_BIND = 11
    RPC_PTYPE_BIND_ACK = 12
    RPC_PTYPE_ALTER_CONTEXT = 14

    @classmethod
    def parse_payload(cls, data: bytes) -> Optional[DCERPCMessage]:
        """Analiza un payload buscando una cabecera DCE-RPC versión 5."""
        if len(data) < 16:
            return None

        # Cabecera DCE-RPC:
        # rpc_vers(1), rpc_vers_minor(1), ptype(1), pfc_flags(1), drep(4), frag_len(2), auth_len(2), call_id(4)
        rpc_vers, rpc_vers_minor, ptype = struct.unpack("!BBB", data[:3])
        if rpc_vers != 5 or rpc_vers_minor != 0:
            return None

        frag_len = struct.unpack("<H", data[8:10])[0]
        call_id = struct.unpack("<I", data[12:16])[0]

        matched_uuid = None
        matched_name = None
        risk_level = "LOW"

        # Si es un paquete Bind (11) o AlterContext (14), extraer el UUID de interfaz
        if ptype in (cls.RPC_PTYPE_BIND, cls.RPC_PTYPE_ALTER_CONTEXT):
            # El bloque de contexto de presentación inicia en offset 24
            if len(data) >= 44:
                # UUID en formato GUID (primeros 16 bytes del syntax abstract en offset variable)
                # Escaneamos los bytes buscando coincidencias con las interfaces conocidas
                for known_str, meta in KNOWN_RPC_INTERFACES.items():
                    raw_guid = uuid.UUID(known_str).bytes_le
                    if raw_guid in data:
                        matched_uuid = known_str
                        matched_name = meta["name"]
                        risk_level = meta["risk"]
                        break

        # Si es Request (0), verificar si contiene firmas de opnums o UUIDs
        elif ptype == cls.RPC_PTYPE_REQUEST:
            for known_str, meta in KNOWN_RPC_INTERFACES.items():
                raw_guid = uuid.UUID(known_str).bytes_le
                if raw_guid in data:
                    matched_uuid = known_str
                    matched_name = meta["name"]
                    risk_level = meta["risk"]
                    break

        return DCERPCMessage(
            ptype=ptype,
            call_id=call_id,
            interface_uuid=matched_uuid,
            interface_name=matched_name,
            risk_level=risk_level,
        )

    parse = parse_payload


class DNSWireMessage:
    """Estructura normalizada de metadatos de un paquete DNS (RFC 1035)."""

    def __init__(
        self,
        transaction_id: int,
        is_response: bool,
        opcode: int,
        rcode: int,
        queries: List[str],
        qtypes: List[int],
        resolved_ips: List[str],
        min_ttl: Optional[int] = None,
    ):
        self.transaction_id = transaction_id
        self.is_response = is_response
        self.opcode = opcode
        self.rcode = rcode
        self.queries = queries
        self.qtypes = qtypes
        self.resolved_ips = resolved_ips
        self.min_ttl = min_ttl

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": f"0x{self.transaction_id:04x}",
            "is_response": self.is_response,
            "opcode": self.opcode,
            "rcode": self.rcode,
            "queries": self.queries,
            "qtypes": self.qtypes,
            "resolved_ips": self.resolved_ips,
            "min_ttl": self.min_ttl,
        }


class DNSWireParser:
    """Decodificador de alto rendimiento para datagramas DNS en cable (UDP/TCP puerto 53)."""

    @staticmethod
    def _decode_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
        """Decodifica un nombre DNS (labels con longitud o puntero comprimido 0xC0)."""
        if depth > 10 or offset >= len(data):
            return "", offset

        labels: List[str] = []
        curr = offset
        jumped = False
        next_offset = offset

        while curr < len(data):
            length = data[curr]
            if length == 0:
                if not jumped:
                    next_offset = curr + 1
                break
            elif (length & 0xC0) == 0xC0:
                if curr + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[curr + 1]
                if not jumped:
                    next_offset = curr + 2
                    jumped = True
                part, _ = DNSWireParser._decode_name(data, ptr, depth + 1)
                if part:
                    labels.append(part)
                break
            else:
                curr += 1
                if curr + length > len(data):
                    break
                try:
                    label = data[curr:curr + length].decode("ascii", errors="replace")
                except Exception:
                    label = "label"
                labels.append(label)
                curr += length
                if not jumped:
                    next_offset = curr

        return ".".join(labels), next_offset

    @classmethod
    def parse(cls, data: bytes) -> Optional[DNSWireMessage]:
        """Parsea un buffer binario DNS y extrae consultas, respuestas y TTLs."""
        if not data or len(data) < 12:
            return None

        # Si viene encapsulado en TCP (prefijo de longitud de 2 bytes)
        if len(data) >= 14:
            tcp_len = int.from_bytes(data[:2], "big")
            if tcp_len == len(data) - 2:
                data = data[2:]

        try:
            tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
            is_response = bool(flags & 0x8000)
            opcode = (flags >> 11) & 0x0F
            rcode = flags & 0x0F

            # Validación de cordura
            if opcode > 5 or qdcount > 50 or ancount > 100:
                return None

            offset = 12
            queries: List[str] = []
            qtypes: List[int] = []

            # 1. Extraer preguntas (Questions)
            for _ in range(qdcount):
                if offset >= len(data):
                    break
                qname, offset = cls._decode_name(data, offset)
                if offset + 4 <= len(data):
                    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
                    offset += 4
                    if qname:
                        queries.append(qname)
                        qtypes.append(qtype)

            resolved_ips: List[str] = []
            min_ttl: Optional[int] = None

            # 2. Extraer respuestas (Answers)
            import socket
            for _ in range(ancount):
                if offset >= len(data):
                    break
                aname, offset = cls._decode_name(data, offset)
                if offset + 10 <= len(data):
                    atype, aclass, attl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                    offset += 10
                    if min_ttl is None or attl < min_ttl:
                        min_ttl = attl

                    if offset + rdlength <= len(data):
                        if atype == 1 and rdlength == 4:  # Registro A (IPv4)
                            try:
                                ip_str = socket.inet_ntoa(data[offset:offset + 4])
                                resolved_ips.append(ip_str)
                            except Exception:
                                pass
                        offset += rdlength

            return DNSWireMessage(
                transaction_id=tx_id,
                is_response=is_response,
                opcode=opcode,
                rcode=rcode,
                queries=queries,
                qtypes=qtypes,
                resolved_ips=resolved_ips,
                min_ttl=min_ttl,
            )
        except Exception:
            return None


class HTTPWireMessage:
    """Estructura normalizada de una petición o respuesta HTTP extraída del cable (DPI L7)."""

    def __init__(
        self,
        method: str = "",
        uri: str = "",
        path: str = "",
        query: str = "",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
        body_sample: bytes = b"",
        is_request: bool = True,
        status_code: Optional[int] = None,
    ):
        self.method = method.upper()
        self.uri = uri
        self.path = path
        self.query = query
        self.version = version
        self.headers = headers or {}
        self.body_sample = body_sample
        self.is_request = is_request
        self.status_code = status_code

    @property
    def user_agent(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "user-agent":
                return v
        return ""

    @property
    def host(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "host":
                return v
        return ""

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v
        return ""


class HTTPWireParser:
    """Decodificador ligero y de ultra-baja latencia para flujos HTTP/1.x en la carga útil de NetFlow."""

    HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"}

    @classmethod
    def is_http(cls, data: bytes) -> bool:
        if not data:
            return False
        first_token = data.split(b" ", 1)[0].upper()
        if first_token in cls.HTTP_METHODS:
            return True
        if data.startswith(b"HTTP/1.") or data.startswith(b"HTTP/2"):
            return True
        return False

    @classmethod
    def parse(cls, data: bytes) -> Optional[HTTPWireMessage]:
        if not data or not cls.is_http(data):
            return None
        try:
            parts = data.split(b"\r\n\r\n", 1)
            if len(parts) == 1:
                parts = data.split(b"\n\n", 1)
            header_bytes = parts[0]
            body_bytes = parts[1] if len(parts) > 1 else b""

            lines = header_bytes.split(b"\r\n") if b"\r\n" in header_bytes else header_bytes.split(b"\n")
            if not lines:
                return None

            first_line = lines[0].decode("utf-8", errors="replace").strip()
            tokens = first_line.split()

            # Petición HTTP
            if tokens and tokens[0].upper().encode() in cls.HTTP_METHODS:
                method = tokens[0].upper()
                uri = tokens[1] if len(tokens) > 1 else "/"
                version = tokens[2] if len(tokens) > 2 else "HTTP/1.1"

                path_parts = uri.split("?", 1)
                path = path_parts[0]
                query = path_parts[1] if len(path_parts) > 1 else ""

                headers: Dict[str, str] = {}
                for line in lines[1:]:
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if ":" in line_str:
                        h_name, h_val = line_str.split(":", 1)
                        headers[h_name.strip()] = h_val.strip()

                return HTTPWireMessage(
                    method=method,
                    uri=uri,
                    path=path,
                    query=query,
                    version=version,
                    headers=headers,
                    body_sample=body_bytes[:2048],
                    is_request=True,
                )
            # Respuesta HTTP
            elif tokens and tokens[0].upper().startswith("HTTP/"):
                version = tokens[0]
                status_code = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 200
                headers = {}
                for line in lines[1:]:
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if ":" in line_str:
                        h_name, h_val = line_str.split(":", 1)
                        headers[h_name.strip()] = h_val.strip()

                return HTTPWireMessage(
                    method="RESPONSE",
                    version=version,
                    headers=headers,
                    body_sample=body_bytes[:2048],
                    is_request=False,
                    status_code=status_code,
                )
        except Exception:
            return None
        return None

