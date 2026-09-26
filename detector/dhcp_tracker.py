"""
NovaFlow NDR - DHCP Lease Tracker & Asset Reassignment Processor
Decodifica transacciones DHCP (Bootstrap Protocol / RFC 2131) y coordina
con el EntityLedger para mantener trazabilidad ininterrumpida de activos.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

from detector.entity import EntityLedger


class DHCPLeaseTracker:
    """Procesador de eventos DHCP para seguimiento dinámico de identidades."""

    # Tipos de mensaje DHCP (Opción 53)
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8

    def __init__(self, ledger: EntityLedger):
        self.ledger = ledger
        self.total_leases_processed = 0

    def process_lease_event(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        event_type: str = "ACK",
    ) -> Dict[str, Any]:
        """Registra un evento DHCP formal actualizando el libro mayor de activos."""
        normalized_mac = mac.lower().replace("-", ":")
        entity = self.ledger.reassign_ip_lease(
            mac=normalized_mac,
            new_ip=ip,
            hostname=hostname,
        )
        self.total_leases_processed += 1
        return {
            "status": "PROCESSED",
            "event_type": event_type,
            "mac": normalized_mac,
            "current_ip": entity.current_ip,
            "entity_id": entity.entity_id,
            "hostname": entity.hostname,
        }

    @classmethod
    def parse_dhcp_payload(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Decodifica un datagrama UDP BOOTP/DHCP (puertos 67/68) de longitud mínima 240 bytes.
        Extrae yiaddr (IP asignada), chaddr (MAC cliente) y opciones (Option 53, Option 12).
        """
        if len(data) < 240:
            return None

        # BOOTP Header: op(1), htype(1), hlen(1), hops(1), xid(4), secs(2), flags(2), ciaddr(4), yiaddr(4), siaddr(4), giaddr(4), chaddr(16)
        op, htype, hlen = struct.unpack("!BBB", data[:3])
        if op not in (1, 2):  # 1=BOOTREQUEST, 2=BOOTREPLY
            return None

        yiaddr_bytes = data[16:20]
        yiaddr = ".".join(str(b) for b in yiaddr_bytes)

        # MAC cliente (primeros hlen bytes de chaddr, máximo 6 para Ethernet)
        mac_len = min(hlen, 6)
        mac_raw = data[28:28 + mac_len]
        mac = ":".join(f"{b:02x}" for b in mac_raw)

        # Magic Cookie DHCP: 99.130.83.99 (0x63825363)
        magic_cookie = data[236:240]
        if magic_cookie != b"\x63\x82\x53\x63":
            return None

        # Analizar opciones TLV
        offset = 240
        msg_type = None
        hostname = None

        while offset < len(data):
            opt_code = data[offset]
            if opt_code == 255:  # End Option
                break
            if opt_code == 0:  # Pad Option
                offset += 1
                continue

            if offset + 1 >= len(data):
                break
            opt_len = data[offset + 1]
            opt_val = data[offset + 2:offset + 2 + opt_len]
            offset += 2 + opt_len

            if opt_code == 53 and len(opt_val) >= 1:  # DHCP Message Type
                msg_type = opt_val[0]
            elif opt_code == 12:  # Hostname
                hostname = opt_val.decode("utf-8", errors="replace")

        return {
            "mac": mac,
            "yiaddr": yiaddr,
            "msg_type": msg_type,
            "hostname": hostname,
        }
