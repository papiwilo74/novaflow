"""
Pruebas unitarias para la Fase 3: Motor de Estado de Entidades y Libro Mayor de Activos.
"""

import struct
import time
import unittest
from starlette.testclient import TestClient

from api.main import app
from api.security.auth import JWTManager, Role
from detector.entity import AssetEntity, AssetRole, EntityLedger
from detector.dhcp_tracker import DHCPLeaseTracker
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


def build_synthetic_dhcp_ack(
    chaddr_mac: bytes = b"\x00\x0c\x29\x4b\x82\x1a",
    yiaddr: str = "10.0.50.125",
    hostname: str = "FINANCE-PC01",
) -> bytes:
    """Construye un paquete UDP BOOTP/DHCP ACK sintético conforme a RFC 2131."""
    buf = bytearray(240)
    buf[0] = 2  # BOOTREPLY
    buf[1] = 1  # Ethernet
    buf[2] = 6  # MAC length 6 bytes
    # yiaddr at offset 16
    ip_parts = [int(p) for p in yiaddr.split(".")]
    buf[16:20] = bytes(ip_parts)
    # chaddr at offset 28
    buf[28:28 + len(chaddr_mac)] = chaddr_mac
    # Magic Cookie DHCP at offset 236
    buf[236:240] = b"\x63\x82\x53\x63"

    # Option 53: DHCP ACK (len 1, val 5)
    buf.extend(b"\x35\x01\x05")

    # Option 12: Hostname
    h_bytes = hostname.encode("utf-8")
    buf.extend(bytes([12, len(h_bytes)]))
    buf.extend(h_bytes)

    # Option 255: End
    buf.append(255)

    return bytes(buf)


class TestEntityLedger(unittest.TestCase):
    """Batería de validación de estado de identidades, DHCP y decaimiento de Threat Score."""

    def setUp(self):
        self.admin_token = JWTManager.create_token(
            {
                "sub": "soc-admin-tester",
                "role": Role.ADMIN,
                "tenant_id": "default",
                "name": "Admin Tester",
            },
            expires_in_minutes=30,
        )
        self.auth_headers = {"Authorization": f"Bearer {self.admin_token}"}

    def test_asset_entity_threat_score_decay_and_multipliers(self):
        """Verifica que el Threat Score decaiga exponencialmente y respete multiplicadores de rol."""
        entity = AssetEntity(
            current_ip="10.0.0.10",
            role=AssetRole.DOMAIN_CONTROLLER,
        )
        t0 = 1700000000.0
        alert_crit = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.MALICIOUS_C2,
            src_ip="10.0.0.10",
        )
        entity.add_alert(alert_crit, current_time=t0)

        # En t0: raw=60.0, DC multiplier=2.5 -> score = min(100, 60*2.5) = 100.0
        score_t0 = entity.calculate_dynamic_threat_score(current_time=t0)
        self.assertEqual(score_t0, 100.0)

        # En t0 + 3600s (media vida de 1 hora): raw base decae a la mitad (30.0)
        # 30.0 * 2.5 = 75.0
        score_t1 = entity.calculate_dynamic_threat_score(current_time=t0 + 3600.0)
        self.assertAlmostEqual(score_t1, 75.0, delta=1.0)

        # Si el activo fuera una WORKSTATION (multiplicador 1.0)
        entity.role = AssetRole.WORKSTATION
        score_ws = entity.calculate_dynamic_threat_score(current_time=t0 + 3600.0)
        self.assertAlmostEqual(score_ws, 30.0, delta=1.0)

    def test_entity_ledger_ip_migration_and_resolution(self):
        """Valida que una entidad conserve su historial al migrar de IP mediante DHCP."""
        ledger = EntityLedger()
        mac = "00:0c:29:4b:82:1a"

        # 1. Registro inicial
        e1 = ledger.get_or_create(ip="10.0.50.10", mac=mac, hostname="LAPTOP-CORP")
        self.assertEqual(e1.current_ip, "10.0.50.10")

        # 2. Agregar una alerta
        alert = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.PORT_SCAN,
            src_ip="10.0.50.10",
        )
        ledger.record_alert(alert)
        self.assertEqual(len(e1.alert_ids), 1)

        # 3. La máquina renueva DHCP obteniendo otra IP
        e2 = ledger.reassign_ip_lease(mac=mac, new_ip="10.0.50.99", hostname="LAPTOP-CORP")
        self.assertEqual(e1.entity_id, e2.entity_id, "Debe ser exactamente la misma entidad persistente")
        self.assertEqual(e2.current_ip, "10.0.50.99")
        self.assertEqual(len(e2.ip_history), 1)
        self.assertEqual(e2.ip_history[0]["ip"], "10.0.50.10")
        # El historial de alertas y Threat Score se conserva
        self.assertEqual(len(e2.alert_ids), 1)

        # 4. Búsqueda por la nueva IP
        lookup = ledger.get_by_ip("10.0.50.99")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.entity_id, e1.entity_id)

    def test_dhcp_tracker_binary_parsing(self):
        """Verifica la decodificación de datagramas UDP BOOTP/DHCP crudos."""
        payload = build_synthetic_dhcp_ack(
            chaddr_mac=b"\x00\x50\x56\xc0\x00\x08",
            yiaddr="192.168.100.45",
            hostname="SRV-DATABASE",
        )
        parsed = DHCPLeaseTracker.parse_dhcp_payload(payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["yiaddr"], "192.168.100.45")
        self.assertEqual(parsed["mac"], "00:50:56:c0:00:08")
        self.assertEqual(parsed["msg_type"], 5)  # ACK
        self.assertEqual(parsed["hostname"], "SRV-DATABASE")

    def test_entities_api_endpoints(self):
        """Verifica las operaciones REST sobre el libro mayor de activos."""
        with TestClient(app) as client:
            # 1. Inyectar lease DHCP por API
            lease_payload = {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "10.200.1.50",
                "hostname": "DC-PRIMARY",
                "event_type": "ACK",
            }
            res_lease = client.post("/api/v1/entities/dhcp/lease", json=lease_payload, headers=self.auth_headers)
            self.assertEqual(res_lease.status_code, 200)
            entity_id = res_lease.json()["entity_id"]

            # 2. Consultar detalles
            res_details = client.get(f"/api/v1/entities/{entity_id}", headers=self.auth_headers)
            self.assertEqual(res_details.status_code, 200)
            self.assertEqual(res_details.json()["hostname"], "DC-PRIMARY")

            # 3. Elevar rol a DOMAIN_CONTROLLER
            res_role = client.patch(
                f"/api/v1/entities/{entity_id}/role",
                json={"role": "DOMAIN_CONTROLLER"},
                headers=self.auth_headers,
            )
            self.assertEqual(res_role.status_code, 200)
            self.assertEqual(res_role.json()["new_role"], "DOMAIN_CONTROLLER")
            self.assertEqual(res_role.json()["new_role_multiplier"], 2.5)

            # 4. Búsqueda por IP
            res_ip = client.get("/api/v1/entities/lookup/by-ip/10.200.1.50", headers=self.auth_headers)
            self.assertEqual(res_ip.status_code, 200)
            self.assertEqual(res_ip.json()["entity_id"], entity_id)

            # 5. Listado general
            res_list = client.get("/api/v1/entities?limit=10", headers=self.auth_headers)
            self.assertEqual(res_list.status_code, 200)
            self.assertGreaterEqual(res_list.json()["total_tracked"], 1)


if __name__ == "__main__":
    unittest.main()
