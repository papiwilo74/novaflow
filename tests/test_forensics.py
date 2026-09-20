"""
Tests unitarios para el motor de cadena de custodia DFIR y volcado PCAP por incidente.
"""

import os
import tempfile
import unittest

from collector.forensics import ForensicEvidenceCollector, PcapWriter
from collector.pcap_reader import PcapReader
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestForensicEvidence(unittest.TestCase):
    def setUp(self):
        self.alert = SecurityAlert(
            alert_id="inc-999-scan",
            category=AlertCategory.PORT_SCAN,
            severity=AlertSeverity.HIGH,
            title="Escaneo de Puertos Distribuido",
            description="Escaneo horizontal detectado hacia servidores CDE",
            src_ip="192.168.1.150",
            dst_ip="10.0.0.80",
            dst_port=443,
            protocol=6,
            confidence=0.95,
        )

    def test_pcap_writer_and_reader_roundtrip(self):
        """Valida que PcapWriter genere un archivo PCAP válido decodificable por PcapReader."""
        pcap_bytes, evidence = ForensicEvidenceCollector.generate_incident_pcap(self.alert)

        self.assertGreater(len(pcap_bytes), 24)
        self.assertEqual(evidence.alert_id, "inc-999-scan")
        self.assertEqual(evidence.pcap_filename, "incident_inc-999-scan.pcap")
        self.assertEqual(evidence.packet_count, 5)
        self.assertEqual(len(evidence.sha256_hash), 64)  # Hexadecimal SHA-256
        self.assertEqual(evidence.integrity_status, "VERIFIED_IMMUTABLE")

        # Guardar en archivo temporal y validar decodificación con PcapReader nativo
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name

        try:
            reader = PcapReader(tmp_path)
            packets = list(reader)
            self.assertEqual(len(packets), 5)

            for ts, pkt_data in packets:
                self.assertGreater(len(pkt_data), 54)  # Ethernet(14) + IP(20) + TCP(20)
                # Validar tipo de enlace Ethernet (0x0800 IPv4)
                eth_type = int.from_bytes(pkt_data[12:14], byteorder="big")
                self.assertEqual(eth_type, 0x0800)

                # Validar protocolo IP (6 = TCP)
                proto = pkt_data[14 + 9]
                self.assertEqual(proto, 6)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_incident_pcap_with_custom_flows(self):
        """Valida la generación de PCAP basada en flujos asociados específicos."""
        flows = [
            {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "src_port": 12345, "dst_port": 80, "protocol": 6, "tcp_flags": 0x02},
            {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "src_port": 12345, "dst_port": 80, "protocol": 6, "tcp_flags": 0x10},
            {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.1", "src_port": 12345, "dst_port": 80, "protocol": 6, "tcp_flags": 0x18},
        ]
        pcap_bytes, evidence = ForensicEvidenceCollector.generate_incident_pcap(self.alert, associated_flows=flows)
        self.assertEqual(evidence.packet_count, 3)
        self.assertEqual(evidence.file_size_bytes, len(pcap_bytes))

    def test_api_pcap_download_and_evidence(self):
        """Valida los endpoints REST de descarga de PCAP y metadatos de evidencia DFIR."""
        from fastapi.testclient import TestClient
        from api.main import app
        from api.state import system_state
        from detector.engine import DetectionEngine

        client = TestClient(app)
        engine = DetectionEngine()
        engine.alerts_history.append(self.alert)
        system_state.engine = engine

        headers = {"X-API-Key": "novaflow-admin-key-9988"}

        # 1. Metadatos de evidencia
        res_ev = client.get(f"/api/v1/alerts/{self.alert.alert_id}/evidence", headers=headers)
        self.assertEqual(res_ev.status_code, 200)
        ev_data = res_ev.json()
        self.assertEqual(ev_data["alert_id"], self.alert.alert_id)
        self.assertEqual(ev_data["integrity_status"], "VERIFIED_IMMUTABLE")
        self.assertIn("sha256_hash", ev_data)

        # 2. Descarga binaria PCAP
        res_pcap = client.get(f"/api/v1/alerts/{self.alert.alert_id}/pcap", headers=headers)
        self.assertEqual(res_pcap.status_code, 200)
        self.assertIn("application/vnd.tcpdump.pcap", res_pcap.headers["content-type"])
        self.assertEqual(res_pcap.headers["x-forensic-sha256"], ev_data["sha256_hash"])
        self.assertGreater(len(res_pcap.content), 24)


if __name__ == "__main__":
    unittest.main()
