"""
NovaFlow NDR - Automated Tests for High-Scale Threat Intel & Counting Bloom Filter
Valida el Filtro de Bloom Contable probabilístico O(1), ingestión de feeds Feodo / STIX 2.1 y descarte rápido.
"""

from datetime import datetime, timezone
import unittest

from collector.parser import NetFlowRecord
from detector.bloom_threat_intel import CountingBloomFilter, HighScaleThreatIntel
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity


class TestCountingBloomFilter(unittest.TestCase):
    def test_bloom_add_contains_remove(self):
        """Valida que el Counting Bloom Filter permita adición, consulta exacta y eliminación."""
        bloom = CountingBloomFilter(capacity=1000, error_rate=0.001)

        # Inserción
        ips = [f"192.0.2.{i}" for i in range(1, 20)]
        for ip in ips:
            bloom.add(ip)

        # Cero falsos negativos: todos los elementos insertados deben retornar True
        for ip in ips:
            self.assertTrue(bloom.contains(ip), f"Falso negativo detectado para {ip}")

        # Elementos no insertados deben retornar False
        self.assertFalse(bloom.contains("198.51.100.254"))
        self.assertFalse(bloom.contains("10.255.255.1"))

        # Eliminación dinámica
        target = "192.0.2.5"
        self.assertTrue(bloom.remove(target))
        self.assertFalse(bloom.contains(target))

        # El resto de elementos debe seguir presente
        self.assertTrue(bloom.contains("192.0.2.6"))
        self.assertTrue(bloom.contains("192.0.2.4"))

    def test_bloom_memory_footprint(self):
        """Valida que la huella de memoria sea sumamente reducida."""
        bloom = CountingBloomFilter(capacity=10_000, error_rate=0.001)
        # Menos de 200 KB para 10,000 elementos
        self.assertLess(bloom.memory_size_bytes(), 200_000)


class TestHighScaleThreatIntel(unittest.TestCase):
    def setUp(self):
        self.intel = HighScaleThreatIntel(capacity=5000)
        self.now = datetime.now(timezone.utc)

    def _make_flow(self, src: str, dst: str, dst_port: int = 443) -> NetFlowRecord:
        return NetFlowRecord(
            timestamp=self.now,
            timestamp_ms=int(self.now.timestamp() * 1000),
            src_ip=src,
            dst_ip=dst,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=10,
            bytes=1500,
            first_switched=1000,
            last_switched=2000,
            src_port=51234,
            dst_port=dst_port,
            tcp_flags=0x18,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def test_seed_iocs_and_benign_bypass(self):
        """Valida la consulta de IOCs semilla y el descarte instantáneo de IPs benignas."""
        # IP Maliciosa semilla
        match = self.intel.query_ip("198.51.100.77")
        self.assertIsNotNone(match)
        self.assertEqual(match["threat_name"], "Cobalt Strike C2")
        self.assertEqual(match["threat_actor"], "APT29")

        # IP Benigna (descarte inmediato)
        no_match = self.intel.query_ip("8.8.8.8")
        self.assertIsNone(no_match)

    def test_feodo_tracker_feed_ingestion(self):
        """Valida la ingestión de feeds CSV de Abuse.ch Feodo Tracker."""
        sample_feed = (
            "# Feodo Tracker C2 IP Blocklist\n"
            "# Firstseen,DstIP,DstPort,C2Status,LastOnline,Malware\n"
            "2026-09-01,185.220.101.5,443,online,2026-09-19,QakBot\n"
            "2026-09-02,194.26.29.112,8080,online,2026-09-19,Emotet\n"
            "2026-09-03,45.142.214.88,443,online,2026-09-19,Dridex\n"
        )
        loaded = self.intel.load_feodo_tracker_feed(sample_feed)
        self.assertEqual(loaded, 3)

        # Verificar consulta
        res = self.intel.query_ip("185.220.101.5")
        self.assertIsNotNone(res)
        self.assertIn("QakBot", res["threat_name"])
        self.assertEqual(res["source"], "FEODO_TRACKER")

        # Verificar flujo
        flow = self._make_flow(src="10.0.0.15", dst="185.220.101.5", dst_port=443)
        alert = self.intel.analyze_flow(flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.MALICIOUS_C2)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)

    def test_stix_21_bundle_ingestion(self):
        """Valida la ingestión de paquetes de indicadores STIX 2.1 JSON."""
        stix_bundle = {
            "type": "bundle",
            "id": "bundle--fe6a7b31-3dc1-4c12-9c3f-25c27bf23f6e",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--9d8a3a0e-561b-4f76-9c44-b0a5c4bc1c52",
                    "name": "BlackCat Ransomware C2",
                    "pattern": "[ipv4-addr:value = '91.215.85.17']",
                    "labels": ["ALPHV", "Ransomware"],
                }
            ],
        }
        loaded = self.intel.load_stix_bundle(stix_bundle)
        self.assertEqual(loaded, 1)

        res = self.intel.query_ip("91.215.85.17")
        self.assertIsNotNone(res)
        self.assertEqual(res["threat_name"], "BlackCat Ransomware C2")
        self.assertEqual(res["source"], "STIX_2.1")

    def test_ioc_dynamic_expiration(self):
        """Valida que la eliminación/expiración dinámica de IOCs funcione en cable."""
        self.intel.add_ioc(ip="203.0.113.88", threat_name="Temporary IOC")
        self.assertIsNotNone(self.intel.query_ip("203.0.113.88"))

        # Expirar/eliminar
        self.assertTrue(self.intel.remove_ioc("203.0.113.88"))
        self.assertIsNone(self.intel.query_ip("203.0.113.88"))

    def test_detection_engine_bloom_intel_integration(self):
        """Valida que DetectionEngine integre HighScaleThreatIntel sin interferencias."""
        engine = DetectionEngine()

        # Ingestar nuevo IOC en la instancia de Bloom Intel del motor
        engine.bloom_intel.add_ioc(
            ip="194.165.16.89",
            threat_name="LockBit 3.0 Exfiltration Drop",
            threat_actor="LockBitSupp",
            confidence=0.97,
        )

        flow = self._make_flow(src="10.0.0.22", dst="194.165.16.89", dst_port=443)
        alerts = engine.analyze_flow(flow)

        c2_alerts = [a for a in alerts if a.category == AlertCategory.MALICIOUS_C2]
        self.assertGreaterEqual(len(c2_alerts), 1)
        self.assertIn("LockBit", c2_alerts[0].description)


if __name__ == "__main__":
    unittest.main()
