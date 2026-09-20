"""
NovaFlow NDR - Detection Engine & Threat Intelligence Tests (Phase 2)
Valida la precisión heurística, concordancia de C2 y detección de anomalías por ML.
"""

import unittest
from datetime import datetime, timezone

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.rules.port_scan import PortScanDetector
from detector.rules.bandwidth_exfil import BandwidthExfiltrationDetector
from detector.rules.syn_flood import SynFloodDetector
from detector.rules.dns_tunnel import DnsTunnelDetector
from detector.rules.threat_intel import ThreatIntelMatcher
from detector.ml.isolation_forest import NetworkIsolationForestDetector
from detector.engine import DetectionEngine


def make_record(
    src_ip="192.168.1.10",
    dst_ip="142.250.190.46",
    src_port=45000,
    dst_port=443,
    protocol=6,
    tcp_flags=0x18,
    packets=10,
    bytes_count=10000,
) -> NetFlowRecord:
    now = datetime.now(timezone.utc)
    return NetFlowRecord(
        timestamp=now,
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="192.168.1.1",
        input_snmp=1,
        output_snmp=2,
        packets=packets,
        bytes=bytes_count,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        protocol=protocol,
        tos=0,
        src_as=65001,
        dst_as=15169,
        src_mask=24,
        dst_mask=24,
    )


class TestDetectionEngine(unittest.TestCase):

    def test_port_scan_detection(self):
        """Valida que un barrido de más de 15 puertos dispare una alerta de PORT_SCAN."""
        detector = PortScanDetector(port_threshold=15, window_seconds=10.0)
        attacker = "192.168.1.200"
        target = "10.0.0.5"

        alerts = []
        for port in range(20, 45):  # 25 puertos distintos
            flow = make_record(
                src_ip=attacker,
                dst_ip=target,
                dst_port=port,
                protocol=6,
                tcp_flags=0x02,  # SYN
                packets=1,
                bytes_count=54,
            )
            alert = detector.analyze_flow(flow)
            if alert:
                alerts.append(alert)

        self.assertGreater(len(alerts), 0)
        first_alert = alerts[0]
        self.assertEqual(first_alert.category, AlertCategory.PORT_SCAN)
        self.assertEqual(first_alert.src_ip, attacker)
        self.assertIn(first_alert.severity, (AlertSeverity.HIGH, AlertSeverity.MEDIUM))
        self.assertGreaterEqual(first_alert.metrics["unique_ports_scanned"], 15)

    def test_bandwidth_exfiltration_detection(self):
        """Valida que un volumen anómalo saliente (>20MB) dispare una alerta de EXFILTRATION."""
        detector = BandwidthExfiltrationDetector(single_flow_threshold_bytes=20_000_000)
        insider = "10.0.0.15"  # IP privada
        public_ip = "198.51.100.99"  # IP pública

        # Flujo masivo de 65 Megabytes
        flow = make_record(
            src_ip=insider,
            dst_ip=public_ip,
            dst_port=443,
            packets=50000,
            bytes_count=65_000_000,
        )

        alert = detector.analyze_flow(flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.EXFILTRATION)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.src_ip, insider)
        self.assertGreater(alert.metrics["megabytes"], 60.0)

    def test_syn_flood_detection(self):
        """Valida que una ráfaga de flujos SYN hacia un servicio dispare SYN_FLOOD."""
        detector = SynFloodDetector(syn_count_threshold=30, window_seconds=5.0)
        target = "10.0.0.5"

        alerts = []
        for i in range(40):
            flow = make_record(
                src_ip=f"185.10.{i}.1",
                dst_ip=target,
                dst_port=80,
                protocol=6,
                tcp_flags=0x02,  # SYN
                packets=1,
                bytes_count=54,
            )
            alert = detector.analyze_flow(flow)
            if alert:
                alerts.append(alert)

        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].category, AlertCategory.SYN_FLOOD)
        self.assertEqual(alerts[0].dst_ip, target)
        self.assertEqual(alerts[0].dst_port, 80)

    def test_dns_tunnel_detection(self):
        """Valida que paquetes DNS (puerto 53) con payload inflado (>320B/pkt) disparen DNS_TUNNEL."""
        detector = DnsTunnelDetector(avg_packet_size_threshold=320)
        tunnel_flow = make_record(
            src_ip="192.168.1.55",
            dst_ip="203.0.113.8",
            dst_port=53,
            protocol=17,  # UDP
            tcp_flags=0,
            packets=10,
            bytes_count=4500,  # 450 bytes por paquete
        )

        alert = detector.analyze_flow(tunnel_flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.DNS_TUNNEL)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertGreater(alert.metrics["avg_bytes_per_packet"], 320)

    def test_threat_intel_matching(self):
        """Valida que una conexión hacia una IP clasificada en la base C2 genere alerta MALICIOUS_C2."""
        matcher = ThreatIntelMatcher()
        c2_flow = make_record(
            src_ip="192.168.1.10",
            dst_ip="198.51.100.77",  # Cobalt Strike C2 conocido
            dst_port=8443,
        )

        alert = matcher.analyze_flow(c2_flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.MALICIOUS_C2)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.metrics["malware_family"], "Cobalt Strike C2")

    def test_ml_anomaly_detection(self):
        """Valida que el modelo de Machine Learning aprenda el baseline y detecte un flujo anómalo."""
        ml_detector = NetworkIsolationForestDetector()

        # Generar baseline normal
        normal_flows = [
            make_record(
                src_ip="192.168.1.10",
                dst_ip="142.250.190.46",
                src_port=50000 + (i % 1000),
                dst_port=443,
                protocol=6,
                tcp_flags=0x18,
                packets=15,
                bytes_count=8000 + (i * 20),
            )
            for i in range(100)
        ]
        ml_detector.train_baseline(normal_flows)
        self.assertTrue(ml_detector.is_trained)

        # Flujo basal -> no debe generar alerta
        normal_test = make_record(packets=15, bytes_count=8500)
        self.assertIsNone(ml_detector.analyze_flow(normal_test))

        # Flujo anómalo extremo (desvío de paquetes y flags)
        outlier = make_record(
            packets=8000,
            bytes_count=20_000_000,
            tcp_flags=0x02,
            dst_port=31337,
        )
        alert = ml_detector.analyze_flow(outlier)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.ANOMALY_ML)

    def test_unified_engine_pipeline(self):
        """Valida el orquestador unificado procesando múltiples flujos simultáneamente."""
        engine = DetectionEngine()

        # Entrenar ML en baseline
        baseline = [make_record() for _ in range(50)]
        engine.ml_detector.train_baseline(baseline)

        # Inyectar tráfico normal + un ataque C2
        normal = make_record(src_ip="192.168.1.10", dst_ip="1.1.1.1", dst_port=53, protocol=17, bytes_count=120)
        c2 = make_record(src_ip="192.168.1.10", dst_ip="198.51.100.77")

        alerts_normal = engine.analyze_flow(normal)
        self.assertEqual(len(alerts_normal), 0)

        alerts_c2 = engine.analyze_flow(c2)
        self.assertEqual(len(alerts_c2), 1)
        self.assertEqual(engine.stats["total_alerts"], 1)
        self.assertEqual(engine.stats["by_severity"]["CRITICAL"], 1)

    def test_mitre_mapping_and_cef_export(self):
        """Valida que las alertas tengan su mapeo formal MITRE ATT&CK y exporten a formato CEF y Syslog RFC 5424."""
        alert = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.PORT_SCAN,
            title="Escaneo de Puertos Reconocido",
            description="Múltiples puertos TCP sondeados con SYN",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            dst_port=80,
            confidence=0.94,
        )

        # 1. Validar MITRE ATT&CK
        self.assertIsNotNone(alert.mitre)
        self.assertEqual(alert.mitre["tactic"], "Discovery")
        self.assertEqual(alert.mitre["technique_id"], "T1046")
        self.assertEqual(alert.mitre["technique_name"], "Network Service Discovery")
        self.assertIn("https://attack.mitre.org/techniques/T1046/", alert.mitre["url"])

        # 2. Validar exportación a ArcSight CEF:0
        cef_string = alert.to_cef()
        self.assertTrue(cef_string.startswith("CEF:0|NovaSec|NovaFlow|1.0.0|PORT_SCAN|"))
        self.assertIn("src=192.168.1.100", cef_string)
        self.assertIn("dst=10.0.0.5", cef_string)
        self.assertIn("cs2=T1046", cef_string)
        self.assertIn("cs3=Discovery", cef_string)

        # 3. Validar exportación a Syslog RFC 5424
        syslog_string = alert.to_syslog_rfc5424()
        self.assertTrue(syslog_string.startswith("<35>1 "))
        self.assertIn("novaflow-ndr novaflow-threat-engine", syslog_string)
        self.assertIn(cef_string, syslog_string)


if __name__ == "__main__":
    unittest.main()
