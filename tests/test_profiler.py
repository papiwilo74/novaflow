"""
NovaFlow NDR - Asset Profiling & Dynamic Behavioral Baseline Tests (Phase 1 Enterprise)
Valida la convergencia matemática del Algoritmo de Welford, la clasificación autónoma de roles
y la detección de exfiltración por Z-Score dinámico.
"""

import statistics
import unittest
from datetime import datetime, timezone

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity
from detector.profiler import (
    AssetRole,
    AssetRoleClassifier,
    DynamicBaselineProfiler,
    HostWelfordAccumulator,
)
from detector.rules.bandwidth_exfil import BandwidthExfiltrationDetector
from detector.rules.lateral_movement import LateralMovementDetector


def make_flow(
    src_ip="192.168.1.100",
    dst_ip="203.0.113.5",
    src_port=54321,
    dst_port=443,
    bytes_val=50000,
    packets_val=40,
    protocol=6,
) -> NetFlowRecord:
    return NetFlowRecord(
        timestamp=datetime.now(timezone.utc),
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="192.168.1.1",
        input_snmp=1,
        output_snmp=2,
        packets=packets_val,
        bytes=bytes_val,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=0x18,
        protocol=protocol,
        tos=0,
        src_as=65000,
        dst_as=13335,
        src_mask=24,
        dst_mask=24,
    )


class TestWelfordAccumulator(unittest.TestCase):
    """Pruebas de precisión numérica para el acumulador online de Welford."""

    def test_welford_mathematical_convergence(self):
        """Verifica que el cálculo online de Welford coincida con statistics.mean y statistics.stdev."""
        samples = [1024, 2048, 1500, 3200, 1800, 2900, 4100, 1200, 2500, 3100, 2200]
        acc = HostWelfordAccumulator()

        for s in samples:
            acc.update(s)

        expected_mean = statistics.mean(samples)
        expected_stdev = statistics.stdev(samples)
        expected_var = statistics.variance(samples)

        self.assertAlmostEqual(acc.mean_bytes, expected_mean, places=4)
        self.assertAlmostEqual(acc.variance_bytes, expected_var, places=4)
        self.assertAlmostEqual(acc.stdev_bytes, expected_stdev, places=4)

    def test_z_score_calculation(self):
        """Verifica que el cálculo del Z-Score detecte observaciones estadísticamente anómalas."""
        acc = HostWelfordAccumulator()
        # Calibrar con 20 muestras estables (media ~50,000, stdev ~5,000)
        base_samples = [48000, 52000, 50000, 49000, 51000, 53000, 47000, 50500, 49500, 52500] * 2
        for s in base_samples:
            acc.update(s)

        # Muestra normal
        z_normal = acc.calculate_z_score(55000)
        self.assertLess(z_normal, 3.0)

        # Muestra anómala (+6 desviaciones estándar)
        stdev = acc.stdev_bytes
        mean = acc.mean_bytes
        anomalous_val = mean + (4.0 * stdev)
        z_anomalous = acc.calculate_z_score(anomalous_val)
        self.assertGreaterEqual(z_anomalous, 3.8)


class TestAssetRoleClassifier(unittest.TestCase):
    """Pruebas unitarias para la clasificación automática de roles de activos de red."""

    def setUp(self):
        self.classifier = AssetRoleClassifier()

    def test_dns_server_classification(self):
        """Un host interno que recibe tráfico UDP/53 desde múltiples clientes debe ser clasificado como DNS."""
        dns_ip = "192.168.1.53"
        for i in range(1, 10):
            client = f"192.168.1.{i}"
            flow = make_flow(src_ip=client, dst_ip=dns_ip, dst_port=53, protocol=17)
            self.classifier.observe_flow(flow)

        self.assertEqual(self.classifier.get_role(dns_ip), AssetRole.INFRASTRUCTURE_DNS)

    def test_domain_controller_classification(self):
        """Un host que sirve Kerberos (88) y LDAP (389) debe ser clasificado como INFRASTRUCTURE_DC."""
        dc_ip = "10.0.0.1"
        for i in range(10, 20):
            client = f"10.0.0.{i}"
            f1 = make_flow(src_ip=client, dst_ip=dc_ip, dst_port=88)
            f2 = make_flow(src_ip=client, dst_ip=dc_ip, dst_port=389)
            self.classifier.observe_flow(f1)
            self.classifier.observe_flow(f2)

        self.assertEqual(self.classifier.get_role(dc_ip), AssetRole.INFRASTRUCTURE_DC)

    def test_admin_management_station_classification(self):
        """Un host que inicia conexiones administrativas salientes hacia 5+ hosts debe ser ADMIN_MANAGEMENT."""
        mgmt_ip = "10.0.50.254"
        for i in range(1, 8):
            target = f"10.0.1.{i}"
            flow = make_flow(src_ip=mgmt_ip, dst_ip=target, dst_port=5985)  # WinRM
            self.classifier.observe_flow(flow)

        self.assertEqual(self.classifier.get_role(mgmt_ip), AssetRole.ADMIN_MANAGEMENT)

    def test_default_workstation(self):
        """Un host sin servicios entrantes es considerado WORKSTATION."""
        client_ip = "192.168.1.99"
        flow = make_flow(src_ip=client_ip, dst_ip="93.184.216.34", dst_port=443)
        self.classifier.observe_flow(flow)
        self.assertEqual(self.classifier.get_role(client_ip), AssetRole.WORKSTATION)


class TestDynamicBaselineIntegration(unittest.TestCase):
    """Pruebas de integración de la línea base gaussiana con los detectores de NovaFlow."""

    def test_low_volume_exfiltration_detected_via_z_score(self):
        """
        Una estación de trabajo con línea base de 50 KB envía 2.5 MB al exterior.
        Aunque no alcanza el umbral estático de 20 MB, Z > 3.5 dispara alerta de exfiltración.
        """
        profiler = DynamicBaselineProfiler(anomaly_z_threshold=3.5, min_samples_for_baseline=10)
        detector = BandwidthExfiltrationDetector(
            single_flow_threshold_bytes=20_000_000,
            host_profiler=profiler,
        )

        host_ip = "192.168.1.80"
        ext_target = "198.51.100.99"

        # 1. Calibrar línea base con 15 flujos de baja transferencia con variación realista (47-53 KB)
        base_samples = [48000, 52000, 50000, 49000, 51000, 53000, 47000, 50500, 49500, 52500,
                        48500, 51500, 50200, 49800, 51200]
        for val in base_samples:
            f_cal = make_flow(src_ip=host_ip, dst_ip="142.250.190.46", bytes_val=val)
            profiler.ingest_flow(f_cal)

        # 2. Flujo anómalo: 2.5 MB transferidos (50 veces más que la media histórica)
        f_anomalous = make_flow(src_ip=host_ip, dst_ip=ext_target, bytes_val=2_500_000)
        # Ingestar en profiler y luego evaluar en detector
        dev_res = profiler.ingest_flow(f_anomalous)
        self.assertTrue(dev_res.is_statistically_anomalous)
        self.assertGreater(dev_res.z_score, 10.0)

        alert = detector.analyze_flow(f_anomalous)
        self.assertIsNotNone(alert, "Debe alertar exfiltración por anomalía gaussiana Z-score")
        self.assertEqual(alert.category, AlertCategory.EXFILTRATION)
        self.assertIn("Desviación de Comportamiento", alert.title)
        self.assertIn("welford_z_score", alert.metrics)
        self.assertGreaterEqual(alert.metrics["welford_z_score"], 3.5)

    def test_lateral_movement_suppression_on_classified_admin(self):
        """
        Un host clasificado como ADMIN_MANAGEMENT no debe disparar falso positivo de movimiento lateral
        cuando realiza despliegues de parches legítimos.
        """
        profiler = DynamicBaselineProfiler()
        detector = LateralMovementDetector(target_threshold=3, host_profiler=profiler)

        admin_ip = "10.0.100.5"

        # 1. Entrenar al clasificador para que reconozca a admin_ip como estación de gestión
        for i in range(1, 10):
            f_train = make_flow(src_ip=admin_ip, dst_ip=f"10.0.2.{i}", dst_port=5985)
            profiler.ingest_flow(f_train)

        self.assertEqual(profiler.classifier.get_role(admin_ip), AssetRole.ADMIN_MANAGEMENT)

        # 2. Cuando el detector analiza conexiones de este host, debe suprimir la alerta
        for i in range(20, 26):
            f_patch = make_flow(src_ip=admin_ip, dst_ip=f"10.0.3.{i}", dst_port=445)
            alert = detector.analyze_flow(f_patch)
            self.assertIsNone(alert, "Un host de gestión administrativa clasificado no debe disparar alerta de movimiento lateral")


if __name__ == "__main__":
    unittest.main()
