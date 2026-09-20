"""
NovaFlow NDR - Automated Tests for Synthetic Traffic Generator & Benchmark CLI
Valida la generación de flujos benignos, inyección de ataques, empaquetado binario NetFlow v5 y benchmark.
"""

import unittest
from tools.traffic_gen import EnterpriseTrafficGenerator, build_netflow_v5_packet, run_benchmark_test


class TestTrafficGenerator(unittest.TestCase):
    def setUp(self):
        self.gen = EnterpriseTrafficGenerator(seed=123)

    def test_generate_benign_flow(self):
        """Valida que los flujos benignos generados sean sintáctica y semánticamente correctos."""
        flow = self.gen.generate_benign_flow()
        self.assertIsNotNone(flow)
        self.assertTrue(flow.src_ip.startswith("10.0."))
        self.assertIn(flow.protocol, [6, 17])
        self.assertGreater(flow.bytes, 0)
        self.assertGreater(flow.packets, 0)

    def test_generate_attack_bursts(self):
        """Valida la inyección de patrones de ataque de red."""
        # 1. Port Scan
        scan_flows = self.gen.generate_port_scan_burst(attacker_ip="10.0.99.1", target_ip="10.0.0.5")
        self.assertEqual(len(scan_flows), 20)
        ports = {f.dst_port for f in scan_flows}
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(445, ports)
        for f in scan_flows:
            self.assertEqual(f.tcp_flags, 2)  # SYN

        # 2. C2 Beacon
        c2 = self.gen.generate_c2_beacon_flow(infected_ip="10.0.1.20", c2_ip="198.51.100.99")
        self.assertEqual(c2.dst_ip, "198.51.100.99")
        self.assertEqual(c2.dst_port, 443)

        # 3. Exfiltration Burst
        exfil = self.gen.generate_exfiltration_burst(infected_ip="10.0.1.20", drop_ip="203.0.113.50")
        self.assertEqual(exfil.dst_ip, "203.0.113.50")
        self.assertGreater(exfil.bytes, 10 * 1024 * 1024)

    def test_build_netflow_v5_packet(self):
        """Valida el empaquetador binario de datagramas NetFlow v5 (Header 24B + N * 48B)."""
        flows = [self.gen.generate_benign_flow() for _ in range(5)]
        packet = build_netflow_v5_packet(flows)
        expected_len = 24 + (5 * 48)
        self.assertEqual(len(packet), expected_len)

        # Validar versión en los primeros 2 bytes (Big Endian uint16 = 5)
        self.assertEqual(packet[0], 0x00)
        self.assertEqual(packet[1], 0x05)

    def test_benchmark_in_memory_execution(self):
        """Valida que run_benchmark_test ejecute la suite de estrés en memoria y retorne métricas."""
        result = run_benchmark_test(total_flows=100, inject_attacks=True)
        self.assertIn("total_flows", result)
        self.assertIn("throughput_flows_per_sec", result)
        self.assertIn("avg_latency_microseconds", result)
        self.assertIn("alerts_triggered", result)
        self.assertGreater(result["total_flows"], 100)
        self.assertGreater(result["alerts_triggered"], 0)


if __name__ == "__main__":
    unittest.main()
