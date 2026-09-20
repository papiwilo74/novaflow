"""
NovaFlow NDR - Automated Unit & Regression Tests (Phase 1)
"""

import unittest
from collector.parser import NetFlowParser, NetFlowRecord
from generator.scenarios import TrafficScenarioGenerator, FlowDefinition
from generator.generator import NetFlowV5PacketBuilder


class TestNovaFlowCore(unittest.TestCase):
    def test_netflow_v5_roundtrip_serialization(self):
        """Prueba que un flujo empaquetado binariamente se desempaqueta exactamente igual."""
        original_flow = FlowDefinition(
            src_ip="192.168.1.105",
            dst_ip="142.250.190.46",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=45,
            bytes=52800,
            first_switched=1000,
            last_switched=2500,
            src_port=54321,
            dst_port=443,
            tcp_flags=0x18,  # ACK + PSH
            protocol=6,      # TCP
            tos=0,
            src_as=65001,
            dst_as=15169,
            src_mask=24,
            dst_mask=24,
        )

        # Empaquetar a binario (24 bytes header + 48 bytes record = 72 bytes)
        pkt_bytes = NetFlowV5PacketBuilder.build_packet([original_flow], seq_number=42)
        self.assertEqual(len(pkt_bytes), 72)

        # Desempaquetar
        header, records = NetFlowParser.parse_packet(pkt_bytes)

        self.assertIsNotNone(header)
        self.assertEqual(header.version, 5)
        self.assertEqual(header.count, 1)
        self.assertEqual(header.flow_sequence, 42)

        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.src_ip, original_flow.src_ip)
        self.assertEqual(rec.dst_ip, original_flow.dst_ip)
        self.assertEqual(rec.next_hop, original_flow.next_hop)
        self.assertEqual(rec.src_port, original_flow.src_port)
        self.assertEqual(rec.dst_port, original_flow.dst_port)
        self.assertEqual(rec.packets, original_flow.packets)
        self.assertEqual(rec.bytes, original_flow.bytes)
        self.assertEqual(rec.tcp_flags, original_flow.tcp_flags)
        self.assertEqual(rec.protocol, original_flow.protocol)
        self.assertEqual(rec.input_snmp, original_flow.input_snmp)
        self.assertEqual(rec.output_snmp, original_flow.output_snmp)
        self.assertEqual(rec.flow_version, 5)

    def test_corrupted_packet_handling(self):
        """Prueba que paquetes truncados o corruptos no produzcan excepciones fatales."""
        # Menos de 24 bytes (invalido)
        h, r = NetFlowParser.parse_packet(b"too_short")
        self.assertIsNone(h)
        self.assertEqual(r, [])

        # Header indicando version invalida (v9 y v10 son soportadas, v99 no)
        fake_header = b"\x00\x63" + b"\x00" * 22  # Version 99 (invalida)
        h, r = NetFlowParser.parse_packet(fake_header)
        self.assertIsNone(h)
        self.assertEqual(r, [])

    def test_scenario_generators(self):
        """Prueba que los generadores de escenarios produzcan flujos conformes."""
        normal = TrafficScenarioGenerator.normal_traffic(count=15)
        self.assertEqual(len(normal), 15)
        for f in normal:
            self.assertIn(f.protocol, (6, 17))
            self.assertGreater(f.bytes, 0)
            self.assertGreater(f.packets, 0)

        scan = TrafficScenarioGenerator.port_scan_attack(count=20, attacker_ip="192.168.1.185")
        self.assertEqual(len(scan), 20)
        for f in scan:
            self.assertEqual(f.src_ip, "192.168.1.185")
            self.assertEqual(f.tcp_flags, 0x02)  # SYN
            self.assertEqual(f.protocol, 6)

        flood = TrafficScenarioGenerator.syn_flood_attack(count=30, target_ip="10.0.0.5")
        self.assertEqual(len(flood), 30)
        for f in flood:
            self.assertEqual(f.dst_ip, "10.0.0.5")
            self.assertEqual(f.tcp_flags, 0x02)

        exfil = TrafficScenarioGenerator.data_exfiltration_attack(insider_ip="10.0.0.15")
        self.assertEqual(len(exfil), 1)
        self.assertGreater(exfil[0].bytes, 50_000_000)  # Mayor a 50 MB


if __name__ == "__main__":
    unittest.main()
