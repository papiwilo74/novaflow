"""
Pruebas unitarias para la Fase 4: Sonda de Captura eBPF/XDP y Emulador de Ring Buffer.
"""

import os
from pathlib import Path
import struct
import time
import unittest

from collector.ebpf_loader import (
    EBPFProbeMode,
    FlowEvent,
    UserspaceRingBuffer,
    XDPProbeManager,
)
from scripts.run_ebpf_benchmark import generate_synthetic_packet


class TestEBPFProbe(unittest.TestCase):
    """Batería de validación de la sonda eBPF/XDP y el canal de Ring Buffer."""

    def test_c_kernel_source_compliance(self):
        """Verifica que el archivo de código fuente C eBPF esté presente y estructurado."""
        c_path = Path(__file__).resolve().parent.parent / "collector" / "ebpf" / "novaflow_xdp.bpf.c"
        self.assertTrue(c_path.is_file(), "El código fuente C eBPF debe existir en collector/ebpf/")

        content = c_path.read_text(encoding="utf-8")
        self.assertIn("SEC(\"xdp\")", content)
        self.assertIn("novaflow_xdp_prog", content)
        self.assertIn("BPF_MAP_TYPE_HASH", content)
        self.assertIn("BPF_MAP_TYPE_RINGBUF", content)
        self.assertIn("flow_table", content)
        self.assertIn("events_rb", content)

    def test_ring_buffer_enqueue_and_drain(self):
        """Valida las operaciones de encolado y vaciado por lotes del Ring Buffer."""
        rb = UserspaceRingBuffer(capacity=10)

        # Encolar 15 eventos en buffer de capacidad 10
        for i in range(15):
            ev = FlowEvent(
                src_ip=f"10.0.0.{i}",
                dst_ip="192.168.1.1",
                src_port=1000 + i,
                dst_port=443,
                protocol=6,
                tcp_flags=0x18,
                packets=5,
                bytes=500,
                duration_ms=10.0,
                timestamp=time.time(),
            )
            rb.push(ev)

        self.assertEqual(rb.total_enqueued, 15)
        self.assertEqual(rb.total_dropped, 5)
        self.assertEqual(len(rb), 10)

        # Drenar lote de 6
        batch1 = rb.drain(max_count=6)
        self.assertEqual(len(batch1), 6)
        self.assertEqual(len(rb), 4)

        # Drenar los restantes
        batch2 = rb.drain(max_count=10)
        self.assertEqual(len(batch2), 4)
        self.assertEqual(len(rb), 0)

    def test_packet_dissection_and_flow_aggregation(self):
        """Verifica que los paquetes crudos se decodifiquen y agreguen en la tabla de flujos."""
        probe = XDPProbeManager(interface="test-veth", force_emulator=True)
        self.assertEqual(probe.mode, EBPFProbeMode.USERSPACE_RINGBUF_EMULATOR)

        src_ip_int = 0x0A000005  # 10.0.0.5
        dst_ip_int = 0xC0A80164  # 192.168.1.100

        # Inyectar 3 paquetes TCP PSH/ACK para el mismo flujo
        for _ in range(3):
            pkt = generate_synthetic_packet(
                src_ip_int=src_ip_int,
                dst_ip_int=dst_ip_int,
                src_port=54321,
                dst_port=443,
                flags=0x18,
            )
            res = probe.process_raw_packet(pkt)
            self.assertTrue(res)

        stats = probe.get_stats()
        self.assertEqual(stats["total_packets"], 3)
        self.assertEqual(stats["active_flows_in_table"], 1)

        # Inyectar paquete FIN (0x01) para cerrar el flujo y gatillar emisión al Ring Buffer
        fin_pkt = generate_synthetic_packet(
            src_ip_int=src_ip_int,
            dst_ip_int=dst_ip_int,
            src_port=54321,
            dst_port=443,
            flags=0x01,
        )
        probe.process_raw_packet(fin_pkt)

        # La tabla activa debe haberse vaciado tras la emisión del evento de cierre
        self.assertEqual(len(probe._flow_table), 0)
        self.assertEqual(len(probe.ring_buffer), 1)

        # Drenar evento y validar conversión a NetFlowRecord
        events = probe.drain_events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.src_ip, "10.0.0.5")
        self.assertEqual(ev.dst_ip, "192.168.1.100")
        self.assertEqual(ev.src_port, 54321)
        self.assertEqual(ev.dst_port, 443)
        self.assertEqual(ev.packets, 4)

        record = ev.to_netflow_record()
        self.assertEqual(record.src_ip, "10.0.0.5")
        self.assertEqual(record.dst_port, 443)
        self.assertEqual(record.packets, 4)

    def test_probe_throughput_capacity(self):
        """Valida que el emulador de sonda procese ráfagas sostenidas a alta velocidad."""
        probe = XDPProbeManager(interface="test-veth", ringbuf_capacity=10000, force_emulator=True)
        pkt = generate_synthetic_packet(0x0A000001, 0x0A000002, 1234, 80)

        t_start = time.perf_counter()
        count = 10000
        for _ in range(count):
            probe.process_raw_packet(pkt)
        elapsed = time.perf_counter() - t_start

        pps = count / max(elapsed, 0.0001)
        # Debe procesar holgadamente más de 20,000 pps en memoria
        self.assertGreater(pps, 20000.0)


if __name__ == "__main__":
    unittest.main()
