"""
NovaFlow NDR - Test Suite for Phase 3: Wire-Speed Decoupled Multiprocessing Pipeline.
Verifica la integridad del ring buffer en memoria compartida (SharedMemoryRingBuffer),
la simetría del balanceador de 5-tuplas y el pipeline de multiprocesamiento desacoplado.
"""

import os
import socket
import struct
import time
import unittest

from collector.pipeline import (
    WireSpeedPipeline,
    compute_symmetric_5tuple_hash,
    extract_quick_5tuple_from_v5,
)
from collector.ring_buffer import SharedMemoryRingBuffer


def make_v5_packet(
    src_ip: str = "10.0.0.10",
    dst_ip: str = "192.168.1.5",
    src_port: int = 12345,
    dst_port: int = 80,
    proto: int = 6,
    packets: int = 10,
    bytes_count: int = 1500,
) -> bytes:
    """Construye un paquete UDP NetFlow v5 binario canónico para pruebas."""
    hdr = struct.pack(
        "!HHIIIIBBH",
        5,      # version
        1,      # count
        1000,   # uptime
        int(time.time()),
        0,
        1,      # seq
        0, 0, 0,
    )
    rec = struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        socket.inet_aton("0.0.0.0"),
        1, 2,
        packets,
        bytes_count,
        1000, 2000,
        src_port,
        dst_port,
        0, 2, proto, 0, 0, 0, 24, 24, 0,
    )
    return hdr + rec


class TestSharedMemoryRingBuffer(unittest.TestCase):
    """Batería de validación de SharedMemoryRingBuffer."""

    def test_single_write_and_read(self):
        """Verifica la escritura y lectura unitaria en memoria compartida."""
        ring_name = "test_shm_single"
        with SharedMemoryRingBuffer(ring_name, capacity=8, slot_size=256, create=True) as ring:
            payload = b"TEST_PAYLOAD_NOVAFLOW_01"
            self.assertTrue(ring.write(payload, flags=1))

            res = ring.read()
            self.assertIsNotNone(res)
            data, flags, ts_ns = res
            self.assertEqual(data, payload)
            self.assertEqual(flags, 1)
            self.assertGreater(ts_ns, 0)

            # Búfer vacío
            self.assertIsNone(ring.read())

    def test_batch_read(self):
        """Verifica la lectura por lotes de alta velocidad."""
        ring_name = "test_shm_batch"
        with SharedMemoryRingBuffer(ring_name, capacity=16, slot_size=128, create=True) as ring:
            for i in range(5):
                ring.write(f"item_{i}".encode("utf-8"))

            batch = ring.read_batch(max_items=10)
            self.assertEqual(len(batch), 5)
            for idx, (data, flags, ts) in enumerate(batch):
                self.assertEqual(data, f"item_{idx}".encode("utf-8"))

            # Siguiente lote debe estar vacío
            self.assertEqual(len(ring.read_batch()), 0)

    def test_circular_wraparound(self):
        """Verifica que el índice circular rote correctamente más allá de la capacidad."""
        ring_name = "test_shm_wrap"
        capacity = 4
        with SharedMemoryRingBuffer(ring_name, capacity=capacity, slot_size=64, create=True) as ring:
            for cycle in range(3):
                for i in range(capacity):
                    self.assertTrue(ring.write(f"val_{cycle}_{i}".encode("utf-8")))
                for i in range(capacity):
                    item = ring.read()
                    self.assertIsNotNone(item)
                    self.assertEqual(item[0], f"val_{cycle}_{i}".encode("utf-8"))

    def test_backpressure_and_dropped_counter(self):
        """Verifica que la condición de saturación incremente el contador dropped sin bloquear."""
        ring_name = "test_shm_backpressure"
        with SharedMemoryRingBuffer(ring_name, capacity=3, slot_size=64, create=True) as ring:
            self.assertTrue(ring.write(b"pkt_1"))
            self.assertTrue(ring.write(b"pkt_2"))
            self.assertTrue(ring.write(b"pkt_3"))

            # Cuarto paquete excede la capacidad: debe ser descartado
            self.assertFalse(ring.write(b"pkt_4"))
            self.assertFalse(ring.write(b"pkt_5"))

            m = ring.metrics
            self.assertEqual(m["capacity"], 3)
            self.assertEqual(m["pending_packets"], 3)
            self.assertEqual(m["dropped_packets"], 2)
            self.assertEqual(m["utilization_pct"], 100.0)


class TestSymmetricHashingAndQuickExtraction(unittest.TestCase):
    """Batería de validación para balanceo simétrico por 5-tupla."""

    def test_symmetric_5tuple_hashing(self):
        """Garantiza que cliente->servidor y servidor->cliente asignen al mismo worker."""
        num_workers = 4
        # Flujo 1
        h_fwd = compute_symmetric_5tuple_hash("192.168.1.100", "10.0.0.1", 49152, 443, 6, num_workers)
        h_rev = compute_symmetric_5tuple_hash("10.0.0.1", "192.168.1.100", 443, 49152, 6, num_workers)
        self.assertEqual(h_fwd, h_rev)

        # Flujo 2 UDP
        h_dns_fwd = compute_symmetric_5tuple_hash("10.0.5.20", "8.8.8.8", 53210, 53, 17, num_workers)
        h_dns_rev = compute_symmetric_5tuple_hash("8.8.8.8", "10.0.5.20", 53, 53210, 17, num_workers)
        self.assertEqual(h_dns_fwd, h_dns_rev)

    def test_quick_5tuple_extraction_from_v5(self):
        """Verifica la extracción binaria en nanosegundos sin parsing completo."""
        pkt = make_v5_packet(
            src_ip="172.16.0.40",
            dst_ip="10.10.10.1",
            src_port=44444,
            dst_port=445,
            proto=6,
        )
        t5 = extract_quick_5tuple_from_v5(pkt)
        self.assertIsNotNone(t5)
        src_ip, dst_ip, src_port, dst_port, proto = t5
        self.assertEqual(src_ip, "172.16.0.40")
        self.assertEqual(dst_ip, "10.10.10.1")
        self.assertEqual(src_port, 44444)
        self.assertEqual(dst_port, 445)
        self.assertEqual(proto, 6)


class TestWireSpeedPipelineIntegration(unittest.TestCase):
    """Batería de validación end-to-end del pipeline desacoplado multiproceso."""

    def test_pipeline_flow_ingestion_and_metrics(self):
        """Verifica la ingesta multi-worker paralela y la consolidación de métricas."""
        pipeline = WireSpeedPipeline(num_workers=2, ring_capacity=100, slot_size=512)
        pipeline.start()
        try:
            total_packets = 30
            for i in range(total_packets):
                pkt = make_v5_packet(
                    src_ip=f"10.0.1.{i+1}",
                    dst_ip="192.168.1.1",
                    dst_port=80,
                )
                self.assertTrue(pipeline.submit_packet(pkt))

            # Dar breve margen a los workers para procesar
            time.sleep(0.4)

            metrics = pipeline.get_metrics()
            self.assertEqual(metrics["total_submitted_packets"], total_packets)
            self.assertEqual(metrics["total_worker_packets"], total_packets)
            self.assertEqual(metrics["total_worker_flows"], total_packets)
            self.assertEqual(len(metrics["workers"]), 2)
            self.assertTrue(all(w["pid"] > 0 for w in metrics["workers"]))
        finally:
            pipeline.stop()

    def test_pipeline_threat_detection_and_alert_propagation(self):
        """Verifica que un ataque analizado en un worker propague alertas al hilo principal."""
        pipeline = WireSpeedPipeline(num_workers=2, ring_capacity=100, slot_size=512)
        pipeline.start()
        try:
            attacker = "10.0.99.77"
            victim = "10.0.0.1"

            # Simular barrido rápido de puertos (> 15 puertos)
            for port in range(1, 25):
                pkt = make_v5_packet(
                    src_ip=attacker,
                    dst_ip=victim,
                    dst_port=port,
                    proto=6,
                    packets=1,
                    bytes_count=40,
                )
                pipeline.submit_packet(pkt)

            time.sleep(0.4)

            alerts = pipeline.get_alerts()
            self.assertGreaterEqual(len(alerts), 1)
            first_alert = alerts[0]
            self.assertIn("src_ip", first_alert)
            self.assertEqual(first_alert["src_ip"], attacker)
            self.assertEqual(first_alert["category"], "PORT_SCAN")
        finally:
            pipeline.stop()


if __name__ == "__main__":
    unittest.main()
