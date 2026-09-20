"""
NovaFlow NDR - Test Suite para PCAP Reader / Replay
Valida la lectura y decodificación nativa de capturas de red estándar (.pcap)
y la integración con el parser binario de NetFlow v5.
"""

import os
import socket
import struct
import tempfile
import unittest

from collector.pcap_reader import PcapReader, PcapWriter
from collector.parser import NetFlowParser, NetFlowHeader, NetFlowRecord
from scripts.replay_pcap import replay_pcap


class TestPcapReaderAndReplay(unittest.TestCase):
    def setUp(self):
        self.sample_pcap = os.path.join(
            os.path.dirname(__file__), "..", "captures", "sample_netflow_v5_cisco.pcap"
        )

    def test_sample_cisco_pcap_exists(self):
        """Verifica que el archivo PCAP de muestra esté presente en el repositorio."""
        self.assertTrue(os.path.isfile(self.sample_pcap), f"No se encontró: {self.sample_pcap}")
        self.assertGreater(os.path.getsize(self.sample_pcap), 100)

    def test_pcap_reader_decodes_cisco_capture(self):
        """Valida que PcapReader desempaquete correctamente los paquetes del sample PCAP."""
        reader = PcapReader(self.sample_pcap)
        packets = list(reader)

        self.assertEqual(len(packets), 5, "El sample PCAP debe contener exactamente 5 paquetes")
        for ts, raw_pkt in packets:
            self.assertGreater(ts, 1600000000.0)
            self.assertGreater(len(raw_pkt), 42)  # Ethernet (14) + IP (20) + UDP (8)

    def test_extract_udp_payload_and_netflow_parse(self):
        """Valida que los payloads extraídos del PCAP coincidan con datagramas NetFlow v5 válidos."""
        reader = PcapReader(self.sample_pcap)
        total_records_found = 0

        for _, raw_pkt in reader:
            payload = PcapReader.extract_udp_payload(raw_pkt, target_port=2055)
            self.assertIsNotNone(payload, "Cada paquete del sample debe tener como destino o origen UDP 2055")

            header, records = NetFlowParser.parse_packet(payload)
            self.assertIsNotNone(header)
            self.assertEqual(header.version, 5)
            self.assertEqual(len(records), header.count)
            total_records_found += len(records)

        # De acuerdo a la generación de sample_netflow_v5_cisco:
        # Pkt 1: flujos normales
        # Pkt 2: flujos port scan
        # Pkt 3: flujos normales
        # Pkt 4: flujos exfiltración
        # Pkt 5: flujos normales
        # Total = 51 flujos
        self.assertEqual(total_records_found, 51)

    def test_pcap_corrupted_header_handling(self):
        """Valida que un archivo PCAP con firma mágica incorrecta o corrupto lance ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(b"\x00\x00\x00\x00" + b"\x00" * 20)
            tmp_path = tmp.name

        try:
            reader = PcapReader(tmp_path)
            with self.assertRaises(ValueError):
                list(reader)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_pcap_writer_and_reader_roundtrip(self):
        """Valida la creación sintética con PcapWriter y posterior lectura con PcapReader."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            fake_payload = b"NETFLOW_TEST_PAYLOAD_12345678"
            packets_to_write = [
                (1700000000.123456, "192.168.1.1", "192.168.1.200", 50000, 2055, fake_payload),
                (1700000001.654321, "10.0.0.5", "10.0.0.1", 60000, 2055, fake_payload * 2),
            ]

            PcapWriter.create_pcap(tmp_path, packets_to_write)
            reader = PcapReader(tmp_path)
            read_packets = list(reader)

            self.assertEqual(len(read_packets), 2)

            # Verificar payload extraído
            extracted_0 = PcapReader.extract_udp_payload(read_packets[0][1], target_port=2055)
            self.assertEqual(extracted_0, fake_payload)

            extracted_1 = PcapReader.extract_udp_payload(read_packets[1][1], target_port=2055)
            self.assertEqual(extracted_1, fake_payload * 2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_replay_pcap_to_udp_listener(self):
        """Valida que replay_pcap envíe correctamente los datagramas a un socket UDP de prueba."""
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))  # Puerto efímero libre
        assigned_port = receiver.getsockname()[1]
        receiver.settimeout(2.0)

        try:
            # Replay hacia el socket asignado
            stats = replay_pcap(
                pcap_path=self.sample_pcap,
                target_host="127.0.0.1",
                target_port=assigned_port,
                realtime=False,
                max_packets=3,
            )

            self.assertEqual(stats["netflow_datagrams_sent"], 3)
            self.assertGreater(stats["bytes_sent"], 0)

            # Recibir en el socket de prueba
            received_datagrams = 0
            while received_datagrams < 3:
                data, addr = receiver.recvfrom(65535)
                self.assertGreater(len(data), 24)  # Mínimo tamaño de cabecera NetFlow
                received_datagrams += 1

            self.assertEqual(received_datagrams, 3)
        finally:
            receiver.close()


if __name__ == "__main__":
    unittest.main()
