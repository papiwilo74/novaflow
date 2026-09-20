"""
NovaFlow NDR - NetFlow v5 Synthetic Packet Generator
Constructor binario y transmisor UDP para pruebas de carga y simulación de ciberseguridad.
"""

import argparse
import logging
import os
import socket
import struct
import sys
import time
from typing import List

# Permitir ejecución tanto como script directo como módulo
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from generator.scenarios import FlowDefinition, TrafficScenarioGenerator
except ImportError:
    from scenarios import FlowDefinition, TrafficScenarioGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("NovaFlow.Generator")

HEADER_FORMAT = "!HHIIIIBBH"
RECORD_FORMAT = "!4s4s4sHHIIIIHHBBBBHHBBH"


class NetFlowV5PacketBuilder:
    """Serializador binario de paquetes NetFlow v5 conformes a RFC."""

    @staticmethod
    def build_packet(flows: List[FlowDefinition], seq_number: int = 1) -> bytes:
        """
        Empaqueta hasta 30 registros de flujo en un datagrama UDP NetFlow v5 válido.
        """
        count = min(len(flows), 30)
        flows_to_pack = flows[:count]

        now = time.time()
        unix_secs = int(now)
        unix_nsecs = int((now - unix_secs) * 1_000_000_000)
        sys_uptime = int((time.monotonic() * 1000)) & 0xFFFFFFFF

        # Empaquetar Header (24 bytes)
        header_bytes = struct.pack(
            HEADER_FORMAT,
            5,               # version = 5
            count,           # count = registros en este datagrama
            sys_uptime,      # SysUptime ms
            unix_secs,       # unix_secs
            unix_nsecs,      # unix_nsecs
            seq_number,      # flow_sequence
            0,               # engine_type
            0,               # engine_id
            0,               # sampling_interval
        )

        # Empaquetar Registros (48 bytes c/u)
        records_bytes = bytearray()
        for f in flows_to_pack:
            rec = struct.pack(
                RECORD_FORMAT,
                socket.inet_aton(f.src_ip),
                socket.inet_aton(f.dst_ip),
                socket.inet_aton(f.next_hop),
                f.input_snmp,
                f.output_snmp,
                f.packets,
                f.bytes,
                f.first_switched,
                f.last_switched,
                f.src_port,
                f.dst_port,
                0,             # pad1
                f.tcp_flags,
                f.protocol,
                f.tos,
                f.src_as,
                f.dst_as,
                f.src_mask,
                f.dst_mask,
                0,             # pad2
            )
            records_bytes.extend(rec)

        return header_bytes + bytes(records_bytes)


class NetFlowSender:
    """Envía paquetes NetFlow a través de socket UDP."""

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 2055):
        self.target_host = target_host
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sequence = 1

    def send_flows(self, flows: List[FlowDefinition]) -> int:
        """Divide los flujos en fragmentos de 30 y los envía vía UDP."""
        total_sent = 0
        chunk_size = 30

        for i in range(0, len(flows), chunk_size):
            chunk = flows[i : i + chunk_size]
            pkt = NetFlowV5PacketBuilder.build_packet(chunk, seq_number=self.sequence)
            self.sock.sendto(pkt, (self.target_host, self.target_port))
            self.sequence += len(chunk)
            total_sent += len(chunk)

        return total_sent

    def close(self):
        self.sock.close()


def run_simulation(
    target_host: str = "127.0.0.1",
    target_port: int = 2055,
    scenario: str = "all",
    rate_flows_sec: int = 200,
    duration_secs: int = 10,
):
    """Ejecuta una sesión de simulación transmitiendo flujos sintéticos."""
    sender = NetFlowSender(target_host, target_port)
    logger.info(f"Iniciando simulación hacia {target_host}:{target_port}")
    logger.info(f"Escenario: '{scenario}' | Velocidad: {rate_flows_sec} flows/s | Duración: {duration_secs}s")

    start_time = time.time()
    total_flows_transmitted = 0

    try:
        while (time.time() - start_time) < duration_secs:
            loop_start = time.time()
            flows_batch: List[FlowDefinition] = []

            if scenario in ("normal", "all"):
                flows_batch.extend(TrafficScenarioGenerator.normal_traffic(count=25))

            if scenario in ("portscan", "all"):
                flows_batch.extend(TrafficScenarioGenerator.port_scan_attack(count=20))

            if scenario in ("synflood", "all"):
                flows_batch.extend(TrafficScenarioGenerator.syn_flood_attack(count=25))

            if scenario in ("exfiltration", "all"):
                flows_batch.extend(TrafficScenarioGenerator.data_exfiltration_attack())

            sent = sender.send_flows(flows_batch)
            total_flows_transmitted += sent

            # Control de tasa de transmisión
            elapsed = time.time() - loop_start
            expected_time = sent / rate_flows_sec
            sleep_time = max(0.001, expected_time - elapsed)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        logger.info("Simulación detenida por el usuario.")
    finally:
        total_duration = max(0.01, time.time() - start_time)
        avg_rate = total_flows_transmitted / total_duration
        sender.close()
        logger.info(
            f"=== Simulación finalizada ===\n"
            f"  - Total Flujos Transmitidos: {total_flows_transmitted:,}\n"
            f"  - Duración Real: {total_duration:.2f} s\n"
            f"  - Velocidad Promedio: {avg_rate:.1f} flows/s"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaFlow NDR Synthetic NetFlow Generator")
    parser.add_argument("--host", default="127.0.0.1", help="Target UDP collector IP")
    parser.add_argument("--port", type=int, default=2055, help="Target UDP collector Port")
    parser.add_argument(
        "--scenario",
        choices=["normal", "portscan", "synflood", "exfiltration", "all"],
        default="all",
        help="Traffic scenario to generate",
    )
    parser.add_argument("--rate", type=int, default=150, help="Target flows per second")
    parser.add_argument("--duration", type=int, default=5, help="Simulation duration in seconds")

    args = parser.parse_args()
    run_simulation(
        target_host=args.host,
        target_port=args.port,
        scenario=args.scenario,
        rate_flows_sec=args.rate,
        duration_secs=args.duration,
    )
