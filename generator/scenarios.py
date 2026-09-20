"""
NovaFlow NDR - Attack and Traffic Scenarios
Generadores de patrones de tráfico legítimo y vectores de ciberamenaza.
"""

import random
import time
from dataclasses import dataclass
from typing import List, Generator

@dataclass
class FlowDefinition:
    src_ip: str
    dst_ip: str
    next_hop: str
    input_snmp: int
    output_snmp: int
    packets: int
    bytes: int
    first_switched: int
    last_switched: int
    src_port: int
    dst_port: int
    tcp_flags: int
    protocol: int
    tos: int = 0
    src_as: int = 65001
    dst_as: int = 15169
    src_mask: int = 24
    dst_mask: int = 24


class TrafficScenarioGenerator:
    """Genera flujos sintéticos para diferentes escenarios de prueba."""

    INTERNAL_SUBNET = ["192.168.1.{}".format(i) for i in range(10, 60)]
    INTERNAL_SERVERS = ["10.0.0.2", "10.0.0.5", "10.0.0.10", "10.0.0.15"]
    PUBLIC_CDNS = ["142.250.190.46", "151.101.1.69", "104.244.42.1", "13.107.42.14"]
    DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8", "192.168.1.1"]

    @classmethod
    def normal_traffic(cls, count: int = 20) -> List[FlowDefinition]:
        """Genera tráfico corporativo típico (HTTP, HTTPS, DNS, SSH)."""
        flows = []
        now_ms = int(time.time() * 1000) & 0xFFFFFFFF

        for _ in range(count):
            proto_choice = random.choices(["HTTPS", "HTTP", "DNS", "SSH"], weights=[60, 15, 20, 5])[0]
            src_ip = random.choice(cls.INTERNAL_SUBNET)
            src_port = random.randint(32768, 65000)

            if proto_choice == "HTTPS":
                dst_ip = random.choice(cls.PUBLIC_CDNS)
                dst_port = 443
                protocol = 6  # TCP
                tcp_flags = 0x18  # ACK + PSH
                packets = random.randint(10, 80)
                bytes_count = packets * random.randint(800, 1400)
            elif proto_choice == "HTTP":
                dst_ip = random.choice(cls.PUBLIC_CDNS)
                dst_port = 80
                protocol = 6
                tcp_flags = 0x18
                packets = random.randint(5, 30)
                bytes_count = packets * random.randint(400, 1200)
            elif proto_choice == "DNS":
                dst_ip = random.choice(cls.DNS_RESOLVERS)
                dst_port = 53
                protocol = 17  # UDP
                tcp_flags = 0
                packets = random.randint(1, 4)
                bytes_count = packets * random.randint(64, 180)
            else:  # SSH
                dst_ip = random.choice(cls.INTERNAL_SERVERS)
                dst_port = 22
                protocol = 6
                tcp_flags = 0x10  # ACK
                packets = random.randint(20, 120)
                bytes_count = packets * random.randint(100, 500)

            flows.append(
                FlowDefinition(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    next_hop="192.168.1.1",
                    input_snmp=1,
                    output_snmp=2,
                    packets=packets,
                    bytes=bytes_count,
                    first_switched=now_ms - 5000,
                    last_switched=now_ms,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_flags=tcp_flags,
                    protocol=protocol,
                )
            )
        return flows

    @classmethod
    def port_scan_attack(cls, count: int = 40, attacker_ip: str = "192.168.1.185") -> List[FlowDefinition]:
        """
        Escenario: Escaneo de puertos vertical/horizontal.
        Una misma IP origen contacta múltiples puertos distintos con flags SYN (0x02) y paquetes mínimos.
        """
        flows = []
        now_ms = int(time.time() * 1000) & 0xFFFFFFFF
        target_server = "10.0.0.5"
        scanned_ports = random.sample(range(20, 5000), min(count, 4000))

        for port in scanned_ports:
            flows.append(
                FlowDefinition(
                    src_ip=attacker_ip,
                    dst_ip=target_server,
                    next_hop="192.168.1.1",
                    input_snmp=1,
                    output_snmp=2,
                    packets=1,
                    bytes=random.randint(44, 60),  # Tamaño típico de paquete TCP SYN
                    first_switched=now_ms - 200,
                    last_switched=now_ms,
                    src_port=random.randint(40000, 65000),
                    dst_port=port,
                    tcp_flags=0x02,  # TCP SYN
                    protocol=6,      # TCP
                )
            )
        return flows

    @classmethod
    def syn_flood_attack(cls, count: int = 50, target_ip: str = "10.0.0.5", target_port: int = 80) -> List[FlowDefinition]:
        """
        Escenario: Ataque de denegación de servicio (SYN Flood).
        Múltiples IPs aleatorias (spoofed) saturando un único servicio destino con flag SYN.
        """
        flows = []
        now_ms = int(time.time() * 1000) & 0xFFFFFFFF

        for _ in range(count):
            spoofed_ip = f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            flows.append(
                FlowDefinition(
                    src_ip=spoofed_ip,
                    dst_ip=target_ip,
                    next_hop="10.0.0.1",
                    input_snmp=2,
                    output_snmp=1,
                    packets=1,
                    bytes=54,
                    first_switched=now_ms - 100,
                    last_switched=now_ms,
                    src_port=random.randint(1024, 65535),
                    dst_port=target_port,
                    tcp_flags=0x02,  # SYN
                    protocol=6,
                )
            )
        return flows

    @classmethod
    def data_exfiltration_attack(cls, insider_ip: str = "10.0.0.15", rogue_c2_ip: str = "198.51.100.77") -> List[FlowDefinition]:
        """
        Escenario: Exfiltración pesada de datos.
        Un servidor interno transfiere volúmenes anómalos de megabytes hacia un C2 exterior.
        """
        now_ms = int(time.time() * 1000) & 0xFFFFFFFF
        # Flujo individual de 85 MB de subida
        return [
            FlowDefinition(
                src_ip=insider_ip,
                dst_ip=rogue_c2_ip,
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=3,
                packets=65000,
                bytes=88_500_000,  # ~88.5 Megabytes
                first_switched=now_ms - 30000,
                last_switched=now_ms,
                src_port=49152,
                dst_port=8443,
                tcp_flags=0x18,   # ACK + PSH
                protocol=6,
            )
        ]
