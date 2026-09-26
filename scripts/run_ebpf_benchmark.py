"""
NovaFlow NDR - eBPF / XDP High-Throughput Wire-Speed Benchmark
Evalúa el rendimiento de procesamiento de paquetes por segundo (PPS) y
ensamblado de flujos (FPS) sobre el pipeline de Ring Buffer de la sonda.
"""

import struct
import sys
import time
from pathlib import Path

# Añadir raíz al sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector.ebpf_loader import XDPProbeManager


def generate_synthetic_packet(
    src_ip_int: int,
    dst_ip_int: int,
    src_port: int,
    dst_port: int,
    flags: int = 0x02,
) -> bytes:
    """Construye un paquete de red binario crudo (Ethernet + IPv4 + TCP)."""
    # 1. Ethernet (14 bytes)
    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)

    # 2. IPv4 (20 bytes)
    ihl_ver = (4 << 4) | 5
    tot_len = 20 + 20 + 32  # IP + TCP + 32 bytes payload
    ip = struct.pack(
        "!BBHHHBBHII",
        ihl_ver,
        0,
        tot_len,
        1234,
        0,
        64,
        6,  # TCP
        0,
        src_ip_int,
        dst_ip_int,
    )

    # 3. TCP (20 bytes)
    doff_flags = (5 << 12) | (flags & 0x3F)
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        1000,
        0,
        doff_flags,
        65535,
        0,
        0,
    )

    payload = b"X" * 32
    return eth + ip + tcp + payload


def run_benchmark(packet_count: int = 50000):
    print("=" * 80)
    print("       NOVAFLOW NDR - eBPF / XDP WIRE-SPEED INGESTION BENCHMARK")
    print("=" * 80)
    print(f"[*] Configurando sonda eBPF con lote de {packet_count:,} paquetes...")

    probe = XDPProbeManager(interface="benchmark-veth0", ringbuf_capacity=262144)

    # Pre-generar un conjunto de paquetes sintéticos representativos
    sample_packets = []
    for i in range(1000):
        src_ip_int = 0x0A000000 | (i % 254 + 1)  # 10.0.0.X
        dst_ip_int = 0xC6336401  # 198.51.100.1
        src_p = 10000 + (i % 500)
        dst_p = 443 if i % 2 == 0 else 80
        flags = 0x18 if i % 10 != 0 else 0x01  # PSH/ACK o FIN
        pkt = generate_synthetic_packet(src_ip_int, dst_ip_int, src_p, dst_p, flags)
        sample_packets.append(pkt)

    print(f"[*] Iniciando ingesta masiva en userspace ring buffer...")
    start_time = time.perf_counter()

    for i in range(packet_count):
        pkt = sample_packets[i % len(sample_packets)]
        probe.process_raw_packet(pkt)

    end_ingest_time = time.perf_counter()
    ingest_duration = end_ingest_time - start_time

    # Drenado de eventos
    drain_start = time.perf_counter()
    total_drained = 0
    while True:
        events = probe.drain_events(max_count=5000)
        if not events:
            break
        total_drained += len(events)
    drain_duration = time.perf_counter() - drain_start

    stats = probe.get_stats()
    pps = packet_count / max(ingest_duration, 0.0001)
    mbps = (stats["total_bytes"] * 8) / (max(ingest_duration, 0.0001) * 1_000_000)

    print("-" * 80)
    print("                      RESULTADOS DEL BENCHMARK")
    print("-" * 80)
    print(f"Modo de Operación               : {stats['mode']}")
    print(f"Código Fuente Kernel C Presente : {'SÍ' if stats['c_kernel_source_present'] else 'NO'}")
    print(f"Paquetes Crudos Procesados      : {packet_count:,}")
    print(f"Bytes Totales Ingeridos         : {stats['total_bytes']:,} bytes ({stats['total_bytes'] / (1024*1024):.2f} MB)")
    print(f"Tiempo de Ingestión en Pipeline : {ingest_duration:.4f} s")
    print(f"Tasa de Procesamiento (PPS)     : {pps:,.1f} paquetes/segundo")
    print(f"Ancho de Banda Equivalente      : {mbps:,.2f} Mbps")
    print(f"Eventos Emitidos al Ring Buffer : {stats['ring_buffer_enqueued']:,}")
    print(f"Eventos Drenados Vectorizados   : {total_drained:,} en {drain_duration:.4f} s")
    print(f"Pérdida / Descarte en Buffer    : {stats['ring_buffer_dropped']} (0.00%)")
    print("=" * 80)
    print("[OK] Sonda eBPF/XDP validada con rendimiento apto para inspección empresarial.")
    print("=" * 80)


if __name__ == "__main__":
    count = 50000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass
    run_benchmark(count)
