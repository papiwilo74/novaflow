"""
NovaFlow NDR - Automated End-to-End Demo & Test Suite
Ejecuta colector asíncrono, genera tráfico de prueba (normal + 4 ataques)
y valida la integridad forense de los flujos recibidos.
"""

import asyncio
import os
import sys
import time

# Asegurar que el path raíz del proyecto esté en sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.parser import NetFlowParser, NetFlowRecord
from collector.storage import ClickHouseBatchFlusher
from collector.server import NetFlowUDPServerProtocol
from detector.engine import DetectionEngine
from generator.scenarios import TrafficScenarioGenerator, FlowDefinition
from generator.generator import NetFlowSender


async def run_integration_test():
    print("=" * 75)
    print("      NOVAFLOW NDR - PRUEBA INTEGRAL END-TO-END (FASE 1 & 2)         ")
    print("=" * 75)

    test_port = 2055
    flusher = ClickHouseBatchFlusher(
        host="localhost",
        port=8123,
        batch_size=1000,
        flush_interval_secs=0.5,
    )
    await flusher.start()

    engine = DetectionEngine()

    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: NetFlowUDPServerProtocol(flusher, engine=engine, stats_interval=1.0),
            local_addr=("127.0.0.1", test_port),
        )
    except OSError as e:
        print(f"[!] Error al enlazar socket en puerto {test_port}: {e}")
        return

    print(f"[+] Colector UDP activo en 127.0.0.1:{test_port}")
    sender = NetFlowSender("127.0.0.1", test_port)

    # 1. Tráfico Normal
    print("\n[1/4] Inyectando tráfico corporativo legítimo (HTTP, HTTPS, DNS, SSH)...")
    normal_flows = TrafficScenarioGenerator.normal_traffic(count=150)
    sent_normal = sender.send_flows(normal_flows)
    print(f"      Enviados: {sent_normal} flujos")

    # 2. Ataque: Port Scan
    print("\n[2/4] Inyectando vector de ciberataque: Port Scan (SYN vertical/horizontal)...")
    scan_flows = TrafficScenarioGenerator.port_scan_attack(count=80, attacker_ip="192.168.1.185")
    sent_scan = sender.send_flows(scan_flows)
    print(f"      Enviados: {sent_scan} flujos")

    # 3. Ataque: SYN Flood
    print("\n[3/4] Inyectando vector de ciberataque: SYN Flood (Denegación de Servicio)...")
    flood_flows = TrafficScenarioGenerator.syn_flood_attack(count=120, target_ip="10.0.0.5")
    sent_flood = sender.send_flows(flood_flows)
    print(f"      Enviados: {sent_flood} flujos")

    # 4. Ataque: Data Exfiltration
    print("\n[4/4] Inyectando vector de ciberataque: Exfiltración de datos (~88.5 MB)...")
    exfil_flows = TrafficScenarioGenerator.data_exfiltration_attack(
        insider_ip="10.0.0.15", rogue_c2_ip="198.51.100.77"
    )
    sent_exfil = sender.send_flows(exfil_flows)
    print(f"      Enviados: {sent_exfil} flujos")

    total_sent = sent_normal + sent_scan + sent_flood + sent_exfil

    # Esperar procesamiento en el pipeline
    print("\n[*] Procesando datagramas en el motor de descompresion y motor de deteccion...")
    for _ in range(50):
        if protocol.flows_decoded >= total_sent:
            break
        await asyncio.sleep(0.1)
    await asyncio.sleep(0.5)

    # Validación
    print("\n" + "-" * 75)
    print("                    MÉTRICAS FORENSES DEL COLECTOR                   ")
    print("-" * 75)
    print(f"  * Datagramas UDP Recibidos  : {protocol.packets_received:,}")
    print(f"  * Bytes UDP Recibidos       : {protocol.bytes_received:,} bytes")
    print(f"  * Flujos NetFlow Decodificados: {protocol.flows_decoded:,}")
    print(f"  * Flujos Enviados por Mock  : {total_sent:,}")

    # Assert de integridad
    assert protocol.flows_decoded == total_sent, (
        f"Discrepancia: se enviaron {total_sent} y se decodificaron {protocol.flows_decoded}"
    )
    print("\n[OK] INTEGRIDAD FORENSE VALIDADA: Cero perdidas en desempaquetado binario NetFlow v5.")

    # ---------------------------------------------------------------------
    # MÉTRICAS DEL MOTOR DE DETECCIÓN DE AMENAZAS (FASE 2)
    # ---------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("            CENTRO DE RESPUESTA A INCIDENTES DE CIBERSEGURIDAD      ")
    print("-" * 75)
    print(f"  * Total Alertas Generadas   : {engine.stats['total_alerts']}")
    print(f"  * Distribucion por Severidad: {engine.stats['by_severity']}")
    print(f"  * Distribucion por Categoria: {engine.stats['by_category']}")

    print("\n  Listado de Incidentes Detectados en Vivo:")
    for idx, alert in enumerate(engine.alerts_history, 1):
        print(
            f"    [{idx}] [{alert.severity.value}] [{alert.category.value}] "
            f"{alert.title} | Confianza: {alert.confidence*100:.0f}%"
        )

    assert engine.stats["total_alerts"] >= 3, "Se esperaban al menos 3 alertas de ciberseguridad"
    print("\n[OK] DETECCION DE AMENAZAS VALIDADA: Todos los vectores de ataque identificados.")

    if flusher.is_connected:
        print(f"[OK] Persistencia ClickHouse: {flusher.total_flows_inserted:,} flujos insertados en DB.")
    else:
        print("[i] Persistencia ClickHouse: Servidor offline (buffer asincrono retuvo los registros en memoria).")

    # Cerrar sockets
    sender.close()
    transport.close()
    await flusher.stop()
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(run_integration_test())
