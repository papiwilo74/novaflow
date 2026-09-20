"""
NovaFlow NDR - ClickHouse Ingestion Verification Tool
Consulta métricas en ClickHouse para validar la ingesta y agregación de flujos.
"""

import sys
import requests

CLICKHOUSE_HTTP_URL = "http://localhost:8123/"


def run_query(query: str, format_name: str = "TabSeparatedWithNames") -> str:
    """Ejecuta una consulta SQL en ClickHouse vía HTTP."""
    resp = requests.post(
        CLICKHOUSE_HTTP_URL,
        params={"query": f"{query} FORMAT {format_name}"},
        timeout=5.0,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Error ({resp.status_code}): {resp.text.strip()}")
    return resp.text.strip()


def check_health() -> bool:
    try:
        r = requests.get(f"{CLICKHOUSE_HTTP_URL}ping", timeout=2.0)
        return r.status_code == 200 and r.text.strip() == "Ok."
    except Exception:
        return False


def main():
    print("=" * 70)
    print("      NOVAFLOW NDR - VERIFICADOR DE INGESTA ANALÍTICA CLICKHOUSE      ")
    print("=" * 70)

    if not check_health():
        print("\n[!] AVISO: ClickHouse no está accesible en http://localhost:8123")
        print("    Para iniciarlo con Docker Compose ejecuta:")
        print("    cd docker && docker compose up -d\n")
        sys.exit(1)

    print("[+] ClickHouse Server: ONLINE (http://localhost:8123)\n")

    # 1. Total de Flujos
    try:
        total_flows = run_query("SELECT count() FROM novaflow.flows_raw", "TabSeparated")
        total_bytes = run_query("SELECT formatReadableSize(sum(bytes)) FROM novaflow.flows_raw", "TabSeparated")
        total_packets = run_query("SELECT sum(packets) FROM novaflow.flows_raw", "TabSeparated")
        print(f"  * Total Flujos Almacenados : {int(total_flows):,}")
        print(f"  * Total Bytes Procesados   : {total_bytes}")
        print(f"  * Total Paquetes           : {int(total_packets):,}")
    except Exception as e:
        print(f"[!] Error consultando tabla principal: {e}")
        return

    # 2. Distribución de Protocolos
    print("\n--- Distribución de Protocolos (Tabla de Flujos) ---")
    proto_query = """
    SELECT 
        multiIf(protocol = 6, 'TCP', protocol = 17, 'UDP', protocol = 1, 'ICMP', toString(protocol)) AS proto,
        count() AS flows,
        sum(packets) AS pkts,
        formatReadableSize(sum(bytes)) AS vol
    FROM novaflow.flows_raw
    GROUP BY proto
    ORDER BY flows DESC
    """
    print(run_query(proto_query))

    # 3. Top Talkers
    print("\n--- Top Talkers (Mayor Consumo de Ancho de Banda) ---")
    top_query = """
    SELECT 
        src_ip,
        dst_ip,
        count() AS flow_count,
        formatReadableSize(sum(bytes)) AS bandwidth
    FROM novaflow.flows_raw
    GROUP BY src_ip, dst_ip
    ORDER BY sum(bytes) DESC
    LIMIT 5
    """
    print(run_query(top_query))

    # 4. Verificación de Vistas Materializadas
    print("\n--- Estado de Vista Materializada (mv_traffic_minute) ---")
    mv_query = """
    SELECT 
        minute,
        protocol,
        flow_count,
        formatReadableSize(total_bytes) AS bytes
    FROM novaflow.agg_traffic_minute
    ORDER BY minute DESC
    LIMIT 5
    """
    try:
        print(run_query(mv_query))
    except Exception as e:
        print(f"[!] Info sobre MV: {e}")

    print("\n" + "=" * 70)
    print("[OK] Verificacion completada con exito.")


if __name__ == "__main__":
    main()
