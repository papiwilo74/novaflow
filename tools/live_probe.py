"""
NovaFlow NDR - Live Flow Probe & Traffic Sensor
Sonda de telemetría de red en vivo para capturar y traducir actividad ofensiva real
(OmniBreach, Nmap, Curl, scripts DAST) a datagramas NetFlow v5 estándar (RFC Cisco).

Modos de operación:
1. TARGET  : Servidor web objetivo/honeypot que recibe ataques reales y genera NetFlow.
2. RELAY   : Proxy transparente que reenvía peticiones a un backend y extrae telemetría.
3. SNIFFER : Sniffer de socket crudo (Windows Administrator / SIO_RCVALL).
"""

import argparse
import http.server
import json
import logging
import os
import random
import select
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Garantizar que el directorio raíz del proyecto esté en sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from collector.parser import NetFlowRecord
from tools.traffic_gen import build_netflow_v5_packet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [LiveProbe] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("NovaFlow.LiveProbe")


class NetFlowEmitter:
    """Emisor UDP de datagramas binarios NetFlow v5 hacia NovaFlow NDR."""

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 2055):
        self.target_host = target_host
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.total_flows_sent = 0
        self.total_packets_sent = 0

    def send_flows(self, flows: List[NetFlowRecord]):
        if not flows:
            return
        # NetFlow v5 soporta hasta 30 registros por datagrama
        for i in range(0, len(flows), 30):
            chunk = flows[i:i + 30]
            try:
                pkt_bytes = build_netflow_v5_packet(chunk)
                self.sock.sendto(pkt_bytes, (self.target_host, self.target_port))
                self.total_flows_sent += len(chunk)
                self.total_packets_sent += 1
            except Exception as e:
                logger.error(f"Error emitiendo datagrama NetFlow v5: {e}")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class FlowAggregator:
    """
    Agregador en memoria de paquetes y conexiones TCP/UDP para generar registros NetFlow v5.
    Mantiene ventanas de flujo y calcula bytes_sent, bytes_received, paquetes y flags.
    """

    def __init__(self, emitter: NetFlowEmitter, flush_interval_secs: float = 1.0):
        self.emitter = emitter
        self.flush_interval = flush_interval_secs
        self._lock = threading.Lock()
        self._active_flows: Dict[Tuple[str, str, int, int, int], Dict[str, Any]] = {}
        self._running = False
        self._timer_thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._timer_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._timer_thread.start()

    def stop(self):
        self._running = False
        self.flush()

    def record_activity(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        bytes_count: int,
        packets_count: int = 1,
        tcp_flags: int = 24,  # PSH, ACK por defecto
    ):
        """Registra actividad de red entre dos extremos."""
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        now_ms = int(time.time() * 1000) & 0x7FFFFFFF

        with self._lock:
            if key not in self._active_flows:
                self._active_flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "bytes": bytes_count,
                    "packets": packets_count,
                    "tcp_flags": tcp_flags,
                    "first_switched": now_ms,
                    "last_switched": now_ms,
                }
            else:
                flow = self._active_flows[key]
                flow["bytes"] += bytes_count
                flow["packets"] += packets_count
                flow["tcp_flags"] |= tcp_flags
                flow["last_switched"] = now_ms

    def flush(self) -> int:
        """Convierte los flujos activos acumulados en NetFlowRecord y los emite a NovaFlow."""
        with self._lock:
            if not self._active_flows:
                return 0
            to_flush = list(self._active_flows.values())
            self._active_flows.clear()

        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF
        records = []
        for f in to_flush:
            record = NetFlowRecord(
                timestamp=now,
                timestamp_ms=now_ms,
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=2,
                packets=f["packets"],
                bytes=f["bytes"],
                first_switched=f["first_switched"],
                last_switched=f["last_switched"],
                src_port=f["src_port"],
                dst_port=f["dst_port"],
                tcp_flags=f["tcp_flags"],
                protocol=f["protocol"],
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            )
            records.append(record)

        self.emitter.send_flows(records)
        return len(records)

    def _flush_loop(self):
        while self._running:
            time.sleep(self.flush_interval)
            try:
                flushed = self.flush()
                if flushed > 0:
                    logger.debug(f"Emitidos {flushed} flujos NetFlow a NovaFlow.")
            except Exception as e:
                logger.error(f"Error en bucle de volcado de flujos: {e}")


# ==============================================================================
# MODO 1: SERVIDOR OBJETIVO REACTIVO (VULNERABLE TARGET HONEYPOT)
# ==============================================================================
class TargetHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Manejador HTTP que registra y mide cada petición de ataque."""

    aggregator: Optional[FlowAggregator] = None
    server_port: int = 8080
    blocked_ips: set = set()

    def log_message(self, format, *args):
        # Redirigir logs estándar de BaseHTTPRequestHandler a logger
        logger.info(f"[HTTP] {self.client_address[0]}:{self.client_address[1]} - {format % args}")

    def _handle_request(self, method: str):
        client_ip, client_port = self.client_address[0], self.client_address[1]

        # Verificar escudo activo de auto-contención SOAR
        if client_ip in self.blocked_ips:
            logger.warning(f"[SHIELD BLOCKED] Conexión rechazada de host aislado: {client_ip}")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            msg = json.dumps({
                "status": "BLOCKED",
                "shield": "NovaFlow NDR SOAR Active Defense",
                "reason": "Host aislado preventivamente por detección de escaneo/ataque en tiempo real",
                "attacker_ip": client_ip,
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        req_bytes = len(self.raw_requestline) + len(str(self.headers).encode("utf-8")) + len(body)
        server_ip = "127.0.0.1"

        # Simular respuestas según endpoint atacado
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""

        # Flags: SYN ya ocurrió; para la petición enviamos PSH, ACK (24)
        status_code = 200
        resp_data: bytes = b""

        if path == "/" or path == "/index.html":
            resp_data = b'{"service": "Enterprise Target App", "status": "ONLINE", "version": "2.4.1"}'
        elif path == "/login":
            if b"admin" in body and b"password" in body:
                status_code = 401
                resp_data = b'{"error": "Credenciales invalidas", "attempt_logged": true}'
            else:
                resp_data = b'{"form": "login", "auth_methods": ["password", "mfa"]}'
        elif path.startswith("/api/v1/users"):
            resp_data = json.dumps([
                {"id": 1, "username": "admin", "role": "SuperAdmin"},
                {"id": 2, "username": "finance_lead", "role": "Finance"},
                {"id": 3, "username": "dba_user", "role": "DBA"},
            ]).encode("utf-8")
        elif "/admin" in path:
            status_code = 403
            resp_data = b'{"error": "Access Denied: IP no autorizada"}'
        elif "/download" in path or "/export" in path:
            # Simular descarga de gran volumen (fuga/exfiltración de datos)
            chunk_size = 50 * 1024  # 50 KB por chunk
            resp_data = b"X" * chunk_size
        else:
            # Detección de inyecciones SQL o XSS en query string
            if any(sqli in query.lower() for sqli in ["select", "union", "'", "--", "or 1=1"]):
                status_code = 500
                resp_data = b'{"error": "SQL Syntax Error near UNION SELECT table_name"}'
            else:
                resp_data = b'{"message": "Endpoint procesado exitosamente"}'

        # Responder al cliente HTTP (OmniBreach)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.send_header("Server", "Apache-Coyote/1.1")
        self.end_headers()
        self.wfile.write(resp_data)

        # Medir telemetría L3/L4 real
        resp_bytes = len(resp_data) + 120  # Incluye cabeceras HTTP aproximadas
        total_bytes = req_bytes + resp_bytes

        if self.aggregator:
            # 1. Registrar flujo de ida (Cliente -> Servidor)
            self.aggregator.record_activity(
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=self.server_port,
                protocol=6,  # TCP
                bytes_count=req_bytes,
                packets_count=max(2, req_bytes // 500 + 1),
                tcp_flags=24,  # PSH, ACK
            )
            # 2. Registrar flujo de vuelta (Servidor -> Cliente)
            self.aggregator.record_activity(
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=self.server_port,
                dst_port=client_port,
                protocol=6,  # TCP
                bytes_count=resp_bytes,
                packets_count=max(2, resp_bytes // 1400 + 1),
                tcp_flags=24,  # PSH, ACK
            )

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")


def start_soar_sync(novaflow_api_url: str, target_classes: List[Any], poll_interval: float = 1.0):
    """Sincroniza en segundo plano las IPs aisladas por NovaFlow NDR hacia el escudo perimetral."""
    def _sync_worker():
        base_url = novaflow_api_url.rstrip("/")
        while True:
            try:
                req = urllib.request.Request(f"{base_url}/api/v1/soar/containments")
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        for item in data.get("containments", []):
                            ip = item.get("target_ip")
                            if ip:
                                for cls in target_classes:
                                    if ip not in cls.blocked_ips:
                                        cls.blocked_ips.add(ip)
                                        logger.warning(f"[SOAR SHIELD] Host aislado en escudo perimetral: {ip} (Motivo: {item.get('reason')})")
            except Exception:
                pass
            time.sleep(poll_interval)

    t = threading.Thread(target=_sync_worker, daemon=True)
    t.start()


def run_target_mode(listen_port: int, novaflow_host: str, novaflow_port: int, novaflow_api: str = "http://127.0.0.1:8000"):
    """Inicia el servidor objetivo interactivo y la sonda NetFlow."""
    emitter = NetFlowEmitter(novaflow_host, novaflow_port)
    aggregator = FlowAggregator(emitter, flush_interval_secs=0.5)
    aggregator.start()

    # Iniciar sincronización de contención SOAR (escudo activo)
    start_soar_sync(novaflow_api, [TargetHTTPRequestHandler])

    TargetHTTPRequestHandler.aggregator = aggregator
    TargetHTTPRequestHandler.server_port = listen_port

    server_address = ("0.0.0.0", listen_port)
    httpd = http.server.ThreadingHTTPServer(server_address, TargetHTTPRequestHandler)

    print("=" * 80)
    print("        NOVAFLOW NDR - LIVE TARGET PROBE (MODO OBJETIVO REACTIVO)        ")
    print("=" * 80)
    print(f"  [>] Servidor Objetivo : http://localhost:{listen_port}")
    print(f"  [>] Colector NovaFlow : udp://{novaflow_host}:{novaflow_port}")
    print("  [>] Endpoints listos  : /, /login, /admin, /api/v1/users, /download")
    print("=" * 80)
    print(f"[*] Escuchando tráfico HTTP/TCP real en 0.0.0.0:{listen_port}...")
    print(f"[*] ¡Apunta OmniBreach o Nmap hacia http://localhost:{listen_port} ahora!")
    print("=" * 80)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Deteniendo servidor objetivo y emisor de telemetría...")
    finally:
        httpd.server_close()
        aggregator.stop()
        emitter.close()
        print("[OK] Sonda local finalizada.")


# ==============================================================================
# MODO 2: PROXY RELAY TRANSPARENTE
# ==============================================================================
class RelayHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Proxy HTTP inverso que reenvía peticiones y extrae telemetría NetFlow."""

    aggregator: Optional[FlowAggregator] = None
    relay_target_url: str = "http://127.0.0.1:3000"
    server_port: int = 8080
    blocked_ips: set = set()

    def log_message(self, format, *args):
        logger.info(f"[RELAY] {self.client_address[0]}:{self.client_address[1]} -> {self.relay_target_url} {format % args}")

    def _handle_relay(self, method: str):
        client_ip = self.client_address[0]

        # Verificar escudo activo de auto-contención SOAR
        if client_ip in self.blocked_ips:
            logger.warning(f"[SHIELD BLOCKED] Conexión de {client_ip} rechazada por auto-contención SOAR hacia {self.relay_target_url}")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            resp_body = json.dumps({
                "status": "BLOCKED",
                "shield": "NovaFlow NDR SOAR Active Defense",
                "reason": "Host aislado preventivamente tras detectar actividad maliciosa en tiempo real",
                "attacker_ip": client_ip,
                "target_protected": self.relay_target_url,
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        target_full_url = f"{self.relay_target_url.rstrip('/')}{self.path}"
        req_bytes = len(self.raw_requestline) + len(str(self.headers).encode("utf-8")) + (len(body) if body else 0)

        # Preparar petición de reenvío
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        req = urllib.request.Request(target_full_url, data=body, headers=headers, method=method)

        resp_status = 502
        resp_headers: Dict[str, str] = {}
        resp_body = b'{"error": "Bad Gateway en Relay"}'

        try:
            with urllib.request.urlopen(req, timeout=10.0) as response:
                resp_status = response.status
                resp_headers = dict(response.headers)
                resp_body = response.read()
        except urllib.error.HTTPError as e:
            resp_status = e.code
            resp_headers = dict(e.headers)
            resp_body = e.read()
        except Exception as e:
            resp_body = json.dumps({"error": f"Fallo al contactar target: {e}"}).encode("utf-8")

        # Devolver respuesta al cliente
        self.send_response(resp_status)
        for k, v in resp_headers.items():
            if k.lower() not in ["content-length", "transfer-encoding"]:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

        # Registrar telemetría
        resp_bytes = len(resp_body) + 120
        if self.aggregator:
            self.aggregator.record_activity(
                src_ip=self.client_address[0],
                dst_ip="127.0.0.1",
                src_port=self.client_address[1],
                dst_port=self.server_port,
                protocol=6,
                bytes_count=req_bytes,
                packets_count=max(2, req_bytes // 500 + 1),
            )
            self.aggregator.record_activity(
                src_ip="127.0.0.1",
                dst_ip=self.client_address[0],
                src_port=self.server_port,
                dst_port=self.client_address[1],
                protocol=6,
                bytes_count=resp_bytes,
                packets_count=max(2, resp_bytes // 1400 + 1),
            )

    def do_GET(self):
        self._handle_relay("GET")

    def do_POST(self):
        self._handle_relay("POST")

    def do_PUT(self):
        self._handle_relay("PUT")

    def do_DELETE(self):
        self._handle_relay("DELETE")


def run_relay_mode(listen_port: int, relay_target: str, novaflow_host: str, novaflow_port: int, novaflow_api: str = "http://127.0.0.1:8000"):
    emitter = NetFlowEmitter(novaflow_host, novaflow_port)
    aggregator = FlowAggregator(emitter, flush_interval_secs=0.5)
    aggregator.start()

    # Iniciar sincronización de contención SOAR (escudo activo)
    start_soar_sync(novaflow_api, [RelayHTTPRequestHandler])

    RelayHTTPRequestHandler.aggregator = aggregator
    RelayHTTPRequestHandler.relay_target_url = relay_target
    RelayHTTPRequestHandler.server_port = listen_port

    server_address = ("0.0.0.0", listen_port)
    httpd = http.server.ThreadingHTTPServer(server_address, RelayHTTPRequestHandler)

    print("=" * 80)
    print("          NOVAFLOW NDR - LIVE FLOW PROBE (MODO PROXY RELAY)             ")
    print("=" * 80)
    print(f"  [>] Proxy Escucha     : http://localhost:{listen_port}")
    print(f"  [>] Reenvío a Target  : {relay_target}")
    print(f"  [>] Colector NovaFlow : udp://{novaflow_host}:{novaflow_port}")
    print("=" * 80)
    print(f"[*] ¡Apunta OmniBreach hacia http://localhost:{listen_port}!")
    print("=" * 80)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Deteniendo proxy relay...")
    finally:
        httpd.server_close()
        aggregator.stop()
        emitter.close()


# ==============================================================================
# MODO 3: SNIFFER CRUDO DE SOCKETS (ADMINISTRATOR REQUIRED EN WINDOWS)
# ==============================================================================
def run_sniffer_mode(interface_ip: str, novaflow_host: str, novaflow_port: int):
    """Captura paquetes IPv4 directamente de la tarjeta de red mediante SOCK_RAW."""
    emitter = NetFlowEmitter(novaflow_host, novaflow_port)
    aggregator = FlowAggregator(emitter, flush_interval_secs=1.0)
    aggregator.start()

    print("=" * 80)
    print("          NOVAFLOW NDR - LIVE FLOW PROBE (MODO RAW SNIFFER)             ")
    print("=" * 80)
    print(f"  [>] Interfaz de Escucha : {interface_ip}")
    print(f"  [>] Destino NovaFlow    : udp://{novaflow_host}:{novaflow_port}")
    print("=" * 80)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((interface_ip, 0))
        if hasattr(socket, "SIO_RCVALL"):
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            logger.info("Modo promiscuo SIO_RCVALL habilitado en Windows.")
    except Exception as e:
        logger.error(f"Fallo al abrir raw socket en {interface_ip}: {e}")
        print("\n[!] Requiere privilegios de Administrador para abrir SOCK_RAW en Windows.")
        print("[!] Tip: Usa el modo '--mode target' que no requiere privilegios especiales.")
        aggregator.stop()
        emitter.close()
        return

    try:
        while True:
            raw_pkt, _ = s.recvfrom(65535)
            if len(raw_pkt) < 20:
                continue

            # Decodificar cabecera IPv4
            ip_header = raw_pkt[:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            ihl = (version_ihl & 0xF) * 4
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            pkt_len = len(raw_pkt)

            src_port = 0
            dst_port = 0
            tcp_flags = 0

            if protocol == 6 and len(raw_pkt) >= ihl + 14:  # TCP
                tcp_hdr = raw_pkt[ihl:ihl + 14]
                tcph = struct.unpack("!HHIIB", tcp_hdr[:13])
                src_port = tcph[0]
                dst_port = tcph[1]
                tcp_flags = raw_pkt[ihl + 13]
            elif protocol == 17 and len(raw_pkt) >= ihl + 8:  # UDP
                udp_hdr = raw_pkt[ihl:ihl + 4]
                udph = struct.unpack("!HH", udp_hdr)
                src_port = udph[0]
                dst_port = udph[1]

            if src_port and dst_port:
                aggregator.record_activity(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    bytes_count=pkt_len,
                    packets_count=1,
                    tcp_flags=tcp_flags,
                )
    except KeyboardInterrupt:
        print("\n[*] Deteniendo sniffer crudo...")
    finally:
        if hasattr(socket, "SIO_RCVALL"):
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()
        aggregator.stop()
        emitter.close()


# ==============================================================================
# CLI ENTRYPOINT
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaFlow NDR - Live Flow Probe")
    parser.add_argument(
        "--mode",
        choices=["target", "relay", "sniffer"],
        default="target",
        help="Modo de sonda: 'target' (servidor objetivo reactivo), 'relay' (proxy transparente), 'sniffer' (raw socket)",
    )
    parser.add_argument("--port", type=int, default=8080, help="Puerto de escucha HTTP (target o relay)")
    parser.add_argument("--relay-target", type=str, default="http://127.0.0.1:3000", help="URL destino para modo relay")
    parser.add_argument("--interface", type=str, default="127.0.0.1", help="IP de interfaz para modo sniffer")
    parser.add_argument("--novaflow-host", type=str, default="127.0.0.1", help="IP del colector NovaFlow")
    parser.add_argument("--novaflow-port", type=int, default=2055, help="Puerto UDP del colector NovaFlow (2055)")
    parser.add_argument("--novaflow-api", type=str, default="http://127.0.0.1:8000", help="URL base de la API REST de NovaFlow (8000)")
    args = parser.parse_args()

    if args.mode == "target":
        run_target_mode(args.port, args.novaflow_host, args.novaflow_port, args.novaflow_api)
    elif args.mode == "relay":
        run_relay_mode(args.port, args.relay_target, args.novaflow_host, args.novaflow_port, args.novaflow_api)
    elif args.mode == "sniffer":
        run_sniffer_mode(args.interface, args.novaflow_host, args.novaflow_port)
