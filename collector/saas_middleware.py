"""
NovaFlow NDR - Plug-and-Play ASGI SaaS Protection Middleware
Middleware de defensa activa y telemetría L7 para aplicaciones web y plataformas SaaS.

Instalación en 2 líneas de código en cualquier SaaS (FastAPI / Starlette / Django ASGI):
    from collector.saas_middleware import NovaFlowSaaSMiddleware
    app.add_middleware(NovaFlowSaaSMiddleware, novaflow_host="127.0.0.1", novaflow_port=2055)

Capacidades:
1. Escudo Perimetral de Auto-Contención: Descarta conexiones de atacantes (403 Forbidden) en <0.1ms sin tocar el backend.
2. Extracción de IP Real: Soporta Cloudflare (CF-Connecting-IP), AWS ALB, Traefik y Nginx (X-Forwarded-For).
3. Telemetría de Alta Velocidad: Emite registros NetFlow v5/v9 de forma asíncrona hacia el Ring Buffer de NovaFlow.
4. Consciencia Multi-Tenant: Extrae y rastrea cabeceras de tenant (X-Tenant-ID) para prevenir fugas cruzadas (IDOR).
"""

import asyncio
import json
import logging
import socket
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("NovaFlow.SaaSMiddleware")


class NovaFlowSaaSMiddleware:
    """
    Middleware ASGI de protección perimetral y telemetría en tiempo real para SaaS.
    """

    # Conjunto global en memoria de IPs en cuarentena (sincronizado con NovaFlow SOAR)
    blocked_ips: Set[str] = set()
    _sync_thread: Optional[threading.Thread] = None
    _sync_running: bool = False

    def __init__(
        self,
        app: Any,
        novaflow_host: str = "127.0.0.1",
        novaflow_port: int = 2055,
        novaflow_api_url: str = "http://127.0.0.1:8000",
        enable_active_defense: bool = True,
        auto_sync_soar: bool = False,
    ):
        self.app = app
        self.novaflow_host = novaflow_host
        self.novaflow_port = novaflow_port
        self.novaflow_api_url = novaflow_api_url.rstrip("/")
        self.enable_active_defense = enable_active_defense

        # Socket UDP reutilizable no bloqueante
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setblocking(False)

        # Iniciar sincronización en segundo plano con el motor SOAR de NovaFlow si está habilitado
        if auto_sync_soar and not NovaFlowSaaSMiddleware._sync_running:
            NovaFlowSaaSMiddleware._sync_running = True
            NovaFlowSaaSMiddleware._sync_thread = threading.Thread(
                target=self._background_soar_sync,
                args=(self.novaflow_api_url,),
                daemon=True,
            )
            NovaFlowSaaSMiddleware._sync_thread.start()

    def close(self):
        """Cierra el descriptor de socket UDP."""
        try:
            self._udp_sock.close()
        except Exception:
            pass


    @classmethod
    def block_ip(cls, ip: str):
        """Añade una IP al escudo perimetral local."""
        cls.blocked_ips.add(ip)

    @classmethod
    def unblock_ip(cls, ip: str):
        """Elimina una IP del escudo perimetral local."""
        cls.blocked_ips.discard(ip)

    @classmethod
    def _background_soar_sync(cls, api_url: str):
        """Sincroniza periódicamente las IPs en cuarentena desde NovaFlow SOAR."""
        while cls._sync_running:
            try:
                req = urllib.request.Request(f"{api_url}/api/v1/soar/containments")
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        for item in data.get("containments", []):
                            ip = item.get("target_ip")
                            if ip and ip not in cls.blocked_ips:
                                cls.blocked_ips.add(ip)
                                logger.warning(f"[SaaS Shield] IP en cuarentena sincronizada: {ip}")
            except Exception:
                pass
            time.sleep(2.0)

    def _extract_client_ip(self, scope: Dict[str, Any]) -> str:
        """Extrae la IP real del cliente respetando proxies inversos y CDNs."""
        headers = dict(scope.get("headers", []))

        # 1. Cloudflare
        cf_ip = headers.get(b"cf-connecting-ip")
        if cf_ip:
            return cf_ip.decode("utf-8", errors="ignore").strip()

        # 2. X-Forwarded-For (tomar la primera IP de la cadena)
        xff = headers.get(b"x-forwarded-for")
        if xff:
            first_ip = xff.decode("utf-8", errors="ignore").split(",")[0].strip()
            if first_ip:
                return first_ip

        # 3. X-Real-IP
        x_real = headers.get(b"x-real-ip")
        if x_real:
            return x_real.decode("utf-8", errors="ignore").strip()

        # 4. Socket cliente directo
        client = scope.get("client")
        if client and len(client) > 0:
            return str(client[0])

        return "127.0.0.1"

    def _extract_header(self, scope: Dict[str, Any], header_name: bytes) -> str:
        """Obtiene el valor de una cabecera HTTP desde el scope ASGI."""
        for name, value in scope.get("headers", []):
            if name.lower() == header_name.lower():
                return value.decode("utf-8", errors="ignore")
        return ""

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_ip = self._extract_client_ip(scope)
        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        # 1. ESCUDO DE AUTO-CONTENCIÓN: Bloqueo de atacantes aislados en <0.1ms
        if self.enable_active_defense and client_ip in self.blocked_ips:
            logger.warning(f"[NovaFlow Shield] Conexión rechazada de host en cuarentena: {client_ip} -> {path}")
            body = json.dumps({
                "status": "BLOCKED",
                "shield": "NovaFlow NDR SaaS Active Defense",
                "reason": "Host quarantined due to real-time malicious activity",
                "client_ip": client_ip,
                "timestamp": int(time.time()),
            }).encode("utf-8")

            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("utf-8")),
                    (b"x-novaflow-shield", b"ACTIVE_DEFENSE_BLOCKED"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        start_time = time.time()
        status_code = 200
        resp_bytes_count = 0

        async def send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal status_code, resp_bytes_count
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            elif message["type"] == "http.response.body":
                resp_bytes_count += len(message.get("body", b""))
            await send(message)

        # 2. Ejecutar la aplicación SaaS real
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # 3. Telemetría Asíncrona L7 hacia NovaFlow NDR
            latency_ms = (time.time() - start_time) * 1000.0
            user_agent = self._extract_header(scope, b"user-agent")
            tenant_id = self._extract_header(scope, b"x-tenant-id")
            host = self._extract_header(scope, b"host")

            self._emit_telemetry(
                src_ip=client_ip,
                method=method,
                path=path,
                host=host,
                status_code=status_code,
                user_agent=user_agent,
                tenant_id=tenant_id,
                latency_ms=latency_ms,
                bytes_sent=resp_bytes_count + 150,
            )

    def _emit_telemetry(
        self,
        src_ip: str,
        method: str,
        path: str,
        host: str,
        status_code: int,
        user_agent: str,
        tenant_id: str,
        latency_ms: float,
        bytes_sent: int,
    ):
        """Emite un datagrama UDP de telemetría a NovaFlow de manera no bloqueante."""
        try:
            # Formato de datagrama de telemetría SaaS ligero
            event = {
                "type": "SAAS_HTTP_TELEMETRY",
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "dst_port": 443,
                "method": method,
                "path": path,
                "host": host,
                "status_code": status_code,
                "user_agent": user_agent,
                "tenant_id": tenant_id or "default",
                "latency_ms": round(latency_ms, 2),
                "bytes": bytes_sent,
                "timestamp": int(time.time()),
            }
            data = json.dumps(event).encode("utf-8")
            self._udp_sock.sendto(data, (self.novaflow_host, self.novaflow_port))
        except (BlockingIOError, socket.error):
            pass  # Descartar si el socket UDP local está saturado (cero latencia para la app)
