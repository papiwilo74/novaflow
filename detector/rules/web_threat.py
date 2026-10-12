"""
NovaFlow NDR - Web Application & SaaS Threat Detection Rule
Protección especializada para aplicaciones web y plataformas SaaS contra:
1. Credential Stuffing & Fuerza Bruta de Autenticación (T1110)
2. Inundación L7 y Abuso de Rate Limiting en APIs (T1498)
3. Fuga de Metadatos Cloud y SSRF (Server-Side Request Forgery - T1190)
4. Bots Automatizados, Scrapers y Herramientas DAST (T1595)
5. Intrusión Lateral Este-Oeste contra Bases de Datos Internas (PostgreSQL, Redis, MySQL, MongoDB - T1021)
"""

import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from collector.l7_parsers import HTTPWireMessage
from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


# Endpoints sensibles de autenticación SaaS
AUTH_ENDPOINTS: Set[str] = {
    "/login",
    "/auth",
    "/signin",
    "/oauth",
    "/tokens",
    "/api/v1/auth",
    "/api/v1/login",
    "/api/v1/users/login",
    "/api/auth/callback",
    "/admin/login",
    "/user/login",
    "/session",
}

# IPs de metadatos de proveedores cloud (IMDS)
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS IMDSv1/v2, GCP, Azure, OpenStack
    "100.100.100.200",  # Alibaba Cloud
    "192.0.0.192",      # Oracle Cloud
}

# Firmas de User-Agent de escáneres ofensivos y bots
KNOWN_BOT_USER_AGENTS: List[Tuple[str, str, AlertSeverity]] = [
    ("sqlmap", "SQLMap Automated SQL Injection Tool", AlertSeverity.CRITICAL),
    ("nikto", "Nikto Web Vulnerability Scanner", AlertSeverity.HIGH),
    ("nuclei", "Nuclei Vulnerability Scanner", AlertSeverity.HIGH),
    ("wpscan", "WPScan CMS Scanner", AlertSeverity.MEDIUM),
    ("masscan", "Masscan High-Speed Scanner", AlertSeverity.HIGH),
    ("python-requests", "Python Requests Automated Client", AlertSeverity.MEDIUM),
    ("aiohttp", "Python AioHTTP Async Bot", AlertSeverity.MEDIUM),
    ("go-http-client", "Golang Automated HTTP Client", AlertSeverity.MEDIUM),
    ("curl/", "cURL Command-Line Tool", AlertSeverity.LOW),
    ("scrapy", "Scrapy Web Scraping Framework", AlertSeverity.MEDIUM),
    ("headlesschrome", "Headless Chrome Automation", AlertSeverity.MEDIUM),
    ("postmanruntime", "Postman API Automation", AlertSeverity.LOW),
]

# Puertos estándar de bases de datos y caches internas en arquitecturas SaaS
DATABASE_PORTS: Dict[int, str] = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis In-Memory Cache",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5672: "RabbitMQ Message Broker",
    6443: "Kubernetes API Server",
}


class WebThreatDetector:
    """
    Detector heurístico y de comportamiento L7 enfocado exclusivamente
    en la protección de aplicaciones web y arquitecturas SaaS modernas.
    """

    def __init__(
        self,
        auth_rate_threshold: int = 8,
        auth_window_secs: float = 10.0,
        api_flood_threshold: int = 35,
        api_flood_window_secs: float = 5.0,
        tenant_hopping_threshold: int = 3,
        tenant_window_secs: float = 30.0,
        alert_cooldown_secs: float = 15.0,
    ):
        self.auth_rate_threshold = auth_rate_threshold
        self.auth_window_secs = auth_window_secs
        self.api_flood_threshold = api_flood_threshold
        self.api_flood_window_secs = api_flood_window_secs
        self.tenant_hopping_threshold = tenant_hopping_threshold
        self.tenant_window_secs = tenant_window_secs
        self.alert_cooldown_secs = alert_cooldown_secs

        # Historiales deslizantes en memoria
        # src_ip -> deque of (timestamp, path)
        self._auth_history: Dict[str, deque] = defaultdict(deque)
        # src_ip -> deque of (timestamp, path)
        self._api_flood_history: Dict[str, deque] = defaultdict(deque)
        # src_ip -> deque of (timestamp, tenant_id)
        self._tenant_history: Dict[str, deque] = defaultdict(deque)


        # Cooldowns para evitar tormentas de alertas: (alert_key) -> float
        self._last_alert: Dict[str, float] = {}

    def _is_cooling_down(self, key: str, now: float) -> bool:
        last = self._last_alert.get(key, 0.0)
        if (now - last) < self.alert_cooldown_secs:
            return True
        self._last_alert[key] = now
        return False

    def evaluate_http_message(
        self,
        msg: HTTPWireMessage,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
    ) -> Optional[SecurityAlert]:
        """
        Inspecciona una petición HTTP decodificada en tiempo real.
        Evalúa Credential Stuffing, Inundación L7, SSRF y User-Agents de Bots.
        """
        now = time.time()
        path_lower = (msg.path or "/").lower()

        # ------------------------------------------------------------------
        # 1. Detección de Fuga de Metadatos Cloud / SSRF en Headers o URI
        # ------------------------------------------------------------------
        if dst_ip in CLOUD_METADATA_IPS or any(meta_ip in (msg.host or "") for meta_ip in CLOUD_METADATA_IPS):
            alert_key = f"ssrf_meta_{src_ip}_{dst_ip}"
            if not self._is_cooling_down(alert_key, now):
                return SecurityAlert(
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.WEB_APP_THREAT,
                    title=f"Intento Crítico de Fuga de Metadatos Cloud (SSRF) desde {src_ip}",
                    description=(
                        f"El host {src_ip} intentó acceder al servicio de metadatos de infraestructura "
                        f"en la nube ({dst_ip}:{dst_port} - URI: {msg.uri}). Vector clásico de SSRF "
                        f"utilizado para robar credenciales IAM temporales y tokens de instancia."
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=6,
                    confidence=0.98,
                    metrics={
                        "attack_vector": "SSRF_CLOUD_METADATA",
                        "metadata_target": dst_ip,
                        "uri": msg.uri,
                        "method": msg.method,
                        "host_header": msg.host,
                    },
                )

        # ------------------------------------------------------------------
        # 2. Detección de Credential Stuffing & Fuerza Bruta de Autenticación
        # ------------------------------------------------------------------
        is_auth_endpoint = any(path_lower == ep or path_lower.startswith(ep + "/") for ep in AUTH_ENDPOINTS)
        if is_auth_endpoint and msg.method in ("POST", "PUT"):
            history = self._auth_history[src_ip]
            while history and (now - history[0][0]) > self.auth_window_secs:
                history.popleft()
            history.append((now, path_lower))

            if len(history) >= self.auth_rate_threshold:
                alert_key = f"cred_stuffing_{src_ip}_{path_lower}"
                if not self._is_cooling_down(alert_key, now):
                    return SecurityAlert(
                        severity=AlertSeverity.CRITICAL,
                        category=AlertCategory.WEB_APP_THREAT,
                        title=f"Ataque de Credential Stuffing / Fuerza Bruta Web desde {src_ip}",
                        description=(
                            f"Se detectó una ráfaga anómala de {len(history)} intentos de autenticación "
                            f"en {self.auth_window_secs:.1f} segundos hacia '{msg.path}' desde {src_ip}. "
                            f"Indica un ataque automatizado de fuerza bruta o relleno de credenciales en el SaaS."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=6,
                        confidence=0.94,
                        metrics={
                            "attack_vector": "CREDENTIAL_STUFFING",
                            "attempts_count": len(history),
                            "window_seconds": self.auth_window_secs,
                            "endpoint": msg.path,
                            "method": msg.method,
                        },
                    )

        # ------------------------------------------------------------------
        # 3. Detección de Inundación HTTP L7 / Abuso de Tasa en APIs SaaS
        # ------------------------------------------------------------------
        flood_history = self._api_flood_history[src_ip]
        while flood_history and (now - flood_history[0][0]) > self.api_flood_window_secs:
            flood_history.popleft()
        flood_history.append((now, path_lower))

        if len(flood_history) >= self.api_flood_threshold:
            alert_key = f"api_flood_{src_ip}"
            if not self._is_cooling_down(alert_key, now):
                return SecurityAlert(
                    severity=AlertSeverity.HIGH,
                    category=AlertCategory.WEB_APP_THREAT,
                    title=f"Inundación HTTP L7 / Abuso de Rate Limiting desde {src_ip}",
                    description=(
                        f"El cliente {src_ip} ha emitido {len(flood_history)} peticiones HTTP en "
                        f"{self.api_flood_window_secs:.1f} segundos contra los endpoints de la aplicación SaaS. "
                        f"Supera el umbral operativo y pone en riesgo la disponibilidad de workers del backend."
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=6,
                    confidence=0.91,
                    metrics={
                        "attack_vector": "API_FLOOD_RATE_ABUSE",
                        "request_count": len(flood_history),
                        "window_seconds": self.api_flood_window_secs,
                        "latest_endpoint": msg.path,
                    },
                )

        # ------------------------------------------------------------------
        # 3.5. Detección de Violación de Aislamiento Multi-Tenant (BOLA / IDOR / Tenant Hopping)
        # ------------------------------------------------------------------
        tenant_candidate = ""
        for h_key, h_val in msg.headers.items():
            if h_key.lower() in ("x-tenant-id", "x-tenant", "x-org-id"):
                tenant_candidate = h_val.strip()
                break

        if not tenant_candidate:
            import re
            m = re.search(r"/(?:tenants|orgs|workspaces)/([a-zA-Z0-9_\-]+)", path_lower)
            if m:
                tenant_candidate = m.group(1)

        if tenant_candidate:
            t_history = self._tenant_history[src_ip]
            while t_history and (now - t_history[0][0]) > self.tenant_window_secs:
                t_history.popleft()
            t_history.append((now, tenant_candidate))

            distinct_tenants = {t for _, t in t_history}
            if len(distinct_tenants) >= self.tenant_hopping_threshold:
                alert_key = f"idor_hopping_{src_ip}"
                if not self._is_cooling_down(alert_key, now):
                    return SecurityAlert(
                        severity=AlertSeverity.CRITICAL,
                        category=AlertCategory.WEB_APP_THREAT,
                        title=f"Violación de Aislamiento Multi-Tenant (IDOR / Tenant Hopping) desde {src_ip}",
                        description=(
                            f"El cliente {src_ip} ha intentado acceder secuencialmente a {len(distinct_tenants)} "
                            f"organizaciones/tenants diferentes ({', '.join(list(distinct_tenants)[:4])}) en "
                            f"{self.tenant_window_secs:.1f} segundos. Ataque crítico contra la confidencialidad multi-inquilino del SaaS."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=6,
                        confidence=0.95,
                        metrics={
                            "attack_vector": "MULTI_TENANT_IDOR_HOPPING",
                            "tenants_count": len(distinct_tenants),
                            "tenants_seen": list(distinct_tenants),
                            "window_seconds": self.tenant_window_secs,
                        },
                    )

        # ------------------------------------------------------------------
        # 4. Detección de Herramientas Ofensivas DAST / Scrapers no Autorizados
        # ------------------------------------------------------------------
        ua = msg.user_agent.lower()

        if ua:
            for pattern, tool_name, tool_sev in KNOWN_BOT_USER_AGENTS:
                if pattern in ua:
                    # Si es curl o python-requests pero solo hizo 1 petición ocasional, alertar solo si es tool ofensiva
                    if tool_sev in (AlertSeverity.CRITICAL, AlertSeverity.HIGH) or len(flood_history) > 3:
                        alert_key = f"bot_tool_{src_ip}_{pattern}"
                        if not self._is_cooling_down(alert_key, now):
                            return SecurityAlert(
                                severity=tool_sev,
                                category=AlertCategory.WEB_APP_THREAT,
                                title=f"Escáner / Herramienta Automatizada Detectada: {tool_name}",
                                description=(
                                    f"Petición dirigida a {msg.path} desde {src_ip} identificada con firma "
                                    f"de agente de usuario automatizado: '{msg.user_agent}'. "
                                    f"Herramienta identificada: {tool_name}."
                                ),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=6,
                                confidence=0.88,
                                metrics={
                                    "attack_vector": "OFFENSIVE_TOOL_OR_BOT",
                                    "tool": tool_name,
                                    "user_agent": msg.user_agent,
                                    "endpoint": msg.path,
                                },
                            )

        # ------------------------------------------------------------------
        # 5. Detección de Inyección SQL (T1190 / CWE-89) en URI o Payload
        # ------------------------------------------------------------------
        from urllib.parse import unquote
        uri_decoded = unquote(unquote(msg.uri or ""))
        body_decoded = unquote(msg.body_sample.decode("utf-8", errors="ignore") if msg.body_sample else "")
        raw_combined = f"{uri_decoded} {body_decoded}".lower()
        sqli_patterns = [
            "' or '1'='1",
            "' or 1=1",
            "\" or \"1\"=\"1",
            "union select",
            "union all select",
            "select * from",
            "drop table",
            "1=1--",
            "'--",
            "sleep(",
            "pg_sleep(",
            "benchmark(",
            "waitfor delay",
        ]
        for pat in sqli_patterns:
            if pat in raw_combined:
                alert_key = f"sqli_{src_ip}_{pat}"
                if not self._is_cooling_down(alert_key, now):
                    return SecurityAlert(
                        severity=AlertSeverity.CRITICAL,
                        category=AlertCategory.WEB_APP_THREAT,
                        title=f"Intento Crítico de Inyección SQL (SQLi) desde {src_ip}",
                        description=(
                            f"Se detectó un patrón inequívoco de inyección SQL ('{pat}') en la petición HTTP "
                            f"hacia '{msg.path}' desde {src_ip}. Indica un intento de elusión de autenticación "
                            f"o extracción no autorizada de la base de datos de OrderFlowApp / SaaS."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=6,
                        confidence=0.97,
                        metrics={
                            "attack_vector": "SQL_INJECTION",
                            "pattern_detected": pat,
                            "endpoint": msg.path,
                            "method": msg.method,
                        },
                    )

        # ------------------------------------------------------------------
        # 6. Detección de Fuzzing de Archivos Sensibles y Traversal (T1595 / T1083)
        # ------------------------------------------------------------------
        sensitive_patterns = [
            "/.env",
            "/.git",
            "/wp-admin",
            "/phpmyadmin",
            "/id_rsa",
            "/etc/passwd",
            "/etc/shadow",
            "/.aws/credentials",
            "/docker-compose.yml",
            "/server.js.bak",
            "/database.sql",
        ]
        for spat in sensitive_patterns:
            if spat in path_lower:
                alert_key = f"sensitive_fuzz_{src_ip}_{spat}"
                if not self._is_cooling_down(alert_key, now):
                    return SecurityAlert(
                        severity=AlertSeverity.HIGH,
                        category=AlertCategory.WEB_APP_THREAT,
                        title=f"Fuzzing de Archivos Sensibles / Configuración Crítica desde {src_ip}",
                        description=(
                            f"El host {src_ip} intentó acceder a recursos de configuración sensible "
                            f"('{spat}') en '{msg.path}'. Firma clásica de escaneo DAST automatizado por OmniBreach."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=6,
                        confidence=0.92,
                        metrics={
                            "attack_vector": "SENSITIVE_FILE_FUZZING",
                            "resource": spat,
                            "endpoint": msg.path,
                            "method": msg.method,
                        },
                    )

        return None

    def evaluate_east_west_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """
        Inspecciona el tráfico Este-Oeste entre contenedores o microservicios internos.
        Identifica intentos de acceso directo o exfiltración a bases de datos o metadatos
        desde componentes web comprometidos.
        """
        now = time.time()

        # 1. Tráfico hacia IP de Metadatos Cloud a nivel L3/L4
        if flow.dst_ip in CLOUD_METADATA_IPS:
            alert_key = f"ew_metadata_{flow.src_ip}_{flow.dst_ip}"
            if not self._is_cooling_down(alert_key, now):
                return SecurityAlert(
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.WEB_APP_THREAT,
                    title=f"Intrusión SSRF Este-Oeste: Acceso a Metadatos Cloud desde {flow.src_ip}",
                    description=(
                        f"Un contenedor o pod web ({flow.src_ip}) generó un flujo de red directo "
                        f"hacia la IP de metadatos de la nube {flow.dst_ip}:{flow.dst_port}. "
                        f"Evidencia inequívoca de compromiso por SSRF buscando robar roles IAM de la infraestructura."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=0.99,
                    metrics={
                        "attack_vector": "SSRF_CLOUD_METADATA",
                        "metadata_ip": flow.dst_ip,
                        "bytes": flow.bytes,
                        "packets": flow.packets,
                    },
                )

        # 2. Acceso Anómalo a Bases de Datos Internas (PostgreSQL, MySQL, Redis, MongoDB)
        # Si un pod o IP externa/DMZ intenta conectarse directamente a un puerto de datos
        if flow.dst_port in DATABASE_PORTS:
            service_name = DATABASE_PORTS[flow.dst_port]
            # Si el flujo proviene de una IP pública o de un host no registrado en la lista blanca de la BD
            if not flow.src_ip.startswith("127.") and not flow.src_ip.startswith("10.0.99."):  # 10.0.99.x = subnet DB legítima de ejemplo
                # Si es un puerto de cache o DB expuesto o consultado inesperadamente
                if flow.dst_port == 6379 or flow.bytes > 500000:  # Redis no autenticado o dump masivo
                    alert_key = f"ew_db_{flow.src_ip}_{flow.dst_port}"
                    if not self._is_cooling_down(alert_key, now):
                        return SecurityAlert(
                            severity=AlertSeverity.HIGH,
                            category=AlertCategory.WEB_APP_THREAT,
                            title=f"Acceso Anómalo Este-Oeste a Base de Datos ({service_name}) desde {flow.src_ip}",
                            description=(
                                f"Se registró tráfico inusual hacia el servicio de base de datos {service_name} "
                                f"en el puerto {flow.dst_port} desde el host {flow.src_ip} ({flow.bytes} bytes). "
                                f"Posible intento de extracción no autorizada de datos o compromiso de servicio interno."
                            ),
                            src_ip=flow.src_ip,
                            dst_ip=flow.dst_ip,
                            dst_port=flow.dst_port,
                            protocol=flow.protocol,
                            confidence=0.86,
                            metrics={
                                "attack_vector": "EAST_WEST_DB_EXPOSURE",
                                "database_service": service_name,
                                "bytes": flow.bytes,
                                "packets": flow.packets,
                            },
                        )

        return None
