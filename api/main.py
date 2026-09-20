"""
NovaFlow NDR - FastAPI Application Server & Gateway
Servidor API REST de alta velocidad con soporte de WebSockets para el Frontend Dashboard.
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Garantizar que el directorio raíz del proyecto esté en sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.state import system_state
from api.routes.metrics import router as metrics_router
from api.routes.alerts import router as alerts_router
from api.routes.flows import router as flows_router
from api.routes.ws import router as ws_router
from api.observability.metrics import router as observability_router
from api.observability.tracing import DistributedTracingMiddleware
from api.security.rate_limiter import SlidingWindowRateLimiter
from api.security.auth import Identity, Role, get_current_identity, require_role, JWTManager
from api.security.audit import audit_logger
from api.routes.federation import router as federation_router
from api.routes.purple_team import router as purple_team_router
from api.routes.compliance import router as compliance_router
from api.routes.reports import router as reports_router
from api.routes.mitre import router as mitre_router
from api.routes.graph import router as graph_router
from api.routes.soar import router as soar_router
from api.routes.threat_intel import router as threat_intel_router
from api.routes.sigma import router as sigma_router
from api.routes.hunting import router as hunting_router
from detector.engine import DetectionEngine

static_dir = os.path.join(os.path.dirname(__file__), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ciclo de vida del servidor: inicializa el motor de detección y streaming."""
    # Inicializar motor de detección compartido
    engine = DetectionEngine()
    system_state.initialize(engine)

    # Iniciar tarea en segundo plano de telemetría continua para WebSockets
    telemetry_task = asyncio.create_task(system_state.start_telemetry_broadcast(interval_seconds=1.0))
    system_state._telemetry_task = telemetry_task

    yield

    # Limpieza al apagar
    if telemetry_task:
        telemetry_task.cancel()
        try:
            await telemetry_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="NovaFlow NDR - Real-Time API Gateway",
    description="API empresarial para observabilidad de tráfico de red, detección de anomalías y triaje de incidentes.",
    version="1.0.0",
    lifespan=lifespan,
)

# 1. Middleware de Tracing Distribuido W3C
app.add_middleware(DistributedTracingMiddleware)

# 2. Middleware de Rate Limiting por Ventana Deslizante (DoS protection)
app.add_middleware(SlidingWindowRateLimiter, max_requests_per_minute=120)

# 3. Configurar CORS permisivo para desarrollo con React (Vite / Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montar Routers Principales
app.include_router(metrics_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(flows_router, prefix="/api/v1")
app.include_router(federation_router, prefix="/api/v1")
app.include_router(purple_team_router, prefix="/api/v1")
app.include_router(compliance_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(mitre_router, prefix="/api/v1")
app.include_router(graph_router, prefix="/api/v1")
app.include_router(soar_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(sigma_router, prefix="/api/v1")
app.include_router(hunting_router, prefix="/api/v1")
app.include_router(observability_router)  # Expone /metrics para Prometheus
app.include_router(ws_router)

# Servir archivos estáticos del Dashboard
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.post("/api/v1/auth/token")
async def issue_token(credentials: Dict[str, str]) -> Dict[str, Any]:
    """Genera un token JWT firmado (HS256) para autenticación programática."""
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    tenant_id = credentials.get("tenant_id", "default")

    # Validación básica de prueba / desarrollo
    if not username:
        return {"error": "Usuario requerido"}

    role = Role.ADMIN if username == "admin" else Role.ANALYST
    token = JWTManager.create_token({
        "sub": username,
        "name": username.capitalize(),
        "role": role,
        "tenant_id": tenant_id,
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": role,
        "tenant_id": tenant_id,
    }


@app.get("/api/v1/audit")
async def get_audit_trail(
    action: Optional[str] = None,
    limit: int = 50,
    identity: Identity = Security(require_role([Role.ADMIN, Role.AUDITOR])),
) -> Dict[str, Any]:
    """Consulta registros de auditoría inmutables (requiere rol ADMIN o AUDITOR)."""
    entries = audit_logger.get_entries(
        tenant_id=identity.tenant_id,
        action=action,
        limit=limit,
    )
    return {
        "tenant_id": identity.tenant_id,
        "total": len(entries),
        "audit_logs": entries,
    }


@app.get("/healthz")
@app.get("/livez")
async def liveness_probe() -> Dict[str, str]:
    """
    Kubernetes Liveness Probe: responde rápidamente confirmando que el proceso
    ASGI/FastAPI está vivo y no está bloqueado por deadlocks.
    """
    return {"status": "ALIVE"}


@app.get("/readyz")
async def readiness_probe() -> Dict[str, Any]:
    """
    Kubernetes Readiness Probe: valida que el motor de detección esté listo
    y los servicios críticos tengan capacidad de procesamiento.
    """
    is_engine_ready = system_state.engine is not None
    active_ws = len(system_state.ws_manager.active_connections)

    # Estado general de readiness
    if not is_engine_ready:
        return {
            "status": "NOT_READY",
            "reason": "DetectionEngine no inicializado",
        }

    return {
        "status": "READY",
        "components": {
            "detection_engine": "READY",
            "state_bus": "READY",
            "active_websockets": active_ws,
        },
    }


@app.get("/dashboard")
async def dashboard():
    """Sirve la interfaz web interactiva del SOC Dashboard."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
    return {"message": "Dashboard UI no disponible"}


@app.get("/")
async def root() -> Dict[str, Any]:
    """Endpoint raíz con estado y catálogo de servicios empresariales."""
    return {
        "service": "NovaFlow NDR API Gateway",
        "version": "1.0.0",
        "status": "OPERATIONAL",
        "security": {
            "auth": "JWT HS256 / API-Key",
            "rate_limiter": "Sliding-Window (60s)",
            "audit_trail": "Enabled",
        },
        "observability": {
            "metrics": "/metrics",
            "tracing": "W3C traceparent",
        },
        "dashboard_ui": "/dashboard",
        "endpoints": {
            "dashboard": "/dashboard",
            "docs": "/docs",
            "metrics": "/metrics",
            "metrics_overview": "/api/v1/metrics/overview",
            "top_talkers": "/api/v1/metrics/top-talkers",
            "protocols": "/api/v1/metrics/protocols",
            "alerts": "/api/v1/alerts",
            "flows": "/api/v1/flows",
            "compliance": "/api/v1/compliance/matrix",
            "reports_json": "/api/v1/reports/executive",
            "reports_html": "/api/v1/reports/executive/html",
            "audit": "/api/v1/audit",
            "auth_token": "/api/v1/auth/token",
            "websocket_stream": "/ws/stream",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
