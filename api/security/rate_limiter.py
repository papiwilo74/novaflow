"""
NovaFlow NDR - Sliding Window Rate Limiter Middleware
Protección contra ataques de denegación de servicio (DoS) y fuerza bruta en la API.
"""

import time
from collections import defaultdict, deque
from typing import Dict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from api.security.config import security_config


class SlidingWindowRateLimiter(BaseHTTPMiddleware):
    """
    Middleware de limitación de tasa por ventana deslizante.
    Monitorea peticiones por IP o API Key en ventanas de 60 segundos.
    """

    def __init__(self, app, max_requests_per_minute: int = 120):
        super().__init__(app)
        self.max_requests = max_requests_per_minute
        self.window_seconds = 60.0
        # client_identifier -> deque of request timestamps
        self._clients: Dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if not security_config.RATE_LIMIT_ENABLED:
            return await call_next(request)

        # Excluir archivos estáticos y WebSockets del rate limit agresivo
        path = request.url.path
        if path.startswith("/static") or path == "/dashboard" or path.startswith("/ws"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")
        identifier = f"key:{api_key}" if api_key else f"ip:{client_ip}"

        now = time.time()
        client_history = self._clients[identifier]

        # Limpiar peticiones fuera de la ventana de 60s
        while client_history and (now - client_history[0]) > self.window_seconds:
            client_history.popleft()

        if len(client_history) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - client_history[0])) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Has excedido el límite de {self.max_requests} peticiones por minuto.",
                    "retry_after_seconds": max(1, retry_after),
                },
                headers={"Retry-After": str(max(1, retry_after))},
            )

        client_history.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.max_requests - len(client_history)))
        return response
