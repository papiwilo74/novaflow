"""
NovaFlow NDR - Distributed Tracing & OpenTelemetry Context
Genera identificadores de traza W3C (traceparent) para correlación de eventos en microservicios.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    name: str
    start_time: float
    end_time: Optional[float] = None
    attributes: Dict[str, str] = field(default_factory=dict)

    def finish(self):
        self.end_time = time.time()

    @property
    def duration_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return (time.time() - self.start_time) * 1000

    def to_w3c_header(self) -> str:
        """Retorna cabecera estándar W3C TraceContext: version-trace_id-parent_id-flags"""
        return f"00-{self.trace_id}-{self.span_id}-01"


class Tracer:
    """Trazador ligero para profiling y correlación de latencia."""

    @staticmethod
    def start_span(name: str, parent_trace_id: Optional[str] = None) -> TraceSpan:
        trace_id = parent_trace_id or uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]
        return TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            name=name,
            start_time=time.time(),
        )


tracer = Tracer()


from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class DistributedTracingMiddleware(BaseHTTPMiddleware):
    """Middleware ASGI que propaga e inyecta W3C traceparent headers en todas las respuestas."""

    async def dispatch(self, request: Request, call_next):
        incoming_trace = request.headers.get("traceparent")
        parent_id = None
        if incoming_trace:
            parts = incoming_trace.split("-")
            if len(parts) >= 2:
                parent_id = parts[1]

        span = tracer.start_span(name=f"HTTP {request.method} {request.url.path}", parent_trace_id=parent_id)
        response = await call_next(request)
        span.finish()

        response.headers["traceparent"] = span.to_w3c_header()
        response.headers["X-Response-Time-Ms"] = f"{span.duration_ms:.2f}"
        return response
