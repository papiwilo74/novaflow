"""
NovaFlow NDR - Bi-Flow & Session Stitching Engine
Ensambla flujos unidireccionales NetFlow v5 en sesiones bidireccionales (Bi-Flow).
Calcula métricas avanzadas como el ratio de bytes subida/bajada (Bytes_Out / Bytes_In)
y el estado del handshake TCP, eliminando falsos positivos en descargas legítimas.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord


@dataclass
class BiFlowSession:
    """Representa una sesión de comunicación bidireccional L4 ensamblada."""
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    protocol: int
    bytes_sent: int = 0         # Bytes transferidos de cliente a servidor
    bytes_received: int = 0     # Bytes transferidos de servidor a cliente
    packets_sent: int = 0
    packets_received: int = 0
    client_flags: int = 0       # Flags TCP acumulados de cliente
    server_flags: int = 0       # Flags TCP acumulados de servidor
    first_seen: float = 0.0
    last_seen: float = 0.0
    handshake_status: str = "UNANSWERED"  # UNANSWERED, ESTABLISHED, RESET

    @property
    def bytes_ratio(self) -> float:
        """
        Ratio de asimetría: Bytes Enviados / Bytes Recibidos.
        - Exfiltración / Ataques: ratio > 20.0 (subida masiva con pocos ACKs).
        - Descargas benignas web: ratio < 0.2 (bajada masiva frente a peticiones).
        - Navegación interactiva estándar: 0.2 <= ratio <= 5.0.
        """
        if self.bytes_received <= 0:
            return float(self.bytes_sent) if self.bytes_sent > 0 else 1.0
        return round(self.bytes_sent / self.bytes_received, 3)

    @property
    def upload_ratio(self) -> float:
        """Alias de bytes_ratio para compatibilidad con motores de reglas Sigma y heurísticas."""
        return self.bytes_ratio

    @property
    def is_bidirectional(self) -> bool:
        return self.bytes_sent > 0 and self.bytes_received > 0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, round(self.last_seen - self.first_seen, 3))

    def to_dict(self) -> Dict[str, object]:
        return {
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "bytes_ratio": self.bytes_ratio,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "handshake_status": self.handshake_status,
            "duration_seconds": self.duration_seconds,
        }


class BiFlowStitcher:
    """
    Ensambla flujos NetFlow v5 unidireccionales en sesiones de transporte bidireccionales.
    Empareja automáticamente flujos forward (A -> B) y reverse (B -> A).
    """

    def __init__(self, session_timeout_seconds: float = 60.0):
        self.session_timeout_seconds = session_timeout_seconds
        # Canonical 5-tuple key -> BiFlowSession
        # Clave canónica: (min_ip, max_ip, min_port, max_port, protocol)
        self._sessions: Dict[Tuple[str, str, int, int, int], BiFlowSession] = {}

    @staticmethod
    def _make_canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> Tuple[str, str, int, int, int]:
        """Genera una clave simétrica única para la conversación independientemente de la dirección."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def ingest_flow(self, flow: NetFlowRecord) -> BiFlowSession:
        """
        Ingesta un registro de flujo individual y lo ensambla con su flujo inverso complementario.
        Retorna la sesión BiFlow actualizada.
        """
        key = self._make_canonical_key(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
        flow_ts = flow.timestamp.timestamp() if hasattr(flow.timestamp, "timestamp") else datetime.now(timezone.utc).timestamp()

        # Limpiar sesiones expiradas
        self._prune_expired_sessions(flow_ts)

        session = self._sessions.get(key)
        if not session:
            # Determinar rol de cliente y servidor heurísticamente:
            # 1. Flags TCP: SYN sin ACK => src es cliente. SYN+ACK => src es servidor.
            # 2. Puertos: El puerto efímero (> puerto destino o > 1024) suele ser el cliente.
            is_syn = bool((flow.tcp_flags & 0x02) and not (flow.tcp_flags & 0x10))
            is_syn_ack = bool((flow.tcp_flags & 0x02) and (flow.tcp_flags & 0x10))

            if is_syn:
                is_src_client = True
            elif is_syn_ack:
                is_src_client = False
            elif flow.src_port < flow.dst_port:
                # src_port es menor (ej. 443 < 52144), por ende src es el servidor
                is_src_client = False
            else:
                # src_port >= dst_port (ej. 52144 > 443), src es el cliente
                is_src_client = True

            if is_src_client:
                client_ip, client_port = flow.src_ip, flow.src_port
                server_ip, server_port = flow.dst_ip, flow.dst_port
                bytes_sent = flow.bytes
                bytes_received = 0
                packets_sent = flow.packets
                packets_received = 0
                client_flags = flow.tcp_flags
                server_flags = 0
            else:
                client_ip, client_port = flow.dst_ip, flow.dst_port
                server_ip, server_port = flow.src_ip, flow.src_port
                bytes_sent = 0
                bytes_received = flow.bytes
                packets_sent = 0
                packets_received = flow.packets
                client_flags = 0
                server_flags = flow.tcp_flags

            session = BiFlowSession(
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
                protocol=flow.protocol,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received,
                client_flags=client_flags,
                server_flags=server_flags,
                first_seen=flow_ts,
                last_seen=flow_ts,
            )
            self._sessions[key] = session
            return session

        # La sesión ya existe: actualizar métricas en la dirección correspondiente
        session.last_seen = max(session.last_seen, flow_ts)
        session.first_seen = min(session.first_seen, flow_ts)

        if flow.src_ip == session.client_ip and flow.src_port == session.client_port:
            # Dirección forward: Cliente -> Servidor
            session.bytes_sent += flow.bytes
            session.packets_sent += flow.packets
            session.client_flags |= flow.tcp_flags
        else:
            # Dirección reverse: Servidor -> Cliente (Respuesta)
            session.bytes_received += flow.bytes
            session.packets_received += flow.packets
            session.server_flags |= flow.tcp_flags

        # Evaluar estado de handshake TCP si es protocolo 6
        if session.protocol == 6:
            has_client_syn = bool(session.client_flags & 0x02)
            has_server_syn_ack = bool((session.server_flags & 0x02) and (session.server_flags & 0x10))
            has_rst = bool((session.client_flags & 0x04) or (session.server_flags & 0x04))

            if has_rst:
                session.handshake_status = "RESET"
            elif has_client_syn and has_server_syn_ack:
                session.handshake_status = "ESTABLISHED"
            elif session.bytes_received > 0:
                session.handshake_status = "ESTABLISHED"

        return session

    def get_session(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> Optional[BiFlowSession]:
        """Obtiene la sesión bidireccional ensamblada para una 5-tupla específica."""
        key = self._make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol)
        return self._sessions.get(key)

    def get_biflow(self, flow: NetFlowRecord) -> Optional[BiFlowSession]:
        """Obtiene la sesión bidireccional correspondiente a un flujo NetFlowRecord."""
        return self.get_session(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)

    def get_aggregate_ratio(self, src_ip: str, dst_ip: str) -> float:
        """
        Calcula el ratio acumulado de bytes enviados vs recibidos entre un par de hosts.
        Permite saber con alta certeza si el tráfico es predominantemente de subida o bajada.
        """
        total_sent = 0
        total_recv = 0
        for session in self._sessions.values():
            if session.client_ip == src_ip and session.server_ip == dst_ip:
                total_sent += session.bytes_sent
                total_recv += session.bytes_received
            elif session.server_ip == src_ip and session.client_ip == dst_ip:
                total_sent += session.bytes_received
                total_recv += session.bytes_sent

        if total_recv <= 0:
            return float(total_sent) if total_sent > 0 else 1.0
        return round(total_sent / total_recv, 3)

    def _prune_expired_sessions(self, current_ts: float):
        """Elimina sesiones inactivas más antiguas que la ventana de expiración."""
        if len(self._sessions) < 500:
            return
        cutoff = current_ts - self.session_timeout_seconds
        keys_to_remove = [k for k, s in self._sessions.items() if s.last_seen < cutoff]
        for k in keys_to_remove:
            del self._sessions[k]
