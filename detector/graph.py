"""
NovaFlow NDR - Attack Graph & Blast Radius Engine
Construcción de topología de red G=(V,E), rastreo causal de 'Patient Zero' y cálculo de radio de explosión.
"""

from collections import deque
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from collector.parser import NetFlowRecord
from detector.models import AlertSeverity, SecurityAlert
from detector.profiler import AssetRole

logger = logging.getLogger("NovaFlow.AttackGraph")


class GraphNode:
    """Representa un host o activo dentro de la topología de red."""

    def __init__(self, ip: str, role: AssetRole = AssetRole.WORKSTATION):
        self.ip = ip
        self.role = role
        self.compromised = False
        self.compromised_at: Optional[datetime] = None
        self.alert_ids: List[str] = []
        self.risk_score: float = 0.0
        self.first_seen: datetime = datetime.now(timezone.utc)
        self.last_seen: datetime = datetime.now(timezone.utc)
        self.in_degree: int = 0
        self.out_degree: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.ip,
            "ip": self.ip,
            "role": self.role.value,
            "compromised": self.compromised,
            "compromised_at": self.compromised_at.isoformat() if self.compromised_at else None,
            "risk_score": round(self.risk_score, 2),
            "alert_count": len(self.alert_ids),
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class GraphEdge:
    """Representa un vector de comunicación dirigida (flujos) entre dos hosts."""

    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocols: Set[int] = set()
        self.dst_ports: Set[int] = set()
        self.total_bytes: int = 0
        self.total_packets: int = 0
        self.flow_count: int = 0
        self.first_seen: datetime = datetime.now(timezone.utc)
        self.last_seen: datetime = datetime.now(timezone.utc)
        self.has_lateral_movement: bool = False
        self.has_c2_communication: bool = False

    def update_flow(self, flow: NetFlowRecord):
        self.protocols.add(flow.protocol)
        self.dst_ports.add(flow.dst_port)
        self.total_bytes += flow.bytes
        self.total_packets += flow.packets
        self.flow_count += 1
        self.last_seen = flow.timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.src_ip,
            "target": self.dst_ip,
            "protocols": list(self.protocols),
            "dst_ports": sorted(list(self.dst_ports))[:20],
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "flow_count": self.flow_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "has_lateral_movement": self.has_lateral_movement,
            "has_c2_communication": self.has_c2_communication,
        }


class AttackGraphEngine:
    """
    Motor de análisis de grafos de ataque de red G=(V, E).
    Mantiene la topología de red en tiempo real, rastrea el 'Patient Zero'
    y calcula el 'Blast Radius' ante incidentes de seguridad.
    """

    # Ponderaciones de criticidad para el cálculo de Blast Radius
    CRITICALITY_WEIGHTS = {
        AssetRole.INFRASTRUCTURE_DC: 45.0,
        AssetRole.INTERNAL_SERVER: 25.0,
        AssetRole.ADMIN_MANAGEMENT: 25.0,
        AssetRole.INFRASTRUCTURE_DNS: 15.0,
        AssetRole.WORKSTATION: 5.0,
    }

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[Tuple[str, str], GraphEdge] = {}
        # Lista de adyacencia directa (outbound) y reversa (inbound)
        self.out_edges: Dict[str, Set[str]] = {}
        self.in_edges: Dict[str, Set[str]] = {}
        # Historial de alertas de intrusión causal ordenadas temporalmente
        self.compromise_timeline: List[Dict[str, Any]] = []

    def get_or_create_node(self, ip: str, role: Optional[AssetRole] = None) -> GraphNode:
        if ip not in self.nodes:
            self.nodes[ip] = GraphNode(ip=ip, role=role or AssetRole.WORKSTATION)
            self.out_edges[ip] = set()
            self.in_edges[ip] = set()
        elif role and self.nodes[ip].role == AssetRole.WORKSTATION and role != AssetRole.WORKSTATION:
            self.nodes[ip].role = role
        return self.nodes[ip]

    def ingest_flow(self, flow: NetFlowRecord):
        """Incorpora un flujo NetFlow actualizando nodos y aristas del grafo."""
        src_node = self.get_or_create_node(flow.src_ip)
        dst_node = self.get_or_create_node(flow.dst_ip)

        src_node.last_seen = flow.timestamp
        dst_node.last_seen = flow.timestamp

        edge_key = (flow.src_ip, flow.dst_ip)
        if edge_key not in self.edges:
            self.edges[edge_key] = GraphEdge(flow.src_ip, flow.dst_ip)
            self.edges[edge_key].first_seen = flow.timestamp
            self.out_edges[flow.src_ip].add(flow.dst_ip)
            self.in_edges[flow.dst_ip].add(flow.src_ip)
            src_node.out_degree = len(self.out_edges[flow.src_ip])
            dst_node.in_degree = len(self.in_edges[flow.dst_ip])

        self.edges[edge_key].update_flow(flow)

    def ingest_alert(self, alert: SecurityAlert):
        """Registra un evento de seguridad comprometiendo los nodos involucrados."""
        src_node = self.get_or_create_node(alert.src_ip)
        dst_node = self.get_or_create_node(alert.dst_ip)

        # Severidad a puntaje de riesgo
        sev_scores = {
            AlertSeverity.LOW: 15.0,
            AlertSeverity.MEDIUM: 40.0,
            AlertSeverity.HIGH: 75.0,
            AlertSeverity.CRITICAL: 100.0,
        }
        score = sev_scores.get(alert.severity, 20.0) * alert.confidence

        # Marcar nodo origen como comprometido/sospechoso si severidad >= MEDIUM
        if alert.severity in (AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            if not src_node.compromised:
                src_node.compromised = True
                src_node.compromised_at = alert.timestamp
            src_node.risk_score = min(100.0, max(src_node.risk_score, score))
            src_node.alert_ids.append(alert.id)

            edge_key = (alert.src_ip, alert.dst_ip)
            if edge_key in self.edges:
                if alert.category.value == "LATERAL_MOVEMENT":
                    self.edges[edge_key].has_lateral_movement = True
                    # Si hubo movimiento lateral exitoso hacia el destino, marcar también dst_node
                    if not dst_node.compromised:
                        dst_node.compromised = True
                        dst_node.compromised_at = alert.timestamp
                    dst_node.risk_score = min(100.0, max(dst_node.risk_score, score * 0.8))
                    dst_node.alert_ids.append(alert.id)
                elif alert.category.value in ("MALICIOUS_C2", "C2_BEACONING"):
                    self.edges[edge_key].has_c2_communication = True

            self.compromise_timeline.append({
                "alert_id": alert.id,
                "timestamp": alert.timestamp,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "category": alert.category.value,
                "severity": alert.severity.value,
            })

    def find_patient_zero(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Rastrea causalmente hacia atrás la cadena de intrusión para encontrar el
        'Patient Zero' (nodo raíz que originó el compromiso de target_ip).
        """
        if target_ip not in self.nodes:
            return None

        visited: Set[str] = set()
        queue: deque = deque([[target_ip]])
        longest_path: List[str] = [target_ip]
        earliest_node = target_ip

        target_node = self.nodes[target_ip]
        earliest_time = target_node.compromised_at or datetime.now(timezone.utc)

        while queue:
            current_path = queue.popleft()
            curr = current_path[-1]

            # Explorar aristas entrantes de hosts comprometidos
            incoming_sources = self.in_edges.get(curr, set())
            extended = False

            for parent_ip in incoming_sources:
                if parent_ip in visited:
                    continue

                parent_node = self.nodes.get(parent_ip)
                edge = self.edges.get((parent_ip, curr))

                # Condición causal: el padre debe estar comprometido o tener movimiento lateral/C2 hacia curr
                is_causal = False
                if edge and (edge.has_lateral_movement or edge.has_c2_communication):
                    is_causal = True
                elif parent_node and parent_node.compromised:
                    if parent_node.compromised_at and target_node.compromised_at:
                        if parent_node.compromised_at <= target_node.compromised_at:
                            is_causal = True
                    else:
                        is_causal = True

                if is_causal:
                    visited.add(parent_ip)
                    new_path = current_path + [parent_ip]
                    queue.append(new_path)
                    extended = True

                    if len(new_path) > len(longest_path):
                        longest_path = new_path
                        earliest_node = parent_ip

            if not extended and len(current_path) > len(longest_path):
                longest_path = current_path
                earliest_node = curr

        # El camino reconstruido va desde target hacia atrás; invertirlo para que sea raíz -> target
        infection_path = list(reversed(longest_path))
        root_node = self.nodes.get(earliest_node, target_node)

        return {
            "target_ip": target_ip,
            "patient_zero_ip": root_node.ip,
            "patient_zero_role": root_node.role.value,
            "first_compromised_at": root_node.compromised_at.isoformat() if root_node.compromised_at else None,
            "infection_path": infection_path,
            "total_hops": len(infection_path) - 1,
            "is_self_originating": root_node.ip == target_ip,
        }

    def calculate_blast_radius(self, host_ip: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Calcula el radio de explosión (Blast Radius) y Blast Score (0-100) desde un host
        hacia activos críticos alcanzables en la red mediante BFS.
        """
        if host_ip not in self.nodes:
            return {
                "start_ip": host_ip,
                "blast_score": 0.0,
                "reachable_hosts_count": 0,
                "critical_assets_exposed": [],
                "depth_distribution": {},
            }

        start_node = self.nodes[host_ip]
        visited: Dict[str, int] = {host_ip: 0}
        queue: deque = deque([(host_ip, 0)])

        critical_assets_exposed: List[Dict[str, Any]] = []
        depth_counts: Dict[int, int] = {d: 0 for d in range(1, max_depth + 1)}
        total_weighted_risk = 0.0

        while queue:
            curr_ip, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for next_ip in self.out_edges.get(curr_ip, set()):
                if next_ip not in visited:
                    next_depth = depth + 1
                    visited[next_ip] = next_depth
                    depth_counts[next_depth] = depth_counts.get(next_depth, 0) + 1
                    queue.append((next_ip, next_depth))

                    next_node = self.nodes.get(next_ip)
                    if next_node:
                        # Ponderación por rol y atenuación por distancia (1/d^0.75)
                        weight = self.CRITICALITY_WEIGHTS.get(next_node.role, 5.0)
                        attenuation = 1.0 / (next_depth ** 0.75)
                        total_weighted_risk += weight * attenuation

                        if next_node.role in (
                            AssetRole.INFRASTRUCTURE_DC,
                            AssetRole.INTERNAL_SERVER,
                            AssetRole.ADMIN_MANAGEMENT,
                        ):
                            critical_assets_exposed.append({
                                "ip": next_ip,
                                "role": next_node.role.value,
                                "hops_distance": next_depth,
                                "compromised": next_node.compromised,
                                "risk_score": next_node.risk_score,
                            })

        # Normalizar Blast Score a escala 0.0 - 100.0
        # Un valor >= 100 de weighted risk alcanza el tope 100%
        normalized_blast_score = min(100.0, round((total_weighted_risk / 120.0) * 100.0, 1))
        # Si el host inicial ya está comprometido o tiene riesgo propio alto, ponderar el baseline
        if start_node.compromised:
            normalized_blast_score = min(100.0, max(normalized_blast_score, start_node.risk_score * 0.5))

        return {
            "start_ip": host_ip,
            "start_role": start_node.role.value,
            "blast_score": normalized_blast_score,
            "risk_level": "CRITICAL" if normalized_blast_score >= 70 else (
                "HIGH" if normalized_blast_score >= 45 else ("MEDIUM" if normalized_blast_score >= 20 else "LOW")
            ),
            "reachable_hosts_count": len(visited) - 1,
            "critical_assets_exposed": sorted(
                critical_assets_exposed, key=lambda x: x["hops_distance"]
            ),
            "depth_distribution": depth_counts,
        }

    def export_topology_json(self, filter_compromised_only: bool = False) -> Dict[str, Any]:
        """
        Exporta la topología en formato estándar Cytoscape/D3:
        { "nodes": [ { "data": {...} } ], "edges": [ { "data": {...} } ] }
        """
        selected_nodes: Set[str] = set()

        if filter_compromised_only:
            selected_nodes = {ip for ip, n in self.nodes.items() if n.compromised}
            # Incluir vecinos inmediatos de nodos comprometidos
            neighbor_nodes: Set[str] = set()
            for ip in selected_nodes:
                neighbor_nodes.update(self.out_edges.get(ip, set()))
                neighbor_nodes.update(self.in_edges.get(ip, set()))
            selected_nodes.update(neighbor_nodes)
        else:
            selected_nodes = set(self.nodes.keys())

        nodes_data = []
        for ip in selected_nodes:
            node = self.nodes.get(ip)
            if node:
                nodes_data.append({"data": node.to_dict()})

        edges_data = []
        for (src, dst), edge in self.edges.items():
            if src in selected_nodes and dst in selected_nodes:
                edges_data.append({"data": edge.to_dict()})

        return {
            "nodes": nodes_data,
            "edges": edges_data,
            "summary": {
                "total_nodes": len(nodes_data),
                "total_edges": len(edges_data),
                "compromised_nodes": sum(1 for n in nodes_data if n["data"]["compromised"]),
            },
        }
