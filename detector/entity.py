"""
NovaFlow NDR - Entity State Engine & Asset Identity Ledger
Gestor unificado del estado de identidad de activos de red. Rastrea entidades
lógicas más allá de la volatilidad de direcciones IP mediante correlación de MAC,
Hostname y usuario, con decaimiento exponencial de Threat Score ponderado por criticidad.
"""

from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from detector.models import AlertSeverity, SecurityAlert


class AssetRole(str, Enum):
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE_SERVER = "DATABASE_SERVER"
    WEB_SERVER = "WEB_SERVER"
    JUMP_HOST = "JUMP_HOST"
    WORKSTATION = "WORKSTATION"
    IOT_DEVICE = "IOT_DEVICE"
    UNKNOWN = "UNKNOWN"


# Multiplicadores de impacto según criticidad institucional del activo
ROLE_CRITICALITY_MULTIPLIERS: Dict[AssetRole, float] = {
    AssetRole.DOMAIN_CONTROLLER: 2.5,
    AssetRole.DATABASE_SERVER: 2.0,
    AssetRole.JUMP_HOST: 1.8,
    AssetRole.WEB_SERVER: 1.5,
    AssetRole.WORKSTATION: 1.0,
    AssetRole.IOT_DEVICE: 0.8,
    AssetRole.UNKNOWN: 1.0,
}

# Puntaje base aportado por cada nivel de severidad de alerta
SEVERITY_SCORE_WEIGHTS: Dict[AlertSeverity, float] = {
    AlertSeverity.LOW: 5.0,
    AlertSeverity.MEDIUM: 15.0,
    AlertSeverity.HIGH: 35.0,
    AlertSeverity.CRITICAL: 60.0,
}


@dataclass
class AssetEntity:
    """Entidad persistente de activo con estado de identidad y riesgo dinámico."""

    entity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    current_ip: str = "0.0.0.0"
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    user_identity: Optional[str] = None
    role: AssetRole = AssetRole.WORKSTATION
    raw_threat_score: float = 0.0
    last_score_update: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ip_history: List[Dict[str, Any]] = field(default_factory=list)
    observed_open_ports: Set[int] = field(default_factory=set)
    ja4_fingerprints: Set[str] = field(default_factory=set)
    alert_ids: List[str] = field(default_factory=list)

    def calculate_dynamic_threat_score(
        self,
        current_time: Optional[float] = None,
        half_life_seconds: float = 3600.0,
    ) -> float:
        """
        Calcula el puntaje de amenaza actual aplicando decaimiento exponencial:
        S(t) = S_0 * e^(-lambda * dt) * role_multiplier
        lambda = ln(2) / half_life
        """
        now = current_time if current_time is not None else time.time()
        dt = max(0.0, now - self.last_score_update)
        decay_constant = math.log(2.0) / max(1.0, half_life_seconds)
        decayed_base = self.raw_threat_score * math.exp(-decay_constant * dt)

        multiplier = ROLE_CRITICALITY_MULTIPLIERS.get(self.role, 1.0)
        final_score = round(min(100.0, decayed_base * multiplier), 2)
        return final_score

    def add_alert(self, alert: SecurityAlert, current_time: Optional[float] = None):
        """Acumula una nueva alerta de seguridad actualizando el puntaje base."""
        now = current_time if current_time is not None else time.time()
        # Primero aplicar decaimiento sobre el puntaje acumulado previo
        dt = max(0.0, now - self.last_score_update)
        decay_constant = math.log(2.0) / 3600.0
        self.raw_threat_score = self.raw_threat_score * math.exp(-decay_constant * dt)
        self.last_score_update = now
        self.last_seen = now

        # Sumar el nuevo peso de la alerta
        weight = SEVERITY_SCORE_WEIGHTS.get(alert.severity, 10.0)
        self.raw_threat_score += weight
        if alert.alert_id not in self.alert_ids:
            self.alert_ids.append(alert.alert_id)

    def record_ip(self, ip: str, timestamp: Optional[float] = None):
        """Actualiza la dirección IP activa y mantiene el histórico cronológico."""
        now = timestamp if timestamp is not None else time.time()
        self.last_seen = now
        if ip != self.current_ip:
            self.ip_history.append({
                "ip": self.current_ip,
                "transition_time": now,
            })
            self.current_ip = ip

    def to_dict(self, current_time: Optional[float] = None) -> Dict[str, Any]:
        """Serialización estructurada para consumo de API y dashboards SOC."""
        return {
            "entity_id": self.entity_id,
            "current_ip": self.current_ip,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "user_identity": self.user_identity,
            "role": self.role.value,
            "role_multiplier": ROLE_CRITICALITY_MULTIPLIERS.get(self.role, 1.0),
            "threat_score": self.calculate_dynamic_threat_score(current_time),
            "raw_threat_score": round(self.raw_threat_score, 2),
            "alerts_count": len(self.alert_ids),
            "alert_ids": self.alert_ids[-10:],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "ip_history": self.ip_history,
            "observed_ports": sorted(list(self.observed_open_ports)),
            "ja4_count": len(self.ja4_fingerprints),
        }


class EntityLedger:
    """Libro mayor de activos con resolución de identidades y búsqueda O(1)."""

    def __init__(self):
        self._entities: Dict[str, AssetEntity] = {}
        self._ip_index: Dict[str, str] = {}  # ip -> entity_id
        self._mac_index: Dict[str, str] = {}  # mac -> entity_id
        self._hostname_index: Dict[str, str] = {}  # hostname -> entity_id

    def get_or_create(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        role: AssetRole = AssetRole.WORKSTATION,
        user: Optional[str] = None,
    ) -> AssetEntity:
        """
        Resuelve una entidad existente mediante MAC, Hostname o IP.
        Si no existe en el libro mayor, la registra formalmente.
        """
        entity_id: Optional[str] = None

        if mac and mac in self._mac_index:
            entity_id = self._mac_index[mac]
        elif hostname and hostname.lower() in self._hostname_index:
            entity_id = self._hostname_index[hostname.lower()]
        elif ip in self._ip_index:
            entity_id = self._ip_index[ip]

        if entity_id and entity_id in self._entities:
            entity = self._entities[entity_id]
            entity.record_ip(ip)
            if mac and not entity.mac_address:
                entity.mac_address = mac
                self._mac_index[mac] = entity.entity_id
            if hostname and not entity.hostname:
                entity.hostname = hostname
                self._hostname_index[hostname.lower()] = entity.entity_id
            if user and not entity.user_identity:
                entity.user_identity = user
            return entity

        # Crear nueva entidad
        new_entity = AssetEntity(
            current_ip=ip,
            mac_address=mac,
            hostname=hostname,
            user_identity=user,
            role=role,
        )
        self._entities[new_entity.entity_id] = new_entity
        self._ip_index[ip] = new_entity.entity_id
        if mac:
            self._mac_index[mac] = new_entity.entity_id
        if hostname:
            self._hostname_index[hostname.lower()] = new_entity.entity_id

        return new_entity

    def get_by_id(self, entity_id: str) -> Optional[AssetEntity]:
        return self._entities.get(entity_id)

    def get_by_ip(self, ip: str) -> Optional[AssetEntity]:
        entity_id = self._ip_index.get(ip)
        if entity_id:
            return self._entities.get(entity_id)
        return None

    def record_alert(self, alert: SecurityAlert, current_time: Optional[float] = None):
        """Asocia la alerta a la entidad de origen (o destino si aplica) y ajusta su Threat Score."""
        src_ip = alert.src_ip
        entity = self.get_by_ip(src_ip)
        if not entity and src_ip and src_ip != "0.0.0.0":
            entity = self.get_or_create(ip=src_ip)

        if entity:
            entity.add_alert(alert, current_time=current_time)

    def reassign_ip_lease(self, mac: str, new_ip: str, hostname: Optional[str] = None):
        """Gestiona la reasignación de lease DHCP conservando el historial del activo."""
        entity = None
        if mac in self._mac_index:
            entity = self._entities.get(self._mac_index[mac])

        if entity:
            old_ip = entity.current_ip
            if old_ip in self._ip_index and self._ip_index[old_ip] == entity.entity_id:
                del self._ip_index[old_ip]

            entity.record_ip(new_ip)
            self._ip_index[new_ip] = entity.entity_id
            if hostname:
                entity.hostname = hostname
                self._hostname_index[hostname.lower()] = entity.entity_id
            return entity

        # Si el MAC no estaba registrado, crear entidad nueva
        return self.get_or_create(ip=new_ip, mac=mac, hostname=hostname)

    def list_entities(
        self,
        role: Optional[AssetRole] = None,
        min_score: float = 0.0,
        limit: int = 50,
    ) -> List[AssetEntity]:
        """Retorna las entidades filtradas y ordenadas por nivel de riesgo decreciente."""
        now = time.time()
        results = []
        for e in self._entities.values():
            if role and e.role != role:
                continue
            score = e.calculate_dynamic_threat_score(now)
            if score >= min_score:
                results.append(e)

        results.sort(key=lambda x: x.calculate_dynamic_threat_score(now), reverse=True)
        return results[:limit]

    def total_entities(self) -> int:
        return len(self._entities)
