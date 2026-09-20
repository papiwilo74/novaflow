"""
NovaFlow NDR - Immutable Audit Trail Logger
Registro inmutable de actividades sensibles para cumplimiento normativo (SOC2, ISO 27001, GDPR).
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger("NovaFlow.Audit")


@dataclass
class AuditEntry:
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = "system"
    role: str = "ANALYST"
    tenant_id: str = "default"
    action: str = ""  # e.g. "ALERT_STATUS_UPDATE", "FLOW_FORENSIC_EXPORT", "RULE_CONFIG_CHANGE"
    resource_id: str = ""
    client_ip: str = "127.0.0.1"
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "SUCCESS"  # SUCCESS, DENIED, ERROR

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "resource_id": self.resource_id,
            "client_ip": self.client_ip,
            "details": self.details,
            "status": self.status,
        }


class AuditLogger:
    """Administrador de registros de auditoría inmutables."""

    def __init__(self, ch_url: str = "http://localhost:8123/", max_in_memory: int = 5000):
        self.ch_url = ch_url
        self.max_in_memory = max_in_memory
        self._entries: List[AuditEntry] = []

    def log(
        self,
        user_id: str,
        role: str,
        tenant_id: str,
        action: str,
        resource_id: str = "",
        client_ip: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
    ) -> AuditEntry:
        entry = AuditEntry(
            user_id=user_id,
            role=role,
            tenant_id=tenant_id,
            action=action,
            resource_id=resource_id,
            client_ip=client_ip,
            details=details or {},
            status=status,
        )

        self._entries.append(entry)
        if len(self._entries) > self.max_in_memory:
            self._entries.pop(0)

        logger.info(
            f"[AUDITORÍA] [{entry.status}] {entry.action} por {entry.user_id} ({entry.role}) "
            f"en tenant '{entry.tenant_id}' sobre recurso '{entry.resource_id}'"
        )

        # Persistencia en ClickHouse novaflow.audit_trail
        self._persist_to_clickhouse(entry)
        return entry

    def _persist_to_clickhouse(self, entry: AuditEntry):
        try:
            ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            details_json = json.dumps(entry.details).replace("\t", " ")
            line = (
                f"{entry.audit_id}\t{ts_str}\t{entry.user_id}\t{entry.role}\t"
                f"{entry.tenant_id}\t{entry.action}\t{entry.resource_id}\t"
                f"{entry.client_ip}\t{details_json}\t{entry.status}\n"
            )
            query = (
                f"INSERT INTO novaflow.audit_trail ("
                f"audit_id, timestamp, user_id, role, tenant_id, action, resource_id, client_ip, details, status"
                f") FORMAT TabSeparated"
            )
            requests.post(self.ch_url, params={"query": query}, data=line.encode("utf-8"), timeout=0.5)
        except Exception:
            pass

    def get_entries(
        self,
        tenant_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        results = self._entries
        if tenant_id and tenant_id != "*":
            results = [e for e in results if e.tenant_id == tenant_id]
        if action:
            results = [e for e in results if e.action == action]
        return [e.to_dict() for e in list(reversed(results))[:limit]]


audit_logger = AuditLogger()
