"""
NovaFlow NDR - Security Alert Models & Data Structures
Estructuras tipadas para incidentes y alertas de ciberseguridad.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Dict, Any, Optional, List


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertCategory(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    SYN_FLOOD = "SYN_FLOOD"
    EXFILTRATION = "EXFILTRATION"
    DNS_TUNNEL = "DNS_TUNNEL"
    MALICIOUS_C2 = "MALICIOUS_C2"
    ANOMALY_ML = "ANOMALY_ML"
    C2_BEACONING = "C2_BEACONING"
    ATTACK_CAMPAIGN = "ATTACK_CAMPAIGN"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    ANOMALOUS_TLS = "ANOMALOUS_TLS"


@dataclass
class SecurityAlert:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: AlertCategory = AlertCategory.ANOMALY_ML
    title: str = ""
    description: str = ""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    dst_port: int = 0
    protocol: int = 6  # 6=TCP, 17=UDP, 1=ICMP
    confidence: float = 0.85
    tenant_id: str = "default"
    metrics: Dict[str, Any] = field(default_factory=dict)
    status: str = "NEW"  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    mitre: Optional[Dict[str, str]] = None
    compliance: Optional[List[Dict[str, str]]] = None

    def __post_init__(self):
        if self.mitre is None:
            from detector.mitre import get_mitre_for_category
            self.mitre = get_mitre_for_category(self.category).to_dict()

        if self.compliance is None:
            from detector.compliance import get_compliance_for_category
            self.compliance = get_compliance_for_category(self.category)

    @property
    def id(self) -> str:
        return self.alert_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "confidence": round(self.confidence, 2),
            "tenant_id": self.tenant_id,
            "mitre": self.mitre,
            "compliance": self.compliance,
            "metrics": self.metrics,
            "status": self.status,
        }

    def to_cef(self) -> str:
        """
        Exporta el incidente al estándar ArcSight Common Event Format (CEF:0).
        Formato universal consumido por Splunk, Wazuh, QRadar y Elastic SIEM.
        """
        sev_map = {
            AlertSeverity.LOW: 3,
            AlertSeverity.MEDIUM: 5,
            AlertSeverity.HIGH: 8,
            AlertSeverity.CRITICAL: 10,
        }
        cef_sev = sev_map.get(self.severity, 5)
        proto_name = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else str(self.protocol))
        
        # Limpiar caracteres especiales de cabecera CEF
        clean_title = self.title.replace("|", "\\|").replace("=", "\\=")
        clean_desc = self.description.replace("|", "\\|").replace("=", "\\=")
        
        ext_parts = [
            f"src={self.src_ip}",
            f"dst={self.dst_ip}",
            f"dpt={self.dst_port}",
            f"proto={proto_name}",
            f"msg={clean_desc}",
            f"cs1={self.status}",
            f"cs1Label=IncidentStatus",
            f"cfp1={self.confidence}",
            f"cfp1Label=ConfidenceScore",
        ]
        
        if self.mitre:
            ext_parts.append(f"cs2={self.mitre.get('technique_id', '')}")
            ext_parts.append(f"cs2Label=MitreTechniqueId")
            ext_parts.append(f"cs3={self.mitre.get('tactic', '')}")
            ext_parts.append(f"cs3Label=MitreTactic")

        extension = " ".join(ext_parts)
        return f"CEF:0|NovaSec|NovaFlow|1.0.0|{self.category.value}|{clean_title}|{cef_sev}|{extension}"

    def to_syslog_rfc5424(self) -> str:
        """
        Exporta el evento bajo el estándar RFC 5424 de Syslog.
        Facility: Security/Authorization (4), Severity: Alert (1) a Warning (4).
        """
        pri = 34 if self.severity == AlertSeverity.CRITICAL else (35 if self.severity == AlertSeverity.HIGH else 36)
        ts = self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        cef_payload = self.to_cef()
        return f"<{pri}>1 {ts} novaflow-ndr novaflow-threat-engine - ID{self.alert_id[:8]} [novasec@5424 tenant=\"{self.tenant_id}\"] {cef_payload}"

    def to_ocsf(self) -> Dict[str, Any]:
        """
        Exporta el incidente al estándar abierto OCSF v1.1.0 (Open Cybersecurity Schema Framework).
        Categoría 2: Findings, Clase 2001: Security Finding.
        Utilizado por AWS Security Lake, Snowflake, Splunk y Databricks.
        """
        sev_map = {
            AlertSeverity.LOW: 2,       # Low
            AlertSeverity.MEDIUM: 3,    # Medium
            AlertSeverity.HIGH: 4,      # High
            AlertSeverity.CRITICAL: 5,  # Critical
        }
        status_map = {
            "NEW": 1,            # New
            "INVESTIGATING": 2,  # In Progress
            "RESOLVED": 4,       # Resolved
            "FALSE_POSITIVE": 5, # Suppressed
        }

        proto_name = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else str(self.protocol))

        attacks = []
        if self.mitre:
            attacks.append({
                "version": "v14.1",
                "tactic": {
                    "name": self.mitre.get("tactic", ""),
                },
                "technique": {
                    "uid": self.mitre.get("technique_id", ""),
                    "name": self.mitre.get("technique_name", ""),
                    "sub_technique": self.mitre.get("subtechnique_id"),
                },
            })

        return {
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "time": int(self.timestamp.timestamp()),
            "severity_id": sev_map.get(self.severity, 3),
            "severity": self.severity.value,
            "status_id": status_map.get(self.status, 1),
            "status": self.status,
            "confidence_score": int(self.confidence * 100),
            "finding_info": {
                "uid": self.alert_id,
                "title": self.title,
                "desc": self.description,
                "types": [self.category.value],
            },
            "attacks": attacks,
            "network_activity": {
                "direction": "Outbound",
                "protocol_num": self.protocol,
                "protocol_name": proto_name,
                "src_endpoint": {
                    "ip": self.src_ip,
                },
                "dst_endpoint": {
                    "ip": self.dst_ip,
                    "port": self.dst_port,
                },
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "NovaFlow NDR",
                    "vendor_name": "NovaSec",
                    "version": "1.0.0",
                },
                "tenant_id": self.tenant_id,
            },
            "unmapped": self.metrics,
        }
