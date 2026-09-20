"""
NovaFlow NDR - MITRE ATT&CK Framework Heatmap & Matrix REST Router
Provee telemetría térmica en tiempo real, conteo de técnicas hostiles y matrices tácticas de ataque.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Security

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from detector.mitre import MITRE_MAPPING, get_mitre_for_category
from detector.models import AlertCategory, AlertSeverity

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK Matrix"])

# Catálogo canónico de tácticas y técnicas de red supervisadas
TACTICS_ORDER = [
    "Reconnaissance",
    "Discovery",
    "Command and Control",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
    "Defense Evasion",
    "Enterprise Kill Chain",
]


@router.get("/matrix")
async def get_mitre_matrix(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Retorna la taxonomía de técnicas de MITRE ATT&CK supervisadas por los motores de NovaFlow NDR.
    """
    tactics_dict: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for cat, mitre_ref in MITRE_MAPPING.items():
        data = mitre_ref.to_dict()
        data["category"] = cat.value
        tactics_dict[mitre_ref.tactic].append(data)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tactics": dict(tactics_dict),
    }


@router.get("/heatmap")
async def get_mitre_heatmap(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Calcula la matriz térmica (Heatmap) en tiempo real basada en las alertas activas en el sensor.
    Retorna el nivel térmico (0 a 3), cantidad de incidentes y entidades IP comprometidas por técnica.
    """
    engine = system_state.engine
    alerts = engine.alerts_history if engine else []

    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    # Mapeo por technique_id
    technique_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "max_severity": "LOW",
        "heat_score": 0,  # 0=Inactive, 1=Low/Med, 2=High, 3=Critical
        "sources": set(),
        "targets": set(),
        "last_seen": None,
        "alert_ids": [],
    })

    severity_weights = {
        AlertSeverity.LOW.value: 1,
        AlertSeverity.MEDIUM.value: 1,
        AlertSeverity.HIGH.value: 2,
        AlertSeverity.CRITICAL.value: 3,
    }

    for alert in alerts:
        mitre_data = getattr(alert, "mitre", None) or get_mitre_for_category(alert.category).to_dict()
        tech_id = mitre_data.get("technique_id", "T0000")

        stat = technique_stats[tech_id]
        stat["count"] += 1
        stat["sources"].add(alert.src_ip)
        stat["targets"].add(alert.dst_ip)
        stat["alert_ids"].append(alert.alert_id)

        # Determinar máxima severidad
        current_heat = severity_weights.get(alert.severity.value, 1)
        if current_heat > stat["heat_score"]:
            stat["heat_score"] = current_heat
            stat["max_severity"] = alert.severity.value

        ts_str = alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)
        stat["last_seen"] = ts_str

    # Construir resultado enriquecido con metadatos MITRE
    cells = []
    for cat, mitre_ref in MITRE_MAPPING.items():
        tech_id = mitre_ref.technique_id
        stat = technique_stats.get(tech_id, {
            "count": 0,
            "max_severity": "NONE",
            "heat_score": 0,
            "sources": set(),
            "targets": set(),
            "last_seen": None,
            "alert_ids": [],
        })

        cells.append({
            "category": cat.value,
            "tactic": mitre_ref.tactic,
            "technique_id": tech_id,
            "technique_name": mitre_ref.technique_name,
            "subtechnique_id": mitre_ref.subtechnique_id,
            "subtechnique_name": mitre_ref.subtechnique_name,
            "url": mitre_ref.url or f"https://attack.mitre.org/techniques/{tech_id}/",
            "active_alerts_count": stat["count"],
            "heat_score": stat["heat_score"],
            "max_severity": stat["max_severity"],
            "sources": sorted(list(stat["sources"]))[:10],
            "targets": sorted(list(stat["targets"]))[:10],
            "last_seen": stat["last_seen"],
        })

    total_active = sum(c["active_alerts_count"] for c in cells)
    max_heat = max((c["heat_score"] for c in cells), default=0)

    threat_level = "GREEN"
    if max_heat == 3:
        threat_level = "CRITICAL_RED"
    elif max_heat == 2:
        threat_level = "ELEVATED_ORANGE"
    elif max_heat == 1:
        threat_level = "MONITORED_YELLOW"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_level": threat_level,
        "total_mitre_alerts": total_active,
        "tactics_order": TACTICS_ORDER,
        "cells": cells,
    }


@router.get("/techniques/{technique_id}/alerts")
async def get_alerts_by_technique(
    technique_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Retorna la lista de incidentes asociados a una técnica MITRE específica para drill-down interactivo.
    """
    engine = system_state.engine
    alerts = engine.alerts_history if engine else []

    matched_alerts = []
    for a in alerts:
        mitre_data = getattr(a, "mitre", None) or get_mitre_for_category(a.category).to_dict()
        if mitre_data.get("technique_id") == technique_id:
            matched_alerts.append(a.to_dict())

    return {
        "technique_id": technique_id,
        "count": len(matched_alerts),
        "alerts": matched_alerts,
    }


@router.get("/navigator-layer.json")
async def get_mitre_navigator_layer(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Exporta la postura de detección y los incidentes activos en formato estándar
    MITRE ATT&CK Navigator v4.5 (capa importable directamente en https://mitre-attack.github.io/attack-navigator/).
    """
    engine = system_state.engine
    alerts = engine.alerts_history if engine else []

    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    tech_counts: Dict[str, int] = defaultdict(int)
    tech_max_sev: Dict[str, str] = defaultdict(lambda: "LOW")

    sev_weights = {
        AlertSeverity.LOW.value: 1,
        AlertSeverity.MEDIUM.value: 3,
        AlertSeverity.HIGH.value: 7,
        AlertSeverity.CRITICAL.value: 10,
    }

    for alert in alerts:
        mitre_data = getattr(alert, "mitre", None) or get_mitre_for_category(alert.category).to_dict()
        tech_id = mitre_data.get("technique_id", "T0000")
        tech_counts[tech_id] += 1
        current_sev = alert.severity.value
        if sev_weights.get(current_sev, 1) > sev_weights.get(tech_max_sev[tech_id], 1):
            tech_max_sev[tech_id] = current_sev

    techniques_layer = []
    for cat, mitre_ref in MITRE_MAPPING.items():
        count = tech_counts.get(mitre_ref.technique_id, 0)
        max_sev = tech_max_sev.get(mitre_ref.technique_id, "LOW")
        score = sev_weights.get(max_sev, 1) if count > 0 else 0

        color = "#1e293b"  # Default inactivo
        if count > 0:
            if max_sev == AlertSeverity.CRITICAL.value:
                color = "#ef4444"
            elif max_sev == AlertSeverity.HIGH.value:
                color = "#f97316"
            else:
                color = "#f59e0b"

        tactic_slug = mitre_ref.tactic.lower().replace(" ", "-")

        techniques_layer.append({
            "techniqueID": mitre_ref.technique_id,
            "tactic": tactic_slug,
            "score": score,
            "color": color,
            "comment": f"{count} incidentes observados en telemetría L3/L4" if count > 0 else "Supervisión activa sin incidentes",
            "enabled": True,
        })

    return {
        "name": "NovaFlow NDR - Cobertura Táctica y Detección de Amenazas",
        "versions": {
            "attack": "14",
            "navigator": "4.8.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Capa exportada automáticamente por NovaFlow NDR con la matriz de técnicas detectadas.",
        "gradient": {
            "colors": ["#1e293b", "#f59e0b", "#f97316", "#ef4444"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "Perímetro Limpio / Sin incidentes", "color": "#1e293b"},
            {"label": "Actividad Moderada (Baja / Media)", "color": "#f59e0b"},
            {"label": "Amenaza Elevada (Alta)", "color": "#f97316"},
            {"label": "Compromiso Crítico Activo", "color": "#ef4444"},
        ],
        "techniques": techniques_layer,
    }
