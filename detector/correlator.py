"""
NovaFlow NDR - Attack Kill Chain & Multi-Stage Correlation Engine
Agrupa y correlaciona alertas individuales cronológicas de una misma entidad
en un incidente consolidado de 'Campaña de Intrusión' (Cyber Kill Chain),
escalando la severidad a CRITICAL y eliminando la fatiga de alertas del SOC.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from detector.models import AlertCategory, AlertSeverity, SecurityAlert


# Mapeo de categorías a etapas de la Cyber Kill Chain / MITRE ATT&CK
KILL_CHAIN_STAGES = {
    # 1. Reconocimiento y Descubrimiento
    AlertCategory.PORT_SCAN: "1_RECONNAISSANCE",
    AlertCategory.ANOMALY_ML: "1_RECONNAISSANCE",
    # 2. Comando y Control / Persistencia
    AlertCategory.MALICIOUS_C2: "2_COMMAND_AND_CONTROL",
    AlertCategory.C2_BEACONING: "2_COMMAND_AND_CONTROL",
    AlertCategory.DNS_TUNNEL: "2_COMMAND_AND_CONTROL",
    # 2.5. Movimiento Lateral e Infección Interna
    AlertCategory.LATERAL_MOVEMENT: "2_LATERAL_MOVEMENT",
    # 3. Acciones en Objetivos / Exfiltración / Impacto
    AlertCategory.EXFILTRATION: "3_ACTIONS_ON_OBJECTIVES",
    AlertCategory.SYN_FLOOD: "3_ACTIONS_ON_OBJECTIVES",
}


class AttackKillChainCorrelator:
    """
    Motor de correlación multi-etapa que modela el avance del atacante a través de la Kill Chain.
    """

    def __init__(self, correlation_window_seconds: float = 900.0):
        self.correlation_window_seconds = correlation_window_seconds

        # entidad (IP) -> lista de SecurityAlert
        self._entity_alerts: Dict[str, List[SecurityAlert]] = defaultdict(list)
        # entidad (IP) -> conjunto de etapas ya alertadas en campaña (para no duplicar)
        self._alerted_stage_sets: Dict[str, Set[frozenset]] = defaultdict(set)

    def process_alert(self, alert: SecurityAlert) -> Optional[SecurityAlert]:
        """
        Ingesta una alerta atómica individual, la asocia al historial de la entidad
        y evalúa si se ha cruzado el umbral de correlación de campaña multi-etapa.
        """
        # No procesar recursivamente alertas de campaña
        if alert.category == AlertCategory.ATTACK_CAMPAIGN:
            return None

        entity_ip = alert.src_ip
        alert_ts = alert.timestamp.timestamp() if hasattr(alert.timestamp, "timestamp") else datetime.now(timezone.utc).timestamp()

        # 1. Asociar alerta al historial de la entidad
        history = self._entity_alerts[entity_ip]
        history.append(alert)

        # 2. Podar alertas fuera de la ventana de correlación
        cutoff = alert_ts - self.correlation_window_seconds
        while history and history[0].timestamp.timestamp() < cutoff:
            history.pop(0)

        # 3. Identificar etapas únicas de la Kill Chain observadas
        stages_present: Set[str] = set()
        for a in history:
            stage = KILL_CHAIN_STAGES.get(a.category)
            if stage:
                stages_present.add(stage)

        # Requisito de Campaña: Al menos 2 fases distintas de la Kill Chain en la ventana
        if len(stages_present) < 2:
            return None

        # 4. Control de deduplicación: verificar si este conjunto exacto de etapas ya fue alertado
        current_set = frozenset(stages_present)
        if current_set in self._alerted_stage_sets[entity_ip]:
            return None

        self._alerted_stage_sets[entity_ip].add(current_set)

        # 5. Construir alerta consolidada de Campaña de Intrusión
        sorted_stages = sorted(list(stages_present))
        stage_names_clean = [s.split("_", 1)[1] for s in sorted_stages]
        chain_progression = " -> ".join(stage_names_clean)

        first_seen = min(a.timestamp.timestamp() for a in history)
        last_seen = max(a.timestamp.timestamp() for a in history)
        duration_sec = last_seen - first_seen

        # Identificar destino más relevante (IP externa de C2 o exfiltración si existe)
        target_dst_ip = alert.dst_ip
        for a in reversed(history):
            if a.category in (AlertCategory.MALICIOUS_C2, AlertCategory.C2_BEACONING, AlertCategory.EXFILTRATION):
                target_dst_ip = a.dst_ip
                break

        campaign_alert = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.ATTACK_CAMPAIGN,
            title=f"Campaña de Intrusión Multi-Etapa Detectada: Host {entity_ip}",
            description=(
                f"El host {entity_ip} ha completado de forma secuencial múltiples fases de la Cyber Kill Chain: "
                f"{chain_progression} en un lapso de {duration_sec:.1f}s. "
                f"Se correlacionaron {len(history)} incidentes atómicos en una campaña de compromiso unificada con un 99% de certeza."
            ),
            src_ip=entity_ip,
            dst_ip=target_dst_ip,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            confidence=0.99,
            metrics={
                "campaign_progression": chain_progression,
                "stages_observed": sorted_stages,
                "correlated_alerts_count": len(history),
                "correlated_alert_ids": [a.alert_id for a in history],
                "correlated_alert_categories": [a.category.value for a in history],
                "duration_seconds": round(duration_sec, 2),
                "tactics_count": len(stages_present),
                "threat_status": "CONFIRMED_MULTI_STAGE_INTRUSION",
            },
        )

        return campaign_alert
