"""
NovaFlow NDR - Bayesian & Markovian Kill Chain Campaign Correlator
Motor de correlación causal multi-etapa que consolida alertas individuales en
Casos de Campaña activos, modelando la progresión del adversario mediante
matrices de transición de Markov y actualización bayesiana de certeza de compromiso.
"""

from __future__ import annotations

import math
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class KillChainStage(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


# Probabilidades de transición de Markov entre etapas del ciclo de intrusión
MARKOV_TRANSITIONS: Dict[KillChainStage, Dict[KillChainStage, float]] = {
    KillChainStage.RECONNAISSANCE: {
        KillChainStage.INITIAL_ACCESS: 0.65,
        KillChainStage.LATERAL_MOVEMENT: 0.70,
        KillChainStage.CREDENTIAL_ACCESS: 0.50,
    },
    KillChainStage.INITIAL_ACCESS: {
        KillChainStage.LATERAL_MOVEMENT: 0.80,
        KillChainStage.CREDENTIAL_ACCESS: 0.75,
        KillChainStage.COMMAND_AND_CONTROL: 0.85,
    },
    KillChainStage.LATERAL_MOVEMENT: {
        KillChainStage.CREDENTIAL_ACCESS: 0.85,
        KillChainStage.COMMAND_AND_CONTROL: 0.75,
        KillChainStage.EXFILTRATION: 0.65,
    },
    KillChainStage.CREDENTIAL_ACCESS: {
        KillChainStage.LATERAL_MOVEMENT: 0.80,
        KillChainStage.COMMAND_AND_CONTROL: 0.85,
        KillChainStage.EXFILTRATION: 0.90,
    },
    KillChainStage.COMMAND_AND_CONTROL: {
        KillChainStage.LATERAL_MOVEMENT: 0.70,
        KillChainStage.EXFILTRATION: 0.95,
        KillChainStage.IMPACT: 0.80,
    },
    KillChainStage.EXFILTRATION: {
        KillChainStage.IMPACT: 0.60,
    },
    KillChainStage.IMPACT: {},
}


def map_alert_to_stage(alert: SecurityAlert) -> KillChainStage:
    """Mapea una alerta individual a su etapa en el Enterprise Kill Chain."""
    cat = alert.category
    if cat == AlertCategory.PORT_SCAN:
        return KillChainStage.RECONNAISSANCE
    elif cat == AlertCategory.SYN_FLOOD:
        return KillChainStage.IMPACT
    elif cat == AlertCategory.LATERAL_MOVEMENT:
        return KillChainStage.LATERAL_MOVEMENT
    elif cat == AlertCategory.IDENTITY_ATTACK:
        return KillChainStage.CREDENTIAL_ACCESS
    elif cat in (AlertCategory.MALICIOUS_C2, AlertCategory.C2_BEACONING, AlertCategory.ANOMALOUS_TLS, AlertCategory.DGA_DOMAIN):
        return KillChainStage.COMMAND_AND_CONTROL
    elif cat in (AlertCategory.EXFILTRATION, AlertCategory.DNS_TUNNEL):
        return KillChainStage.EXFILTRATION
    return KillChainStage.RECONNAISSANCE


@dataclass
class CampaignCase:
    """Caso consolidado de intrusión multi-etapa correlacionado."""

    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    primary_asset: str = "0.0.0.0"
    involved_assets: Set[str] = field(default_factory=set)
    alerts: List[SecurityAlert] = field(default_factory=list)
    stages: Set[KillChainStage] = field(default_factory=set)
    stage_transitions: List[Tuple[KillChainStage, float]] = field(default_factory=list)
    bayesian_probability: float = 0.05
    status: str = "ACTIVE"  # ACTIVE, ESCALATED, CONTAINED, RESOLVED
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    escalated_alert_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "primary_asset": self.primary_asset,
            "involved_assets": sorted(list(self.involved_assets)),
            "total_alerts": len(self.alerts),
            "stages_count": len(self.stages),
            "stages": [s.value for s in self.stages],
            "bayesian_probability": round(self.bayesian_probability, 4),
            "certainty_percentage": f"{self.bayesian_probability * 100:.1f}%",
            "status": self.status,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "escalated_alert_id": self.escalated_alert_id,
            "recent_alerts": [
                {
                    "alert_id": a.alert_id,
                    "title": a.title,
                    "category": a.category.value,
                    "severity": a.severity.value,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                }
                for a in self.alerts[-5:]
            ],
        }


class BayesianCampaignEngine:
    """Motor de correlación causal y seguimiento de campañas multi-etapa."""

    def __init__(self, time_window_seconds: float = 1800.0):
        self.time_window_seconds = time_window_seconds
        self.cases: Dict[str, CampaignCase] = {}
        # asset_ip -> campaign_id
        self._asset_to_case: Dict[str, str] = {}

    def ingest_alert(
        self,
        alert: SecurityAlert,
        timestamp: Optional[float] = None,
    ) -> Tuple[Optional[CampaignCase], Optional[SecurityAlert]]:
        """
        Ingesta una alerta, la asocia a un caso existente o crea uno nuevo,
        actualiza la probabilidad bayesiana y emite una alerta consolidada si procede.
        """
        now = timestamp if timestamp is not None else time.time()
        stage = map_alert_to_stage(alert)
        src = alert.src_ip
        dst = alert.dst_ip

        # Resolver caso por IP de origen o destino
        case_id = self._asset_to_case.get(src) or self._asset_to_case.get(dst)
        case: Optional[CampaignCase] = None

        if case_id and case_id in self.cases:
            candidate = self.cases[case_id]
            # Verificar si está dentro de la ventana de tiempo
            if now - candidate.last_updated <= self.time_window_seconds:
                case = candidate

        if not case:
            case = CampaignCase(primary_asset=src)
            self.cases[case.campaign_id] = case

        # Asociar activos
        case.involved_assets.add(src)
        if dst and dst != "0.0.0.0":
            case.involved_assets.add(dst)
        self._asset_to_case[src] = case.campaign_id
        if dst and dst != "0.0.0.0":
            self._asset_to_case[dst] = case.campaign_id

        # Registrar alerta
        case.alerts.append(alert)
        case.last_updated = now

        # Verificar transición de Markov
        markov_bonus = 1.0
        if case.stage_transitions:
            last_stage = case.stage_transitions[-1][0]
            if last_stage != stage:
                # Transición de etapa
                transition_prob = MARKOV_TRANSITIONS.get(last_stage, {}).get(stage, 0.40)
                markov_bonus = 1.0 + (transition_prob * 0.5)

        case.stages.add(stage)
        case.stage_transitions.append((stage, now))

        # Actualización Bayesiana
        # Likelihood ratio según severidad y novedad de etapa
        sev_weights = {
            AlertSeverity.LOW: 1.5,
            AlertSeverity.MEDIUM: 2.5,
            AlertSeverity.HIGH: 4.5,
            AlertSeverity.CRITICAL: 8.0,
        }
        likelihood_ratio = sev_weights.get(alert.severity, 2.0) * markov_bonus

        # Teorema de Bayes en forma de Odds:
        # Odds_post = Odds_prior * Likelihood_Ratio
        prior_p = min(0.999, max(0.01, case.bayesian_probability))
        prior_odds = prior_p / (1.0 - prior_p)
        post_odds = prior_odds * likelihood_ratio
        new_p = post_odds / (1.0 + post_odds)
        case.bayesian_probability = min(0.999, round(new_p, 4))

        # Escalación a Alerta Consolidada de Campaña
        escalated_alert = None
        if len(case.stages) >= 2 and case.bayesian_probability >= 0.85:
            if case.status != "ESCALATED":
                case.status = "ESCALATED"
                stage_names = " -> ".join([s.value for s in case.stages])
                escalated_alert = SecurityAlert(
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.ATTACK_CAMPAIGN,
                    title=f"Campaña de Intrusi\u00f3n Multi-Etapa Confirmada ({len(case.stages)} Etapas): Host {case.primary_asset}",
                    description=(
                        f"El motor de correlaci\u00f3n causal confirm\u00f3 una campa\u00f1a activa contra el activo {case.primary_asset} "
                        f"con certeza bayesiana del {case.bayesian_probability * 100:.1f}%. "
                        f"Etapas observadas: {stage_names}. Activos comprometidos: {', '.join(list(case.involved_assets)[:4])}."
                    ),
                    src_ip=case.primary_asset,
                    dst_ip=dst,
                    confidence=case.bayesian_probability,
                    campaign_id=case.campaign_id,
                    metrics={
                        "campaign_id": case.campaign_id,
                        "stages": [s.value for s in case.stages],
                        "total_alerts": len(case.alerts),
                        "bayesian_probability": case.bayesian_probability,
                        "involved_assets": list(case.involved_assets),
                    },
                )
                case.escalated_alert_id = escalated_alert.alert_id

        return case, escalated_alert

    def list_cases(self, status: Optional[str] = None) -> List[CampaignCase]:
        cases = list(self.cases.values())
        if status:
            cases = [c for c in cases if c.status.upper() == status.upper()]
        cases.sort(key=lambda x: x.bayesian_probability, reverse=True)
        return cases

    def get_case(self, campaign_id: str) -> Optional[CampaignCase]:
        return self.cases.get(campaign_id)
