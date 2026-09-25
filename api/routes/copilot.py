"""
NovaFlow NDR - AI SOC Copilot & Incident Responder API Router
Provee endpoints de asistencia interactiva, diagnósticos forenses (X-NDR),
asesoría de mitigación táctica SOAR y traducción de lenguaje natural a Threat Hunting DSL.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel, Field

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from detector.copilot import soc_copilot
from detector.playbooks import MitigationPlaybookGenerator
from detector.hunting import execute_flow_hunt

router = APIRouter(prefix="/copilot", tags=["SOC AI Copilot & Explainable NDR"])


class ExplainRequest(BaseModel):
    alert_id: Optional[str] = Field(None, example="550e8400-e29b-41d4-a716-446655440000")
    alert_data: Optional[Dict[str, Any]] = Field(None, description="Datos de alerta opcionales si no está en memoria")


class ContainmentRequest(BaseModel):
    alert_id: Optional[str] = Field(None, example="550e8400-e29b-41d4-a716-446655440000")
    alert_data: Optional[Dict[str, Any]] = Field(None)


class HuntTranslateRequest(BaseModel):
    query: str = Field(..., example="Búscame conexiones salientes con más de 10 megas hacia servidores externos")
    execute: bool = Field(default=False, description="Si es True, ejecuta la consulta traducida sobre el historial de flujos")


class ChatRequest(BaseModel):
    message: str = Field(..., example="¿Cómo determinó NovaFlow que este flujo era una exfiltración?")
    history: Optional[List[Dict[str, str]]] = Field(default=None)
    include_system_context: bool = Field(default=True)


@router.get("/health")
async def get_copilot_health(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Diagnóstico de salud del Copiloto SOC:
    Verifica estado de Ollama, disponibilidad de la GPU NVIDIA RTX 4060,
    modelo llama3.1:8b y nivel activo de inferencia.
    """
    return await soc_copilot.check_health()


@router.post("/explain")
async def explain_alert(
    req: ExplainRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Genera un informe forense formal (Explainable NDR) que traduce los metadatos de red,
    bytes y técnicas MITRE a un diagnóstico institucional accionable.
    """
    engine = system_state.engine
    alert_dict: Optional[Dict[str, Any]] = None

    if req.alert_id and engine:
        found = next((a for a in reversed(engine.alerts_history) if a.alert_id == req.alert_id), None)
        if found:
            alert_dict = found.to_dict()

    if not alert_dict:
        alert_dict = req.alert_data

    if not alert_dict:
        raise HTTPException(
            status_code=404,
            detail=f"Alerta con ID '{req.alert_id}' no encontrada en el historial y no se proveyeron datos de alerta.",
        )

    return await soc_copilot.explain_incident(alert_dict)


@router.post("/containment")
async def recommend_containment(
    req: ContainmentRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Asesora al analista sobre la mitigación táctica, analizando el riesgo de impacto
    colateral y emitiendo comandos declarativos de firewall perimetral.
    """
    engine = system_state.engine
    alert_dict: Optional[Dict[str, Any]] = None
    alert_obj = None

    if req.alert_id and engine:
        alert_obj = next((a for a in reversed(engine.alerts_history) if a.alert_id == req.alert_id), None)
        if alert_obj:
            alert_dict = alert_obj.to_dict()

    if not alert_dict:
        alert_dict = req.alert_data

    if not alert_dict:
        raise HTTPException(status_code=404, detail="Alerta no especificada o no encontrada.")

    # Generar playbook declarativo determinista si tenemos el objeto
    playbook_dict = None
    if alert_obj:
        try:
            pb = MitigationPlaybookGenerator.generate_playbook(alert_obj)
            playbook_dict = pb.to_dict()
        except Exception:
            pass

    return await soc_copilot.recommend_containment(alert_dict, playbook_data=playbook_dict)


@router.post("/hunt-translate")
async def translate_threat_hunt(
    req: HuntTranslateRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Traduce una consulta analítica en lenguaje humano ("Búscame flujos con más de 10 megas...")
    al lenguaje DSL booleano estricto de NovaFlow y opcionalmente la ejecuta.
    """
    result = await soc_copilot.translate_threat_hunt(req.query)

    if req.execute:
        # Ejecutar la consulta contra los flujos en memoria
        dsl_str = result.get("translated_dsl", "")
        flows = list(system_state.recent_flows) if hasattr(system_state, "recent_flows") else []
        try:
            hunt_res = execute_flow_hunt(query=dsl_str, flows=flows, limit=50)
            result["executed"] = True
            result["matched_flows_count"] = hunt_res.get("total_matched", 0)
            result["matches"] = hunt_res.get("results", [])
            result["execution_time_ms"] = hunt_res.get("execution_time_ms", 0.0)
        except Exception as e:
            result["executed"] = False
            result["execution_error"] = str(e)

    return result


@router.post("/chat")
async def copilot_chat(
    req: ChatRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Canal de conversación interactivo con el Copiloto de Ciberseguridad de NovaFlow.
    Asiste en triaje de incidentes, arquitectura de red y correlación de amenazas.
    """
    context = None
    if req.include_system_context and system_state.engine:
        engine = system_state.engine
        context = {
            "flows_analyzed": engine.stats.get("flows_analyzed", 0),
            "total_alerts": len(engine.alerts_history),
            "recent_alerts_count": min(len(engine.alerts_history), 5),
            "recent_categories": [a.category.value for a in engine.alerts_history[-5:]],
            "current_throughput_fps": system_state.current_fps,
        }

    return await soc_copilot.chat(
        message=req.message,
        history=req.history,
        context=context,
    )
