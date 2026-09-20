"""
NovaFlow NDR - Sigma Rules REST Router
Endpoints para inspección, recarga en caliente y prueba de reglas de detección declarativas en formato Sigma.
"""

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel

from api.state import system_state
from api.security.auth import Identity, Role, get_current_identity, require_role

router = APIRouter(prefix="/rules/sigma", tags=["Sigma Detection Rules"])


class TestSigmaRuleRequest(BaseModel):
    rule_yaml: str
    flow: Dict[str, Any]


class AddSigmaRuleRequest(BaseModel):
    rule_yaml: str


@router.get("")
async def list_sigma_rules(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna la lista de todas las reglas Sigma cargadas en el motor de detección."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "sigma_engine"):
        return {"total": 0, "rules": []}

    rules_list = [r.to_dict() for r in engine.sigma_engine.rules.values()]
    return {
        "total": len(rules_list),
        "rules": rules_list,
    }


@router.post("/reload")
async def reload_sigma_rules(
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Recarga en caliente todas las reglas YAML desde el directorio de configuración."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "sigma_engine"):
        raise HTTPException(status_code=503, detail="Motor de reglas Sigma no inicializado")

    rules_dir = engine.sigma_engine.rules_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "sigma"
    )
    loaded = engine.sigma_engine.load_directory(rules_dir)
    return {
        "status": "SUCCESS",
        "rules_loaded": loaded,
        "directory": rules_dir,
    }


@router.post("")
async def add_dynamic_sigma_rule(
    req: AddSigmaRuleRequest,
    identity: Identity = Security(require_role([Role.ADMIN])),
) -> Dict[str, Any]:
    """Incorpora una nueva regla Sigma YAML en caliente sin reiniciar el servidor."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "sigma_engine"):
        raise HTTPException(status_code=503, detail="Motor de reglas Sigma no inicializado")

    rule = engine.sigma_engine.load_rule_text(req.rule_yaml)
    if not rule:
        raise HTTPException(status_code=400, detail="Formato YAML de regla Sigma inválido o incompleto")

    return {
        "status": "ADDED",
        "rule": rule.to_dict(),
    }


@router.post("/test")
async def test_sigma_rule_match(
    req: TestSigmaRuleRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Prueba una regla Sigma contra un flujo simulado sin persistirla en el motor."""
    from detector.sigma_engine import SigmaEngine
    from collector.parser import NetFlowRecord
    from datetime import datetime, timezone

    temp_engine = SigmaEngine()
    rule = temp_engine.load_rule_text(req.rule_yaml)
    if not rule:
        raise HTTPException(status_code=400, detail="Sintaxis de regla Sigma inválida")

    f = req.flow
    record = NetFlowRecord(
        timestamp=datetime.now(timezone.utc),
        timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        src_ip=str(f.get("src_ip", "10.0.0.1")),
        dst_ip=str(f.get("dst_ip", "10.0.0.2")),
        next_hop="0.0.0.0",
        input_snmp=1,
        output_snmp=2,
        packets=int(f.get("packets", 10)),
        bytes=int(f.get("bytes", 1500)),
        first_switched=0,
        last_switched=1000,
        src_port=int(f.get("src_port", 50000)),
        dst_port=int(f.get("dst_port", 80)),
        tcp_flags=int(f.get("tcp_flags", 2)),
        protocol=int(f.get("protocol", 6)),
        tos=0,
        src_as=0,
        dst_as=0,
        src_mask=24,
        dst_mask=24,
    )

    alerts = temp_engine.evaluate_flow(record, upload_ratio=float(f.get("upload_ratio", 0.5)))
    return {
        "matched": len(alerts) > 0,
        "rule_id": rule.id,
        "alerts_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
