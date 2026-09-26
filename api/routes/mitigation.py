"""
NovaFlow NDR - Edge Mitigation & Cloud-Native Zero-Trust REST Router
Endpoints para generación de políticas BGP Flowspec (RFC 5575) para routers troncales
y manifiestos Cilium/Kubernetes Zero-Trust para contención en microservicios.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel, Field

from api.security.auth import Identity, Role, get_current_identity, require_role
from api.state import system_state
from detector.edge_mitigation import (
    BGPFlowspecAction,
    BGPFlowspecGenerator,
    BGPFlowspecRule,
    CloudNativeZeroTrustGenerator,
)

router = APIRouter(prefix="/mitigation", tags=["Edge Mitigation & Zero-Trust"])


class BGPFlowspecRequest(BaseModel):
    alert_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = 6
    action: Optional[BGPFlowspecAction] = BGPFlowspecAction.DROP_TRAFFIC
    redirect_vrf: Optional[str] = None


class CloudNativePolicyRequest(BaseModel):
    target_ip: str
    namespace: Optional[str] = "production"
    incident_id: Optional[str] = "INC-AUTO-01"


@router.post("/bgp-flowspec")
async def generate_bgp_flowspec(
    req: BGPFlowspecRequest,
    identity: Identity = Security(require_role(Role.ADMIN)),
) -> Dict[str, Any]:
    """Genera reglas BGP Flowspec (RFC 5575) para ExaBGP, Juniper Junos y Cisco IOS-XR."""
    rule: Optional[BGPFlowspecRule] = None

    if req.alert_id:
        engine = getattr(system_state, "engine", None)
        alert = None
        if engine and hasattr(engine, "_active_alerts"):
            for a in engine._active_alerts:
                if a.alert_id == req.alert_id:
                    alert = a
                    break
        if alert:
            rule = BGPFlowspecGenerator.generate_from_alert(
                alert,
                action=req.action or BGPFlowspecAction.DROP_TRAFFIC,
                redirect_vrf=req.redirect_vrf,
            )

    if not rule:
        rule = BGPFlowspecRule(
            src_prefix=req.src_ip,
            dst_prefix=req.dst_ip,
            protocol=req.protocol,
            dst_port=req.dst_port,
            action=req.action or BGPFlowspecAction.DROP_TRAFFIC,
            redirect_vrf=req.redirect_vrf,
        )

    return {
        "rule_id": rule.rule_id,
        "action": rule.action.value,
        "exabgp_syntax": rule.to_exabgp(),
        "juniper_junos_syntax": rule.to_juniper_junos(),
        "cisco_iosxr_syntax": rule.to_cisco_iosxr(),
    }


@router.post("/cloud-native")
async def generate_cloud_native_policy(
    req: CloudNativePolicyRequest,
    identity: Identity = Security(require_role(Role.ADMIN)),
) -> Dict[str, Any]:
    """Genera manifiestos Zero-Trust para Cilium y Kubernetes estándar."""
    cilium_yaml = CloudNativeZeroTrustGenerator.generate_cilium_quarantine_policy(
        target_ip=req.target_ip,
        namespace=req.namespace or "production",
        incident_id=req.incident_id or "INC-001",
    )
    k8s_yaml = CloudNativeZeroTrustGenerator.generate_k8s_network_policy(
        pod_label_key="io.kubernetes.pod.ip",
        pod_label_val=req.target_ip,
        namespace=req.namespace or "production",
    )

    return {
        "target_ip": req.target_ip,
        "namespace": req.namespace,
        "cilium_network_policy_yaml": cilium_yaml,
        "kubernetes_network_policy_yaml": k8s_yaml,
    }
