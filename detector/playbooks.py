"""
NovaFlow NDR - Active Defense & SOAR Mitigation Playbooks Engine
Genera automáticamente comandos y políticas de bloqueo declarativas para firewalls
corporativos (iptables, nftables, Cisco IOS ACL, AWS NACL, Linux Null-Route) ante incidentes.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from detector.models import AlertCategory, AlertSeverity, SecurityAlert


@dataclass
class MitigationRule:
    platform: str          # "Linux iptables", "Linux nftables", "Cisco IOS ACL", "AWS Network ACL", "Linux Null-Route"
    command_type: str      # "CLI", "JSON", "BGP"
    block_command: str
    rollback_command: str
    explanation: str


@dataclass
class IncidentPlaybook:
    alert_id: str
    target_ip_to_block: str
    incident_category: str
    incident_severity: str
    recommended_action: str
    estimated_impact: str  # "LOW", "MEDIUM", "HIGH"
    quarantine_ttl_seconds: int
    rules: List[MitigationRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "target_ip_to_block": self.target_ip_to_block,
            "incident_category": self.incident_category,
            "incident_severity": self.incident_severity,
            "recommended_action": self.recommended_action,
            "estimated_impact": self.estimated_impact,
            "quarantine_ttl_seconds": self.quarantine_ttl_seconds,
            "rules": [
                {
                    "platform": r.platform,
                    "command_type": r.command_type,
                    "block_command": r.block_command,
                    "rollback_command": r.rollback_command,
                    "explanation": r.explanation,
                }
                for r in self.rules
            ],
        }


class MitigationPlaybookGenerator:
    """Generador de playbooks de contención y respuesta activa ante incidentes."""

    @staticmethod
    def generate_playbook(alert: SecurityAlert) -> IncidentPlaybook:
        # Determinar si bloqueamos el origen (atacante) o el destino (en caso de exfiltración externa o C2)
        if alert.category in (AlertCategory.MALICIOUS_C2, AlertCategory.EXFILTRATION, AlertCategory.C2_BEACONING):
            target_ip = alert.dst_ip  # Bloquear la IP maliciosa externa / canal C2
            action_desc = f"Bloquear tráfico saliente hacia el servidor externo hostil/C2 {target_ip}"
            impact = "LOW"
        elif alert.category == AlertCategory.ATTACK_CAMPAIGN:
            target_ip = alert.src_ip  # Aislar de inmediato al host interno comprometido
            action_desc = f"AISLAMIENTO DE EMERGENCIA: Cuarentena total para el host comprometido {target_ip} involucrado en campaña de intrusión"
            impact = "HIGH"
        elif alert.category == AlertCategory.LATERAL_MOVEMENT:
            target_ip = alert.src_ip  # Aislar de inmediato al host interno infectado que propaga malware
            action_desc = f"CUARENTENA DE RED: Aislar host interno {target_ip} por propagación de movimiento lateral (T1021)"
            impact = "HIGH"
        else:
            target_ip = alert.src_ip  # Bloquear al atacante interno/externo que escanea o inunda
            action_desc = f"Aislar en cuarentena la dirección de origen atacante {target_ip}"
            impact = "MEDIUM" if target_ip.startswith("10.") or target_ip.startswith("192.168.") else "LOW"

        rules: List[MitigationRule] = []

        # 1. Linux Netfilter / iptables
        rules.append(
            MitigationRule(
                platform="Linux iptables",
                command_type="CLI",
                block_command=f"sudo iptables -I INPUT 1 -s {target_ip} -j DROP && sudo iptables -I FORWARD 1 -s {target_ip} -j DROP",
                rollback_command=f"sudo iptables -D INPUT -s {target_ip} -j DROP && sudo iptables -D FORWARD -s {target_ip} -j DROP",
                explanation=f"Inserta reglas inmediatas de descarte (DROP) en la tabla filter para cortar tráfico entrante y enrutado desde {target_ip}.",
            )
        )

        # 2. Modern Linux nftables
        rules.append(
            MitigationRule(
                platform="Linux nftables",
                command_type="CLI",
                block_command=f"sudo nft add element inet filter blackhole {{ {target_ip} }}",
                rollback_command=f"sudo nft delete element inet filter blackhole {{ {target_ip} }}",
                explanation=f"Añade la dirección {target_ip} al conjunto 'blackhole' de alto rendimiento en nftables sin recargar el firewall.",
            )
        )

        # 3. Cisco IOS / ASA Access Control List (ACL)
        rules.append(
            MitigationRule(
                platform="Cisco IOS ACL",
                command_type="CLI",
                block_command=f"configure terminal\nip access-list extended SEC_INCIDENT_ISOLATION\n 1 deny ip host {target_ip} any log\nexit",
                rollback_command=f"configure terminal\nip access-list extended SEC_INCIDENT_ISOLATION\n no 1 deny ip host {target_ip} any log\nexit",
                explanation=f"Aplica denegación explícita con registro de auditoría en la lista de control de acceso de switches y routers Cisco.",
            )
        )

        # 4. AWS Cloud Network ACL (NACL) - Declarative JSON
        aws_json = (
            f'{{\n'
            f'  "NetworkAclId": "acl-0123456789abcdef0",\n'
            f'  "RuleNumber": 50,\n'
            f'  "Protocol": "-1",\n'
            f'  "RuleAction": "deny",\n'
            f'  "Egress": false,\n'
            f'  "CidrBlock": "{target_ip}/32"\n'
            f'}}'
        )
        aws_rollback = f"aws ec2 delete-network-acl-entry --network-acl-id acl-0123456789abcdef0 --rule-number 50 --ingress"
        rules.append(
            MitigationRule(
                platform="AWS Network ACL (NACL)",
                command_type="JSON",
                block_command=aws_json,
                rollback_command=aws_rollback,
                explanation=f"Entrada declarativa para AWS CLI / Terraform para aislar el tráfico de {target_ip}/32 a nivel de subnet en VPC.",
            )
        )

        # 5. Linux Kernel Blackhole / Null-Route (BGP / Router defense)
        rules.append(
            MitigationRule(
                platform="Linux Null-Route",
                command_type="CLI",
                block_command=f"sudo ip route add blackhole {target_ip}/32",
                rollback_command=f"sudo ip route del blackhole {target_ip}/32",
                explanation=f"Descarta instantáneamente los paquetes a nivel de kernel mediante una ruta blackhole sin consumir sockets.",
            )
        )

        return IncidentPlaybook(
            alert_id=alert.alert_id,
            target_ip_to_block=target_ip,
            incident_category=alert.category.value,
            incident_severity=alert.severity.value,
            recommended_action=action_desc,
            estimated_impact=impact,
            quarantine_ttl_seconds=3600,  # 1 hora de cuarentena por defecto
            rules=rules,
        )
