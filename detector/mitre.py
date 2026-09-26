"""
NovaFlow NDR - MITRE ATT&CK Framework Mapping
Mapeo formal de vectores de amenaza de red contra las matrices de MITRE ATT&CK for Enterprise.
"""

from dataclasses import dataclass
from typing import Dict, Optional
from detector.models import AlertCategory


@dataclass(frozen=True)
class MitreAttackRef:
    tactic: str           # e.g. "Discovery", "Impact", "Exfiltration"
    technique_id: str     # e.g. "T1046"
    technique_name: str   # e.g. "Network Service Discovery"
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    url: str = ""

    def to_dict(self) -> Dict[str, str]:
        res = {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "url": self.url or f"https://attack.mitre.org/techniques/{self.technique_id}/",
        }
        if self.subtechnique_id:
            res["subtechnique_id"] = self.subtechnique_id
            res["subtechnique_name"] = self.subtechnique_name or ""
            res["url"] = f"https://attack.mitre.org/techniques/{self.technique_id}/{self.subtechnique_id.split('.')[-1]}/"
        return res


# Mapeo oficial de categorías de NovaFlow a MITRE ATT&CK
MITRE_MAPPING: Dict[AlertCategory, MitreAttackRef] = {
    AlertCategory.PORT_SCAN: MitreAttackRef(
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    ),
    AlertCategory.SYN_FLOOD: MitreAttackRef(
        tactic="Impact",
        technique_id="T1498",
        technique_name="Network Denial of Service",
        subtechnique_id="T1498.001",
        subtechnique_name="Direct Network Flood",
        url="https://attack.mitre.org/techniques/T1498/001/",
    ),
    AlertCategory.EXFILTRATION: MitreAttackRef(
        tactic="Exfiltration",
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        subtechnique_id="T1048.003",
        subtechnique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
        url="https://attack.mitre.org/techniques/T1048/003/",
    ),
    AlertCategory.DNS_TUNNEL: MitreAttackRef(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        subtechnique_id="T1071.004",
        subtechnique_name="DNS",
        url="https://attack.mitre.org/techniques/T1071/004/",
    ),
    AlertCategory.MALICIOUS_C2: MitreAttackRef(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        url="https://attack.mitre.org/techniques/T1071/",
    ),
    AlertCategory.ANOMALY_ML: MitreAttackRef(
        tactic="Defense Evasion",
        technique_id="T1036",
        technique_name="Masquerading / Baseline Anomaly",
        url="https://attack.mitre.org/techniques/T1036/",
    ),
    AlertCategory.C2_BEACONING: MitreAttackRef(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol: C2 Beaconing",
        subtechnique_id="T1071.001",
        subtechnique_name="Web Protocols",
        url="https://attack.mitre.org/techniques/T1071/001/",
    ),
    AlertCategory.ATTACK_CAMPAIGN: MitreAttackRef(
        tactic="Enterprise Kill Chain",
        technique_id="T1046+T1071+T1048",
        technique_name="Multi-Stage Attack Campaign",
        url="https://attack.mitre.org/",
    ),
    AlertCategory.LATERAL_MOVEMENT: MitreAttackRef(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.002",
        subtechnique_name="SMB/Windows Admin Shares",
        url="https://attack.mitre.org/techniques/T1021/002/",
    ),
    AlertCategory.ANOMALOUS_TLS: MitreAttackRef(
        tactic="Command and Control",
        technique_id="T1573",
        technique_name="Encrypted Channel",
        subtechnique_id="T1573.001",
        subtechnique_name="Symmetric Cryptography",
        url="https://attack.mitre.org/techniques/T1573/001/",
    ),
    AlertCategory.DGA_DOMAIN: MitreAttackRef(
        tactic="Command and Control",
        technique_id="T1568",
        technique_name="Dynamic Resolution",
        subtechnique_id="T1568.002",
        subtechnique_name="Domain Generation Algorithms",
        url="https://attack.mitre.org/techniques/T1568/002/",
    ),
    AlertCategory.IDENTITY_ATTACK: MitreAttackRef(
        tactic="Credential Access",
        technique_id="T1558",
        technique_name="Steal or Forge Kerberos Tickets",
        subtechnique_id="T1558.003",
        subtechnique_name="Kerberoasting",
        url="https://attack.mitre.org/techniques/T1558/003/",
    ),
}


def get_mitre_for_category(category: AlertCategory) -> MitreAttackRef:
    """Obtiene la referencia MITRE ATT&CK correspondiente a una categoría de alerta."""
    return MITRE_MAPPING.get(
        category,
        MitreAttackRef(
            tactic="Unknown",
            technique_id="T0000",
            technique_name="Unclassified Network Behavior",
        ),
    )
