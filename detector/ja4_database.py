"""
NovaFlow NDR - JA4 & JA3 Cryptographic Threat Intelligence Database
Repositorio de firmas TLS para detección de implantes maliciosos, marcos C2 y
herramientas ofensivas sin requerir descifrado SSL (Encrypted Traffic Analysis).
"""

from typing import Any, Dict, Optional, Set


# Catálogo de huellas JA4 maliciosas conocidas (Cobalt Strike, Sliver, Meterpreter, etc.)
KNOWN_MALICIOUS_JA4: Dict[str, Dict[str, Any]] = {
    # Cobalt Strike Malleable C2 profiles
    "t13d1516h2_8daaf6152771_e562703ab855": {
        "family": "Cobalt Strike C2",
        "actor": "APT29 / Multiple",
        "severity": "CRITICAL",
        "tool": "Cobalt Strike TeamServer HTTPS Listener",
        "mitre_technique": "T1071.001",
    },
    "t12d190800_2b7b7fa6f157_26279f15d2a9": {
        "family": "Cobalt Strike C2",
        "actor": "FIN7",
        "severity": "CRITICAL",
        "tool": "Cobalt Strike v4.4 Default TLS",
        "mitre_technique": "T1071.001",
    },
    # Sliver C2 Implants
    "t13d2112h2_40f064c5a92a_c4c2a3782b5e": {
        "family": "Sliver C2",
        "actor": "BishopFox / Red Team",
        "severity": "CRITICAL",
        "tool": "Sliver Go HTTPS Implant",
        "mitre_technique": "T1071.001",
    },
    "t13i190800_40f064c5a92a_e562703ab855": {
        "family": "Sliver C2",
        "actor": "Unknown Threat Actor",
        "severity": "CRITICAL",
        "tool": "Sliver Direct IP HTTPS Session",
        "mitre_technique": "T1071.001",
    },
    # Metasploit / Meterpreter HTTPS Payloads
    "t12d170800_3b1d9c12e87a_14f3b79a5281": {
        "family": "Metasploit Meterpreter",
        "actor": "Offensive Operators",
        "severity": "CRITICAL",
        "tool": "windows/x64/meterpreter_reverse_https",
        "mitre_technique": "T1573.002",
    },
    # Recon & Scanning Tools (Nmap SSL, Masscan)
    "t12i010000_000000000000_000000000000": {
        "family": "Recon Tool / SSL Scanner",
        "actor": "Security Scanner",
        "severity": "MEDIUM",
        "tool": "Nmap SSL Enumeration / Raw Probe",
        "mitre_technique": "T1046",
    },
}

# Catálogo de huellas JA3 clásicas maliciosas (MD5)
KNOWN_MALICIOUS_JA3: Dict[str, Dict[str, Any]] = {
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "Metasploit Meterpreter",
        "actor": "Offensive Operators",
        "severity": "CRITICAL",
        "tool": "Meterpreter reverse_https standard",
        "mitre_technique": "T1573.002",
    },
    "72a589da586844d7f0818ce684948eea": {
        "family": "Cobalt Strike C2",
        "actor": "APT29",
        "severity": "CRITICAL",
        "tool": "Cobalt Strike 4.x beacon",
        "mitre_technique": "T1071.001",
    },
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "TrickBot / Emotet",
        "actor": "Wizard Spider",
        "severity": "CRITICAL",
        "tool": "TrickBot Banking Trojan HTTPS",
        "mitre_technique": "T1071.001",
    },
}

# Catálogo de huellas legítimas habituales (navegadores y herramientas de sistema estándar)
KNOWN_LEGITIMATE_JA4_PREFIXES: Set[str] = {
    "t13d1516h2",  # Chrome Desktop reciente
    "t13d1715h2",  # Edge Desktop
    "t13d1615h2",  # Firefox Desktop
    "t13d1413h2",  # Safari Desktop / iOS
    "t13d030400",  # Curl / OpenSSL básico
}


class JA4Database:
    """Motor de consulta e inteligencia de huellas TLS en memoria."""

    def __init__(
        self,
        custom_ja4: Optional[Dict[str, Dict[str, Any]]] = None,
        custom_ja3: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self._ja4_db: Dict[str, Dict[str, Any]] = dict(KNOWN_MALICIOUS_JA4)
        self._ja3_db: Dict[str, Dict[str, Any]] = dict(KNOWN_MALICIOUS_JA3)
        if custom_ja4:
            self._ja4_db.update(custom_ja4)
        if custom_ja3:
            self._ja3_db.update(custom_ja3)

    def lookup_ja4(self, ja4_hash: str) -> Optional[Dict[str, Any]]:
        """Busca una huella JA4 en el repositorio de amenazas."""
        return self._ja4_db.get(ja4_hash)

    def lookup_ja3(self, ja3_hash: str) -> Optional[Dict[str, Any]]:
        """Busca una huella JA3 en el repositorio de amenazas."""
        return self._ja3_db.get(ja3_hash)

    def is_known_malicious(
        self, ja4_hash: str, ja3_hash: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Verifica si la sesión TLS coincide con un IoC JA4 o JA3."""
        match = self.lookup_ja4(ja4_hash)
        if match:
            return match
        if ja3_hash:
            return self.lookup_ja3(ja3_hash)
        return None

    def is_legitimate_baseline(self, ja4_hash: str) -> bool:
        """Determina si el prefijo JA4_a corresponde a un cliente legítimo registrado."""
        parts = ja4_hash.split("_")
        if parts:
            return parts[0] in KNOWN_LEGITIMATE_JA4_PREFIXES
        return False

    def add_custom_threat(
        self,
        fingerprint: str,
        family: str,
        tool: str,
        severity: str = "HIGH",
        actor: str = "Unknown",
        fp_type: str = "ja4",
    ):
        """Registra dinámicamente una nueva huella TLS maliciosa."""
        meta = {
            "family": family,
            "actor": actor,
            "severity": severity,
            "tool": tool,
            "mitre_technique": "T1071.001",
        }
        if fp_type.lower() == "ja3":
            self._ja3_db[fingerprint] = meta
        else:
            self._ja4_db[fingerprint] = meta
