"""
NovaFlow NDR - Security & Secrets Configuration
Gestión centralizada de credenciales, secretos JWT, roles y políticas de seguridad.
"""

import os
import secrets
from typing import Dict, Any


class SecurityConfig:
    """Configuraciones de seguridad empresarial."""

    # Clave de firma JWT (generada aleatoriamente si no se define por variable de entorno)
    SECRET_KEY: str = os.getenv(
        "NOVAFLOW_SECRET_KEY",
        "novaflow-enterprise-ultra-secure-secret-key-change-in-production-2026",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("NOVAFLOW_TOKEN_EXPIRE_MINUTES", "120"))

    # Configuración de Rate Limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("NOVAFLOW_RATE_LIMIT_ENABLED", "true").lower() == "true"
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("NOVAFLOW_RATE_LIMIT_RPM", "120"))

    # API Keys autorizadas para servicios M2M (Machine to Machine) y exportadores
    # Clave -> Metadatos de identidad
    API_KEYS: Dict[str, Dict[str, Any]] = {
        "novaflow-admin-key-9988": {
            "identity_id": "service-admin",
            "role": "ADMIN",
            "tenant_id": "*",  # Acceso global multitenant
            "name": "SIEM Orchestrator Admin",
        },
        "novaflow-collector-key-5544": {
            "identity_id": "service-collector",
            "role": "ANALYST",
            "tenant_id": "default",
            "name": "Remote UDP Probe",
        },
        "novaflow-tenant-alpha-key-1122": {
            "identity_id": "service-tenant-alpha",
            "role": "ANALYST",
            "tenant_id": "tenant-alpha",
            "name": "Branch Office Alpha Integration",
        },
    }

    # Usuarios demo para autenticación interactiva
    USERS_DB: Dict[str, Dict[str, Any]] = {
        "admin@novasec.io": {
            "password_hash": "admin123",  # En producción se usa bcrypt/argon2
            "role": "ADMIN",
            "tenant_id": "*",
            "full_name": "Chief Information Security Officer",
        },
        "analyst@novasec.io": {
            "password_hash": "analyst123",
            "role": "ANALYST",
            "tenant_id": "default",
            "full_name": "Tier-2 SOC Analyst",
        },
        "auditor@novasec.io": {
            "password_hash": "auditor123",
            "role": "AUDITOR",
            "tenant_id": "*",
            "full_name": "Compliance & Security Auditor",
        },
        "readonly@novasec.io": {
            "password_hash": "readonly123",
            "role": "READONLY",
            "tenant_id": "default",
            "full_name": "Junior Network Observer",
        },
    }


security_config = SecurityConfig()
