"""
NovaFlow NDR - Authentication, Authorization & RBAC Engine
Motor criptográfico de tokens JWT (HS256 nativo), API Keys y control de acceso basado en roles.
"""

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from fastapi import Header, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from api.security.config import security_config


class Role:
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"
    READONLY = "READONLY"


# Jerarquía de permisos
ROLE_HIERARCHY = {
    Role.ADMIN: [Role.ADMIN, Role.ANALYST, Role.AUDITOR, Role.READONLY],
    Role.ANALYST: [Role.ANALYST, Role.READONLY],
    Role.AUDITOR: [Role.AUDITOR, Role.READONLY],
    Role.READONLY: [Role.READONLY],
}


@dataclass
class Identity:
    identity_id: str
    role: str
    tenant_id: str
    name: str
    auth_type: str  # 'JWT', 'API_KEY', o 'DEV_ANONYMOUS'

    def has_role(self, required_role: str) -> bool:
        if self.role == Role.ADMIN:
            return True
        allowed = ROLE_HIERARCHY.get(self.role, [])
        return required_role in allowed

    def can_access_tenant(self, target_tenant: str) -> bool:
        if self.tenant_id == "*" or self.role == Role.ADMIN:
            return True
        return self.tenant_id == target_tenant


class JWTManager:
    """Implementación de alta velocidad de JWT HS256 sin dependencias externas pesadas."""

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        padded = data + "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(padded)

    @classmethod
    def create_token(cls, payload: Dict[str, Any], expires_in_minutes: Optional[int] = None) -> str:
        secret = security_config.SECRET_KEY.encode("utf-8")
        exp_minutes = expires_in_minutes or security_config.ACCESS_TOKEN_EXPIRE_MINUTES
        payload = payload.copy()
        payload["exp"] = int(time.time()) + (exp_minutes * 60)
        payload["iat"] = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = cls._b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
        signature_b64 = cls._b64_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @classmethod
    def decode_token(cls, token: str) -> Dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Token JWT con formato inválido")

        header_b64, payload_b64, signature_b64 = parts
        secret = security_config.SECRET_KEY.encode("utf-8")
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(cls._b64_encode(expected_sig), signature_b64):
            raise HTTPException(status_code=401, detail="Firma de token inválida")

        try:
            payload = json.loads(cls._b64_decode(payload_b64).decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=401, detail="Payload de token corrupto")

        if payload.get("exp", 0) < time.time():
            raise HTTPException(status_code=401, detail="Token expirado")

        return payload


# Esquema de autenticación opcional Bearer
security_bearer = HTTPBearer(auto_error=False)


async def get_current_identity(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Identity:
    """
    Resuelve la identidad del cliente mediante:
    1. Cabecera X-API-Key
    2. Cabecera Authorization: Bearer <JWT>
    3. Fallback en desarrollo para acceso directo al Dashboard
    """
    # 1. Validación de API Key
    if x_api_key:
        api_key_data = security_config.API_KEYS.get(x_api_key)
        if not api_key_data:
            raise HTTPException(status_code=401, detail="API Key no autorizada o revocada")
        return Identity(
            identity_id=api_key_data["identity_id"],
            role=api_key_data["role"],
            tenant_id=api_key_data["tenant_id"],
            name=api_key_data["name"],
            auth_type="API_KEY",
        )

    # 2. Validación de JWT Bearer Token
    if credentials and credentials.scheme.lower() == "bearer":
        payload = JWTManager.decode_token(credentials.credentials)
        return Identity(
            identity_id=payload.get("sub", "unknown"),
            role=payload.get("role", Role.ANALYST),
            tenant_id=payload.get("tenant_id", "default"),
            name=payload.get("name", "Authenticated Analyst"),
            auth_type="JWT",
        )

    # 3. Fallback de desarrollo para navegación en Dashboard web local
    return Identity(
        identity_id="soc-operator-local",
        role=Role.ADMIN,
        tenant_id="*",
        name="Local SOC Operator",
        auth_type="DEV_ANONYMOUS",
    )


def require_role(allowed_roles: List[str]) -> Callable:
    """Fábrica de dependencias de seguridad RBAC para endpoints."""

    async def role_checker(identity: Identity = Security(get_current_identity)):
        # Si es ADMIN, tiene acceso automático a todo
        if identity.role == Role.ADMIN:
            return identity

        for r in allowed_roles:
            if identity.has_role(r):
                return identity

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado. Se requiere uno de los siguientes roles: {allowed_roles}. Tu rol actual es: {identity.role}",
        )

    return role_checker
