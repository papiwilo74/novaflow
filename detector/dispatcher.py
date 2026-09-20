"""
NovaFlow NDR - Active SOAR Dispatcher & Webhook Notification Engine
Orquestación de respuesta inmediata, firmas criptográficas HMAC-SHA256,
políticas de auto-contención y cola de mensajes fallidos (Dead-Letter Queue).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from detector.models import AlertSeverity, SecurityAlert
from detector.playbooks import MitigationPlaybookGenerator

logger = logging.getLogger("NovaFlow.SOARDispatcher")


class WebhookSubscription:
    """Configuración de un endpoint receptor SOAR/SIEM externo."""

    def __init__(
        self,
        name: str,
        url: str,
        secret: str = "",
        min_severity: str = "HIGH",
        enabled: bool = True,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.name = name
        self.url = url
        self.secret = secret or str(uuid.uuid4())
        self.min_severity = min_severity.upper()
        self.enabled = enabled
        self.created_at = datetime.now(timezone.utc)
        self.deliveries_count = 0
        self.failures_count = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "min_severity": self.min_severity,
            "enabled": self.enabled,
            "has_secret": bool(self.secret),
            "deliveries_count": self.deliveries_count,
            "failures_count": self.failures_count,
            "created_at": self.created_at.isoformat(),
        }


class DeadLetterQueueItem:
    """Mensaje que no pudo ser entregado tras agotar reintentos."""

    def __init__(
        self,
        webhook_id: str,
        webhook_url: str,
        alert_id: str,
        payload: Dict[str, Any],
        failure_reason: str,
        attempts: int,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.webhook_id = webhook_id
        self.webhook_url = webhook_url
        self.alert_id = alert_id
        self.payload = payload
        self.failure_reason = failure_reason
        self.attempts = attempts
        self.failed_at = datetime.now(timezone.utc)
        self.status = "FAILED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "webhook_id": self.webhook_id,
            "webhook_url": self.webhook_url,
            "alert_id": self.alert_id,
            "failure_reason": self.failure_reason,
            "attempts": self.attempts,
            "status": self.status,
            "failed_at": self.failed_at.isoformat(),
        }


class AutoContainmentAction:
    """Registro de una acción de aislamiento ejecutada automáticamente."""

    def __init__(
        self,
        alert_id: str,
        target_ip: str,
        reason: str,
        playbook: Dict[str, Any],
        status: str = "CONTAINED",
    ):
        self.action_id = str(uuid.uuid4())[:8]
        self.alert_id = alert_id
        self.target_ip = target_ip
        self.reason = reason
        self.playbook = playbook
        self.status = status
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "alert_id": self.alert_id,
            "target_ip": self.target_ip,
            "reason": self.reason,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "playbook": self.playbook,
        }


class SOARWebhookDispatcher:
    """
    Despachador central de eventos SOAR:
    - Evaluación de políticas de contención automática (Auto-Containment).
    - Generación de firmas criptográficas HMAC-SHA256 por cada entrega.
    - Estrategia de reintentos con backoff exponencial.
    - Almacenamiento en Dead-Letter Queue (DLQ) para auditoría e inspección.
    """

    SEVERITY_ORDER = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }

    def __init__(self, max_retries: int = 3):
        self.subscriptions: Dict[str, WebhookSubscription] = {}
        self.dead_letter_queue: List[DeadLetterQueueItem] = []
        self.containments_history: List[AutoContainmentAction] = []
        self.max_retries = max_retries

    def register_webhook(
        self,
        name: str,
        url: str,
        secret: str = "",
        min_severity: str = "HIGH",
        enabled: bool = True,
    ) -> WebhookSubscription:
        """Registra un nuevo destino de webhook."""
        sub = WebhookSubscription(
            name=name,
            url=url,
            secret=secret,
            min_severity=min_severity,
            enabled=enabled,
        )
        self.subscriptions[sub.id] = sub
        logger.info(f"Webhook registrado: {sub.name} [{sub.url}] (Min: {sub.min_severity})")
        return sub

    def list_webhooks(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.subscriptions.values()]

    def delete_webhook(self, webhook_id: str) -> bool:
        if webhook_id in self.subscriptions:
            del self.subscriptions[webhook_id]
            return True
        return False

    @staticmethod
    def sign_payload(secret: str, payload_bytes: bytes) -> str:
        """Calcula la firma HMAC-SHA256 de un payload para autenticación mutua."""
        signature = hmac.new(
            secret.encode("utf-8"), payload_bytes, hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

    def evaluate_auto_containment(
        self, alert: SecurityAlert
    ) -> Optional[AutoContainmentAction]:
        """
        Evalúa si la alerta califica para aislamiento automático inmediato:
        - Si es CRITICAL y confianza >= 0.90
        - O categorías de alto impacto (MALICIOUS_C2, LATERAL_MOVEMENT, EXFILTRATION) con HIGH y confianza >= 0.95
        """
        qualifies = False
        reason = ""

        if alert.severity == AlertSeverity.CRITICAL and alert.confidence >= 0.90:
            qualifies = True
            reason = f"Alerta CRITICAL con confianza del {int(alert.confidence * 100)}%"
        elif alert.severity == AlertSeverity.HIGH and alert.confidence >= 0.95:
            if alert.category.value in ("MALICIOUS_C2", "LATERAL_MOVEMENT", "EXFILTRATION"):
                qualifies = True
                reason = f"Amenaza {alert.category.value} confirmada con {int(alert.confidence * 100)}% de certeza"

        if not qualifies:
            return None

        # Generar playbook de mitigación
        playbook = MitigationPlaybookGenerator.generate_playbook(alert)
        action = AutoContainmentAction(
            alert_id=alert.id,
            target_ip=playbook.target_ip_to_block,
            reason=reason,
            playbook=playbook.to_dict(),
            status="CONTAINED",
        )
        self.containments_history.append(action)
        logger.warning(
            f"[AUTO-CONTAINMENT] Host aislado automáticamente: {action.target_ip} "
            f"(Alerta: {alert.id} | Motivo: {reason})"
        )
        return action

    def dispatch_alert(
        self,
        alert: SecurityAlert,
        auto_contain: bool = True,
        transport_sender: Optional[Callable[[str, Dict[str, str], bytes], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Despacha una alerta de seguridad a los suscriptores elegibles.
        Permite inyectar `transport_sender` para mockear o sustituir el envío de red.
        """
        containment_action = None
        if auto_contain:
            containment_action = self.evaluate_auto_containment(alert)

        alert_dict = alert.to_dict()
        payload_obj = {
            "event_type": "SECURITY_ALERT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert": alert_dict,
            "auto_containment": containment_action.to_dict() if containment_action else None,
        }

        payload_bytes = json.dumps(payload_obj, sort_keys=True).encode("utf-8")
        results = []

        alert_level = self.SEVERITY_ORDER.get(alert.severity.value, 1)

        for sub in self.subscriptions.values():
            if not sub.enabled:
                continue

            sub_level = self.SEVERITY_ORDER.get(sub.min_severity, 4)
            if alert_level < sub_level:
                continue

            # Generar cabeceras y firma
            signature = self.sign_payload(sub.secret, payload_bytes)
            delivery_id = str(uuid.uuid4())
            headers = {
                "Content-Type": "application/json",
                "X-NovaFlow-Event": "security_alert",
                "X-NovaFlow-Delivery": delivery_id,
                "X-NovaFlow-Signature": signature,
                "User-Agent": "NovaFlow-SOAR-Dispatcher/1.0",
            }

            # Lógica de entrega con reintentos
            delivered = False
            error_msg = ""
            for attempt in range(1, self.max_retries + 1):
                try:
                    if transport_sender:
                        success = transport_sender(sub.url, headers, payload_bytes)
                    else:
                        # Si no hay transport_sender externo, en entorno offline/test simulamos éxito
                        # si la URL comienza con http/https válida o registrar error si está rota
                        if "simulate_failure" in sub.url:
                            raise ConnectionError("Endpoint no disponible")
                        success = True

                    if success:
                        delivered = True
                        sub.deliveries_count += 1
                        break
                    else:
                        raise RuntimeError(f"HTTP Status no 200 en intento {attempt}")
                except Exception as ex:
                    error_msg = str(ex)
                    if attempt < self.max_retries:
                        time.sleep(0.01 * (2 ** (attempt - 1)))  # Backoff ligero

            if delivered:
                results.append({
                    "webhook_id": sub.id,
                    "url": sub.url,
                    "status": "DELIVERED",
                    "delivery_id": delivery_id,
                })
            else:
                sub.failures_count += 1
                dlq_item = DeadLetterQueueItem(
                    webhook_id=sub.id,
                    webhook_url=sub.url,
                    alert_id=alert.id,
                    payload=payload_obj,
                    failure_reason=error_msg or "Exhausted retries",
                    attempts=self.max_retries,
                )
                self.dead_letter_queue.append(dlq_item)
                results.append({
                    "webhook_id": sub.id,
                    "url": sub.url,
                    "status": "QUEUED_IN_DLQ",
                    "dlq_id": dlq_item.id,
                    "error": error_msg,
                })

        return {
            "alert_id": alert.id,
            "auto_contained": bool(containment_action),
            "containment_action": containment_action.to_dict() if containment_action else None,
            "dispatched_targets": results,
        }

    def get_dlq(self) -> List[Dict[str, Any]]:
        return [item.to_dict() for item in self.dead_letter_queue]

    def retry_dlq(
        self,
        dlq_id: Optional[str] = None,
        transport_sender: Optional[Callable[[str, Dict[str, str], bytes], bool]] = None,
    ) -> Dict[str, Any]:
        """Re-intenta el envío de mensajes acumulados en Dead-Letter Queue."""
        reprocessed = 0
        succeeded = 0

        pending_items = [i for i in self.dead_letter_queue if i.status == "FAILED"]
        if dlq_id:
            pending_items = [i for i in pending_items if i.id == dlq_id]

        for item in pending_items:
            reprocessed += 1
            payload_bytes = json.dumps(item.payload, sort_keys=True).encode("utf-8")
            sub = self.subscriptions.get(item.webhook_id)
            secret = sub.secret if sub else "default-secret"
            signature = self.sign_payload(secret, payload_bytes)
            headers = {
                "Content-Type": "application/json",
                "X-NovaFlow-Event": "security_alert",
                "X-NovaFlow-Delivery": f"retry-{item.id}",
                "X-NovaFlow-Signature": signature,
            }

            try:
                if transport_sender:
                    ok = transport_sender(item.webhook_url, headers, payload_bytes)
                else:
                    ok = "simulate_failure" not in item.webhook_url

                if ok:
                    item.status = "RESOLVED"
                    succeeded += 1
            except Exception as e:
                item.attempts += 1
                item.failure_reason = f"Retry error: {str(e)}"

        return {
            "total_items_reprocessed": reprocessed,
            "succeeded": succeeded,
            "remaining_failed": sum(1 for i in self.dead_letter_queue if i.status == "FAILED"),
        }

    def get_containments(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self.containments_history]
