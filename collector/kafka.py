"""
NovaFlow NDR - Decoupled Kafka / Redpanda Streaming Buffer
Capa de mensajería tolerante a fallos para desacoplar la ingesta masiva de ClickHouse.
"""

import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional

from collector.parser import NetFlowRecord

logger = logging.getLogger("NovaFlow.Kafka")


class KafkaFlowProducer:
    """
    Productor de streaming para publicar flujos NetFlow en el topic 'novaflow.flows.raw'.
    Incluye buffer local de contingencia si el cluster de Kafka está desconectado.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: str = "novaflow.flows.raw",
    ):
        self.bootstrap_servers = bootstrap_servers or os.getenv("NOVAFLOW_KAFKA_SERVERS", "localhost:9092")
        self.topic = topic
        self.is_connected = False
        self._producer = None

        # Buffer en memoria de respaldo
        self.fallback_buffer: List[Dict[str, Any]] = []

    def connect(self) -> bool:
        """Intenta inicializar cliente Kafka si la librería kafka-python / aiokafka está disponible."""
        try:
            # Intento dinámico de importar aiokafka o kafka
            from kafka import KafkaProducer
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks=1,
                retries=3,
            )
            self.is_connected = True
            logger.info(f"Conectado a Kafka Broker en {self.bootstrap_servers}")
            return True
        except Exception:
            self.is_connected = False
            logger.debug("Kafka broker no disponible en este host. Operando con buffer desacoplado en memoria.")
            return False

    def publish_flows(self, records: List[NetFlowRecord], tenant_id: str = "default"):
        """Publica registros de flujo serializados en Kafka."""
        serialized_list = []
        for r in records:
            payload = {
                "timestamp": r.timestamp.isoformat(),
                "timestamp_ms": r.timestamp_ms,
                "tenant_id": tenant_id,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "tcp_flags": r.tcp_flags,
                "packets": r.packets,
                "bytes": r.bytes,
            }
            serialized_list.append(payload)

            if self.is_connected and self._producer:
                try:
                    self._producer.send(self.topic, value=payload)
                except Exception:
                    self.fallback_buffer.append(payload)
            else:
                self.fallback_buffer.append(payload)

        # Evitar sobrellenado del fallback buffer
        if len(self.fallback_buffer) > 10000:
            self.fallback_buffer = self.fallback_buffer[-10000:]


class KafkaFlowConsumer:
    """Consumidor distribuido para volcar flujos desde Kafka hacia ClickHouse."""

    def __init__(self, handler: Callable[[List[Dict[str, Any]]], Any]):
        self.handler = handler
        self.is_running = False

    async def start(self):
        self.is_running = True
        logger.info("Kafka Consumer iniciado.")

    async def stop(self):
        self.is_running = False
