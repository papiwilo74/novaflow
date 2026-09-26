"""
NovaFlow NDR - ClickHouse Enterprise Adapter & DDL Schema
Conector para persistencia analítica masiva en ClickHouse con esquema optimizado
MergeTree, y conmutación transparente (fallback) hacia el motor columnar local NFC.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from collector.parser import NetFlowRecord
from storage.columnar import ColumnarFlowStorage

logger = logging.getLogger("NovaFlow.Storage.ClickHouse")

CLICKHOUSE_FLOWS_DDL = """
CREATE DATABASE IF NOT EXISTS novaflow;

CREATE TABLE IF NOT EXISTS novaflow.flows (
    timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    src_ip IPv4 CODEC(ZSTD(1)),
    dst_ip IPv4 CODEC(ZSTD(1)),
    src_port UInt16 CODEC(T64, ZSTD(1)),
    dst_port UInt16 CODEC(T64, ZSTD(1)),
    protocol UInt8 CODEC(T64, ZSTD(1)),
    packets UInt32 CODEC(T64, ZSTD(1)),
    bytes UInt64 CODEC(T64, ZSTD(1)),
    tcp_flags UInt8 CODEC(T64, ZSTD(1)),
    ja4 LowCardinality(String) CODEC(ZSTD(1)),
    ja3 String CODEC(ZSTD(1)),
    sni LowCardinality(String) CODEC(ZSTD(1)),
    tenant_id LowCardinality(String) DEFAULT 'default'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_port)
SETTINGS index_granularity = 8192;
"""


class ClickHouseAdapter:
    """
    Adaptador de almacenamiento analítico empresarial.
    Si ClickHouse no está disponible en la infraestructura, opera de forma
    100% autónoma utilizando el motor columnar embebido ColumnarFlowStorage.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 8123,
        username: str = "default",
        password: str = "",
        database: str = "novaflow",
        local_storage_dir: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database

        self.local_storage = ColumnarFlowStorage(storage_dir=local_storage_dir)
        self.is_connected = False
        self._client: Optional[Any] = None

        if self.host:
            self._try_connect()

    def _try_connect(self):
        """Intenta inicializar el cliente ClickHouse si las dependencias están instaladas."""
        try:
            import clickhouse_connect  # type: ignore
            self._client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                database=self.database,
            )
            self.is_connected = True
            logger.info("Conexión establecida con clúster ClickHouse en %s:%d", self.host, self.port)
        except Exception as e:
            self.is_connected = False
            self._client = None
            logger.info(
                "ClickHouse no disponible (%s). Operando en modo Columnar Local NFC.",
                str(e),
            )

    @classmethod
    def get_ddl(cls) -> str:
        """Retorna las sentencias DDL canónicas para inicializar el clúster ClickHouse."""
        return CLICKHOUSE_FLOWS_DDL.strip()

    def ingest_batch(self, flows: List[NetFlowRecord], ja4_map: Optional[Dict[str, str]] = None):
        """
        Inserta un lote de flujos de red.
        Conmuta transparentemente entre ClickHouse y ColumnarFlowStorage.
        """
        ja4_map = ja4_map or {}
        if self.is_connected and self._client:
            try:
                rows = []
                for f in flows:
                    key = f"{f.src_ip}:{f.src_port}->{f.dst_ip}:{f.dst_port}"
                    ja4 = ja4_map.get(key, "")
                    rows.append([
                        f.timestamp if hasattr(f, "timestamp") else 0,
                        f.src_ip,
                        f.dst_ip,
                        f.src_port,
                        f.dst_port,
                        f.protocol,
                        f.packets,
                        f.bytes,
                        f.tcp_flags,
                        ja4,
                        "",
                        "",
                        "default",
                    ])
                self._client.insert("flows", rows)
                return
            except Exception as e:
                logger.warning("Fallo en inserción ClickHouse, conmutando a NFC: %s", str(e))
                self.is_connected = False

        # Inserción en almacenamiento columnar nativo local
        for f in flows:
            key = f"{f.src_ip}:{f.src_port}->{f.dst_ip}:{f.dst_port}"
            ja4 = ja4_map.get(key, "")
            self.local_storage.append_flow(f, ja4=ja4)

    def query(
        self,
        filters: Optional[Dict[str, Any]] = None,
        columns: Optional[List[str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Ejecuta una consulta analítica."""
        if self.is_connected and self._client:
            # En producción, traduciría filtros a SQL
            pass
        return self.local_storage.query(filters=filters, columns=columns, limit=limit)

    def get_status(self) -> Dict[str, Any]:
        """Informa del estado del motor analítico y volumen indexado."""
        return {
            "mode": "CLICKHOUSE_CLUSTER" if self.is_connected else "LOCAL_COLUMNAR_NFC",
            "host": self.host or "local_embedded",
            "is_connected": self.is_connected,
            "total_indexed_flows": self.local_storage.total_flows(),
            "active_blocks": len(self.local_storage.frozen_blocks) + 1,
        }
