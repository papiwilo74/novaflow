"""
Pruebas unitarias para la Fase 2: Motor de Persistencia y Analítica Columnar Masiva (.nfc / ClickHouse).
"""

import os
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timezone
from typing import Optional
from starlette.testclient import TestClient

from api.main import app
from api.security.auth import JWTManager, Role
from collector.parser import NetFlowRecord
from storage.columnar import ColumnBlock, ColumnarFlowStorage, BlockZoneMap
from storage.clickhouse_adapter import ClickHouseAdapter


def create_flow_record(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 10000,
    dst_port: int = 443,
    protocol: int = 6,
    packets: int = 10,
    bytes_count: int = 1000,
    tcp_flags: int = 0x18,
    dt: Optional[datetime] = None,
) -> NetFlowRecord:
    now = dt or datetime.now(timezone.utc)
    return NetFlowRecord(
        timestamp=now,
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="0.0.0.0",
        input_snmp=1,
        output_snmp=2,
        packets=packets,
        bytes=bytes_count,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        protocol=protocol,
        tos=0,
        src_as=0,
        dst_as=0,
        src_mask=24,
        dst_mask=24,
    )


class TestColumnarStorage(unittest.TestCase):
    """Batería de validación de almacenamiento columnar nativo y adaptador ClickHouse."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="novaflow_nfc_test_")
        self.admin_token = JWTManager.create_token(
            {
                "sub": "soc-admin-tester",
                "role": Role.ADMIN,
                "tenant_id": "default",
                "name": "Admin Tester",
            },
            expires_in_minutes=30,
        )
        self.auth_headers = {"Authorization": f"Bearer {self.admin_token}"}

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_column_block_serialization_and_deserialization(self):
        """Verifica que un bloque columnar se comprima y se restaure sin pérdida de información."""
        block = ColumnBlock(block_id=101)
        now = time.time()

        for i in range(50):
            block.append(
                ts=now + i,
                src_ip=f"10.0.0.{i % 10}",
                dst_ip=f"192.168.1.{i % 5}",
                src_port=10000 + i,
                dst_port=443 if i % 2 == 0 else 80,
                proto=6,
                pkts=10 + i,
                byte_count=1000 + i * 50,
                flags=0x02,
                ja4="t13d1516h2_8daaf6152771_e562703ab855",
            )

        self.assertEqual(len(block), 50)
        self.assertEqual(block.zone_map.row_count, 50)
        self.assertEqual(block.zone_map.min_dst_port, 80)
        self.assertEqual(block.zone_map.max_dst_port, 443)

        # Serializar
        compressed_bytes = block.serialize()
        self.assertIsInstance(compressed_bytes, bytes)
        self.assertGreater(len(compressed_bytes), 0)

        # Deserializar
        restored = ColumnBlock.deserialize(compressed_bytes)
        self.assertEqual(restored.block_id, 101)
        self.assertEqual(len(restored), 50)
        self.assertEqual(restored.src_ips, block.src_ips)
        self.assertEqual(restored.dst_ports, block.dst_ports)
        self.assertEqual(restored.bytes_transferred, block.bytes_transferred)
        self.assertEqual(restored.ja4_hashes[0], "t13d1516h2_8daaf6152771_e562703ab855")

    def test_zone_map_block_skipping(self):
        """Valida que los filtros imposibles para un bloque se podan mediante ZoneMap."""
        zm = BlockZoneMap()
        now = 1700000000.0
        zm.update(
            ts=now,
            src_ip="10.0.1.5",
            dst_ip="192.168.10.20",
            dst_port=443,
            proto=6,
            pkts=5,
            byte_count=500,
        )

        # Filtro que coincide
        self.assertFalse(zm.can_skip({"dst_port": 443}))
        self.assertFalse(zm.can_skip({"src_ip": "10.0.1.5"}))

        # Filtros que NO coinciden y deben podar el bloque
        self.assertTrue(zm.can_skip({"dst_port": 8080}))
        self.assertTrue(zm.can_skip({"src_ip": "10.0.99.99"}))
        self.assertTrue(zm.can_skip({"protocol": 17}))
        self.assertTrue(zm.can_skip({"start_time": now + 100}))

    def test_columnar_storage_rotation_and_queries(self):
        """Verifica la rotación de bloques en disco y la ejecución de consultas analíticas."""
        storage = ColumnarFlowStorage(storage_dir=self.temp_dir, block_size=20)
        base_time = 1700000000.0

        # Insertar 55 flujos -> provocará 2 bloques congelados y 1 activo con 15
        for i in range(55):
            rec = create_flow_record(
                src_ip=f"10.0.0.{i % 4}",
                dst_ip="198.51.100.10",
                src_port=50000 + i,
                dst_port=443 if i < 40 else 80,
                protocol=6,
                packets=10,
                bytes_count=1000 + (i * 100),
                tcp_flags=0x18,
                dt=datetime.fromtimestamp(base_time + i, tz=timezone.utc),
            )
            storage.append_flow(rec, timestamp=base_time + i)

        self.assertEqual(storage.total_flows(), 55)
        self.assertEqual(len(storage.frozen_blocks), 2)
        self.assertEqual(len(storage.active_block), 15)

        # Comprobar que los archivos .nfc fueron escritos en disco
        files = list(os.listdir(self.temp_dir))
        self.assertTrue(any(f.endswith(".nfc") for f in files))

        # Consulta con filtro por puerto
        results_80 = storage.query(filters={"dst_port": 80}, limit=100)
        self.assertEqual(len(results_80), 15)

        results_443 = storage.query(filters={"dst_port": 443}, limit=100)
        self.assertEqual(len(results_443), 40)

        # Top talkers
        top = storage.aggregate_top_talkers(limit=2, by_bytes=True, direction="src")
        self.assertEqual(len(top), 2)
        self.assertIn("10.0.0.", top[0]["ip"])

        # Protocols
        breakdown = storage.aggregate_protocols()
        self.assertIn("TCP", breakdown)
        self.assertEqual(breakdown["TCP"]["flows"], 55)

        # Timeline
        timeline = storage.aggregate_timeline(bucket_seconds=30)
        self.assertGreater(len(timeline), 0)

    def test_clickhouse_adapter_ddl_and_fallback(self):
        """Valida que el adaptador ClickHouse genere DDL corporativo y opere en fallback local."""
        ddl = ClickHouseAdapter.get_ddl()
        self.assertIn("CREATE TABLE IF NOT EXISTS novaflow.flows", ddl)
        self.assertIn("MergeTree()", ddl)
        self.assertIn("PARTITION BY toYYYYMM(timestamp)", ddl)

        # Instanciar sin servidor ClickHouse real (debe usar fallback sin fallar)
        adapter = ClickHouseAdapter(local_storage_dir=self.temp_dir)
        status = adapter.get_status()
        self.assertEqual(status["mode"], "LOCAL_COLUMNAR_NFC")
        self.assertFalse(status["is_connected"])

        # Inserción de lote
        records = [
            create_flow_record(
                src_ip="10.10.10.1",
                dst_ip="10.10.10.2",
                src_port=1234,
                dst_port=53,
                protocol=17,
                packets=2,
                bytes_count=128,
                tcp_flags=0,
            )
        ]
        adapter.ingest_batch(records)
        self.assertEqual(adapter.get_status()["total_indexed_flows"], 1)

    def test_analytics_api_endpoints(self):
        """Verifica la API REST de analítica columnar."""
        with TestClient(app) as client:
            # 1. Status
            res = client.get("/api/v1/analytics/status", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data["clickhouse_compatible"])

            # 2. Query
            res = client.post(
                "/api/v1/analytics/query",
                json={"filters": {}, "limit": 10},
                headers=self.auth_headers,
            )
            self.assertEqual(res.status_code, 200)

            # 3. Top talkers
            res = client.get("/api/v1/analytics/top-talkers?limit=5", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)

            # 4. Protocols
            res = client.get("/api/v1/analytics/protocols", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)

            # 5. Timeline
            res = client.get("/api/v1/analytics/timeline?bucket_seconds=60", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
