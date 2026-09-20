-- =====================================================================
-- NOVAFLOW NDR - ENTERPRISE DDL SCHEMA & MATERIALIZED VIEWS
-- Engine: ClickHouse OLAP Columnar Database (Multi-Tenant & Compliance)
-- =====================================================================

CREATE DATABASE IF NOT EXISTS novaflow;

-- ---------------------------------------------------------------------
-- 1. TABLA PRINCIPAL DE FLUJOS EN BRUTO (Multi-Tenant & Retention TTL)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS novaflow.flows_raw (
    timestamp DateTime CODEC(DoubleDelta, LZ4),
    timestamp_ms UInt16 CODEC(LZ4),
    tenant_id LowCardinality(String) DEFAULT 'default' CODEC(LZ4),
    
    -- Direcciones de Red
    src_ip IPv4 CODEC(LZ4),
    dst_ip IPv4 CODEC(LZ4),
    next_hop IPv4 CODEC(LZ4),
    
    -- Puertos L4
    src_port UInt16 CODEC(T64, LZ4),
    dst_port UInt16 CODEC(T64, LZ4),
    
    -- Protocolo y Banderas
    protocol UInt8 CODEC(T64, LZ4),        -- 6=TCP, 17=UDP, 1=ICMP
    tcp_flags UInt8 CODEC(T64, LZ4),       -- SYN, ACK, FIN, RST, PSH, URG
    tos UInt8 CODEC(T64, LZ4),             -- Type of Service / DSCP
    
    -- Volumetría
    packets UInt32 CODEC(T64, ZSTD(1)),
    bytes UInt64 CODEC(T64, ZSTD(1)),
    
    -- Metadatos NetFlow
    flow_version UInt8 DEFAULT 5 CODEC(LZ4),
    first_switched UInt32 CODEC(DoubleDelta, LZ4),
    last_switched UInt32 CODEC(DoubleDelta, LZ4),
    input_snmp UInt16 CODEC(T64, LZ4),
    output_snmp UInt16 CODEC(T64, LZ4),
    src_mask UInt8 CODEC(LZ4),
    dst_mask UInt8 CODEC(LZ4),
    src_as UInt16 CODEC(T64, LZ4),
    dst_as UInt16 CODEC(T64, LZ4)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, toStartOfMinute(timestamp), protocol, dst_port, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------
-- 2. VISTA MATERIALIZADA: Throughput y Protocolos Multi-Tenant
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS novaflow.agg_traffic_minute (
    minute DateTime CODEC(DoubleDelta, LZ4),
    tenant_id LowCardinality(String) DEFAULT 'default' CODEC(LZ4),
    protocol UInt8 CODEC(T64, LZ4),
    dst_port UInt16 CODEC(T64, LZ4),
    total_bytes UInt64,
    total_packets UInt64,
    flow_count UInt32
)
ENGINE = SummingMergeTree((total_bytes, total_packets, flow_count))
PRIMARY KEY (minute, tenant_id, protocol, dst_port)
ORDER BY (minute, tenant_id, protocol, dst_port);

CREATE MATERIALIZED VIEW IF NOT EXISTS novaflow.mv_traffic_minute
TO novaflow.agg_traffic_minute AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    tenant_id,
    protocol,
    dst_port,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    count() AS flow_count
FROM novaflow.flows_raw
GROUP BY minute, tenant_id, protocol, dst_port;

-- ---------------------------------------------------------------------
-- 3. VISTA MATERIALIZADA: Top Talkers por Minuto Multi-Tenant
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS novaflow.agg_top_talkers_minute (
    minute DateTime CODEC(DoubleDelta, LZ4),
    tenant_id LowCardinality(String) DEFAULT 'default' CODEC(LZ4),
    src_ip IPv4 CODEC(LZ4),
    dst_ip IPv4 CODEC(LZ4),
    protocol UInt8 CODEC(T64, LZ4),
    total_bytes UInt64,
    total_packets UInt64,
    flow_count UInt32
)
ENGINE = SummingMergeTree((total_bytes, total_packets, flow_count))
PRIMARY KEY (minute, tenant_id, src_ip, dst_ip, protocol)
ORDER BY (minute, tenant_id, src_ip, dst_ip, protocol);

CREATE MATERIALIZED VIEW IF NOT EXISTS novaflow.mv_top_talkers_minute
TO novaflow.agg_top_talkers_minute AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    tenant_id,
    src_ip,
    dst_ip,
    protocol,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    count() AS flow_count
FROM novaflow.flows_raw
GROUP BY minute, tenant_id, src_ip, dst_ip, protocol;

-- ---------------------------------------------------------------------
-- 4. TABLA DE INCIDENTES Y ALERTAS DE SEGURIDAD (Multi-Tenant)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS novaflow.security_alerts (
    alert_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now() CODEC(DoubleDelta, LZ4),
    tenant_id LowCardinality(String) DEFAULT 'default' CODEC(LZ4),
    severity Enum8('LOW' = 1, 'MEDIUM' = 2, 'HIGH' = 3, 'CRITICAL' = 4),
    category LowCardinality(String),
    title String,
    description String,
    src_ip IPv4,
    dst_ip IPv4,
    dst_port UInt16,
    protocol UInt8,
    metrics_json String,
    confidence Float32,
    status Enum8('NEW' = 1, 'INVESTIGATING' = 2, 'RESOLVED' = 3, 'FALSE_POSITIVE' = 4) DEFAULT 'NEW'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, severity, category, src_ip)
TTL timestamp + INTERVAL 180 DAY DELETE;

-- ---------------------------------------------------------------------
-- 5. TABLA INMUTABLE DE AUDITORÍA (Compliance SOC2 / ISO 27001)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS novaflow.audit_trail (
    audit_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now() CODEC(DoubleDelta, LZ4),
    user_id LowCardinality(String),
    role LowCardinality(String),
    tenant_id LowCardinality(String),
    action LowCardinality(String),
    resource_id String,
    client_ip String,
    details String,
    status LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, user_id, action)
TTL timestamp + INTERVAL 365 DAY DELETE;
