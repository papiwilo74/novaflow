"""
NovaFlow NDR - Kubernetes Custom Resource Models (Pydantic)
Estructuras tipadas para validación, serialización y reconciliación de NovaFlowCluster y NovaFlowPlugin.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ClusterPhase(str, Enum):
    PENDING = "Pending"
    CREATING = "Creating"
    RUNNING = "Running"
    DEGRADED = "Degraded"
    UPDATING = "Updating"


class WorkerResourceSpec(BaseModel):
    cpu: str = "1000m"
    memory: str = "1Gi"


class ResourceRequirements(BaseModel):
    limits: WorkerResourceSpec = Field(default_factory=WorkerResourceSpec)
    requests: WorkerResourceSpec = Field(default_factory=WorkerResourceSpec)


class WorkerSpec(BaseModel):
    replicas: int = 2
    udp_port: int = 2055
    batch_size: int = 5000
    resources: ResourceRequirements = Field(default_factory=ResourceRequirements)


class ApiSpec(BaseModel):
    replicas: int = 2
    enable_dashboard: bool = True
    service_type: str = "ClusterIP"  # ClusterIP, NodePort, LoadBalancer


class ClickHouseSpec(BaseModel):
    replicas: int = 1
    retention_days: int = 90
    storage_size: str = "100Gi"
    storage_class: Optional[str] = None


class KafkaSpec(BaseModel):
    enabled: bool = True
    broker_url: str = "novaflow-redpanda:9092"


class TenantSpec(BaseModel):
    tenant_id: str
    name: str = ""
    rate_limit_rpm: int = 120
    storage_quota_gb: int = 50


class TLSSpec(BaseModel):
    enabled: bool = False
    secret_name: Optional[str] = None


class NovaFlowClusterSpec(BaseModel):
    version: str = "1.0.0"
    workers: WorkerSpec = Field(default_factory=WorkerSpec)
    api: ApiSpec = Field(default_factory=ApiSpec)
    clickhouse: ClickHouseSpec = Field(default_factory=ClickHouseSpec)
    kafka: KafkaSpec = Field(default_factory=KafkaSpec)
    tenants: List[TenantSpec] = Field(default_factory=list)
    tls: TLSSpec = Field(default_factory=TLSSpec)


class NovaFlowClusterStatus(BaseModel):
    phase: ClusterPhase = ClusterPhase.PENDING
    observed_generation: int = 0
    workers_ready: int = 0
    api_ready: int = 0
    clickhouse_status: str = "Unknown"
    current_throughput_mbps: float = 0.0
    total_alerts: int = 0
    last_reconciled: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    message: str = "Initializing cluster resources"


class NovaFlowPluginSpec(BaseModel):
    plugin_name: str
    category: str = "CUSTOM"
    severity: str = "HIGH"
    description: str = ""
    enabled: bool = True
    python_code: str


class NovaFlowPluginStatus(BaseModel):
    loaded: bool = False
    loaded_at: Optional[str] = None
    flows_evaluated: int = 0
    alerts_fired: int = 0
    last_error: Optional[str] = None
