"""
NovaFlow NDR - Kubernetes Manifests Builder
Genera estructuras declarativas nativas de Kubernetes (Deployments, Services, ConfigMaps, StatefulSets)
a partir de la especificación del Custom Resource NovaFlowCluster.
"""

from typing import Any, Dict, List
from k8s_operator.models import NovaFlowClusterSpec


class ManifestsBuilder:
    """Constructor de manifiestos nativos de Kubernetes para NovaFlow NDR."""

    def __init__(self, cluster_name: str, namespace: str = "novaflow"):
        self.cluster_name = cluster_name
        self.namespace = namespace

    def _labels(self, component: str) -> Dict[str, str]:
        return {
            "app.kubernetes.io/name": "novaflow-ndr",
            "app.kubernetes.io/instance": self.cluster_name,
            "app.kubernetes.io/component": component,
            "app.kubernetes.io/managed-by": "novaflow-operator",
        }

    def build_api_deployment(self, spec: NovaFlowClusterSpec) -> Dict[str, Any]:
        """Genera el Deployment para el API Gateway y Dashboard SOC."""
        labels = self._labels("api-gateway")
        image = f"novasec/novaflow-api:{spec.version}"

        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": f"{self.cluster_name}-api",
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "replicas": spec.api.replicas,
                "selector": {"matchLabels": labels},
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {
                        "maxSurge": "25%",
                        "maxUnavailable": 0,
                    },
                },
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "containers": [
                            {
                                "name": "api-gateway",
                                "image": image,
                                "ports": [
                                    {"name": "http-api", "containerPort": 8000, "protocol": "TCP"},
                                ],
                                "env": [
                                    {"name": "CLICKHOUSE_HOST", "value": f"{self.cluster_name}-clickhouse"},
                                    {"name": "CLICKHOUSE_PORT", "value": "8123"},
                                    {"name": "KAFKA_BROKER", "value": spec.kafka.broker_url if spec.kafka.enabled else ""},
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/livez", "port": 8000},
                                    "initialDelaySeconds": 10,
                                    "periodSeconds": 10,
                                    "timeoutSeconds": 3,
                                    "failureThreshold": 3,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readyz", "port": 8000},
                                    "initialDelaySeconds": 5,
                                    "periodSeconds": 5,
                                    "timeoutSeconds": 2,
                                    "failureThreshold": 2,
                                },
                                "resources": {
                                    "limits": {"cpu": "1000m", "memory": "1Gi"},
                                    "requests": {"cpu": "250m", "memory": "256Mi"},
                                },
                            }
                        ]
                    },
                },
            },
        }

    def build_api_service(self, spec: NovaFlowClusterSpec) -> Dict[str, Any]:
        """Genera el Service para el API Gateway."""
        labels = self._labels("api-gateway")
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.cluster_name}-api",
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "type": spec.api.service_type,
                "selector": labels,
                "ports": [
                    {"name": "http", "port": 8000, "targetPort": 8000, "protocol": "TCP"},
                ],
            },
        }

    def build_workers_deployment(self, spec: NovaFlowClusterSpec) -> Dict[str, Any]:
        """Genera el Deployment para el Pool de Colectores UDP NetFlow/IPFIX."""
        labels = self._labels("udp-collector")
        image = f"novasec/novaflow-collector:{spec.version}"

        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": f"{self.cluster_name}-collector",
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "replicas": spec.workers.replicas,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "containers": [
                            {
                                "name": "udp-worker",
                                "image": image,
                                "ports": [
                                    {"name": "netflow-udp", "containerPort": spec.workers.udp_port, "protocol": "UDP"},
                                ],
                                "env": [
                                    {"name": "UDP_PORT", "value": str(spec.workers.udp_port)},
                                    {"name": "BATCH_SIZE", "value": str(spec.workers.batch_size)},
                                    {"name": "CLICKHOUSE_HOST", "value": f"{self.cluster_name}-clickhouse"},
                                ],
                                "resources": {
                                    "limits": {
                                        "cpu": spec.workers.resources.limits.cpu,
                                        "memory": spec.workers.resources.limits.memory,
                                    },
                                    "requests": {
                                        "cpu": spec.workers.resources.requests.cpu,
                                        "memory": spec.workers.resources.requests.memory,
                                    },
                                },
                            }
                        ]
                    },
                },
            },
        }

    def build_workers_service(self, spec: NovaFlowClusterSpec) -> Dict[str, Any]:
        """Genera el Service UDP LoadBalancer/NodePort para recepción de flujos de routers de red."""
        labels = self._labels("udp-collector")
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{self.cluster_name}-collector-udp",
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "type": "LoadBalancer",
                "selector": labels,
                "ports": [
                    {
                        "name": "netflow",
                        "port": spec.workers.udp_port,
                        "targetPort": spec.workers.udp_port,
                        "protocol": "UDP",
                    }
                ],
            },
        }

    def build_clickhouse_statefulset(self, spec: NovaFlowClusterSpec) -> Dict[str, Any]:
        """Genera el StatefulSet para almacenamiento persistente columnar ClickHouse."""
        labels = self._labels("clickhouse-db")
        return {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": f"{self.cluster_name}-clickhouse",
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "serviceName": f"{self.cluster_name}-clickhouse",
                "replicas": spec.clickhouse.replicas,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "containers": [
                            {
                                "name": "clickhouse",
                                "image": "clickhouse/clickhouse-server:24.3-alpine",
                                "ports": [
                                    {"name": "http", "containerPort": 8123, "protocol": "TCP"},
                                    {"name": "native", "containerPort": 9000, "protocol": "TCP"},
                                ],
                                "volumeMounts": [
                                    {"name": "data", "mountPath": "/var/lib/clickhouse"},
                                ],
                            }
                        ]
                    },
                },
                "volumeClaimTemplates": [
                    {
                        "metadata": {"name": "data"},
                        "spec": {
                            "accessModes": ["ReadWriteOnce"],
                            "resources": {
                                "requests": {"storage": spec.clickhouse.storage_size}
                            },
                        },
                    }
                ],
            },
        }

    def build_all(self, spec: NovaFlowClusterSpec) -> List[Dict[str, Any]]:
        """Construye todos los recursos de Kubernetes correspondientes al cluster."""
        return [
            self.build_clickhouse_statefulset(spec),
            self.build_api_deployment(spec),
            self.build_api_service(spec),
            self.build_workers_deployment(spec),
            self.build_workers_service(spec),
        ]
