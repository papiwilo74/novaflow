"""
NovaFlow NDR - Unified Threat & Anomaly Detection Engine
Orquestador central que combina heurísticas de ciberseguridad, Threat Intelligence y Machine Learning.
"""

import asyncio
import json
import logging
from typing import Callable, Dict, List, Optional
import requests

from collector.parser import NetFlowRecord
from detector.biflow import BiFlowStitcher
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.rules.bandwidth_exfil import BandwidthExfiltrationDetector
from detector.rules.dns_tunnel import DnsTunnelDetector
from detector.rules.port_scan import PortScanDetector
from detector.rules.syn_flood import SynFloodDetector
from detector.rules.threat_intel import ThreatIntelMatcher
from detector.rules.c2_beaconing import C2BeaconingDetector
from detector.rules.lateral_movement import LateralMovementDetector
from detector.profiler import DynamicBaselineProfiler
from detector.correlator import AttackKillChainCorrelator
from detector.ml.isolation_forest import NetworkIsolationForestDetector
import os
from detector.plugins import plugin_manager
from detector.graph import AttackGraphEngine
from detector.dispatcher import SOARWebhookDispatcher
from detector.eta import EncryptedTrafficAnalyzer
from detector.bloom_threat_intel import HighScaleThreatIntel
from detector.sigma_engine import SigmaEngine

logger = logging.getLogger("NovaFlow.DetectionEngine")


class DetectionEngine:
    """
    Motor unificado de análisis en tiempo real para flujos NetFlow.
    Aplica simultáneamente reglas heurísticas, listas de reputación y modelos de ML.
    """

    def __init__(
        self,
        ch_host: str = "localhost",
        ch_port: int = 8123,
        database: str = "novaflow",
    ):
        self.ch_url = f"http://{ch_host}:{ch_port}/"
        self.database = database
        self.ch_reachable = True  # Circuit breaker: si no hay ClickHouse local, conmuta a memoria pura sin latencia

        # 0. Ensamblador Bi-Flow, Perfilador Welford, Grafo de Ataque & Despachador SOAR
        self.biflow_stitcher = BiFlowStitcher()
        self.host_profiler = DynamicBaselineProfiler()
        self.attack_graph = AttackGraphEngine()
        self.soar_dispatcher = SOARWebhookDispatcher()

        # 1. Instanciar Detectores Heurísticos
        self.port_scan_detector = PortScanDetector()
        self.exfil_detector = BandwidthExfiltrationDetector(
            biflow_stitcher=self.biflow_stitcher,
            host_profiler=self.host_profiler,
        )
        self.syn_flood_detector = SynFloodDetector()
        self.dns_tunnel_detector = DnsTunnelDetector()
        self.threat_intel_matcher = ThreatIntelMatcher()
        self.c2_beaconing_detector = C2BeaconingDetector()
        self.lateral_detector = LateralMovementDetector(
            host_profiler=self.host_profiler,
        )
        self.eta_analyzer = EncryptedTrafficAnalyzer(
            biflow_stitcher=self.biflow_stitcher,
        )
        self.bloom_intel = HighScaleThreatIntel()
        sigma_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "sigma")
        self.sigma_engine = SigmaEngine(rules_dir=sigma_dir)

        # 2. Instanciar Motor de Correlación Multi-Etapa (Kill Chain)
        self.kill_chain_correlator = AttackKillChainCorrelator()

        # 3. Instanciar Detector de Machine Learning
        self.ml_detector = NetworkIsolationForestDetector()

        # Almacenamiento y callbacks en tiempo real
        self.alerts_history: List[SecurityAlert] = []
        self.max_history = 5000
        self._listeners: List[Callable[[SecurityAlert], None]] = []

        # Estadísticas acumuladas
        self.stats = {
            "flows_analyzed": 0,
            "total_alerts": 0,
            "by_severity": {s.value: 0 for s in AlertSeverity},
            "by_category": {c.value: 0 for c in AlertCategory},
        }

    def register_listener(self, callback: Callable[[SecurityAlert], None]):
        """Registra un callback para transmitir alertas en tiempo real (p. ej. WebSockets)."""
        self._listeners.append(callback)

    def analyze_flow(self, flow: NetFlowRecord) -> List[SecurityAlert]:
        """
        Analiza un flujo de red individual a través de todas las capas de detección.
        """
        self.stats["flows_analyzed"] += 1
        generated_alerts: List[SecurityAlert] = []

        # 0. Ensamblado Bi-Flow continuo, Perfilado Welford y Topología del Grafo de Ataque
        self.biflow_stitcher.ingest_flow(flow)
        self.host_profiler.ingest_flow(flow)
        self.attack_graph.ingest_flow(flow)

        # 1. Threat Intelligence (Cotejo inmediato de IPs C2)
        alert_c2 = self.threat_intel_matcher.analyze_flow(flow)
        if alert_c2:
            generated_alerts.append(alert_c2)
        else:
            alert_bloom = self.bloom_intel.analyze_flow(flow)
            if alert_bloom:
                generated_alerts.append(alert_bloom)

        # 2. Heurística: Port Scan
        alert_scan = self.port_scan_detector.analyze_flow(flow)
        if alert_scan:
            generated_alerts.append(alert_scan)

        # 3. Heurística: SYN Flood DoS
        alert_flood = self.syn_flood_detector.analyze_flow(flow)
        if alert_flood:
            generated_alerts.append(alert_flood)

        # 4. Heurística: Exfiltración de Ancho de Banda
        alert_exfil = self.exfil_detector.analyze_flow(flow)
        if alert_exfil:
            generated_alerts.append(alert_exfil)

        # 5. Heurística: Túnel DNS
        alert_dns = self.dns_tunnel_detector.analyze_flow(flow)
        if alert_dns:
            generated_alerts.append(alert_dns)

        # 6. Heurística: Balizamiento C2 Sigiloso por Jitter y Periodicidad
        alert_beacon = self.c2_beaconing_detector.analyze_flow(flow)
        if alert_beacon:
            generated_alerts.append(alert_beacon)

        # 6.5. Heurística: Movimiento Lateral e Infección Interna (Fan-out L4)
        alert_lateral = self.lateral_detector.analyze_flow(flow)
        if alert_lateral:
            generated_alerts.append(alert_lateral)

        # 6.6. Análisis de Tráfico Cifrado (ETA / SPLT en flujos TLS/HTTPS)
        alert_eta = self.eta_analyzer.analyze_flow(flow)
        if alert_eta:
            generated_alerts.append(alert_eta)

        # 6.7. Reglas Declarativas Sigma (Cargadas dinámicamente desde YAML)
        sess = self.biflow_stitcher.get_session(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
        upload_ratio = getattr(sess, "upload_ratio", getattr(sess, "bytes_ratio", 0.5)) if sess else 0.5
        sigma_alerts = self.sigma_engine.evaluate_flow(flow, upload_ratio=upload_ratio)
        if sigma_alerts:
            generated_alerts.extend(sigma_alerts)

        # 7. Machine Learning: Isolation Forest (solo si no fue alertado por reglas deterministas)
        if not generated_alerts:
            alert_ml = self.ml_detector.analyze_flow(flow)
            if alert_ml:
                generated_alerts.append(alert_ml)

        # 8. Plugins Dinámicos (CRD NovaFlowPlugin cargados en caliente)
        plugin_alerts = plugin_manager.evaluate_all(flow)
        if plugin_alerts:
            generated_alerts.extend(plugin_alerts)

        # Procesar y registrar alertas emitidas (incluyendo campañas correlacionadas)
        final_emitted_alerts: List[SecurityAlert] = []
        for alert in generated_alerts:
            if flow.campaign_id and not alert.campaign_id:
                alert.campaign_id = flow.campaign_id
            if flow.vector_id and not alert.vector_id:
                alert.vector_id = flow.vector_id
            final_emitted_alerts.append(alert)
            campaign = self._record_alert(alert)
            if campaign:
                if flow.campaign_id and not campaign.campaign_id:
                    campaign.campaign_id = flow.campaign_id
                final_emitted_alerts.append(campaign)

        return final_emitted_alerts

    def analyze_batch(self, flows: List[NetFlowRecord]) -> List[SecurityAlert]:
        """Analiza un lote completo de flujos."""
        all_alerts: List[SecurityAlert] = []
        for flow in flows:
            alerts = self.analyze_flow(flow)
            all_alerts.extend(alerts)
        return all_alerts

    def _record_alert(self, alert: SecurityAlert) -> Optional[SecurityAlert]:
        """Registra la alerta en memoria, emite a observadores y evalúa correlación Kill Chain."""
        self.stats["total_alerts"] += 1
        self.stats["by_severity"][alert.severity.value] += 1
        self.stats["by_category"][alert.category.value] += 1

        self.alerts_history.append(alert)
        if len(self.alerts_history) > self.max_history:
            self.alerts_history.pop(0)

        logger.warning(
            f"[{alert.severity.value}] [{alert.category.value}] {alert.title} "
            f"(Src: {alert.src_ip} -> Dst: {alert.dst_ip}:{alert.dst_port})"
        )

        # Notificar a observadores
        for listener in self._listeners:
            try:
                listener(alert)
            except Exception as e:
                logger.error(f"Error notificando listener: {e}")

        # Actualizar grafo de ataque y despachar alerta a través del orquestador SOAR
        self.attack_graph.ingest_alert(alert)
        self.soar_dispatcher.dispatch_alert(alert)

        # Intentar persistencia asíncrona en ClickHouse
        self._persist_alert_to_db(alert)

        # Evaluar correlación de campañas Multi-Etapa (Kill Chain)
        campaign_alert = self.kill_chain_correlator.process_alert(alert)
        if campaign_alert:
            self._record_alert(campaign_alert)
            return campaign_alert
        return None

    def _persist_alert_to_db(self, alert: SecurityAlert):
        """Inserta la alerta en la tabla novaflow.security_alerts de ClickHouse."""
        if not self.ch_reachable:
            return

        try:
            ts_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            metrics_escaped = json.dumps(alert.metrics).replace("\t", " ")
            title_escaped = alert.title.replace("\t", " ")
            desc_escaped = alert.description.replace("\t", " ")

            line = (
                f"{alert.alert_id}\t{ts_str}\t{alert.severity.value}\t{alert.category.value}\t"
                f"{title_escaped}\t{desc_escaped}\t{alert.src_ip}\t{alert.dst_ip}\t"
                f"{alert.dst_port}\t{alert.protocol}\t{metrics_escaped}\t{alert.confidence}\t{alert.status}\n"
            )

            query = (
                f"INSERT INTO {self.database}.security_alerts ("
                f"alert_id, timestamp, severity, category, title, description, "
                f"src_ip, dst_ip, dst_port, protocol, metrics_json, confidence, status"
                f") FORMAT TabSeparated"
            )

            # Envío asíncrono no bloqueante con circuit breaker
            requests.post(
                self.ch_url,
                params={"query": query},
                data=line.encode("utf-8"),
                timeout=0.1,
            )
        except Exception:
            # Si ClickHouse no está online, conmutar a memoria pura y no reintentar
            self.ch_reachable = False
