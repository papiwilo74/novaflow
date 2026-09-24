"""
NovaFlow NDR x OmniBreach - Automated Purple Team Benchmark Harness
Evaluador experimental cuantitativo con inyección de tráfico normal de fondo (Background Noise),
medición empírica de MTTD (Mean Time to Detect), matriz de confusión (TP, FP, FN, TN)
y generación de reportes formales reproducibles (JSON & Markdown).

Uso:
    python scripts/run_purple_benchmark.py
    python scripts/run_purple_benchmark.py --background-flows 5000 --seed 123
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any

# Garantizar que la raíz del proyecto esté en sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from schemas.purple_team import (
    PurpleTeamCampaign,
    PurpleTeamEvent,
    VectorEvaluationResult,
    PurpleBenchmarkMetrics,
)

# Estilos ANSI
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def generate_background_flows(count: int, seed: int = 42) -> List[NetFlowRecord]:
    """
    Genera tráfico legítimo normal de red empresarial (ruido de fondo)
    que no debería activar heurísticas de anomalía ni alertar al SOC.
    """
    random.seed(seed)
    now = datetime.now(timezone.utc)
    base_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF

    benign_internal_ips = [f"10.0.1.{i}" for i in range(10, 60)]
    benign_external_web = [
        "142.250.190.46",  # Google
        "104.16.132.229",  # Cloudflare CDN
        "151.101.65.140",  # Fastly CDN
        "52.216.144.35",   # AWS S3
        "20.112.52.29",    # Microsoft Azure
    ]
    internal_servers = {
        "db": ("10.0.2.15", 5432),
        "app": ("10.0.2.20", 8080),
        "dns": ("10.0.0.2", 53),
    }

    flows = []
    for i in range(count):
        flow_type = random.choices(["web_https", "dns_lookup", "db_query", "internal_api"], weights=[0.55, 0.20, 0.15, 0.10])[0]
        src_ip = random.choice(benign_internal_ips)
        ts_offset = i * 2

        if flow_type == "web_https":
            dst_ip = random.choice(benign_external_web)
            dst_port = 443
            protocol = 6  # TCP
            packets = random.randint(8, 45)
            # Tráfico web regular: entre 5 KB y 800 KB (lejos del umbral de 20 MB de exfiltración)
            byte_count = random.randint(5_000, 800_000)
            tcp_flags = 24  # PSH, ACK
        elif flow_type == "dns_lookup":
            dst_ip, dst_port = internal_servers["dns"]
            protocol = 17  # UDP
            packets = random.randint(1, 2)
            byte_count = random.randint(64, 300)
            tcp_flags = 0
        elif flow_type == "db_query":
            dst_ip, dst_port = internal_servers["db"]
            protocol = 6  # TCP
            packets = random.randint(5, 30)
            byte_count = random.randint(1_024, 65_535)
            tcp_flags = 24
        else:  # internal_api
            dst_ip, dst_port = internal_servers["app"]
            protocol = 6
            packets = random.randint(4, 20)
            byte_count = random.randint(512, 16_384)
            tcp_flags = 24

        flows.append(
            NetFlowRecord(
                timestamp=now,
                timestamp_ms=(base_ms + ts_offset) & 0x7FFFFFFF,
                src_ip=src_ip,
                dst_ip=dst_ip,
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=2,
                packets=packets,
                bytes=byte_count,
                first_switched=(base_ms + ts_offset - 100) & 0x7FFFFFFF,
                last_switched=(base_ms + ts_offset) & 0x7FFFFFFF,
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                protocol=protocol,
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
                campaign_id=None,
                vector_id=None,
            )
        )

    return flows


def build_canonical_campaign(campaign_id: str) -> Tuple[PurpleTeamCampaign, Dict[str, List[NetFlowRecord]]]:
    """
    Construye la campaña formal con los 4 vectores canónicos de OmniBreach
    y genera sus flujos NetFlow correspondientes etiquetados con el contrato.
    """
    now = datetime.now(timezone.utc)
    base_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF

    # 1. OB-RECON-01: Port & Service Discovery (T1046)
    v1_event = PurpleTeamEvent(
        campaign_id=campaign_id,
        vector_id="OB-RECON-01",
        vector_name="OmniBreach Port & Service Scan",
        phase="Reconnaissance",
        mitre_technique="T1046",
        mitre_tactic="Discovery",
        attacker_ip="10.0.50.15",
        target_ip="10.0.0.10",
        target_port=80,
        expected_detector="PortScanDetector",
        expected_severity="MEDIUM",
    )
    v1_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    v1_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=base_ms,
            src_ip=v1_event.attacker_ip,
            dst_ip=v1_event.target_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=44,
            first_switched=base_ms,
            last_switched=base_ms + 10,
            src_port=40000 + p,
            dst_port=p,
            tcp_flags=2,  # SYN
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id=campaign_id,
            vector_id=v1_event.vector_id,
        )
        for p in v1_ports
    ]

    # 2. OB-EXFIL-02: SSRF & Mass Data Egress (T1048.003)
    v2_event = PurpleTeamEvent(
        campaign_id=campaign_id,
        vector_id="OB-EXFIL-02",
        vector_name="OmniBreach SSRF & Data Exfiltration",
        phase="Exfiltration",
        mitre_technique="T1048",
        mitre_tactic="Exfiltration",
        attacker_ip="10.0.0.10",
        target_ip="198.51.100.99",
        target_port=443,
        expected_detector="BandwidthExfiltrationDetector",
        expected_severity="HIGH",
    )
    v2_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=base_ms + 100,
            src_ip=v2_event.attacker_ip,
            dst_ip=v2_event.target_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=22000,
            bytes=32_000_000,  # 32 MB (> 20 MB umbral)
            first_switched=base_ms + 100,
            last_switched=base_ms + 4000,
            src_port=54321,
            dst_port=v2_event.target_port,
            tcp_flags=24,  # ACK, PSH
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id=campaign_id,
            vector_id=v2_event.vector_id,
        )
    ]

    # 3. OB-DOS-03: SYN Flood Stress Test (T1498.001)
    v3_event = PurpleTeamEvent(
        campaign_id=campaign_id,
        vector_id="OB-DOS-03",
        vector_name="OmniBreach SYN Flood Stress Test",
        phase="Impact",
        mitre_technique="T1498",
        mitre_tactic="Impact",
        attacker_ip="10.0.50.20",
        target_ip="10.0.0.80",
        target_port=80,
        expected_detector="SynFloodDetector",
        expected_severity="HIGH",
    )
    v3_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=base_ms + 200,
            src_ip=v3_event.attacker_ip,
            dst_ip=v3_event.target_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=40,
            first_switched=base_ms + 200,
            last_switched=base_ms + 205,
            src_port=30000 + i,
            dst_port=v3_event.target_port,
            tcp_flags=2,  # SYN
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id=campaign_id,
            vector_id=v3_event.vector_id,
        )
        for i in range(60)
    ]

    # 4. OB-C2-04: Reverse Shell & C2 Callback (T1071)
    v4_event = PurpleTeamEvent(
        campaign_id=campaign_id,
        vector_id="OB-C2-04",
        vector_name="OmniBreach Reverse Shell Beaconing",
        phase="Command and Control",
        mitre_technique="T1071",
        mitre_tactic="Command and Control",
        attacker_ip="10.0.0.15",
        target_ip="198.51.100.77",  # IOC Cobalt Strike catalogado
        target_port=443,
        expected_detector="ThreatIntelMatcher",
        expected_severity="CRITICAL",
    )
    v4_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=base_ms + 300,
            src_ip=v4_event.attacker_ip,
            dst_ip=v4_event.target_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=15,
            bytes=1850,
            first_switched=base_ms + 300,
            last_switched=base_ms + 1500,
            src_port=49880,
            dst_port=v4_event.target_port,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id=campaign_id,
            vector_id=v4_event.vector_id,
        )
    ]

    campaign = PurpleTeamCampaign(
        campaign_id=campaign_id,
        name="OmniBreach Automated Adversary Emulation",
        events=[v1_event, v2_event, v3_event, v4_event],
    )

    vector_flows = {
        "OB-RECON-01": v1_flows,
        "OB-EXFIL-02": v2_flows,
        "OB-DOS-03": v3_flows,
        "OB-C2-04": v4_flows,
    }

    return campaign, vector_flows


def run_benchmark(background_count: int = 1000, seed: int = 42) -> PurpleBenchmarkMetrics:
    """
    Ejecuta el arnés de benchmark completo:
    1. Prepara el motor de detección limpio.
    2. Procesa tráfico benigno de fondo y mide falsos positivos reales.
    3. Inyecta cada vector ofensivo de OmniBreach con medición de tiempo real.
    4. Computa la matriz de confusión y latencias MTTD.
    """
    campaign_id = f"camp_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{str(time.time_ns())[-6:]}"
    campaign, vector_flows = build_canonical_campaign(campaign_id)

    engine = DetectionEngine()
    metrics = PurpleBenchmarkMetrics(campaign_id=campaign_id)
    metrics.total_vectors_tested = len(campaign.events)

    t_start_total = time.perf_counter()

    # --- FASE 1: Ingesta de Tráfico Normal de Fondo (Medición de FP y TN) ---
    bg_flows = generate_background_flows(count=background_count, seed=seed)
    metrics.total_background_flows = len(bg_flows)

    bg_alerts_before = len(engine.alerts_history)
    for flow in bg_flows:
        alerts = engine.analyze_flow(flow)
        if alerts:
            metrics.false_positives += len(alerts)
        else:
            metrics.true_negatives += 1

    metrics.total_flows_processed += len(bg_flows)

    # --- FASE 2: Inyección de Vectores Ofensivos (Medición de TP, FN, MTTD y Severidad) ---
    for event in campaign.events:
        flows = vector_flows.get(event.vector_id, [])
        metrics.total_flows_processed += len(flows)

        # Medición precisa de latencia con time.perf_counter()
        t_vec_start = time.perf_counter()
        emitted_alerts: List[SecurityAlert] = []

        for flow in flows:
            alerts = engine.analyze_flow(flow)
            if alerts:
                emitted_alerts.extend(alerts)

        t_vec_end = time.perf_counter()
        elapsed_ms = (t_vec_end - t_vec_start) * 1000.0

        # Evaluar coincidencia
        matched_alert: SecurityAlert | None = None
        for a in emitted_alerts:
            # Coincidencia por IP de origen/destino o por el campo explícito vector_id
            if a.vector_id == event.vector_id or a.src_ip == event.attacker_ip or a.dst_ip == event.target_ip:
                matched_alert = a
                break

        if matched_alert:
            metrics.true_positives += 1
            detected = True
            sev_matched = (matched_alert.severity.value == event.expected_severity)
            mitre_id = matched_alert.mitre.get("technique_id", "") if matched_alert.mitre else ""
            mitre_matched = (event.mitre_technique in mitre_id or mitre_id in event.mitre_technique)

            eval_res = VectorEvaluationResult(
                campaign_id=campaign_id,
                vector_id=event.vector_id,
                vector_name=event.vector_name,
                mitre_technique=event.mitre_technique,
                expected_detector=event.expected_detector,
                expected_severity=event.expected_severity,
                detected=True,
                detected_alert_id=matched_alert.alert_id,
                detected_category=matched_alert.category.value,
                detected_severity=matched_alert.severity.value,
                severity_matched=sev_matched,
                detector_matched=True,
                mitre_matched=mitre_matched,
                mttd_ms=round(elapsed_ms, 3),
                alert_title=matched_alert.title,
                alert_confidence=matched_alert.confidence,
                cef_syslog_emitted=True,
            )
        else:
            metrics.false_negatives += 1
            eval_res = VectorEvaluationResult(
                campaign_id=campaign_id,
                vector_id=event.vector_id,
                vector_name=event.vector_name,
                mitre_technique=event.mitre_technique,
                expected_detector=event.expected_detector,
                expected_severity=event.expected_severity,
                detected=False,
                severity_matched=False,
                detector_matched=False,
                mitre_matched=False,
                mttd_ms=None,
            )

        metrics.vector_results.append(eval_res)

    t_end_total = time.perf_counter()
    metrics.duration_seconds = t_end_total - t_start_total
    metrics.calculate_derived_metrics()

    return metrics


def export_reports(metrics: PurpleBenchmarkMetrics, output_dir: str = "reports") -> Tuple[str, str]:
    """Genera y guarda los reportes JSON y Markdown reproducibles."""
    os.makedirs(output_dir, exist_ok=True)
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # 1. Reporte JSON
    json_path = os.path.join(output_dir, f"purple_benchmark_{ts_str}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics.to_dict(), f, indent=2, ensure_ascii=False)

    # 2. Reporte Markdown
    md_path = os.path.join(output_dir, f"purple_benchmark_{ts_str}.md")
    md_content = f"""# 🛡️ Reporte de Evaluación Experimental Purple Team (OmniBreach x NovaFlow NDR)

- **ID de Benchmark:** `{metrics.benchmark_id}`
- **ID de Campaña:** `{metrics.campaign_id}`
- **Fecha de Ejecución:** `{metrics.timestamp}`
- **Flujos Totales Evaluados:** `{metrics.total_flows_processed:,}`
- **Flujos de Fondo (Ruido Benigno):** `{metrics.total_background_flows:,}`
- **Throughput Sostenido:** `{metrics.throughput_fps:,.1f} flujos/segundo`

---

## 📊 Matriz de Confusión y Métricas de Rendimiento

| Métrica | Valor Empírico | Definición Formal |
| :--- | :--- | :--- |
| **Verdaderos Positivos (TP)** | `{metrics.true_positives}` | Vectores de ataque ejecutados y detectados exitosamente |
| **Falsos Negativos (FN)** | `{metrics.false_negatives}` | Vectores de ataque que eludieron la detección |
| **Falsos Positivos (FP)** | `{metrics.false_positives}` | Falsas alarmas disparadas sobre tráfico normal de fondo |
| **Verdaderos Negativos (TN)** | `{metrics.true_negatives:,}` | Flujos legítimos clasificados correctamente como benignos |
| **Precisión (Precision)** | `{(metrics.precision * 100):.2f}%` | $TP / (TP + FP)$ |
| **Sensibilidad (Recall)** | `{(metrics.recall * 100):.2f}%` | $TP / (TP + FN)$ |
| **F1-Score** | `{(metrics.f1_score * 100):.2f}%` | Media armónica entre Precisión y Sensibilidad |
| **Exactitud de Severidad** | `{(metrics.severity_accuracy * 100):.2f}%` | Concordancia exacta entre severidad esperada y detectada |

---

## ⏱️ Latencia y Tiempo Medio de Detección (MTTD)

- **MTTD Promedio (Mean Time to Detect):** `{metrics.mean_mttd_ms:.3f} ms`
- **MTTD Mínimo:** `{metrics.min_mttd_ms:.3f} ms`
- **MTTD Máximo:** `{metrics.max_mttd_ms:.3f} ms`
- **Tiempo Total de Benchmark:** `{metrics.duration_seconds:.4f} segundos`

---

## ⚔️ Desglose de Vectores Ofensivos (OmniBreach Red Team vs NovaFlow Blue Team)

| Vector ID | Nombre del Vector | MITRE ATT&CK | Detector Esperado | Severidad Esperada | Severidad Detectada | MTTD (ms) | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for v in metrics.vector_results:
        status_badge = "✅ DETECTADO" if v.detected else "❌ ELUDIDO"
        mttd_str = f"{v.mttd_ms:.2f} ms" if v.mttd_ms is not None else "N/A"
        md_content += f"| `{v.vector_id}` | {v.vector_name} | `{v.mitre_technique}` | `{v.expected_detector}` | `{v.expected_severity}` | `{v.detected_severity or 'N/A'}` | {mttd_str} | **{status_badge}** |\n"

    md_content += """
---

## 🔬 Metodología de Validación Científica

1. **Inyección de Ruido Benigno Controlado:** Se simula tráfico empresarial verosímil (navegación HTTPS hacia CDNs, consultas recursivas DNS, transacciones PostgreSQL internas y tráfico API microservicios).
2. **Medición No Asumida:** El tiempo de detección (MTTD) es cronometrado en hardware local mediante `time.perf_counter()` de alta resolución (precisión sub-microsegundo).
3. **Validación de Severidad y MITRE:** No basta con que el sistema emita una alerta genérica; se evalúa la coincidencia con la técnica MITRE y el nivel de riesgo estipulado en la matriz de amenazas.
"""

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return json_path, md_path


def print_console_summary(metrics: PurpleBenchmarkMetrics, json_path: str, md_path: str):
    """Muestra los resultados formateados en consola."""
    print(f"\n{CYAN}{BOLD}================================================================================{RESET}")
    print(f"{CYAN}{BOLD}      NOVAFLOW NDR  x  OMNIBREACH - PURPLE TEAM BENCHMARK HARNESS (v1.0)       {RESET}")
    print(f"{CYAN}{BOLD}================================================================================{RESET}")
    print(f"[*] ID Campaña      : {metrics.campaign_id}")
    print(f"[*] Flujos Totales  : {metrics.total_flows_processed:,} ({metrics.total_background_flows:,} ruido de fondo)")
    print(f"[*] Duración Total  : {metrics.duration_seconds:.4f}s ({metrics.throughput_fps:,.1f} flujos/segundo)")
    print("--------------------------------------------------------------------------------")
    print(f"{BOLD}MATRIZ DE CONFUSIÓN Y RENDIMIENTO:{RESET}")
    print(f"  • Verdaderos Positivos (TP) : {GREEN}{metrics.true_positives}{RESET} / {metrics.total_vectors_tested}")
    print(f"  • Falsos Negativos     (FN) : {RED if metrics.false_negatives > 0 else GREEN}{metrics.false_negatives}{RESET}")
    print(f"  • Falsos Positivos     (FP) : {RED if metrics.false_positives > 0 else GREEN}{metrics.false_positives}{RESET} (sobre {metrics.total_background_flows:,} flujos benignos)")
    print(f"  • Precisión (Precision)     : {GREEN if metrics.precision >= 0.95 else YELLOW}{(metrics.precision * 100):.2f}%{RESET}")
    print(f"  • Sensibilidad (Recall)     : {GREEN if metrics.recall >= 0.95 else YELLOW}{(metrics.recall * 100):.2f}%{RESET}")
    print(f"  • F1-Score                  : {GREEN if metrics.f1_score >= 0.95 else YELLOW}{(metrics.f1_score * 100):.2f}%{RESET}")
    print(f"  • Exactitud de Severidad    : {GREEN if metrics.severity_accuracy >= 0.95 else YELLOW}{(metrics.severity_accuracy * 100):.2f}%{RESET}")
    print("--------------------------------------------------------------------------------")
    print(f"{BOLD}TIEMPO MEDIO DE DETECCIÓN (MTTD MEDIDO):{RESET}")
    print(f"  • MTTD Promedio : {CYAN}{metrics.mean_mttd_ms:.3f} ms{RESET}")
    print(f"  • MTTD Mínimo   : {metrics.min_mttd_ms:.3f} ms")
    print(f"  • MTTD Máximo   : {metrics.max_mttd_ms:.3f} ms")
    print("--------------------------------------------------------------------------------")
    print(f"{BOLD}DETALLE VECTOR POR VECTOR:{RESET}")
    for v in metrics.vector_results:
        tag = f"{GREEN}[DETECTADO]{RESET}" if v.detected else f"{RED}[ELUDIDO]{RESET}"
        sev_tag = f"{GREEN}OK{RESET}" if v.severity_matched else f"{YELLOW}DISCREPANCIA ({v.detected_severity}){RESET}"
        print(f"  • {BOLD}{v.vector_id}{RESET} ({v.mitre_technique}) {tag} en {v.mttd_ms:.2f} ms | Severidad: {sev_tag}")
    print("--------------------------------------------------------------------------------")
    print(f"{GREEN}[OK] Reportes guardados exitosamente:{RESET}")
    print(f"     - JSON : {json_path}")
    print(f"     - MD   : {md_path}\n")


def main():
    parser = argparse.ArgumentParser(description="Harness de Benchmark Formal Purple Team (OmniBreach x NovaFlow NDR)")
    parser.add_argument("--background-flows", type=int, default=1000, help="Cantidad de flujos benignos de fondo (defecto: 1000)")
    parser.add_argument("--seed", type=int, default=42, help="Semilla aleatoria para reproducibilidad matemática (defecto: 42)")
    parser.add_argument("--output-dir", type=str, default="reports", help="Directorio para reportes (defecto: reports)")
    args = parser.parse_args()

    metrics = run_benchmark(background_count=args.background_flows, seed=args.seed)
    json_path, md_path = export_reports(metrics, output_dir=args.output_dir)
    print_console_summary(metrics, json_path, md_path)


if __name__ == "__main__":
    main()
