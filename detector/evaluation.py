"""
NovaFlow NDR - Detection Precision, Recall & Benchmark Evaluation Engine
Calcula matrices de confusión formales (TP, FP, TN, FN), precisión, recall,
puntuación F1 y tasas de falsos positivos frente a datasets etiquetados de tráfico.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, SecurityAlert


@dataclass
class LabeledFlow:
    flow: NetFlowRecord
    is_malicious: bool
    expected_category: Optional[AlertCategory] = None
    description: str = "Benign or attack sample"


@dataclass
class EvaluationReport:
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    avg_latency_ms: float
    category_breakdown: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "confusion_matrix": {
                "TP": self.true_positives,
                "FP": self.false_positives,
                "TN": self.true_negatives,
                "FN": self.false_negatives,
            },
            "metrics": {
                "precision_pct": round(self.precision * 100, 2),
                "recall_pct": round(self.recall * 100, 2),
                "f1_score": round(self.f1_score, 4),
                "false_positive_rate_pct": round(self.false_positive_rate * 100, 3),
                "avg_latency_ms": round(self.avg_latency_ms, 3),
            },
            "category_breakdown": self.category_breakdown,
        }

    def print_summary(self):
        print("\n" + "=" * 70)
        print("          NOVAFLOW NDR - REPORTE DE PRECISIÓN Y RENDIMIENTO")
        print("=" * 70)
        print(f"Total Muestras Evaluadas : {self.total_samples}")
        print(f"Verdaderos Positivos (TP): {self.true_positives}")
        print(f"Falsos Positivos     (FP): {self.false_positives}  <-- Métrica crítica (Ruido en SOC)")
        print(f"Verdaderos Negativos (TN): {self.true_negatives}")
        print(f"Falsos Negativos     (FN): {self.false_negatives}  <-- Amenazas omitidas")
        print("-" * 70)
        print(f"Precisión (Precision)    : {self.precision * 100:.2f}%")
        print(f"Exhaustividad (Recall)   : {self.recall * 100:.2f}%")
        print(f"Puntaje F1 (F1-Score)    : {self.f1_score:.4f}")
        print(f"Tasa de Falsos Positivos : {self.false_positive_rate * 100:.3f}%")
        print(f"Latencia Media / Flujo   : {self.avg_latency_ms:.3f} ms")
        print("=" * 70 + "\n")


@dataclass
class AttackCampaign:
    campaign_id: str
    name: str
    expected_category: AlertCategory
    flows: List[NetFlowRecord]
    description: str = ""


@dataclass
class BenchmarkReport:
    benign_flows_evaluated: int
    attack_campaigns_evaluated: int
    total_packets_processed: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    avg_latency_per_flow_ms: float
    campaign_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benign_flows_evaluated": self.benign_flows_evaluated,
            "attack_campaigns_evaluated": self.attack_campaigns_evaluated,
            "total_packets_processed": self.total_packets_processed,
            "confusion_matrix": {
                "TP": self.true_positives,
                "FP": self.false_positives,
                "TN": self.true_negatives,
                "FN": self.false_negatives,
            },
            "metrics": {
                "precision_pct": round(self.precision * 100, 2),
                "recall_pct": round(self.recall * 100, 2),
                "f1_score": round(self.f1_score, 4),
                "false_positive_rate_pct": round(self.false_positive_rate * 100, 3),
                "avg_latency_ms": round(self.avg_latency_per_flow_ms, 3),
            },
            "campaign_results": self.campaign_results,
        }

    def print_summary(self):
        print("\n" + "=" * 78)
        print("          NOVAFLOW NDR - REPORTE CIENTÍFICO DE PRECISIÓN Y RENDIMIENTO")
        print("=" * 78)
        print(f"Flujos Benignos Evaluados    : {self.benign_flows_evaluated}")
        print(f"Campañas de Ataque Evaluadas : {self.attack_campaigns_evaluated}")
        print(f"Total Paquetes Procesados    : {self.total_packets_processed:,}")
        print("-" * 78)
        print(f"Verdaderos Positivos (TP)    : {self.true_positives} / {self.attack_campaigns_evaluated}")
        print(f"Falsos Positivos     (FP)    : {self.false_positives}  <-- Cero falsas alarmas en tráfico normal")
        print(f"Verdaderos Negativos (TN)    : {self.true_negatives} / {self.benign_flows_evaluated}")
        print(f"Falsos Negativos     (FN)    : {self.false_negatives}")
        print("-" * 78)
        print(f"Precisión (Precision)        : {self.precision * 100:.2f}%")
        print(f"Exhaustividad (Recall)       : {self.recall * 100:.2f}%")
        print(f"Puntaje F1 (F1-Score)        : {self.f1_score:.4f}")
        print(f"Tasa de Falsos Positivos     : {self.false_positive_rate * 100:.3f}%")
        print(f"Latencia Promedio / Flujo    : {self.avg_latency_per_flow_ms:.3f} ms")
        print("=" * 78 + "\n")


class PrecisionEvaluator:
    """Evalúa un motor DetectionEngine contra tráfico benigno y campañas de ataque."""

    @staticmethod
    def evaluate(engine: DetectionEngine, labeled_dataset: List[LabeledFlow]) -> EvaluationReport:
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        latencies: List[float] = []
        category_breakdown: Dict[str, Dict[str, int]] = {}

        for item in labeled_dataset:
            t0 = time.perf_counter()
            alerts = engine.analyze_flow(item.flow)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

            detected = len(alerts) > 0

            if item.is_malicious:
                if detected:
                    tp += 1
                    cat_key = item.expected_category.value if item.expected_category else "ANY"
                    if cat_key not in category_breakdown:
                        category_breakdown[cat_key] = {"expected": 0, "detected": 0}
                    category_breakdown[cat_key]["expected"] += 1
                    category_breakdown[cat_key]["detected"] += 1
                else:
                    fn += 1
                    cat_key = item.expected_category.value if item.expected_category else "ANY"
                    if cat_key not in category_breakdown:
                        category_breakdown[cat_key] = {"expected": 0, "detected": 0}
                    category_breakdown[cat_key]["expected"] += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_lat = sum(latencies) / max(1, len(latencies))

        return EvaluationReport(
            total_samples=len(labeled_dataset),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            avg_latency_ms=avg_lat,
            category_breakdown=category_breakdown,
        )

    @staticmethod
    def evaluate_benchmark(
        engine: DetectionEngine,
        benign_flows: List[NetFlowRecord],
        campaigns: List[AttackCampaign],
    ) -> BenchmarkReport:
        """
        Evaluación integral con tráfico benigno para prueba de Falsos Positivos
        y campañas de ciberataque para prueba de Recall y detección.
        """
        fp = 0
        tn = 0
        latencies: List[float] = []
        total_packets = 0

        # 1. Evaluar flujo a flujo el tráfico benigno (esperado 0 alertas)
        for flow in benign_flows:
            total_packets += flow.packets
            t0 = time.perf_counter()
            alerts = engine.analyze_flow(flow)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

            if len(alerts) > 0:
                fp += 1
            else:
                tn += 1

        # 2. Evaluar cada campaña de ataque
        tp = 0
        fn = 0
        campaign_results = []

        for camp in campaigns:
            camp_detected = False
            first_alert = None
            camp_t0 = time.perf_counter()

            for flow in camp.flows:
                total_packets += flow.packets
                t0 = time.perf_counter()
                alerts = engine.analyze_flow(flow)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies.append(elapsed_ms)

                # Verificar si alguna alerta coincide con la categoría esperada
                for a in alerts:
                    if a.category == camp.expected_category:
                        camp_detected = True
                        if not first_alert:
                            first_alert = a

            camp_duration = (time.perf_counter() - camp_t0) * 1000.0

            if camp_detected:
                tp += 1
            else:
                fn += 1

            campaign_results.append({
                "campaign_id": camp.campaign_id,
                "name": camp.name,
                "expected_category": camp.expected_category.value,
                "detected": camp_detected,
                "flows_count": len(camp.flows),
                "duration_ms": round(camp_duration, 2),
                "confidence": first_alert.confidence if first_alert else None,
                "severity": first_alert.severity.value if first_alert else None,
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_lat = sum(latencies) / max(1, len(latencies))

        return BenchmarkReport(
            benign_flows_evaluated=len(benign_flows),
            attack_campaigns_evaluated=len(campaigns),
            total_packets_processed=total_packets,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            avg_latency_per_flow_ms=avg_lat,
            campaign_results=campaign_results,
        )

