"""
NovaFlow NDR - Automated Precision & Recall Test Suite
Verifica formalmente que el motor de detección alcance precisión >= 99%
y recall >= 98% sin emitir falsos positivos frente a tráfico legítimo.
"""

import unittest

from detector.engine import DetectionEngine
from detector.evaluation import PrecisionEvaluator
from scripts.benchmark_precision import build_benchmark_traffic


class TestDetectionPrecision(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        self.benign_flows, self.campaigns = build_benchmark_traffic()

    def test_precision_benchmark_execution(self):
        """Valida que el reporte de benchmark cumpla con estándares de producción."""
        report = PrecisionEvaluator.evaluate_benchmark(
            self.engine,
            self.benign_flows,
            self.campaigns,
        )

        # 1. Cero Falsos Positivos en tráfico normal
        self.assertEqual(
            report.false_positives,
            0,
            f"Se generaron {report.false_positives} falsos positivos en tráfico legítimo",
        )
        self.assertEqual(report.true_negatives, len(self.benign_flows))

        # 2. 100% de detección en campañas maliciosas
        self.assertEqual(
            report.true_positives,
            len(self.campaigns),
            f"Se omitieron {report.false_negatives} campañas de ataque",
        )
        self.assertEqual(report.false_negatives, 0)

        # 3. Métricas estadísticas formales
        self.assertGreaterEqual(report.precision, 0.99, "La precisión debe ser >= 99%")
        self.assertGreaterEqual(report.recall, 0.98, "El recall debe ser >= 98%")
        self.assertGreaterEqual(report.f1_score, 0.98, "El F1-Score debe ser >= 0.98")
        self.assertEqual(report.false_positive_rate, 0.0, "La tasa de falsos positivos debe ser 0%")

        # 4. Rendimiento temporal en tiempo real
        self.assertLess(
            report.avg_latency_per_flow_ms,
            5.0,
            f"Latencia por flujo superior a 5ms: {report.avg_latency_per_flow_ms:.2f}ms",
        )

    def test_report_dictionary_serialization(self):
        """Valida que el reporte genere un diccionario estructurado apto para API / JSON."""
        report = PrecisionEvaluator.evaluate_benchmark(
            self.engine,
            self.benign_flows[:10],
            self.campaigns[:2],
        )
        data = report.to_dict()

        self.assertIn("confusion_matrix", data)
        self.assertIn("metrics", data)
        self.assertIn("campaign_results", data)
        self.assertEqual(data["confusion_matrix"]["FP"], 0)
        self.assertIn("precision_pct", data["metrics"])
        self.assertIn("f1_score", data["metrics"])


if __name__ == "__main__":
    unittest.main()
