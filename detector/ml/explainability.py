"""
NovaFlow NDR - Machine Learning Anomaly Explainability & Feature Attribution
Atribución de características (similar a SHAP values) para explicar el porqué de cada anomalía detectada.
"""

import math
from typing import Any, Dict, List, Tuple


class AnomalyExplainer:
    """
    Motor de explicabilidad que calcula la contribución porcentual e impacto
    de cada dimensión de red (bytes, paquetes, puertos, protocolo, flags) en la decisión de anomalía.
    """

    @staticmethod
    def explain_anomaly(
        feature_names: List[str],
        current_values: List[float],
        baseline_stats: Dict[str, Dict[str, float]],
    ) -> Dict[str, Any]:
        """
        Calcula las desviaciones z-score absolutas normalizadas para generar la ponderación de atribución.
        """
        attributions: Dict[str, float] = {}
        deviations: Dict[str, float] = {}
        total_deviation = 0.0

        for idx, name in enumerate(feature_names):
            val = current_values[idx]
            stat = baseline_stats.get(name, {"mean": val, "std": 1.0})
            mean = stat.get("mean", 0.0)
            std = max(0.001, stat.get("std", 1.0))

            dev = abs(val - mean) / std
            deviations[name] = round(dev, 2)
            total_deviation += dev

        # Normalizar a porcentajes de contribución
        for name in feature_names:
            if total_deviation > 0:
                pct = (deviations[name] / total_deviation) * 100.0
            else:
                pct = 100.0 / len(feature_names)
            attributions[name] = round(pct, 1)

        # Ordenar características por mayor impacto
        top_factors = sorted(attributions.items(), key=lambda x: x[1], reverse=True)

        # Generar explicación legible para el analista de seguridad
        primary_factor = top_factors[0]
        explanation_text = (
            f"Anomalía dominada en un {primary_factor[1]}% por desviación extrema en '{primary_factor[0]}'. "
            f"Desviación estandarizada: {deviations.get(primary_factor[0], 0):.1f}σ respecto al perfil basal."
        )

        return {
            "primary_feature": primary_factor[0],
            "feature_attributions": dict(top_factors),
            "standardized_deviations_sigma": deviations,
            "human_explanation": explanation_text,
        }


explainer = AnomalyExplainer()
