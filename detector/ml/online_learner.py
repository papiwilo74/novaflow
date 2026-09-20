"""
NovaFlow NDR - Online Incremental Learning Engine
Actualiza el perfil basal continuo de la red mediante medias móviles exponenciales (EMA) sin reentrenamiento en frío.
"""

from typing import Dict, List


class OnlineDistributionLearner:
    """
    Aprendizaje incremental no supervisado con decaimiento temporal (Welford's algorithm + EMA).
    Permite que el modelo aprenda la evolución legítima de la red sin reentrenar todo el dataset.
    """

    def __init__(self, alpha: float = 0.01):
        # alpha = tasa de aprendizaje incremental (0.01 = adaptación suave a largo plazo)
        self.alpha = alpha
        self.stats: Dict[str, Dict[str, float]] = {}
        self.samples_seen = 0

    def update_with_flow(self, feature_dict: Dict[str, float]):
        """Actualiza incrementalmente la media y varianza estimada de cada característica."""
        self.samples_seen += 1

        for name, val in feature_dict.items():
            if name not in self.stats:
                self.stats[name] = {"mean": val, "var": 1.0, "std": 1.0}
                continue

            current_mean = self.stats[name]["mean"]
            current_var = self.stats[name]["var"]

            # EMA Update
            delta = val - current_mean
            new_mean = current_mean + (self.alpha * delta)
            new_var = (1 - self.alpha) * (current_var + self.alpha * (delta ** 2))
            new_std = max(0.001, new_var ** 0.5)

            self.stats[name]["mean"] = new_mean
            self.stats[name]["var"] = new_var
            self.stats[name]["std"] = new_std

    def get_distribution_stats(self) -> Dict[str, Dict[str, float]]:
        return self.stats


online_learner = OnlineDistributionLearner()
