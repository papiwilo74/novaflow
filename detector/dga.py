"""
NovaFlow NDR - Domain Generation Algorithm (DGA) & Fast-Flux DNS Detector
Motor de clasificación probabilística basado en n-gramas, entropía de Shannon,
razón de alternancia consonante-vocal y seguimiento temporal de rotación de IPs (Fast-Flux).
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


# Tabla de frecuencias relativas de bigramas del lenguaje de dominios benignos (Tranco/Alexa sample)
BENIGN_BIGRAM_LOG_PROBS: Dict[str, float] = {
    "in": -2.1, "er": -2.2, "on": -2.3, "te": -2.4, "an": -2.4, "re": -2.5, "ed": -2.5,
    "at": -2.6, "es": -2.6, "or": -2.7, "en": -2.7, "ti": -2.7, "al": -2.8, "st": -2.8,
    "ar": -2.9, "nt": -2.9, "to": -2.9, "nd": -3.0, "co": -3.0, "ne": -3.0, "se": -3.1,
    "th": -3.1, "le": -3.1, "is": -3.2, "it": -3.2, "ro": -3.2, "he": -3.2, "me": -3.3,
    "de": -3.3, "ic": -3.3, "ra": -3.4, "ve": -3.4, "ma": -3.4, "om": -3.4, "ri": -3.5,
    "li": -3.5, "lo": -3.5, "as": -3.6, "ta": -3.6, "el": -3.6, "ha": -3.7, "ng": -3.7,
    "ca": -3.7, "so": -3.8, "la": -3.8, "ur": -3.8, "di": -3.8, "pe": -3.9, "po": -3.9,
    "ch": -3.9, "pa": -4.0, "ap": -4.0, "su": -4.0, "io": -4.0, "us": -4.1, "ac": -4.1,
    "fo": -4.1, "pr": -4.2, "ow": -4.2, "am": -4.2, "no": -4.3, "ol": -4.3, "il": -4.3,
}
DEFAULT_UNSEEN_BIGRAM_LOG_PROB = -6.5

VOWELS = set("aeiou")


class DGADetector:
    """Clasificador de nombres de dominio algorítmicos (DGA)."""

    # Dominios y sufijos corporativos / CDN comúnmente conocidos
    BENIGN_WHITELIST_SUFFIXES = {
        "google.com", "microsoft.com", "cloudflare.com", "amazon.com", "apple.com",
        "github.com", "akamai.net", "fastly.net", "azure.com", "aws.amazon.com",
    }

    @classmethod
    def extract_sld(cls, domain: str) -> str:
        """Extrae el Second-Level Domain (SLD) principal para análisis lingüístico."""
        cleaned = domain.lower().strip().rstrip(".")
        parts = cleaned.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return cleaned

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Calcula la entropía de Shannon sobre una cadena de caracteres."""
        if not text:
            return 0.0
        counts: Dict[str, int] = defaultdict(int)
        for char in text:
            counts[char] += 1
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @classmethod
    def calculate_bigram_perplexity(cls, text: str) -> float:
        """
        Calcula la perplejidad inversa de bigramas basada en frecuencias benignas.
        Valores altos indican transiciones de caracteres fonéticamente inverosímiles.
        """
        if len(text) < 2:
            return 0.0

        log_prob_sum = 0.0
        count = 0
        for i in range(len(text) - 1):
            pair = text[i:i + 2]
            if pair.isalpha():
                log_prob_sum += BENIGN_BIGRAM_LOG_PROBS.get(pair, DEFAULT_UNSEEN_BIGRAM_LOG_PROB)
                count += 1

        if count == 0:
            return 0.0

        avg_log_prob = log_prob_sum / count
        # Invertir y normalizar: avg_log_prob típicamente entre -2.0 y -6.5
        normalized_anomaly = min(1.0, max(0.0, (-avg_log_prob - 2.5) / 3.5))
        return round(normalized_anomaly, 4)

    @classmethod
    def calculate_vowel_ratio(cls, text: str) -> float:
        """Calcula la proporción de vocales sobre caracteres alfabéticos."""
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        vowel_count = sum(1 for c in letters if c in VOWELS)
        return vowel_count / len(letters)

    @classmethod
    def calculate_digit_ratio(cls, text: str) -> float:
        """Calcula la proporción de dígitos numéricos en la cadena."""
        if not text:
            return 0.0
        digit_count = sum(1 for c in text if c.isdigit())
        return digit_count / len(text)

    @classmethod
    def max_consecutive_consonants(cls, text: str) -> int:
        """Cuenta la ráfaga más larga de consonantes consecutivas."""
        max_run = 0
        current_run = 0
        for c in text.lower():
            if c.isalpha() and c not in VOWELS:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
            else:
                current_run = 0
        return max_run

    @classmethod
    def evaluate_domain(cls, domain: str) -> Dict[str, Any]:
        """
        Evalúa integralmente un dominio determinando su puntuación DGA y familia probable.
        Retorna un dict con dga_score (0.0-1.0), is_dga (booleano) y desglose de métricas.
        """
        cleaned = domain.lower().strip().rstrip(".")

        # Verificar lista blanca de sufijos benignos
        for white in cls.BENIGN_WHITELIST_SUFFIXES:
            if cleaned == white or cleaned.endswith("." + white):
                return {
                    "domain": domain,
                    "sld": cls.extract_sld(domain),
                    "dga_score": 0.05,
                    "is_dga": False,
                    "family_guess": None,
                    "metrics": {"whitelisted": True},
                }

        sld = cls.extract_sld(domain)
        if len(sld) <= 3:
            return {
                "domain": domain,
                "sld": sld,
                "dga_score": 0.1,
                "is_dga": False,
                "family_guess": None,
                "metrics": {"length": len(sld)},
            }

        # 1. Extracción de características numéricas
        entropy = cls.calculate_entropy(sld)
        bigram_anomaly = cls.calculate_bigram_perplexity(sld)
        vowel_ratio = cls.calculate_vowel_ratio(sld)
        digit_ratio = cls.calculate_digit_ratio(sld)
        max_consonants = cls.max_consecutive_consonants(sld)
        sld_len = len(sld)

        # 2. Heurística ponderada de puntuación DGA
        score = 0.0

        # Contribución por anomalía de n-gramas (peso 35%)
        score += bigram_anomaly * 0.35

        # Contribución por entropía alta (peso 25%)
        # Típicamente entropía > 3.4 en SLDs medianos indica aleatoriedad
        if entropy >= 3.6:
            score += 0.25
        elif entropy >= 3.2:
            score += 0.15

        # Contribución por ratio de vocales anómalo (peso 20%)
        # Palabras normales tienen 0.25 a 0.50 de vocales
        if vowel_ratio < 0.15 or vowel_ratio > 0.65:
            score += 0.20
        elif vowel_ratio < 0.22:
            score += 0.10

        # Contribución por consonantes consecutivas (peso 10%)
        if max_consonants >= 5:
            score += 0.15
        elif max_consonants >= 4:
            score += 0.08

        # Contribución por longitud excesiva y dígitos (peso 10%)
        if sld_len >= 16 and (digit_ratio > 0.15 or bigram_anomaly > 0.6):
            score += 0.15
        elif sld_len >= 20:
            score += 0.10

        dga_score = round(min(1.0, max(0.0, score)), 4)
        is_dga = dga_score >= 0.60

        # 3. Clasificación heurística de familia
        family_guess = None
        if is_dga:
            if sld_len >= 16 and digit_ratio > 0.3:
                family_guess = "Locky / Necurs"
            elif max_consonants >= 5 and sld_len >= 12:
                family_guess = "Conficker"
            elif sld_len >= 20 and entropy >= 3.8:
                family_guess = "Sunburst / Cobalt Strike DNS"
            else:
                family_guess = "Generic Algorithmic DGA"

        return {
            "domain": domain,
            "sld": sld,
            "dga_score": dga_score,
            "is_dga": is_dga,
            "family_guess": family_guess,
            "metrics": {
                "entropy": round(entropy, 3),
                "bigram_anomaly": bigram_anomaly,
                "vowel_ratio": round(vowel_ratio, 3),
                "digit_ratio": round(digit_ratio, 3),
                "max_consecutive_consonants": max_consonants,
                "sld_length": sld_len,
            },
        }


class FastFluxTracker:
    """
    Rastreador de resoluciones DNS continuas para detección de Fast-Flux.
    Identifica dominios maliciosos que rotan múltiples direcciones IP con TTLs muy bajos
    y dispersión a través de múltiples subredes / sistemas autónomos.
    """

    def __init__(self, window_seconds: float = 3600.0):
        self.window_seconds = window_seconds
        # domain -> list of (timestamp, ip, ttl)
        self._history: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)

    def record_resolution(
        self,
        domain: str,
        ips: List[str],
        ttl: int,
        timestamp: Optional[float] = None,
    ):
        """Registra una resolución DNS observada para un dominio."""
        now = timestamp if timestamp is not None else time.time()
        cleaned = domain.lower().strip().rstrip(".")
        for ip in ips:
            self._history[cleaned].append((now, ip, ttl))

        # Poda de eventos fuera de la ventana
        cutoff = now - self.window_seconds
        self._history[cleaned] = [e for e in self._history[cleaned] if e[0] >= cutoff]

    def evaluate_flux(self, domain: str, current_time: Optional[float] = None) -> Dict[str, Any]:
        """
        Evalúa si el comportamiento de resolución de un dominio exhibe características Fast-Flux:
        - Múltiples IPs diferentes (> 4).
        - TTL promedio menor o igual a 300 segundos.
        - Dispersión en más de 2 subredes /24 distintas.
        """
        cleaned = domain.lower().strip().rstrip(".")
        events = self._history.get(cleaned, [])
        if not events:
            return {
                "domain": domain,
                "is_fast_flux": False,
                "unique_ips_count": 0,
                "average_ttl": 0,
                "subnets_count": 0,
            }

        unique_ips = set(e[1] for e in events)
        avg_ttl = sum(e[2] for e in events) / len(events)

        # Extraer subredes /24
        subnets = set()
        for ip in unique_ips:
            parts = ip.split(".")
            if len(parts) == 4:
                subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

        is_fast_flux = len(unique_ips) >= 4 and avg_ttl <= 300 and len(subnets) >= 3

        return {
            "domain": domain,
            "is_fast_flux": is_fast_flux,
            "unique_ips_count": len(unique_ips),
            "average_ttl": round(avg_ttl, 1),
            "subnets_count": len(subnets),
            "sample_ips": list(unique_ips)[:5],
        }
