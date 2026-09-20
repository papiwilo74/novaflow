"""
NovaFlow NDR - Shannon Information Entropy & DGA Detection Engine
Calcula la entropía de Shannon sobre cadenas de texto, nombres de dominio y datagramas de red
para identificar algoritmos de generación de dominios (DGA) y túneles encubiertos de datos.
"""

import collections
import math
from typing import Any, Dict, Union


def calculate_shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calcula la entropía de la información de Shannon H(X):
      H(X) = - sum( P(x_i) * log2( P(x_i) ) )

    Escala típica para cadenas de texto:
      - Lenguaje natural (inglés/español): 2.5 <= H <= 3.4
      - Nombres de dominios legítimos: H < 3.5
      - Criptografía / Base64 / Hex / DGA: H > 3.8 (máximo ~4.7 para base64 puro, ~8.0 para bytes uniformes)
    """
    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def evaluate_domain_entropy(domain: str) -> Dict[str, Any]:
    """
    Analiza un nombre de dominio o consulta DNS calculando la entropía de Shannon,
    la proporción de vocales/consonantes y la detección de algoritmos DGA.
    """
    if not domain:
        return {
            "domain": "",
            "subdomain": "",
            "entropy": 0.0,
            "is_dga_candidate": False,
            "classification": "EMPTY",
        }

    clean_domain = domain.lower().strip().rstrip(".")
    labels = clean_domain.split(".")

    # Extraer el subdominio más relevante (generalmente el más largo o de mayor nivel)
    # Por ejemplo en 'a7f9b2c3d4e8.tunnel.c2.io', la carga útil está en 'a7f9b2c3d4e8'
    candidate_label = max(labels[:-2], key=len) if len(labels) > 2 else labels[0]

    entropy = calculate_shannon_entropy(candidate_label)
    label_len = len(candidate_label)

    # Métricas léxicas adicionales
    vowels = set("aeiou")
    digits = set("0123456789")

    vowel_count = sum(1 for c in candidate_label if c in vowels)
    digit_count = sum(1 for c in candidate_label if c in digits)

    vowel_ratio = round(vowel_count / max(1, label_len), 3)
    digit_ratio = round(digit_count / max(1, label_len), 3)

    # Reglas de decisión DGA / Túnel:
    # 1. Entropía alta (H >= 3.85) con longitud suficiente (>= 10 caracteres)
    # 2. Ausencia casi total de vocales (vowel_ratio < 0.15) con entropía moderada-alta
    # 3. Alta proporción de dígitos o formato hexadecimal (digit_ratio > 0.40 y H >= 3.5)
    is_dga = False
    if label_len >= 8:
        if entropy >= 3.85:
            is_dga = True
        elif entropy >= 3.5 and (vowel_ratio < 0.15 or digit_ratio > 0.35):
            is_dga = True
        elif label_len >= 25 and entropy >= 3.4:
            is_dga = True

    if is_dga:
        classification = "HIGH_ENTROPY_DGA"
    elif entropy >= 3.3:
        classification = "MODERATE_ENTROPY"
    else:
        classification = "NATURAL_LANGUAGE"

    return {
        "domain": clean_domain,
        "analyzed_label": candidate_label,
        "label_length": label_len,
        "entropy": entropy,
        "vowel_ratio": vowel_ratio,
        "digit_ratio": digit_ratio,
        "is_dga_candidate": is_dga,
        "classification": classification,
    }
