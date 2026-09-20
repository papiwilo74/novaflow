"""
NovaFlow NDR - Heuristic Rule: DNS Tunneling & Abuse Detector
Detecta canales encubiertos y exfiltración a través de paquetes DNS anómalos.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Optional, Set

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.entropy import calculate_shannon_entropy, evaluate_domain_entropy

# Resolvers públicos y corporativos autorizados de uso común
WHITELISTED_RESOLVERS: Set[str] = {
    "1.1.1.1", "1.0.0.1",       # Cloudflare
    "8.8.8.8", "8.8.4.4",       # Google
    "9.9.9.9", "149.112.112.112", # Quad9
    "192.168.1.1", "10.0.0.1",  # Routers locales
}


class DnsTunnelDetector:
    """
    Analiza el ratio de bytes por paquete y la tasa de peticiones en flujos UDP puerto 53.
    Las herramientas de túnel DNS (iodine, dnscat2) generan paquetes saturados y alto volumen constante.
    """

    def __init__(
        self,
        avg_packet_size_threshold: int = 320,  # Bytes promedio por paquete sospechoso
        query_count_threshold: int = 25,       # Peticiones en ventana
        window_seconds: float = 10.0,
        alert_cooldown_seconds: float = 30.0,
    ):
        self.avg_packet_size_threshold = avg_packet_size_threshold
        self.query_count_threshold = query_count_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # (src_ip, dst_ip) -> deque of (timestamp, packets, bytes)
        self._history: Dict[tuple, deque] = defaultdict(deque)
        self._last_alert: Dict[tuple, float] = {}

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        # Solo flujos UDP (17) hacia puerto DNS (53)
        if flow.protocol != 17 or flow.dst_port != 53:
            return None

        # Si va hacia un resolver corporativo de confianza con tamaño normal, descartar
        if flow.dst_ip in WHITELISTED_RESOLVERS and flow.packets > 0:
            avg_size = flow.bytes / flow.packets
            if avg_size < self.avg_packet_size_threshold:
                return None

        avg_bytes_per_pkt = flow.bytes / max(1, flow.packets)
        now = time.time()
        pair_key = (flow.src_ip, flow.dst_ip)
        history = self._history[pair_key]

        while history and (now - history[0][0]) > self.window_seconds:
            history.popleft()

        history.append((now, flow.packets, flow.bytes))

        total_pkts = sum(item[1] for item in history)
        total_bytes = sum(item[2] for item in history)
        overall_avg = total_bytes / max(1, total_pkts)

        is_suspicious_size = avg_bytes_per_pkt >= self.avg_packet_size_threshold
        is_high_volume = total_pkts >= self.query_count_threshold

        if is_suspicious_size or (is_high_volume and overall_avg > 250):
            last_alert = self._last_alert.get(pair_key, 0)
            if (now - last_alert) >= self.alert_cooldown_seconds:
                self._last_alert[pair_key] = now

                # Cálculo dinámico de confianza: base 0.85 + desviación de tamaño + volumen acumulado
                size_bonus = max(0.0, min(0.08, (avg_bytes_per_pkt - self.avg_packet_size_threshold) / 1000.0))
                vol_bonus = max(0.0, min(0.05, (total_pkts - self.query_count_threshold) * 0.002))
                confidence = round(min(0.98, 0.85 + size_bonus + vol_bonus), 2)

                return SecurityAlert(
                    severity=AlertSeverity.HIGH,
                    category=AlertCategory.DNS_TUNNEL,
                    title=f"Posible Túnel DNS encubierto: {flow.src_ip} -> {flow.dst_ip}",
                    description=(
                        f"Tráfico DNS anómalo detectado desde {flow.src_ip} hacia el servidor {flow.dst_ip}:53. "
                        f"Tamaño promedio por paquete: {avg_bytes_per_pkt:.0f} bytes "
                        f"(umbral normal: <180B). Posible exfiltración o C2 sobre UDP/53."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=53,
                    protocol=17,
                    confidence=confidence,
                    metrics={
                        "avg_bytes_per_packet": round(avg_bytes_per_pkt, 1),
                        "packets_in_window": total_pkts,
                        "bytes_in_window": total_bytes,
                        "window_seconds": self.window_seconds,
                    },
                )

        # Si el flujo incluye metadatos de dominio DNS
        domain = getattr(flow, "domain", None)
        if domain:
            return self.analyze_dns_query(flow.src_ip, flow.dst_ip, domain)

        return None

    def analyze_dns_query(self, src_ip: str, dst_ip: str, domain: str) -> Optional[SecurityAlert]:
        """
        Analiza un nombre de dominio o subdominio DNS usando entropía de Shannon y heurística DGA.
        """
        eval_res = evaluate_domain_entropy(domain)
        if eval_res["is_dga_candidate"]:
            entropy_val = eval_res["entropy"]
            confidence = round(min(0.99, 0.85 + max(0.0, (entropy_val - 3.5)) * 0.1), 2)
            return SecurityAlert(
                severity=AlertSeverity.HIGH,
                category=AlertCategory.DNS_TUNNEL,
                title=f"Consulta DNS de Alta Entropía (DGA / Túnel): {domain}",
                description=(
                    f"Se detectó una consulta DNS anómala hacia '{domain}' desde {src_ip}. "
                    f"Entropía de Shannon H={entropy_val:.2f} (Umbral normal: <3.3), "
                    f"longitud del subdominio: {eval_res['label_length']} caracteres. "
                    "Patrón característico de canal encubierto o malware con Domain Generation Algorithm (DGA)."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=53,
                protocol=17,
                confidence=confidence,
                metrics={
                    "domain": domain,
                    "shannon_entropy": entropy_val,
                    "analyzed_subdomain": eval_res["analyzed_label"],
                    "vowel_ratio": eval_res["vowel_ratio"],
                    "digit_ratio": eval_res["digit_ratio"],
                    "classification": eval_res["classification"],
                },
            )
        return None
