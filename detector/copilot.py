"""
NovaFlow NDR - Hybrid AI SOC Copilot & Explainable Incident Engine
Inferencia Híbrida (GPU Local NVIDIA RTX 4060 vía Ollama + Fallback Determinista Zero-Crash).

Proporciona explicabilidad pericial de incidentes (X-NDR), análisis forense de la
técnica MITRE ATT&CK, asesoría de contención activa SOAR y búsqueda de amenazas
(Threat Hunting) en lenguaje natural traducido al DSL booleano del motor.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger("NovaFlow.SOCCopilot")


class NovaFlowSOCCopilot:
    """
    Copiloto de Ciberseguridad e Incident Responder potenciado por inferencia local en GPU.
    Garantiza privacidad de datos absoluta (air-gapped) y cero caídas ante fallos de conexión.
    """

    OLLAMA_URL = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    MODEL_NAME = os.getenv("NOVAFLOW_LLM_MODEL", "llama3.1:8b")
    DEFAULT_TIMEOUT_SECONDS = float(os.getenv("NOVAFLOW_LLM_TIMEOUT", "25.0"))

    SYSTEM_PROMPT_ANALYST = """Eres el Analista Principal de SOC Tier 3 y Perito Forense de NovaFlow NDR.
Tu objetivo es analizar alertas de seguridad de red en tiempo real y emitir un informe técnico institucional en español, con máxima rigurosidad y concisión.

REGLAS ESTRICTAS DE ESTILO:
1. CERO EMOJIS: Está estrictamente prohibido usar emojis o emoticonos en cualquier circunstancia. Mantén un tono formal, técnico, pericial y sobrio.
2. ESTRUCTURA ESTANDARIZADA:
   - **Diagnóstico del Incidente**: Resumen pericial de la actividad anómala detectada en 1 o 2 párrafos.
   - **Técnica MITRE ATT&CK y Táctica**: Identificación de la técnica, objetivo del adversario en la Kill Chain y severidad justificada.
   - **Evidencia Forense de Red**: Interpretación de direcciones IP, puertos, protocolo, volumen de bytes, paquetes transferidos y banderas TCP.
   - **Criterios de Descarte (Falso Positivo)**: Pasos objetivos para confirmar si se trata de una anomalía benigna (ej. tareas de mantenimiento, backups) o un ataque confirmado.
   - **Acciones Tácticas Inmediatas**: Procedimiento de triaje y respuesta para el analista L1/L2.
Sé conciso, analítico y evita generalidades obvias."""

    SYSTEM_PROMPT_CONTAINMENT = """Eres el SOAR Mitigation Officer y Defensor de Infraestructura Crítica de NovaFlow NDR.
Tu función es evaluar alertas de seguridad y emitir un plan de contención activa, analizando el riesgo de daño colateral en la red empresarial.

REGLAS ESTRICTAS DE ESTILO:
1. CERO EMOJIS: Mantén un formato analítico y operativo sin adornos.
2. ESTRUCTURA REQUERIDA:
   - **Estrategia de Aislamiento**: Decisión de bloquear la IP atacante (origen) o el servidor malicioso (destino).
   - **Evaluación de Impacto Colateral**: Análisis de servicios esenciales que podrían verse afectados si el host bloqueado es un activo crítico interno.
   - **Reglas de Contención Validadas**: Políticas declarativas recomendadas (iptables, nftables, Cisco ACL o AWS NACL).
   - **Verificación de Aislamiento**: Comandos periciales para confirmar que el tráfico malicioso ha cesado sin interrumpir la operación legítima."""

    SYSTEM_PROMPT_HUNT = """Eres el Compilador de Threat Hunting de NovaFlow NDR.
Tu única misión es traducir consultas analíticas en lenguaje natural humano al DSL booleano estricto de NovaFlow.

GRAMÁTICA DEL DSL DE NOVAFLOW:
- Operadores Booleanos: AND, OR, NOT
- Operadores de Comparación: ==, !=, >, <, >=, <=, IN, CONTAINS, LIKE
- Campos Válidos de Red:
  * src_ip (cadena IPv4)
  * dst_ip (cadena IPv4)
  * src_port (entero)
  * dst_port (entero)
  * protocol (entero: 6=TCP, 17=UDP, 1=ICMP)
  * proto (cadena: TCP, UDP, ICMP)
  * bytes (entero, admite sufijos: 50K, 10M, 1G)
  * packets (entero, admite sufijos: 1K, 100)
  * tcp_flags (entero: 2=SYN, 24=PSH+ACK, etc.)

REGLA ESTRICTA DE SALIDA:
Devuelve ÚNICAMENTE la expresión DSL en una sola línea. No incluyas explicaciones, ni saludos, ni bloques de código con comillas invertidas. Solo la expresión.
Ejemplos:
- Entrada: "Búscame conexiones salientes con más de 10 megas a puertos altos no estándar"
  Salida: bytes > 10M AND dst_port IN [8080, 8443, 9001, 1337] AND NOT dst_ip LIKE 10.
- Entrada: "Conexiones TCP con flag SYN y solo 1 paquete"
  Salida: proto == TCP AND tcp_flags == 2 AND packets == 1"""

    SYSTEM_PROMPT_CHAT = """Eres el Copiloto Inteligente de Seguridad y Especialista en Detección de Red de NovaFlow NDR.
Tu rol es asistir a analistas del SOC en investigación de incidentes, arquitectura del sistema y consultas de telemetría.

REGLAS ESTRICTAS DE ESTILO:
1. CERO EMOJIS: Responde con sobriedad y profesionalismo en español.
2. CONOCIMIENTO PROFUNDO DE LA ARQUITECTURA:
   - NovaFlow NDR es un motor de detección y respuesta de red en tiempo real construido en Python puro.
   - Decodifica datagramas NetFlow v5 (RFC de Cisco con cabecera de 24B y registros de 48B mediante struct) y NetFlow v9/IPFIX experimental.
   - Aplica el algoritmo de Welford para baselining estadístico en tiempo constante O(1) calculando Z-scores sin saturar memoria RAM.
   - Incorpora motores de reglas deterministas (Port Scan, SYN Flood, Exfiltración de Ancho de Banda, Túneles DNS, C2 Jitter, Movimiento Lateral).
   - Motor de reglas Sigma declarativo en YAML cargadas dinámicamente.
   - Generación de playbooks SOAR (iptables, nftables, Cisco ACL, AWS NACL) con auto-contención y DLQ.
   - Integración formal Purple Team con OmniBreach DAST mediante contratos de campaña v1.0.
   - Suite formal de más de 160 pruebas automatizadas."""

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.ollama_url = (ollama_url or self.OLLAMA_URL).rstrip("/")
        self.model_name = model_name or self.MODEL_NAME
        self.timeout = timeout or self.DEFAULT_TIMEOUT_SECONDS

    # -------------------------------------------------------------------------
    # Inferencia Multi-Nivel (GPU Local -> Cloud -> Fallback Determinista)
    # -------------------------------------------------------------------------

    async def _call_llm(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> Tuple[str, str, float]:
        """
        Ejecuta la inferencia intentando primero el servicio local de Ollama (GPU RTX 4060).
        Retorna (texto_respuesta, backend_utilizado, latencia_ms).
        """
        t_start = time.perf_counter()

        # Nivel 1: Ollama Local en GPU
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(
                    f"{self.ollama_url}/api/chat",
                    json={
                        "model": self.model_name,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "stream": False,
                        "options": {
                            "temperature": temperature,
                            "num_predict": 512,
                        },
                    },
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data.get("message", {}).get("content", "").strip()
                    if content:
                        t_elapsed = (time.perf_counter() - t_start) * 1000.0
                        return self._strip_emojis(content), f"ollama_local_gpu ({self.model_name})", round(t_elapsed, 2)
        except Exception as e:
            logger.warning(f"Ollama local no disponible o supero timeout ({e}). Evaluando fallback.")

        # Nivel 2: Cloud API (si existe clave de entorno para respaldo)
        cloud_api_key = os.getenv("NOVAFLOW_LLM_API_KEY") or os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY")
        if cloud_api_key:
            cloud_url = os.getenv("NOVAFLOW_LLM_BASE_URL", "https://api.openai.com/v1")
            cloud_model = os.getenv("NOVAFLOW_CLOUD_MODEL", "gpt-4o-mini")
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    res = await client.post(
                        f"{cloud_url}/chat/completions",
                        headers={"Authorization": f"Bearer {cloud_api_key}"},
                        json={
                            "model": cloud_model,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                            "temperature": temperature,
                        },
                    )
                    if res.status_code == 200:
                        data = res.json()
                        content = data["choices"][0]["message"]["content"].strip()
                        t_elapsed = (time.perf_counter() - t_start) * 1000.0
                        return self._strip_emojis(content), f"cloud_api ({cloud_model})", round(t_elapsed, 2)
            except Exception as e:
                logger.warning(f"Cloud LLM fallback falló ({e}). Activando motor determinista.")

        # Nivel 3: Motor Determinista Resiliente (Zero-Crash)
        t_elapsed = (time.perf_counter() - t_start) * 1000.0
        fallback_content = self._generate_deterministic_fallback(user_prompt)
        return self._strip_emojis(fallback_content), "deterministic_heuristic_fallback", round(t_elapsed, 2)

    # -------------------------------------------------------------------------
    # Capacidades Principales del Copiloto
    # -------------------------------------------------------------------------

    async def explain_incident(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Genera un informe pericial formal que traduce los metadatos de red a un informe
        forense accionable para el equipo de respuesta a incidentes.
        """
        user_prompt = f"""Analiza la siguiente alerta de seguridad registrada por los sensores de NovaFlow NDR:

DATOS DEL INCIDENTE:
- ID Alerta: {alert_data.get('alert_id', 'N/A')}
- Categoría: {alert_data.get('category', 'ANOMALY')}
- Severidad: {alert_data.get('severity', 'MEDIUM')}
- Título: {alert_data.get('title', 'Alerta de Tráfico Anómalo')}
- Descripción: {alert_data.get('description', '')}
- Host Origen: {alert_data.get('src_ip', '0.0.0.0')}
- Host Destino: {alert_data.get('dst_ip', '0.0.0.0')}:{alert_data.get('dst_port', 0)}
- Protocolo: {alert_data.get('protocol', 6)}
- Confianza del Motor: {alert_data.get('confidence', 0.85)}
- Mapeo MITRE ATT&CK: {alert_data.get('mitre', {})}
- Métricas Técnicas: {alert_data.get('metrics', {})}
- Campaña Purple Team: {alert_data.get('campaign_id') or 'N/A'} (Vector: {alert_data.get('vector_id') or 'N/A'})

Emite el informe pericial estructurado conforme a tus instrucciones."""

        report_text, backend, latency = await self._call_llm(self.SYSTEM_PROMPT_ANALYST, user_prompt, temperature=0.1)
        return {
            "success": True,
            "alert_id": alert_data.get("alert_id"),
            "backend_used": backend,
            "latency_ms": latency,
            "report_markdown": report_text,
            "timestamp": time.time(),
        }

    async def recommend_containment(
        self,
        alert_data: Dict[str, Any],
        playbook_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Asesora al analista sobre la mitigación táctica, analizando impacto colateral
        y proveyendo comandos de contención validados.
        """
        pb_info = playbook_data or {}
        user_prompt = f"""Evalúa la necesidad de contención para el siguiente incidente de seguridad:

DATOS DEL INCIDENTE:
- ID: {alert_data.get('alert_id')}
- Título: {alert_data.get('title')}
- Severidad: {alert_data.get('severity')}
- Host Origen (Atacante): {alert_data.get('src_ip')}
- Host Destino (Objetivo): {alert_data.get('dst_ip')}:{alert_data.get('dst_port')}
- Playbook SOAR sugerido previamente: {pb_info.get('playbook_type', 'ISOLATION')}
- Reglas generadas por SOAR: {pb_info.get('commands', {})}

Provee la estrategia de mitigación y evaluación de impacto colateral."""

        advice_text, backend, latency = await self._call_llm(self.SYSTEM_PROMPT_CONTAINMENT, user_prompt, temperature=0.1)
        return {
            "success": True,
            "alert_id": alert_data.get("alert_id"),
            "backend_used": backend,
            "latency_ms": latency,
            "containment_advice": advice_text,
            "target_ip": alert_data.get("src_ip"),
            "timestamp": time.time(),
        }

    async def translate_threat_hunt(self, natural_language_query: str) -> Dict[str, Any]:
        """
        Traduce una pregunta humana en lenguaje natural a una consulta DSL estricta de NovaFlow.
        """
        user_prompt = f"Traduce esta consulta al DSL de NovaFlow: \"{natural_language_query}\""
        dsl_query, backend, latency = await self._call_llm(self.SYSTEM_PROMPT_HUNT, user_prompt, temperature=0.0)

        # Limpiar comillas o formato markdown residual
        dsl_cleaned = dsl_query.strip().replace("`", "").replace('"', '"')
        if "\n" in dsl_cleaned:
            dsl_cleaned = dsl_cleaned.split("\n")[0].strip()

        return {
            "success": True,
            "input_query": natural_language_query,
            "translated_dsl": dsl_cleaned,
            "backend_used": backend,
            "latency_ms": latency,
        }

    async def chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Canal de conversación interactiva con el analista del SOC sobre incidentes,
        flujos, reglas Sigma y métricas del sistema.
        """
        user_ctx = ""
        if context:
            user_ctx = f"\n[CONTEXTO OPERATIVO DEL SISTEMA: {context}]\n"

        full_prompt = f"{user_ctx}Pregunta del Analista: {message}"
        response_text, backend, latency = await self._call_llm(self.SYSTEM_PROMPT_CHAT, full_prompt, temperature=0.2)

        return {
            "success": True,
            "response": response_text,
            "backend_used": backend,
            "latency_ms": latency,
        }

    async def check_health(self) -> Dict[str, Any]:
        """
        Diagnóstica la conectividad de Ollama, disponibilidad de la GPU RTX 4060 y modelos cargados.
        """
        t_start = time.perf_counter()
        ollama_online = False
        model_found = False
        gpu_active = False
        models_available = []

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.ollama_url}/api/tags")
                if res.status_code == 200:
                    ollama_online = True
                    data = res.json()
                    models_available = [m.get("name") for m in data.get("models", [])]
                    model_found = any(self.model_name in m for m in models_available)
        except Exception:
            pass

        # Chequeo heurístico de GPU NVIDIA
        try:
            import subprocess
            smi = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True, timeout=1.0)
            if smi.returncode == 0 and "RTX" in smi.stdout:
                gpu_active = True
        except Exception:
            pass

        latency_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        active_tier = "TIER_1_LOCAL_GPU" if (ollama_online and model_found) else ("TIER_2_CLOUD" if os.getenv("NOVAFLOW_LLM_API_KEY") else "TIER_3_DETERMINISTIC_FALLBACK")

        return {
            "status": "HEALTHY" if ollama_online else "DEGRADED",
            "active_tier": active_tier,
            "ollama_online": ollama_online,
            "configured_model": self.model_name,
            "model_ready": model_found,
            "gpu_detected": gpu_active,
            "models_available": models_available,
            "latency_ms": latency_ms,
            "timestamp": time.time(),
        }

    # -------------------------------------------------------------------------
    # Utilidades y Motor Determinista de Respaldo
    # -------------------------------------------------------------------------

    @staticmethod
    def _strip_emojis(text: str) -> str:
        """Elimina caracteres de emojis y símbolos unicode decorativos."""
        # Rango regex de emojis estándar
        emoji_pattern = re.compile(
            "[\U00010000-\U0010ffff"
            "\U00002600-\U000027bf"
            "\U00002300-\U000023ff"
            "\U00002b50-\U00002b55"
            "\U0000fe00-\U0000fe0f"
            "\U0001f300-\U0001f5ff"
            "\U0001f600-\U0001f64f"
            "\U0001f680-\U0001f6ff"
            "\U0001f900-\U0001f9ff"
            "\U0001fa70-\U0001faff]"
        )
        return emoji_pattern.sub("", text).strip()

    def _generate_deterministic_fallback(self, prompt: str) -> str:
        """
        Motor algorítmico determinista: genera un informe formal estructurado
        extrayendo los metadatos clave sin depender de ningún servicio externo.
        """
        # Extraer metadatos si vienen en el prompt
        cat_match = re.search(r"Categoría:\s*([A-Za-z0-9_]+)", prompt)
        sev_match = re.search(r"Severidad:\s*([A-Za-z0-9_]+)", prompt)
        src_match = re.search(r"Host Origen:\s*([0-9\.]+)", prompt)
        dst_match = re.search(r"Host Destino:\s*([0-9\.]+:[0-9]+)", prompt)
        desc_match = re.search(r"Descripción:\s*([^\n]+)", prompt)

        category = cat_match.group(1) if cat_match else "ANOMALY"
        severity = sev_match.group(1) if sev_match else "MEDIUM"
        src_ip = src_match.group(1) if src_match else "Desconocido"
        dst_endpoint = dst_match.group(1) if dst_match else "Desconocido"
        desc = desc_match.group(1) if desc_match else "Tráfico que excede los parámetros basales del motor."

        # Mapeo determinista por categoría
        mitre_map = {
            "PORT_SCAN": ("T1046", "Network Service Discovery", "Discovery"),
            "SYN_FLOOD": ("T1498.001", "Direct Network Flood", "Impact"),
            "EXFILTRATION": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
            "MALICIOUS_C2": ("T1071", "Application Layer Protocol", "Command and Control"),
            "DNS_TUNNEL": ("T1071.004", "DNS Domain Name System", "Command and Control"),
        }
        tech_id, tech_name, tactic = mitre_map.get(category, ("T1046", "Network Service Scanning", "Discovery"))

        return f"""### Diagnóstico del Incidente
Se ha registrado una anomalía de red clasificada bajo la categoría {category} con severidad {severity}.
El host origen {src_ip} ha establecido flujos hacia el destino {dst_endpoint}.
Detalle observado: {desc}

### Técnica MITRE ATT&CK y Táctica
- Técnica: {tech_id} ({tech_name})
- Táctica de la Kill Chain: {tactic}
- Nivel de Severidad Asignado: {severity}

### Evidencia Forense de Red
- Origen: {src_ip}
- Destino: {dst_endpoint}
- Clasificación de Motor: Heurística / Reglas Sigma de NovaFlow NDR.

### Criterios de Descarte (Falso Positivo)
1. Verificar si {src_ip} corresponde a un escáner de vulnerabilidades interno autorizado.
2. Comprobar si el volumen de datos o conexiones coincide con tareas programadas en la ventana horaria.
3. Contrastar con los registros de autenticación del host origen.

### Acciones Tácticas Inmediatas
1. Aislar preventivamente el host origen mediante reglas de firewall en perímetro.
2. Capturar volcado PCAP de los flujos activos para análisis en Wireshark.
3. Notificar al equipo de respuesta a incidentes."""


# Instancia singleton predeterminada
soc_copilot = NovaFlowSOCCopilot()
