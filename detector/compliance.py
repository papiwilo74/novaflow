"""
NovaFlow NDR - Corporate Regulatory Compliance & Standards Engine
Mapeo formal de telemetría de red y alertas de intrusión contra los principales
estándares bancarios e internacionales: PCI-DSS v4.0, ISO/IEC 27001:2022, NIST CSF 2.0 y CIS Controls v8.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from detector.models import AlertCategory


@dataclass(frozen=True)
class ComplianceRef:
    standard: str          # e.g., "PCI-DSS v4.0", "ISO/IEC 27001:2022", "NIST CSF 2.0"
    requirement_id: str    # e.g., "Req 11.4", "Control A.8.16", "DE.CM-01"
    title: str             # e.g., "Network Intrusion Detection & Prevention"
    description: str       # Explicación de cómo el sensor satisface el control
    audit_focus: str       # Evidencia requerida para auditorías


# Catálogo canónico de cumplimiento por categoría de alerta
COMPLIANCE_MAPPING: Dict[AlertCategory, List[ComplianceRef]] = {
    AlertCategory.PORT_SCAN: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Detección y Monitoreo de Intrusiones de Red",
            description="Inspección continua de tráfico en el perímetro y zonas CDE para detectar técnicas de reconocimiento hostil.",
            audit_focus="Registros de barridos de puertos L4 y alertas forenses correlacionadas en tiempo real.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.16",
            title="Monitoreo de Actividades (Monitoring Activities)",
            description="Supervisión de redes y sistemas para identificar comportamientos anómalos o intentos de acceso no autorizados.",
            audit_focus="Métricas de escaneo de puertos y tiempos de respuesta de detección.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01",
            title="Monitoreo Continuo de Red (Network Monitoring)",
            description="La red se monitorea continuamente para descubrir eventos potenciales de ciberseguridad.",
            audit_focus="Alertas de reconocimiento L4 clasificadas con severidad y confianza estadística.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.1",
            title="Centralize Network Alerting",
            description="Centralización y correlación de alertas de eventos de red e intrusiones.",
            audit_focus="Ingesta de flujos NetFlow y notificación inmediata en SIEM / SOC.",
        ),
    ],
    AlertCategory.SYN_FLOOD: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Detección de Ataques de Denegación de Servicio (DoS)",
            description="Monitoreo de tráfico para detectar y alertar anomalías volumétricas y saturación de servicios críticos.",
            audit_focus="Detección de ráfagas SYN y evidencia de IP spoofing.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.20",
            title="Seguridad de Redes (Network Security)",
            description="Protección de servicios de red contra sobrecargas maliciosas y saturación del kernel.",
            audit_focus="Monitoreo de tasa de conexiones incompletas y umbrales de alerta.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.AE-02",
            title="Análisis de Eventos Adversos (Adverse Event Analysis)",
            description="Análisis de eventos anómalos detectados para determinar el método y objetivo del ataque.",
            audit_focus="Telemetría de flujos SYN/s y servicios impactados.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.2",
            title="Deploy a Network Intrusion Detection System",
            description="Despliegue de sistemas de detección de intrusión basados en red en puntos clave.",
            audit_focus="Supervisión continua en socket UDP sin muestreo destructivo.",
        ),
    ],
    AlertCategory.EXFILTRATION: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 10.4.1 / 11.4",
            title="Inspección de Fuga de Datos y Tráfico de Egreso",
            description="Monitoreo y detección de transferencias volumétricas anómalas desde hosts con datos sensibles hacia el exterior.",
            audit_focus="Trazabilidad de volumen en MB transferido a IPs externas no autorizadas.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.23",
            title="Filtrado Web y Fuga de Información (Information Leakage Prevention)",
            description="Controles defensivos para prevenir y detectar la transmisión de datos hacia destinos externos no autorizados.",
            audit_focus="Historial de sesiones masivas de egreso y lista blanca corporativa.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01 / PR.DS-05",
            title="Protección contra Fuga de Datos (Data Leakage Protection)",
            description="Monitoreo de tráfico saliente para detectar exfiltración de activos de información.",
            audit_focus="Alertas de anomalías volumétricas con atributos forenses (IP, bytes, puertos).",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.3",
            title="Deploy Network-Based Anti-Malware / Exfil Defenses",
            description="Supervisión activa del tráfico de red para prevenir y detectar exfiltración.",
            audit_focus="Reglas heurísticas de ancho de banda por ventana deslizante.",
        ),
    ],
    AlertCategory.DNS_TUNNEL: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Detección de Canales Encubiertos y Protocolos Anómalos",
            description="Identificación de abuso de protocolos permitidos (DNS/UDP 53) para tráfico no autorizado o exfiltración.",
            audit_focus="Métricas de tamaño de paquete DNS inflado y ratios anómalos de bytes.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.23",
            title="Prevención de Canales de Fuga Ocultos",
            description="Detección de técnicas de tunneling que intentan eludir controles perimetrales tradicionales.",
            audit_focus="Inspección de consultas a resolvers no autorizados.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01",
            title="Supervisión de Protocolos de Capa de Aplicación",
            description="Detección de tráfico anómalo en puertos estándar de servicios de infraestructura.",
            audit_focus="Alertas de tunneling DNS con confianza superior al 85%.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.3",
            title="Network Protocol Anomaly Monitoring",
            description="Inspección de tráfico DNS para prevenir canales de mando encubiertos.",
            audit_focus="Filtrado contra servidores autorizados y detección de Iodine/dnscat.",
        ),
    ],
    AlertCategory.MALICIOUS_C2: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Detección de Conexiones a Infraestructura Hostil Externa",
            description="Cotejo en tiempo real de tráfico entrante y saliente contra listas de indicadores de compromiso (IoC).",
            audit_focus="Identificación de conexiones directas con servidores de mando y control (C2).",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.16 / A.8.20",
            title="Monitoreo de Amenazas Externas e IoCs",
            description="Detección y bloqueo oportuno de comunicaciones con actores de amenaza conocidos (APT / Ransomware).",
            audit_focus="Matching O(1) e intercepción de subredes CIDR maliciosas.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01 / RS.AN-01",
            title="Identificación de Amenazas Dirigidas",
            description="Detección de canales de comunicación maliciosos salientes asociados a ciberataques dirigidos.",
            audit_focus="Alertas de severidad CRITICAL con familia de malware y actor atribuido.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.1",
            title="Centralize Threat Intelligence Matching",
            description="Correlación continua de flujos contra feeds de reputación de amenazas.",
            audit_focus="Cotejo de IPs de Cobalt Strike, Mirai y botnets activas.",
        ),
    ],
    AlertCategory.ANOMALY_ML: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 10.4.1",
            title="Análisis Estadístico y Comportamental de Línea Base",
            description="Uso de modelos analíticos para detectar desviaciones estadísticas del comportamiento normal de red.",
            audit_focus="Atribución de características y desvíos sigma del tráfico.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.16",
            title="Detección de Comportamientos No Basales",
            description="Establecimiento de líneas base de tráfico y detección de anomalías sutiles.",
            audit_focus="Modelos Isolation Forest y aprendizaje incremental en línea.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.AE-02",
            title="Detección de Anomalías no Tipificadas",
            description="Identificación de patrones que no encajan en reglas deterministas mediante ML explicable.",
            audit_focus="Puntuación de anomalía (score) y explicabilidad dimensional.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.2",
            title="Behavioral Network Anomaly Detection",
            description="Implementación de mecanismos de detección comportamental avanzada.",
            audit_focus="Historial de entrenamiento basal y umbrales de contaminación.",
        ),
    ],
    AlertCategory.C2_BEACONING: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Inspección de Balizamiento C2 y Tráfico Encubierto",
            description="Supervisión continua para detectar canales encubiertos de balizamiento C2 basados en periodicidad.",
            audit_focus="Registros de análisis de jitter, coeficiente de variación y marcas de tiempo de comunicación recurrente.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.16",
            title="Monitoreo de Actividades Anómalas (Beaconing)",
            description="Detección de patrones persistentes de comunicación no autorizada generados por malware residente.",
            audit_focus="Evidencia estadística de frecuencias de balizamiento periódico hacia hosts externos.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01",
            title="Monitoreo de Red para Canales C2",
            description="La red se monitorea continuamente para descubrir canales de comando y control de baja frecuencia.",
            audit_focus="Alertas de balizamiento con estimación de jitter temporal.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.3",
            title="Deploy Network Intrusion Detection (C2 Beaconing)",
            description="Monitoreo de conexiones periódicas salientes sin interacción de usuario.",
            audit_focus="Bitácoras de telemetría de flujo y detección de regularidad en intervalos de llegada.",
        ),
    ],
    AlertCategory.ATTACK_CAMPAIGN: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 12.10.1",
            title="Respuesta a Incidentes y Campañas de Intrusión Complejas",
            description="Plan documentado y capacidad técnica inmediata de contención ante campañas de compromiso confirmadas.",
            audit_focus="Registros de correlación multi-etapa que demuestren detección integrada de la intrusión.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.5.24",
            title="Planificación y Preparación para la Gestión de Incidentes",
            description="Correlación de eventos de seguridad para evaluar la gravedad de una intrusión en curso.",
            audit_focus="Cadena temporal de eventos correlacionados (Kill Chain) con reporte de impacto.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="RS.AN-01",
            title="Análisis Forense de la Campaña de Ataque",
            description="Investigación y correlación de múltiples vectores para determinar el alcance total del compromiso.",
            audit_focus="Línea de tiempo consolidada de tácticas (Discovery -> C2 -> Exfiltration).",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 17.1",
            title="Designate Personnel to Manage Incident Handling",
            description="Orquestación y escalamiento de incidentes confirmados de alta severidad.",
            audit_focus="Alertas consolidadas con playbooks de mitigación de emergencia asignados.",
        ),
    ],
    AlertCategory.LATERAL_MOVEMENT: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 1.2.1",
            title="Restricción del Tráfico Entre Zonas y Segmentación",
            description="Supervisión de comunicaciones entre hosts internos para prevenir saltos laterales no autorizados hacia el CDE.",
            audit_focus="Detección de intentos de propagación horizontal en puertos administrativos (SMB 445, RDP 3389, WinRM 5985).",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.20",
            title="Seguridad de las Redes y Segregación Interna",
            description="Monitoreo de tráfico interno para aislar vectores de propagación lateral entre estaciones de trabajo.",
            audit_focus="Métricas de conexiones inter-hosts no autorizadas y alertas de aislamiento automático.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="PR.AC-05",
            title="Integridad del Perímetro y Segmentación de Red",
            description="Detección de conexiones anómalas de administración remota entre endpoints de usuarios.",
            audit_focus="Evidencia de aislamiento de endpoints comprometidos mediante playbooks SOAR.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 12.2",
            title="Segment Networks Based on Sensitivity",
            description="Control y alerta de conexiones laterales que violen las políticas de segmentación corporativa.",
            audit_focus="Registro de intentos de movimiento lateral bloqueados y puestos en cuarentena.",
        ),
    ],
    AlertCategory.ANOMALOUS_TLS: [
        ComplianceRef(
            standard="PCI-DSS v4.0",
            requirement_id="Req 11.4.1",
            title="Inspección y Monitoreo de Tráfico Cifrado Anómalo",
            description="Detección de canales encubiertos y comunicaciones sospechosas camufladas en TLS/HTTPS.",
            audit_focus="Métricas SPLT (Sequence of Packet Lengths and Times) sin descifrado de payload.",
        ),
        ComplianceRef(
            standard="ISO/IEC 27001:2022",
            requirement_id="Control A.8.20 / A.8.23",
            title="Seguridad de Canales Cifrados y Prevención de Fugas",
            description="Supervisión continua de sesiones TLS para prevenir canales de mando y exfiltración encubierta.",
            audit_focus="Telemetría de flujo y detección estadística de beaconing sobre HTTPS.",
        ),
        ComplianceRef(
            standard="NIST CSF 2.0",
            requirement_id="DE.CM-01",
            title="Supervisión de Tráfico de Red Cifrado",
            description="Monitoreo de actividad anómala en flujos TLS y puertos no estándar.",
            audit_focus="Alertas de canales cifrados sospechosos correlacionadas con MITRE T1573.",
        ),
        ComplianceRef(
            standard="CIS Controls v8",
            requirement_id="Control 13.3",
            title="Deploy Network Intrusion Detection for Encrypted Flows",
            description="Monitoreo y detección de patrones maliciosos en tráfico cifrado.",
            audit_focus="Detección de balizas y túneles TLS sin romper la privacidad corporativa.",
        ),
    ],
}


def get_compliance_for_category(category: AlertCategory) -> List[Dict[str, str]]:
    """Obtiene los registros de cumplimiento normativo asociados a una categoría."""
    refs = COMPLIANCE_MAPPING.get(category, [])
    return [
        {
            "standard": r.standard,
            "requirement_id": r.requirement_id,
            "title": r.title,
            "description": r.description,
            "audit_focus": r.audit_focus,
        }
        for r in refs
    ]


def get_all_compliance_catalog() -> Dict[str, Any]:
    """Retorna el catálogo completo estructurado por estándar internacional."""
    by_standard: Dict[str, List[Dict[str, Any]]] = {
        "PCI-DSS v4.0": [],
        "ISO/IEC 27001:2022": [],
        "NIST CSF 2.0": [],
        "CIS Controls v8": [],
    }

    for cat, refs in COMPLIANCE_MAPPING.items():
        for r in refs:
            entry = {
                "category": cat.value,
                "requirement_id": r.requirement_id,
                "title": r.title,
                "description": r.description,
                "audit_focus": r.audit_focus,
            }
            if r.standard in by_standard:
                by_standard[r.standard].append(entry)

    return {
        "frameworks_count": len(by_standard),
        "standards": by_standard,
        "total_controls_mapped": sum(len(v) for v in by_standard.values()),
    }
