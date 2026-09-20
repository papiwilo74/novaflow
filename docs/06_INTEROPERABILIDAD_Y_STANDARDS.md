# 📘 Módulo 6: Interoperabilidad, Cumplimiento y Simulación Purple Team

> **Propósito de esta Nota**: Dominar los formatos estándar de la industria que permiten a NovaFlow comunicarse con SIEMs comerciales (Splunk, Elastic), Data Lakes en la nube (AWS Security Lake, Snowflake), marcos de auditoría bancaria (PCI-DSS) y herramientas ofensivas (OmniBreach).

---

## 1. Exportación a SIEM: ArcSight CEF:0 y Syslog RFC 5424

Ningún producto de seguridad empresarial vive aislado. Debe reportar sus incidentes al SIEM central de la corporación.

### Formato CEF (Common Event Format de Micro Focus / ArcSight):
CEF es el formato estándar aceptado nativamente por Splunk, Elastic SIEM, Sentinel y Wazuh:

```
CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
```

Ejemplo generado por NovaFlow ([`detector/models.py`](file:///C:/Users/villa/.gemini/antigravity/scratch/novaflow-ndr/detector/models.py)):
```text
CEF:0|NovaSec|NovaFlow|1.0.0|MALICIOUS_C2|Conexión con C2 / IP Maliciosa: 198.51.100.77|10|src=10.0.0.15 dst=198.51.100.77 dpt=443 proto=TCP msg=Tráfico detectado hacia Cobalt Strike C2 cs1=NEW cs1Label=IncidentStatus cfp1=0.98 cfp1Label=ConfidenceScore cs2=T1071 cs2Label=MitreTechniqueId cs3=Command and Control cs3Label=MitreTactic
```

### Encapsulamiento en Syslog RFC 5424:
```text
<131>1 2026-09-19T23:15:00.000Z novaflow-ndr novaflow-threat-engine - ID9a8b7c6d [novasec@5424 tenant="default"] CEF:0|...
```
- `<131>`: Cálculo del `PRI = Facility * 8 + Severity` (Facility 16 = Local0, Severity 3 = Error: $16 \times 8 + 3 = 131$).

---

## 2. El Nuevo Estándar Cloud: OCSF v1.1.0

El **Open Cybersecurity Schema Framework (OCSF)** es una iniciativa respaldada por AWS, Splunk, CrowdStrike y Snowflake para unificar todos los esquemas de seguridad del mundo en un JSON estándar.

NovaFlow exporta cada alerta bajo:
- **Category UID 2**: *Findings* (Hallazgos).
- **Class UID 2001**: *Security Finding* (Incidente de Seguridad).
- **Activity ID 1**: *Create* (Nueva alerta).

### Estructura JSON OCSF generada por `alert.to_ocsf()`:
```json
{
  "class_uid": 2001,
  "class_name": "Security Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "severity_id": 5,
  "severity": "CRITICAL",
  "status_id": 1,
  "status": "NEW",
  "finding_info": {
    "uid": "c2-001",
    "title": "Conexión de Comando y Control C2",
    "types": ["MALICIOUS_C2"]
  },
  "attacks": [
    {
      "tactic": { "name": "Command and Control" },
      "technique": { "uid": "T1071", "name": "Application Layer Protocol" }
    }
  ],
  "network_activity": {
    "protocol_name": "TCP",
    "src_endpoint": { "ip": "10.0.0.10" },
    "dst_endpoint": { "ip": "198.51.100.77", "port": 443 }
  },
  "metadata": {
    "version": "1.1.0",
    "product": { "name": "NovaFlow NDR", "vendor_name": "NovaSec" }
  }
}
```

---

## 3. Matriz de Cumplimiento Regulatorio Corporativo

Cuando un auditor de seguridad bancaria o regulador gubernamental inspecciona una empresa, no le interesa la heurística técnica; le interesa saber si el sistema cumple con la ley.

NovaFlow mapea automáticamente cada incidente a 4 marcos normativos ([`detector/compliance.py`](file:///C:/Users/villa/.gemini/antigravity/scratch/novaflow-ndr/detector/compliance.py)):

```
+-----------------------------------------------------------------------------------+
|                        MARCOS DE CUMPLIMIENTO EN NOVAFLOW                         |
+----------------------+--------------------------+---------------------------------+
| Estándar             | Requisito / Control      | Justificación de Auditoría      |
+----------------------+--------------------------+---------------------------------+
| PCI-DSS v4.0         | Req 10.4.1               | Correlación y registro de red   |
| (Tarjetas de Crédito)| Req 11.4.1               | Detección de intrusiones en CDE |
|                      |                          |                                 |
| ISO/IEC 27001:2022   | Control A.8.16           | Monitoreo continuo de red       |
| (Seguridad Global)   | Control A.8.20           | Seguridad y segmentación de red |
|                      | Control A.8.23           | Supervisión de fuga de datos    |
|                      |                          |                                 |
| NIST CSF 2.0         | DE.CM-01                 | Monitoreo de eventos adversos   |
| (Gobierno USA)       | RS.AN-01                 | Análisis de impacto y vector    |
|                      |                          |                                 |
| CIS Controls v8      | Control 13.1 / 13.3      | Detección de intrusiones de red |
+----------------------+--------------------------+---------------------------------+
```

---

## 4. Ejercicio Purple Team: OmniBreach x NovaFlow NDR

La correlación **Purple Team** es la interacción continua entre el equipo ofensivo (*Red Team*) y el equipo defensivo (*Blue Team*):

```
+---------------------------+                      +---------------------------+
|        RED TEAM           |                      |        BLUE TEAM          |
|      (OmniBreach)         |                      |      (NovaFlow NDR)       |
|   DAST / Web Exploits     |                      |  Network Telemetry / L3-L4|
+-------------+-------------+                      +-------------+-------------+
              |                                                  |
              | 1. Simula Vector Ofensivo (p. ej. SSRF / C2)     |
              +------------------------------------------------->|
                                                                 | 2. Detecta Flujos L4
                                                                 | 3. Mapea Técnica MITRE
                                                                 | 4. Emite Log CEF a SIEM
                                                                 | 5. Genera PCAP Forense
                                                                 | 6. Despacha Playbook SOAR
              | 7. Correlación 100% Exitosa                      |
              |<-------------------------------------------------+
```

### La Sinergia Perfecta:
- **OmniBreach** sabe cómo romper la aplicación web (inyecciones SQL, SSRF, bypass de autenticación, reverse shells).
- **NovaFlow NDR** es el testigo imparcial en la red que captura el tráfico del exploit, mide la asimetría de bytes y genera la evidencia legal y técnica de que la intrusión ocurrió y fue mitigada.
