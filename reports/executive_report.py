"""
NovaFlow NDR - Executive & C-Level Audit Reporting Engine
Genera reportes de ciberseguridad corporativos de alto nivel para CISOs,
Juntas Directivas y Auditores de Cumplimiento (PCI-DSS v4.0, ISO 27001:2022, NIST CSF 2.0).
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from detector.compliance import COMPLIANCE_MAPPING, ComplianceRef
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class ExecutiveReportGenerator:
    """Generador de auditorías e informes ejecutivos de ciberseguridad."""

    @classmethod
    def calculate_risk_scores(cls, alerts: List[SecurityAlert]) -> Dict[str, Any]:
        """
        Calcula la puntuación de riesgo corporativo (0 a 100) y el estado de salud de la red.
        - Risk Score: 0 = Red Segura, 100 = Riesgo Crítico Inminente.
        - Security Posture: 100% = Máxima postura, 0% = Comprometida.
        """
        weights = {
            AlertSeverity.CRITICAL: 25.0,
            AlertSeverity.HIGH: 12.0,
            AlertSeverity.MEDIUM: 4.0,
            AlertSeverity.LOW: 1.0,
        }

        # Sumar puntos de penalización solo de alertas activas o bajo investigación
        active_alerts = [a for a in alerts if a.status in ("NEW", "INVESTIGATING")]
        raw_penalty = sum(weights.get(a.severity, 2.0) for a in active_alerts)

        # Escalar riesgo a 0-100 con saturación logarítmica / lineal acotada
        risk_score = min(100.0, round(raw_penalty, 1))
        posture_score = max(0.0, round(100.0 - risk_score, 1))

        has_critical = any(a.severity == AlertSeverity.CRITICAL for a in active_alerts)
        if risk_score >= 60.0 or has_critical:
            if risk_score >= 60.0:
                posture_status = "CRITICAL_RISK"
                posture_label = "Riesgo Crítico - Requiere Contención Inmediata"
                status_color = "#ef4444"
            else:
                posture_status = "ELEVATED_RISK"
                posture_label = "Riesgo Elevado - Amenazas Críticas Detectadas"
                status_color = "#f97316"
        elif risk_score >= 25.0:
            posture_status = "ELEVATED_RISK"
            posture_label = "Riesgo Elevado - Exposición Activa"
            status_color = "#f97316"
        elif risk_score >= 10.0:
            posture_status = "MODERATE_RISK"
            posture_label = "Riesgo Moderado - Monitoreo Activo"
            status_color = "#eab308"
        else:
            posture_status = "HEALTHY"
            posture_label = "Seguro / Operación Normal"
            status_color = "#10b981"

        return {
            "risk_score": risk_score,
            "posture_score": posture_score,
            "status": posture_status,
            "label": posture_label,
            "status_color": status_color,
            "active_incidents_count": len(active_alerts),
            "total_incidents_count": len(alerts),
        }

    @classmethod
    def generate_report_data(
        cls,
        alerts: List[SecurityAlert],
        recent_flows: Optional[List[Dict[str, Any]]] = None,
        tenant_id: str = "*",
    ) -> Dict[str, Any]:
        """Genera el conjunto de datos estructurado para el reporte ejecutivo."""
        now = datetime.now(timezone.utc)
        flows = recent_flows or []

        # Métricas de riesgo
        risk = cls.calculate_risk_scores(alerts)

        # Desglose de severidad
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_counts = {}
        for a in alerts:
            sev_counts[a.severity.value] = sev_counts.get(a.severity.value, 0) + 1
            cat_counts[a.category.value] = cat_counts.get(a.category.value, 0) + 1

        # Tráfico de red
        total_bytes = sum(f.get("bytes", 0) for f in flows)
        total_packets = sum(f.get("packets", 0) for f in flows)

        # Postura de Cumplimiento Normativo
        compliance_eval = {
            "pci_dss": {
                "name": "PCI-DSS v4.0",
                "status": "NON_COMPLIANT" if (sev_counts["CRITICAL"] + sev_counts["HIGH"]) > 0 else "COMPLIANT",
                "controls": ["Req 10.4 (Log Retention)", "Req 11.4 (Intrusion Detection/NDR)"],
                "active_breaches": [a.title for a in alerts if a.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)],
            },
            "iso_27001": {
                "name": "ISO/IEC 27001:2022",
                "status": "CONFORMING" if sev_counts["CRITICAL"] == 0 else "ACTION_REQUIRED",
                "controls": ["Control A.8.16 (Network Activity)", "Control A.8.20 (Network Security)", "Control A.8.23 (Web/Exfil Filtering)"],
            },
            "nist_csf": {
                "name": "NIST CSF 2.0",
                "status": "ACTIVE_MONITORING",
                "functions": ["DE.CM-01 (Network Monitoring)", "RS.AN-01 (Incident Analysis)"],
            },
        }

        # Resumen ejecutivo
        if risk["risk_score"] >= 40:
            c_summary = (
                f"Durante el periodo auditado, el motor NovaFlow NDR identificó {len(alerts)} anomalías de tráfico de red, "
                f"de las cuales {sev_counts['CRITICAL']} son críticas y {sev_counts['HIGH']} de alta severidad. "
                "Se evidencia actividad hostil que compromete los controles perimetrales y requiere activación del playbook SOAR."
            )
        else:
            c_summary = (
                f"La infraestructura de red presenta una postura de seguridad sólida con una puntuación de {risk['posture_score']}/100. "
                f"Se monitorearon {len(flows)} flujos NetFlow con {len(alerts)} eventos contenidos o de bajo impacto."
            )

        # Hallazgos priorizados
        prioritized_findings = []
        for a in alerts[:15]:
            mitre_id = a.mitre.get("technique_id", "N/A") if isinstance(a.mitre, dict) else "N/A"
            prioritized_findings.append({
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity.value,
                "category": a.category.value,
                "title": a.title,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "confidence": a.confidence,
                "mitre_technique": mitre_id,
                "status": a.status,
                "evidence_pcap_endpoint": f"/api/v1/alerts/{a.alert_id}/pcap",
                "mitigation_playbook_endpoint": f"/api/v1/alerts/{a.alert_id}/playbook",
            })

        return {
            "report_title": "NovaFlow NDR - Reporte Ejecutivo de Seguridad & Auditoría de Cumplimiento",
            "organization": "NovaSec Technologies & Enterprise SOC",
            "generated_at": now.isoformat(),
            "tenant_id": tenant_id,
            "executive_summary": c_summary,
            "risk_assessment": risk,
            "telemetry_stats": {
                "total_flows": len(flows),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "total_mb": round(total_bytes / (1024 * 1024), 2),
            },
            "severity_breakdown": sev_counts,
            "category_breakdown": cat_counts,
            "compliance_evaluation": compliance_eval,
            "findings": prioritized_findings,
        }

    @classmethod
    def generate_html_report(
        cls,
        alerts: List[SecurityAlert],
        recent_flows: Optional[List[Dict[str, Any]]] = None,
        tenant_id: str = "*",
    ) -> str:
        """Renderiza un informe HTML/CSS elegante, moderno e imprimible."""
        data = cls.generate_report_data(alerts, recent_flows, tenant_id)
        risk = data["risk_assessment"]
        stats = data["telemetry_stats"]
        comp = data["compliance_evaluation"]

        # Generar filas de tabla de hallazgos
        findings_rows = []
        for f in data["findings"]:
            sev_color = {
                "CRITICAL": "background:#fee2e2; color:#991b1b; border:1px solid #f87171;",
                "HIGH": "background:#ffedd5; color:#9a3412; border:1px solid #fb923c;",
                "MEDIUM": "background:#fef3c7; color:#92400e; border:1px solid #fcd34d;",
                "LOW": "background:#f1f5f9; color:#334155; border:1px solid #cbd5e1;",
            }.get(f["severity"], "background:#f1f5f9; color:#334155;")

            findings_rows.append(f"""
            <tr>
              <td style="padding:10px 12px; font-family:monospace; font-size:11px; color:#64748b;">{f['timestamp'][:19].replace('T', ' ')}</td>
              <td style="padding:10px 12px;"><span style="display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:700; font-family:monospace; {sev_color}">{f['severity']}</span></td>
              <td style="padding:10px 12px; font-size:12px; font-weight:600; color:#0f172a;">{f['title']}<br><span style="font-size:11px; font-family:monospace; color:#64748b;">MITRE: {f['mitre_technique']} &bull; Cat: {f['category']}</span></td>
              <td style="padding:10px 12px; font-family:monospace; font-size:11px; color:#1e293b;">{f['src_ip']} &rarr; {f['dst_ip']}</td>
              <td style="padding:10px 12px; font-family:monospace; font-size:11px; font-weight:700; color:#059669;">{int(f['confidence'] * 100)}%</td>
              <td style="padding:10px 12px; font-size:11px; font-family:monospace;"><span style="padding:2px 6px; background:#f1f5f9; border-radius:4px;">{f['status']}</span></td>
              <td style="padding:10px 12px; text-align:right;">
                <a href="{f['evidence_pcap_endpoint']}" style="display:inline-block; padding:4px 8px; font-size:11px; font-family:sans-serif; background:#2563eb; color:#fff; text-decoration:none; border-radius:4px;">PCAP</a>
              </td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte Ejecutivo de Seguridad - NovaFlow NDR</title>
  <style>
    @page {{ size: A4; margin: 15mm; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      color: #1e293b;
      background: #f8fafc;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{
      max-width: 1000px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .brand {{
      font-size: 24px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }}
    .brand span {{ color: #2563eb; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      font-family: monospace;
    }}
    .grid-cards {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 28px;
    }}
    .card {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 16px;
      border-radius: 8px;
    }}
    .card-title {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 6px;
    }}
    .card-value {{
      font-size: 26px;
      font-weight: 800;
      color: #0f172a;
      font-family: monospace;
    }}
    .section-title {{
      font-size: 16px;
      font-weight: 700;
      color: #0f172a;
      border-left: 4px solid #2563eb;
      padding-left: 10px;
      margin: 28px 0 14px 0;
    }}
    .summary-box {{
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      padding: 18px;
      font-size: 13px;
      color: #1e3a8a;
      margin-bottom: 24px;
    }}
    .compliance-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }}
    .comp-box {{
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px;
      background: #ffffff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 12px;
    }}
    th {{
      background: #f1f5f9;
      color: #475569;
      text-align: left;
      padding: 10px 12px;
      font-size: 11px;
      font-family: monospace;
      text-transform: uppercase;
      border-bottom: 1px solid #cbd5e1;
    }}
    tr:nth-child(even) {{ background: #f8fafc; }}
    tr:hover {{ background: #f1f5f9; }}
    .footer {{
      margin-top: 40px;
      padding-top: 16px;
      border-top: 1px solid #e2e8f0;
      font-size: 11px;
      color: #94a3b8;
      display: flex;
      justify-content: space-between;
    }}
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .container {{ box-shadow: none; padding: 0; }}
      .no-print {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="no-print" style="margin-bottom: 16px; text-align: right;">
      <button onclick="window.print()" style="background:#2563eb; color:#fff; border:none; padding:8px 18px; border-radius:6px; font-weight:600; font-size:13px; cursor:pointer;">🖨️ Imprimir / Guardar en PDF</button>
    </div>

    <!-- HEADER -->
    <div class="header">
      <div>
        <div class="brand">NOVAFLOW <span>NDR</span></div>
        <div style="font-size:12px; color:#64748b;">Enterprise Network Detection & Response &bull; Auditoría C-Level</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:12px; font-family:monospace; color:#475569;">Fecha: {data['generated_at'][:10]}</div>
        <div style="font-size:11px; color:#94a3b8;">Tenant: {data['tenant_id']}</div>
      </div>
    </div>

    <!-- SUMMARY -->
    <div class="summary-box">
      <strong>Resumen Ejecutivo para la Dirección:</strong><br>
      {data['executive_summary']}
    </div>

    <!-- KPI CARDS -->
    <div class="grid-cards">
      <div class="card" style="border-top: 3px solid {risk['status_color']};">
        <div class="card-title">Corporate Risk Score</div>
        <div class="card-value" style="color:{risk['status_color']};">{risk['risk_score']}<span style="font-size:14px; color:#64748b;">/100</span></div>
        <div style="font-size:11px; font-weight:600; color:{risk['status_color']};">{risk['label']}</div>
      </div>

      <div class="card" style="border-top: 3px solid #3b82f6;">
        <div class="card-title">Security Posture</div>
        <div class="card-value" style="color:#2563eb;">{risk['posture_score']}%</div>
        <div style="font-size:11px; color:#64748b;">Eficacia de Contención</div>
      </div>

      <div class="card" style="border-top: 3px solid #f59e0b;">
        <div class="card-title">Incidentes Activos</div>
        <div class="card-value">{risk['active_incidents_count']}</div>
        <div style="font-size:11px; color:#64748b;">De {risk['total_incidents_count']} registrados</div>
      </div>

      <div class="card" style="border-top: 3px solid #10b981;">
        <div class="card-title">Telemetría L3/L4</div>
        <div class="card-value">{stats['total_mb']}<span style="font-size:12px; color:#64748b;"> MB</span></div>
        <div style="font-size:11px; color:#64748b;">{stats['total_flows']} flujos evaluados</div>
      </div>
    </div>

    <!-- COMPLIANCE EVALUATION -->
    <div class="section-title">Evaluación de Cumplimiento Regulatorio Internacional</div>
    <div class="compliance-grid">
      <div class="comp-box">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="font-size:13px; color:#0f172a;">{comp['pci_dss']['name']}</strong>
          <span class="badge" style="{ 'background:#dcfce7; color:#166534;' if comp['pci_dss']['status']=='COMPLIANT' else 'background:#fee2e2; color:#991b1b;' }">{comp['pci_dss']['status']}</span>
        </div>
        <div style="font-size:11px; color:#64748b; margin-bottom:6px;">Controles Evaluados:</div>
        <ul style="margin:0; padding-left:18px; font-size:11px; color:#334155;">
          {"".join(f"<li>{c}</li>" for c in comp['pci_dss']['controls'])}
        </ul>
      </div>

      <div class="comp-box">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="font-size:13px; color:#0f172a;">{comp['iso_27001']['name']}</strong>
          <span class="badge" style="{ 'background:#dcfce7; color:#166534;' if comp['iso_27001']['status']=='CONFORMING' else 'background:#ffedd5; color:#9a3412;' }">{comp['iso_27001']['status']}</span>
        </div>
        <div style="font-size:11px; color:#64748b; margin-bottom:6px;">Controles Evaluados:</div>
        <ul style="margin:0; padding-left:18px; font-size:11px; color:#334155;">
          {"".join(f"<li>{c}</li>" for c in comp['iso_27001']['controls'])}
        </ul>
      </div>

      <div class="comp-box">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="font-size:13px; color:#0f172a;">{comp['nist_csf']['name']}</strong>
          <span class="badge" style="background:#dbeafe; color:#1e40af;">{comp['nist_csf']['status']}</span>
        </div>
        <div style="font-size:11px; color:#64748b; margin-bottom:6px;">Funciones NIST:</div>
        <ul style="margin:0; padding-left:18px; font-size:11px; color:#334155;">
          {"".join(f"<li>{f}</li>" for f in comp['nist_csf']['functions'])}
        </ul>
      </div>
    </div>

    <!-- FINDINGS TABLE -->
    <div class="section-title">Hallazgos Forenses de Ciberseguridad & Evidencia Pericial</div>
    <table>
      <thead>
        <tr>
          <th>Hora (UTC)</th>
          <th>Severidad</th>
          <th>Incidente & MITRE</th>
          <th>Vector de Tráfico</th>
          <th>Confianza</th>
          <th>Estado</th>
          <th style="text-align:right;">Evidencia</th>
        </tr>
      </thead>
      <tbody>
        {"".join(findings_rows) if findings_rows else '<tr><td colspan="7" style="text-align:center; padding:24px; color:#94a3b8;">No se registraron incidentes en el periodo auditado.</td></tr>'}
      </tbody>
    </table>

    <!-- FOOTER -->
    <div class="footer">
      <div>NovaFlow NDR v1.0.0 &bull; Generado automáticamente para Auditoría de Ciberseguridad</div>
      <div>Confidencial &bull; Cumplimiento PCI-DSS / ISO 27001 / NIST CSF</div>
    </div>
  </div>
</body>
</html>"""
        return html_content
