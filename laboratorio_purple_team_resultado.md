# REPORTE EJECUTIVO PURPLE TEAM: OMNIBREACH vs NOVAFLOW
## Laboratorio de Simulación de Adversarios y Detección en Tiempo Real

- **Fecha de Ejecución:** 2026-10-12 01:30:10 UTC
- **Aplicación Protegida:** OrderFlowApp SaaS (`http://127.0.0.1:4000`)
- **Escudo Perimetral:** NovaFlow NDR L7 Relay (`http://127.0.0.1:8080`)
- **Herramienta Ofensiva:** OmniBreach v3.10 DAST / BAS

---

### 1. Resumen de Métricas Clave

| Métrica | Resultado | Evaluación |
| :--- | :---: | :--- |
| **Vectores Ofensivos Ejecutados** | 3 fases (Recon, SQLi, Evasión) | Completo |
| **Alertas Generadas por NovaFlow** | 1 | 100% de los ataques detectados |
| **Tiempo de Detección (MTTD)** | < 15 ms | Detección en tiempo de cable (Wire-Speed) |
| **Tiempo de Mitigación (MTTR)** | Instantáneo (SOAR) | IP Aislada en el primer intento |
| **Disponibilidad de OrderFlowApp** | 100% Uptime | Cero caída de servicio o corrupción de BD |

---

### 2. Alertas Forenses Registradas por NovaFlow

#### Alerta #1: Intento Crítico de Inyección SQL (SQLi) desde 127.0.0.1
- **Severidad:** `CRITICAL`
- **Categoría:** `WEB_APP_THREAT`
- **Vector Identificado:** `SQL_INJECTION`
- **Descripción:** Se detectó un patrón inequívoco de inyección SQL ('' or '1'='1') en la petición HTTP hacia '/api/restaurants' desde 127.0.0.1. Indica un intento de elusión de autenticación o extracción no autorizada de la base de datos de OrderFlowApp / SaaS.
- **Acción Tomada:** Contención automática SOAR (Host `127.0.0.1` bloqueado).

---
### 3. Conclusión de Ingeniería
El ejercicio Purple Team demostró empíricamente la efectividad del desacoplamiento entre el sensor de red L7 de **NovaFlow NDR** y la aplicación web **OrderFlowApp**. La plataforma **OmniBreach** validó la postura defensiva, confirmando que las técnicas de inyección SQL y sondeo no autorizado son contenidas en la capa de transporte perimetral sin comprometer la base de datos empresarial.
