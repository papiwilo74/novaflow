# 🛡️ Reporte de Evaluación Experimental Purple Team (OmniBreach x NovaFlow NDR)

- **ID de Benchmark:** `bench_b5203996`
- **ID de Campaña:** `camp_20260924_274600`
- **Fecha de Ejecución:** `2026-09-24T03:11:45.101275+00:00`
- **Flujos Totales Evaluados:** `1,080`
- **Flujos de Fondo (Ruido Benigno):** `1,000`
- **Throughput Sostenido:** `3,442.6 flujos/segundo`

---

## 📊 Matriz de Confusión y Métricas de Rendimiento

| Métrica | Valor Empírico | Definición Formal |
| :--- | :--- | :--- |
| **Verdaderos Positivos (TP)** | `4` | Vectores de ataque ejecutados y detectados exitosamente |
| **Falsos Negativos (FN)** | `0` | Vectores de ataque que eludieron la detección |
| **Falsos Positivos (FP)** | `100` | Falsas alarmas disparadas sobre tráfico normal de fondo |
| **Verdaderos Negativos (TN)** | `900` | Flujos legítimos clasificados correctamente como benignos |
| **Precisión (Precision)** | `3.85%` | $TP / (TP + FP)$ |
| **Sensibilidad (Recall)** | `100.00%` | $TP / (TP + FN)$ |
| **F1-Score** | `7.41%` | Media armónica entre Precisión y Sensibilidad |
| **Exactitud de Severidad** | `100.00%` | Concordancia exacta entre severidad esperada y detectada |

---

## ⏱️ Latencia y Tiempo Medio de Detección (MTTD)

- **MTTD Promedio (Mean Time to Detect):** `2.075 ms`
- **MTTD Mínimo:** `0.260 ms`
- **MTTD Máximo:** `4.524 ms`
- **Tiempo Total de Benchmark:** `0.3137 segundos`

---

## ⚔️ Desglose de Vectores Ofensivos (OmniBreach Red Team vs NovaFlow Blue Team)

| Vector ID | Nombre del Vector | MITRE ATT&CK | Detector Esperado | Severidad Esperada | Severidad Detectada | MTTD (ms) | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `OB-RECON-01` | OmniBreach Port & Service Scan | `T1046` | `PortScanDetector` | `MEDIUM` | `MEDIUM` | 3.21 ms | **✅ DETECTADO** |
| `OB-EXFIL-02` | OmniBreach SSRF & Data Exfiltration | `T1048` | `BandwidthExfiltrationDetector` | `HIGH` | `HIGH` | 0.26 ms | **✅ DETECTADO** |
| `OB-DOS-03` | OmniBreach SYN Flood Stress Test | `T1498` | `SynFloodDetector` | `HIGH` | `HIGH` | 4.52 ms | **✅ DETECTADO** |
| `OB-C2-04` | OmniBreach Reverse Shell Beaconing | `T1071` | `ThreatIntelMatcher` | `CRITICAL` | `CRITICAL` | 0.30 ms | **✅ DETECTADO** |

---

## 🔬 Metodología de Validación Científica

1. **Inyección de Ruido Benigno Controlado:** Se simula tráfico empresarial verosímil (navegación HTTPS hacia CDNs, consultas recursivas DNS, transacciones PostgreSQL internas y tráfico API microservicios).
2. **Medición No Asumida:** El tiempo de detección (MTTD) es cronometrado en hardware local mediante `time.perf_counter()` de alta resolución (precisión sub-microsegundo).
3. **Validación de Severidad y MITRE:** No basta con que el sistema emita una alerta genérica; se evalúa la coincidencia con la técnica MITRE y el nivel de riesgo estipulado en la matriz de amenazas.
