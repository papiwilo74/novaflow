# 📚 Manual de Estudio Completo: Arquitectura y Lógica de NovaFlow NDR

> **Para importar en NoteBox / Obsidian / Notion**:  
> Esta carpeta contiene la guía modular completa para comprender, estudiar y defender toda la arquitectura técnica, matemática y de ciberseguridad de **NovaFlow NDR**.

---

## 🗺️ Mapa de Módulos de Estudio

| Módulo | Archivo | Temas Principales |
| :---: | :--- | :--- |
| **01** | [`01_ARQUITECTURA_Y_DISENO.md`](./01_ARQUITECTURA_Y_DISENO.md) | Tríada de Visibilidad (EDR vs SIEM vs NDR), pipeline de datos end-to-end, concurrencia asíncrona (`asyncio`), zero-copy ingestion. |
| **02** | [`02_BINARIOS_Y_NETFLOW_INGESTION.md`](./02_BINARIOS_Y_NETFLOW_INGESTION.md) | Formato binario NetFlow v5 (RFC Cisco), NetFlow v9 e IPFIX (RFC 3954/7011), Bi-Flow Session Stitcher, sintetizador PCAP forense sin C. |
| **03** | [`03_MATEMATICAS_Y_ALGORITMOS.md`](./03_MATEMATICAS_Y_ALGORITMOS.md) | Algoritmo de Welford en $O(1)$, Z-score dinámico, Entropía de Shannon para DNS, análisis de Jitter y Coeficiente de Variación ($CV$), Counting Bloom Filter de 8 bits. |
| **04** | [`04_DETECCIONES_Y_KILL_CHAIN.md`](./04_DETECCIONES_Y_KILL_CHAIN.md) | Las 7 heurísticas de ataque L3/L4/L7, MITRE ATT&CK, máquina de estados temporal multietapa (Recon -> C2 -> Exfiltración). |
| **05** | [`05_GRAFOS_PATIENT_ZERO_Y_SOAR.md`](./05_GRAFOS_PATIENT_ZERO_Y_SOAR.md) | Grafo dirigido $G=(V, E)$, algoritmo causal de Patient Zero, cálculo de Blast Radius ponderado con atenuación, orquestador SOAR y playbooks de contención activa. |
| **06** | [`06_INTEROPERABILIDAD_Y_STANDARDS.md`](./06_INTEROPERABILIDAD_Y_STANDARDS.md) | ArcSight CEF:0, Syslog RFC 5424, estándar cloud OCSF v1.1.0, cumplimiento normativo (PCI-DSS, ISO 27001, NIST CSF), sinergia Purple Team con OmniBreach. |
| **07** | [`07_GUIA_DE_DEFENSA_EN_ENTREVISTA.md`](./07_GUIA_DE_DEFENSA_EN_ENTREVISTA.md) | Matriz de 3 Columnas de Madurez, respuestas tácticas a preguntas complejas de reclutadores y CISOs, glosario de términos avanzados. |
| **08** | [`08_ENTERPRISE_SIGMA_HUNTING_BENCHMARK.md`](./08_ENTERPRISE_SIGMA_HUNTING_BENCHMARK.md) | Motor declarativo Sigma (YAML puro), exportación MITRE Navigator v4.5, Threat Hunting DSL (AST booleano), y generador de tráfico NetFlow v5 con benchmark de latencia en µs. |

---

## 🚀 Ruta de Aprendizaje Sugerida (4 Días)

### Día 1: Fundamentos y Flujo de Paquetes
- Leer **Módulo 1** (Arquitectura) y **Módulo 2** (Binarios NetFlow).
- Practicar la explicación del formato binario de NetFlow y por qué `struct.unpack_from` es superior a duplicar strings en memoria.

### Día 2: Matemáticas y Detección
- Leer **Módulo 3** (Algoritmos) y **Módulo 4** (Detecciones y Kill Chain).
- Escribir en una hoja o pizarra la fórmula del Algoritmo de Welford y la Entropía de Shannon para familiarizarse con el cálculo paso a paso.

### Día 3: Grafos, SOAR y Simulación de Entrevista
- Leer **Módulo 5** (Grafos y Blast Radius) y **Módulo 6** (Interoperabilidad / Purple Team).
- Estudiar a fondo el **Módulo 7** (Guía de Defensa en Entrevistas) simulando responder las 4 preguntas difíciles en voz alta.

### Día 4: Capacidades Enterprise y Benchmarking
- Leer **Módulo 8** (Reglas Sigma, Navigator, Hunting DSL y Benchmark).
- Ejecutar el benchmark en consola (`python tools/traffic_gen.py --mode benchmark --flows 2000`) y familiarizarse con las métricas de throughput (4,800+ flujos/s) y latencia (~204 µs).
