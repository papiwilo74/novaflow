# NovaFlow NDR: Network Detection, Telemetry & Anomaly Engine

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-210%20Passing%20(100%25)-brightgreen.svg)]()
[![Pure Python](https://img.shields.io/badge/Dependencies-Zero%20C%20%2F%20Npcap-orange.svg)]()
[![Standards](https://img.shields.io/badge/Standards-NetFlow%20v5%2Fv9%20%7C%20IPFIX%20%7C%20CEF%20%7C%20OCSF%20%7C%20Sigma%20%7C%20MITRE-blueviolet.svg)]()

**NovaFlow NDR** es una plataforma de análisis de telemetría de red y detección de intrusiones a nivel de transporte (L3/L4/L7), construida en Python utilizando primitivas binarias de bajo nivel (`struct`), concurrencia asíncrona (`asyncio`), baselining estadístico en tiempo constante ($O(1)$), correlación defensiva **Purple Team** y un **Copiloto SOC IA Híbrido** con inferencia local en GPU NVIDIA GeForce RTX 4060.

---

## 🏛️ Declaración de Transparencia de Ingeniería

> **Nota para Evaluadores Técnicos y Reclutadores:**  
> Este proyecto nació para comprender a fondo cómo operan los protocolos de red y los sistemas de detección comerciales (*Corelight, Vectra AI, Cisco Stealthwatch*) a nivel de bytes, sin depender de librerías de alto nivel o cajas negras.  
> 
> Para mantener la máxima honestidad y rigor técnico, la arquitectura del proyecto está clasificada en **tres niveles de madurez**:

```
+----------------------------------------------------------------------------------------------------+
|                                MATRIZ DE MADUREZ DE INGENIERÍA                                     |
+-----------------------------------+------------------------------------+---------------------------+
| 🟢 COLUMNA 1: PRODUCTION-READY    | 🟡 COLUMNA 2: WORKING PROTOTYPES   | 🔵 COLUMNA 3: RESEARCH    |
| (Probado en tests, núcleo sólido) | (Funcional, límites documentados)  | (I+D y visión de producto)|
+-----------------------------------+------------------------------------+---------------------------+
| • Parser NetFlow v5 (RFC Cisco)   | • Bi-Flow Session Stitcher         | • Encrypted Traffic (ETA) |
| • Welford Baselining O(1) Z-score | • Entropía Shannon para DNS        | • Grafo de Ataque G=(V,E) |
| • Heurísticas L4 (PortScan, Flood)| • Escritor PCAP forense en memoria | • Patient Zero & Blast Rad|
| • API Gateway FastAPI + WebSockets| • Playbooks SOAR declarativos      | • NetFlow v9 e IPFIX bin  |
| • Exportador SIEM (CEF / Syslog)  | • Auto-clasificación conductual    | • Counting Bloom Filter   |
| • Motor de Reglas Sigma (YAML)    | • MITRE ATT&CK Navigator v4.5      | • Correlación Kill Chain  |
| • Threat Hunting Engine (AST DSL) | • Generador de Tráfico & Benchmark | • Evasiones de Detección  |
| • Cumplimiento PCI-DSS / ISO 27001| • Detección C2 por Jitter / CV     | • Formato Abierto OCSF    |
| • Sonda de Red en Vivo & Hooks    | • Contrato Purple Team & Benchmark |                           |
| • Copiloto SOC IA (RTX 4060)      | • Inferencia Local Ollama Llama3.1 |                           |
+-----------------------------------+------------------------------------+---------------------------+
```

---

### 🟢 1. Núcleo Implementado y Probado (Defendible en Entrevista)
*Código de producción probado exhaustivamente mediante 210 pruebas automatizadas:*

1. **Parser Binario NetFlow v5 (`collector/parser.py`)**:
   - Decodificación exacta según el RFC de Cisco: cabecera fija de 24 bytes (`!HHIIIIBBH`) y registros de 48 bytes (`!4s4s4sHHIIIIHHBBBBHHBBH`).
   - Cero copias innecesarias en el heap mediante `struct.unpack_from`.
   - Recuperación ante datagramas truncados y validación estricta de `sys_uptime` y timestamps Epoch.
2. **Lógica Matemática del Algoritmo de Welford (`detector/profiler.py`)**:
   - Cálculo en pasada única de media móvil $\mu$, varianza acumulada $M_2$ y $Z$-score ($Z \ge 3.5$).
   - Complejidad temporal y espacial $O(1)$: elimina la necesidad de almacenar ventanas gigantes de flujos históricos en memoria RAM.
3. **Detección Determinista L4 (`detector/rules/`)**:
   - *Port Scanning*: Detección de abanico horizontal (*fan-out*) sobre puertos destino en ventanas temporales.
   - *SYN Flood*: Detección de ráfagas SYN anómalas contra un único socket con discriminación de IP Spoofing.
   - *Exfiltración Volumétrica*: Detección por desvío estadístico y umbrales de ancho de banda.
4. **API Gateway & Streaming SOC (`api/`)**:
   - Servidor FastAPI asíncrono, canal WebSockets para telemetría en vivo, autenticación JWT HS256 y RBAC con roles (`ADMIN`, `ANALYST`, `READONLY`).
5. **Interoperabilidad SIEM / SOC**:
   - Exportación nativa a **ArcSight CEF:0** y **Syslog RFC 5424** consumibles directamente por Splunk, Elastic y Wazuh.

---

### 🟡 2. Prototipos Funcionales (Con Limitaciones de Producción Documentadas)
*Lógica probada y funcional en laboratorio, con conocimiento explícito de sus retos en redes corporativas:*

1. **Ensamblado Bi-Flow (`detector/biflow.py`)**:
   - *Implementado:* Ensambla flujos unidireccionales $A \to B$ y $B \to A$ en sesiones bidireccionales calculando ratios de asimetría.
   - *Límite en producción real:* En redes corporativas existe **ruteo asimétrico** (ida por un ISP/router y vuelta por otro). Requiere un bus de eventos distribuido (ej. Apache Kafka) para sincronizar flujos entre múltiples exportadores.
2. **Entropía de Shannon para Detección de DNS Tunneling (`detector/entropy.py`)**:
   - *Implementado:* Cálculo de $H(X) = -\sum p_i \log_2 p_i$ sobre subdominios para detectar canales Iodine/dnscat ($H(X) \ge 3.8$).
   - *Límite en producción real:* CDNs legítimas (Cloudflare, Akamai, CloudFront) utilizan nombres pseudo-aleatorios que disparan falsos positivos sin una lista blanca rigurosa y aprendizaje contextual.
3. **Escritor Forense PCAP en Memoria (`collector/forensics.py`)**:
   - *Implementado:* Genera archivos `.pcap` libpcap válidos con suma criptográfica SHA-256 para peritaje pericial.
   - *Límite en producción real:* NetFlow no contiene la carga útil completa (*full-payload*); el archivo sintetiza tramas L2/L3/L4 a partir de los metadatos de flujo para triaje rápido en Wireshark.
4. **Generador de Playbooks SOAR (`detector/playbooks.py`, `detector/dispatcher.py`)**:
   - *Implementado:* Generación automática de reglas de contención (`iptables`, `nftables`, `Cisco ACL`, `AWS NACL`) y despacho firmado con HMAC-SHA256 y Dead-Letter Queue (DLQ).
   - *Límite en producción real:* En esta fase emite y despacha políticas declarativas a webhooks; en producción se conectaría a runners de ejecución remota (Ansible Automation Platform, Terraform, AWS SSM).

---

### 🔵 3. Investigación, Modelado y Roadmap Futuro (I+D)
*Módulos que exploran la frontera técnica de soluciones NDR modernas (Darktrace, Vectra, Cisco ETA):*

1. **Encrypted Traffic Analysis (ETA / SPLT) (`detector/eta.py`)**:
   - *Concepto:* Inspirado en Cisco ETA, evalúa la secuencia de longitudes y tiempos de paquetes (SPLT) en el puerto 443 sin descifrar el tráfico TLS.
   - *Roadmap:* Entrenar clasificadores supervisados con datasets públicos de malware cifrado (CTU-13, Stratosphere IPS).
2. **Grafo de Ataque, Patient Zero y Blast Radius (`detector/graph.py`)**:
   - *Concepto:* Modela la topología de red como un grafo dirigido $G=(V, E)$, rastrea causalmente hacia atrás el *Patient Zero* y computa mediante BFS el *Blast Radius* (0-100) hacia activos críticos.
   - *Roadmap:* Para topologías con más de 100,000 activos, migrar el backend en memoria a una base de grafos distribuida (Neo4j / Memgraph).
3. **Decodificador NetFlow v9 e IPFIX (RFC 3954 / 7011) (`collector/netflow_v9.py`)**:
   - *Concepto:* Decodificador binario con caché de plantillas dinámicas (*Template Flowsets*) y soporte nativo IPv6 de 128 bits.
   - *Roadmap:* Incorporar buffer de desordenamiento para manejar pérdidas UDP donde los datos preceden a la plantilla.
4. **Counting Bloom Filter para Threat Intel (`detector/bloom_threat_intel.py`)**:
   - *Concepto:* Filtro probabilístico contable en Python puro con doble hashing ($O(1)$ wire-speed) y parsers para feeds de Abuse.ch Feodo Tracker y STIX 2.1 JSON.

---

## 🔬 Núcleo Técnico: El Parser Binario NetFlow v5

El protocolo NetFlow v5 empaqueta datagramas UDP en formato **Big-Endian** (orden de red). NovaFlow implementa la especificación canónica:

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          version (5)          |          count (1-30)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SysUptime (ms)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       unix_secs (Epoch)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          unix_nsecs                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         flow_sequence                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  engine_type  |   engine_id   |       sampling_interval       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |          1 a 30 Flow Records Consecutivos (48 bytes c/u)      |
   |                                                               |
```

Formato Python Struct:
- **Header (24 bytes):** `!HHIIIIBBH`
- **Record (48 bytes):** `!4s4s4sHHIIIIHHBBBBHHBBH`

---

## ⚔️ Sinergia Purple Team: OmniBreach (Red Team) x NovaFlow NDR (Blue Team)

NovaFlow NDR se complementa de forma natural con **OmniBreach** (herramienta DAST de pruebas de penetración y simulación de adversarios):

```
+---------------------------+                    +---------------------------+
|   OmniBreach (Red Team)   |                    |   NovaFlow NDR (Blue Team)|
|  Offensive DAST Scanner   |                    |   Network Sensor & Engine |
+-------------+-------------+                    +-------------+-------------+
              |                                                ^
              | Simula Vectores Ofensivos                      | Analiza Telemetría
              | (Recon, SSRF, DoS, C2 Egress)                  | Flujos NetFlow L3/L4/L7
              v                                                |
        [ Target Network Infrastructure / Switch / Router NetFlow ]
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | • Alertas MITRE ATT&CK    |
                                                 | • Grafo: Patient Zero     |
                                                 | • Blast Radius Analysis   |
                                                 | • Auto-Containment SOAR   |
                                                 +---------------------------+
```

### Matriz de Correlación Purple Team:

| Vector OmniBreach | Fase Ofensiva | Capa L3/L4/L7 | Detector NovaFlow | Técnica MITRE | Formato SIEM CEF |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OB-RECON-01** | Service Discovery | L4 TCP (SYN Scan) | `PortScanDetector` | `T1046` | `CEF:0\|...\|PORT_SCAN\|...` |
| **OB-EXFIL-02** | SSRF & Data Egress | L4 TCP (>20MB burst) | `BandwidthExfiltrationDetector`| `T1048` | `CEF:0\|...\|EXFILTRATION\|...` |
| **OB-DOS-03** | Flood Stress Test | L4 TCP (Flag 0x02 burst)| `SynFloodDetector` | `T1498` | `CEF:0\|...\|SYN_FLOOD\|...` |
| **OB-C2-04** | C2 Reverse Shell | L4/L7 TCP (Cobalt Strike)| `ThreatIntelMatcher` / `ETA` | `T1071 / T1573` | `CEF:0\|...\|MALICIOUS_C2\|...` |

---

## 🚀 Guía de Ejecución y Pruebas

### 1. Requisitos e Instalación
```bash
git clone https://github.com/tu-usuario/novaflow-ndr.git
cd novaflow-ndr
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Ejecutar la Suite de Pruebas Automatizadas (163 Tests - 100% Passing)
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### 3. Ejecutar Benchmark de Tráfico Empresarial (Throughput & Latencia)
```bash
python tools/traffic_gen.py --mode benchmark --flows 2000
```

### 4. Ejecutar la Demostración Purple Team en Terminal
```bash
python scripts/purple_team_demo.py
```

### 5. Iniciar el Servidor API Gateway y SOC Dashboard
```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
- **SOC Web Dashboard:** [http://127.0.0.1:8000/static/index.html](http://127.0.0.1:8000/static/index.html)
- **Documentación OpenAPI (Swagger):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **MITRE ATT&CK Navigator Layer:** `GET http://127.0.0.1:8000/api/v1/mitre/navigator-layer.json`
- **Catálogo de Reglas Sigma:** `GET http://127.0.0.1:8000/api/v1/rules/sigma`
- **Threat Hunting DSL & Playbooks:** `POST http://127.0.0.1:8000/api/v1/flows/hunt`
- **Topología de Red Cytoscape/D3:** `GET http://127.0.0.1:8000/api/v1/graph/topology`
- **Métricas Prometheus:** `GET http://127.0.0.1:8000/metrics`
- **Contrato Formal Purple Team v1.0:** `GET http://127.0.0.1:8000/api/v1/purple-team/contract`
- **Ejecución de Benchmark REST:** `POST http://127.0.0.1:8000/api/v1/purple-team/benchmark`

### 6. Captura y Detección de Ataques Reales en Vivo (OmniBreach x NovaFlow)
NovaFlow incluye una **Sonda de Flujo en Vivo en Python puro** (`tools/live_probe.py`) que mide el tráfico de red de herramientas ofensivas como OmniBreach y lo exporta como datagramas binarios Cisco NetFlow v5 hacia el colector en `udp://127.0.0.1:2055`:

**Opción A — Servidor Objetivo Reactivo (Target / Honeypot):**
```bash
# Terminal 1: Iniciar NovaFlow NDR (Collector UDP 2055 + API 8000)
python run_novaflow.py

# Terminal 2: Iniciar Sonda Objetivo en puerto 8080 (cero privilegios admin)
python tools/live_probe.py --mode target --port 8080

# Terminal 3: Lanzar escaneo real con OmniBreach apuntando al objetivo
# omnibreach scan --target http://127.0.0.1:8080/
```

**Opción B — Proxy Relevo Transparente (Relay):**
```bash
# Inspecciona el tráfico entre OmniBreach y cualquier aplicación web existente
python tools/live_probe.py --mode relay --port 8080 --target-host 127.0.0.1 --target-port 3000
```

**Opción C — Hook Directo de Telemetría REST:**
```bash
# OmniBreach puede emitir flujos o alertas directamente vía API REST
curl -X POST http://127.0.0.1:8000/api/v1/telemetry/hook \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "10.0.0.50", "dst_ip": "192.168.1.10", "src_port": 49152, "dst_port": 80, "protocol": 6, "packets": 100, "bytes": 50000, "tcp_flags": 2}'
```

### 7. Arnés de Evaluación Experimental Cuantitativo (Ruido de Fondo & MTTD)
Ejecuta la evaluación formal científica de NovaFlow contra campañas de OmniBreach intercaladas en tráfico normal de fondo (Background Noise), midiendo empíricamente latencia MTTD, matriz de confusión (TP, FP, FN, TN) y exportando reportes reproducibles:
```bash
# Ejecutar benchmark experimental con 5,000 flujos benignos de fondo
python scripts/run_purple_benchmark.py --background-flows 5000 --seed 42
```
### 8. Copiloto SOC IA Híbrido & Threat Hunting (NVIDIA RTX 4060 + Ollama)
NovaFlow integra un Copiloto autónomo para analistas SOC Tier 2/3 que acelera el triaje, la explicabilidad forense (X-NDR) y la mitigación de incidentes con inferencia local confidencial:

- **Arquitectura de Resiliencia Multi-Nivel (Zero-Crash)**:
  - **Tier 1 (GPU Local)**: Inferencia en hardware mediante Ollama (`llama3.1:8b`, Q4_K_M) corriendo en la GPU NVIDIA GeForce RTX 4060 (~150 ms de latencia inicial).
  - **Tier 2 (Cloud LLM)**: Enlace de conmutación por error hacia APIs remotas si se configura clave de entorno.
  - **Tier 3 (Algorítmico Determinista)**: Motor heurístico en memoria que genera dictámenes técnicos completos y validados si Ollama o la red están caídos, garantizando disponibilidad del 100% sin excepciones 500.
- **Política Estricta CERO EMOJIS**: Formato analítico, pericial, formal y estructurado en español técnico para entornos corporativos regulados.
- **Endpoints REST (`/api/v1/copilot/`)**:
  - `GET /health`: Diagnóstico de GPU, Ollama y latencia de inferencia.
  - `POST /explain`: Genera informe forense completo a partir de metadatos de red y técnicas MITRE.
  - `POST /containment`: Asesoría de contención activa y evaluación de impacto colateral en activos críticos.
  - `POST /hunt-translate`: Compilador de lenguaje natural a sintaxis booleana AST DSL de NovaFlow (`proto == TCP AND bytes > 10M...`) con opción de ejecución inmediata sobre flujos en memoria.
  - `POST /chat`: Interacción analítica context-aware sobre telemetría y arquitectura del sistema.

### 9. Las 4 Fases de Modernización Enterprise (Comparativa con Plataformas Comerciales)

NovaFlow NDR incorpora los 4 pilares tecnológicos que caracterizan a soluciones de grado empresarial (Corelight/Zeek, Vectra AI, Darktrace, ExtraHop Reveal(x), Cisco Stealthwatch):

#### Fase 1: Extractor de Huellas Criptográficas JA4 / TLS ClientHello & ETA (sin descifrado SSL)
- **Parser binario zero-copy (`collector/tls_parser.py`)**: Extracción de registros TLS Handshake (0x16) y ClientHello (0x01) en cable, con soporte para filtrado RFC 8701 GREASE, SNI, ALPN, curvas elípticas y versiones negociadas.
- **Generador canónico FoxIO JA4 & JA3 (`detector/ja4.py`)**: Computa huellas en formato `[proto][ver][sni][ciphers][exts][alpn]_[hash_ciphers]_[hash_exts]` y digest MD5 JA3 retrocompatible.
- **Perfiles SPLT (Sequence of Packet Lengths and Times)**: Medición de entropía de Shannon y análisis de cadencia de balizamiento C2 sin requerir terminación TLS.
- **Base de inteligencia y regla detectora (`detector/ja4_database.py`, `detector/rules/ja4_threat.py`)**: Detección de Cobalt Strike, Sliver, Meterpreter y herramientas ofensivas.

#### Fase 2: Motor de Persistencia y Analítica Columnar Masiva (ClickHouse & Formato NFC)
- **Almacenamiento columnar nativo (.nfc) (`storage/columnar.py`)**: Compresión binaria con codificación por diccionario de strings, empaquetado vectorial de tipos numéricos y metadatos ZoneMap (min/max time, puertos, IPs) para poda eficiente de bloques en disco y memoria.
- **Adaptador empresarial ClickHouse (`storage/clickhouse_adapter.py`)**: DDL con motor MergeTree, particionamiento temporal mensual (`toYYYYMM(timestamp)`) y códecs DoubleDelta/ZSTD, con conmutación transparente a almacenamiento local.
- **Endpoints REST (`/api/v1/analytics/`)**:
  - `POST /query`: Consulta analítica vectorizada con filtros estructurados.
  - `GET /top-talkers`: Agregación de alto rendimiento por bytes o paquetes.
  - `GET /protocols`: Desglose institucional de distribución de protocolos.
  - `GET /timeline`: Series temporales agrupadas por cubetas configurables.
  - `GET /status`: Diagnóstico operativo del almacenamiento columnar.

#### Fase 3: Motor de Estado de Entidades y Libro Mayor de Activos (Entity State Engine)
- **Entidades persistentes (`detector/entity.py`)**: Modelo `AssetEntity` que correlaciona IP actual, histórico de IPs, MAC, Hostname, rol corporativo y usuario para neutralizar la volatilidad de direcciones IP.
- **Threat Score dinámico con decaimiento exponencial**:
  $$S(t) = S_0 \cdot e^{-\lambda \Delta t} \cdot \text{role\_multiplier}$$
  con ponderación por rol institucional (Domain Controller = 2.5x, Database Server = 2.0x, Jump Host = 1.8x, Workstation = 1.0x).
- **Rastreador de eventos DHCP (`detector/dhcp_tracker.py`)**: Decodificación de transacciones BOOTP/DHCP (RFC 2131) para migrar leases sin perder contexto forense ni fragmentar alertas.
- **Endpoints REST (`/api/v1/entities/`)**:
  - `GET /entities`: Catálogo de activos ordenados por nivel de riesgo decreciente.
  - `GET /entities/{id}`: Ficha forense completa de la entidad.
  - `PATCH /entities/{id}/role`: Actualización de rol corporativo y recalibración de riesgo.
  - `GET /entities/lookup/by-ip/{ip}`: Resolución de entidad activa por dirección IP.
  - `POST /entities/dhcp/lease`: Ingestión manual o programática de eventos DHCP.

#### Fase 4: Sonda de Captura eBPF/XDP y Emulador de Ring Buffer
- **Sonda C eBPF/XDP (`collector/ebpf/novaflow_xdp.bpf.c`)**: Programa de kernel C con gancho directo en controlador de red (NIC), mapas hash `BPF_MAP_TYPE_HASH` para tabla de flujos activa y `BPF_MAP_TYPE_RINGBUF` para despacho asíncrono a userspace.
- **Cargador híbrido (`collector/ebpf_loader.py`)**: Modo nativo para Linux con privilegios y emulador de Ring Buffer de alto rendimiento en espacio de usuario para Windows/macOS.
- **Arnés de benchmarking (`scripts/run_ebpf_benchmark.py`)**: Medición empírica de velocidad de ingesta (>470,000 PPS y >320 Mbps en memoria sin descarte).

### 10. Modernización Enterprise Avanzada: DGA/Fast-Flux, L7 Active Directory, Correlador Bayesiano y Mitigación BGP/Zero-Trust

Para equiparar las capacidades analíticas de plataformas comerciales de grado Tier-1 (*Corelight, ExtraHop Reveal(x), Vectra AI, Darktrace*), NovaFlow NDR implementa cuatro pilares adicionales:

#### Pilar 1: Motor DGA (N-Gramas) & Fast-Flux DNS
- **Modelado Estadístico de Dominios (`detector/dga.py`)**:
  - Evaluación lingüística por modelo de bigramas entrenado sobre dominios benignos comunes.
  - Cálculo de perplejidad inversa, ratio de vocales, densidad de consonantes consecutivas y entropía de Shannon.
  - Función de penalización por longitud para desenmascarar algoritmos DGA pseudoaleatorios (e.g., Conficker, Necurs, Mirai, Gameover Zeus) sin depender de listas estáticas.
- **Rastreador de Rotación Fast-Flux (`detector/dga.py`)**:
  - Detección de infraestructuras C2 resilientes mediante seguimiento temporal de rotación acelerada de direcciones IP por FQDN.
  - Umbrales configurables de rotación multired (/24 y /16) con TTL promedio anómalo ($TTL < 300\text{ s}$).
- **Regla Detectora y Taxonomía (`detector/rules/dga_threat.py`)**:
  - Emisión de alertas de categoría `DGA_DOMAIN` asociadas a MITRE ATT&CK T1568.002 (Dynamic Resolution: Domain Generation Algorithms) y T1568.001 (Fast Flux DNS).

#### Pilar 2: Inspección L7 de Protocolos de Identidad (Active Directory / Kerberos & DCE-RPC/SMB)
- **Parser Puro ASN.1 DER para Kerberos (`collector/l7_parsers.py`)**:
  - Decodificación binaria de mensajes AS-REQ (0x0A) y TGS-REQ (0x0C) sobre el puerto 88 (TCP/UDP).
  - Extracción de realm, service principal names (sname), cifrados negociados (`etype`) y atributos de preautenticación (`padata`).
- **Parser de Mensajes DCE-RPC sobre SMB (`collector/l7_parsers.py`)**:
  - Decodificación de transacciones RPC v5.0 sobre puertos 135 y 445 (SMB Named Pipes).
  - Identificación de operaciones de vinculación (Bind) y llamadas (Request) con resolución de UUIDs de interfaces de red críticas (`drsuapi`, `svcctl`, `samr`, `lsarpc`).
- **Regla Detectora de Amenazas a Identidad (`detector/rules/ad_threat.py`)**:
  - **Kerberoasting**: Solicitudes TGS-REQ solicitando cifrado débil RC4-HMAC (`etype 23`) contra SPNs de servicio para extracción de hashes fuera de línea (MITRE T1558.003).
  - **AS-REP Roasting**: Solicitudes AS-REQ con preautenticación deshabilitada (`PA-ENC-TIMESTAMP` ausente) para comprometer cuentas vulnerables (MITRE T1558.004).
  - **DCSync / Replicación Forzada**: Llamadas directas a la interfaz `drsuapi` (Directory Replication Service) para volcado no autorizado de credenciales NTDS.dit (MITRE T1003.006).
  - **PsExec Lateral Movement**: Conexiones a `svcctl` (Service Control Manager) para creación remota de servicios e inyección de procesos (MITRE T1543.003 / T1021.002).

#### Pilar 3: Correlador Causal Multi-Etapa de Kill Chain Bayesiano / Markoviano
- **Motor Causal de Campañas (`detector/campaign_correlator.py`)**:
  - Mapeo de incidentes individuales hacia fases formales de intrusión: *Reconnaissance*, *Resource Development*, *Initial Access*, *Execution*, *Persistence*, *Credential Access*, *Lateral Movement*, *Command and Control*, *Exfiltration*, *Impact*.
  - Matriz de probabilidades de transición markoviana ($P(S_{t} \mid S_{t-1})$) que premia secuencias de ataque lógicas según el modelo MITRE ATT&CK.
  - Modelo de actualización de probabilidad bayesiana acumulada con decaimiento temporal y factor de escalado multiplicativo ($odds \leftarrow odds \cdot L_i$).
  - Escalado automático a incidente de severidad `CRITICAL` con categoría `ATTACK_CAMPAIGN` cuando la probabilidad posterior alcanza o supera $P \ge 0.85$.
- **Endpoints REST (`/api/v1/campaigns/`)**:
  - `GET /api/v1/campaigns`: Consulta de campañas de intrusión activas ordenadas por probabilidad causal.
  - `GET /api/v1/campaigns/{id}`: Detalle forense de la campaña, fases comprometidas y secuencia temporal de alertas correlacionadas.
  - `POST /api/v1/campaigns/{id}/status`: Transición controlada del ciclo de vida del caso (`ACTIVE`, `INVESTIGATING`, `CONTAINED`, `CLOSED`).

#### Pilar 4: Mitigación Activa en Borde BGP Flowspec (RFC 5575) y Políticas Zero-Trust Kubernetes
- **Generador de Reglas BGP Flowspec (`detector/edge_mitigation.py`)**:
  - Generación de políticas SDN perimetrales multi-sintaxis para contención a velocidad de hardware:
    - **ExaBGP**: `flow route { match { ... } then { discard; } }`.
    - **Juniper Junos**: Sintaxis jerárquica `routing-options flow route ... then discard`.
    - **Cisco IOS-XR**: Bloques de configuración formal `class-map` y `policy-map type pbr`.
  - Acciones soportadas: `DISCARD` (descarte inmediato), `RATE_LIMIT` (limitación a X bps), `REDIRECT_VRF` (desvío a red de cuarentena o sandbox) y `TRAFFIC_MARKING` (etiquetado DSCP).
- **Generador de Políticas Zero-Trust Cloud-Native (`detector/edge_mitigation.py`)**:
  - **Cilium NetworkPolicy (Cilium CNI L7)**: Manifiesto YAML `cilium.io/v2` con aislamiento por endpoint selector, bloqueo de egress hostil y deny-all por defecto.
  - **Kubernetes NetworkPolicy (K8s Core)**: Manifiesto YAML estándar `networking.k8s.io/v1` con aislamiento ingress/egress a nivel de pod.
- **Endpoints REST (`/api/v1/mitigation/`)**:
  - `POST /api/v1/mitigation/bgp-flowspec`: Generación inmediata de reglas BGP Flowspec a partir de una alerta o parámetros ad-hoc.
  - `POST /api/v1/mitigation/cloud-native`: Generación de manifiestos YAML declarativos para orquestadores Kubernetes / Cilium.

---

## Licencia y Propósito Académico
Este proyecto se distribuye bajo la licencia MIT. Diseñado con fines de investigación, formación en seguridad de redes y demostración de arquitectura de sistemas en ingeniería de ciberseguridad.
