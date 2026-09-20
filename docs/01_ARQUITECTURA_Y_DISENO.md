# 📘 Módulo 1: Arquitectura, Visión General y Diseño del Sistema

> **Propósito de esta Nota**: Comprender qué es un NDR (*Network Detection and Response*), en qué se diferencia de un EDR, Firewall o SIEM, y cuál es el ciclo de vida de un flujo de red desde el socket UDP hasta la alerta en el SOC.

---

## 1. ¿Qué es un NDR y por qué existe?

En el ecosistema de ciberseguridad corporativo existen tres pilares fundamentales (la llamada **Tríada de Visibilidad de Gartner**):

```
                      +-------------------+
                      |      SIEM         |
                      | (Splunk, Elastic) |
                      +---------+---------+
                               / \
                              /   \
                             /     \
                            v       v
         +--------------------+   +--------------------+
         |       EDR          |   |       NDR          |
         | (CrowdStrike, S1)  |   | (NovaFlow, Vectra) |
         +--------------------+   +--------------------+
```

1. **EDR (Endpoint Detection and Response)**: Agente instalado en servidores y laptops.
   - *Fortaleza*: Sabe qué proceso (`powershell.exe`), qué hash de archivo y qué usuario ejecutó una acción.
   - *Punto Ciego*: No se puede instalar en dispositivos IoT, switches de red, impresoras, cámaras, dispositivos médicos, ni en máquinas atacadas donde el malware desactiva el agente.
2. **SIEM (Security Information and Event Management)**: Agregador de logs.
   - *Fortaleza*: Correlaciona logs de Active Directory, VPN, antivirus y bases de datos.
   - *Punto Ciego*: Solo ve lo que las aplicaciones deciden loguear. Los atacantes borran logs de eventos.
3. **NDR (Network Detection and Response - NovaFlow)**:
   - *Premisa Fundacional*: **"Los paquetes en el cable nunca mienten"**.
   - Aunque un atacante borre logs locales o desactive el antivirus en la máquina víctima, para moverse lateralmente, comunicarse con su servidor de control (C2) o exfiltrar datos, **está obligado a enviar paquetes por la red física**.
   - El NDR analiza la telemetría de red pasivamente (sin interrumpir el tráfico) y detecta anomalías matemáticas y heurísticas de ataque.

---

## 2. Flujo de Datos End-to-End en NovaFlow NDR

```
[ Router / Switch Cisco ]
           |
           | Datagramas UDP (Puerto 2055)
           v
+-------------------------------------------------------------------+
| 1. COLECTOR UDP ASÍNCRONO (`collector/service.py`)                 |
|    - Asyncio DatagramProtocol / Socket no bloqueante             |
+-------------------------------------------------------------------+
           | Buffer Binario
           v
+-------------------------------------------------------------------+
| 2. PARSER MULTI-PROTOCOLO (`collector/parser.py`, `netflow_v9.py`) |
|    - Auto-dispatch de versión (NetFlow v5 / v9 / IPFIX RFC 7011) |
|    - Desempaquetado con `struct.unpack_from` (Zero-Copy)         |
+-------------------------------------------------------------------+
           | `NetFlowRecord` Normalizado
           v
+-------------------------------------------------------------------+
| 3. BI-FLOW SESSION STITCHER (`collector/biflow.py`)                |
|    - Ensamblado de conversaciones bidireccionales (A <-> B)       |
|    - Cálculo de simetría de bytes (Upload Ratio / Download Ratio) |
+-------------------------------------------------------------------+
           | `BiFlowRecord` Enriquecido
           v
+-------------------------------------------------------------------+
| 4. PIPELINE DE DETECCIÓN PARALELO (`detector/engine.py`)           |
|    |--> Profiler Estadístico O(1) (Algoritmo de Welford / Z-score)|
|    |--> High-Scale Threat Intel (Counting Bloom Filter)           |
|    |--> Encrypted Traffic Analysis (SPLT / ETA sin descifrado)    |
|    |--> Entropía Shannon (Túneles DNS / DGA)                      |
|    |--> Detección de Movimiento Lateral (SMB / RDP / WinRM)       |
|    |--> Análisis de Periodicidad C2 (Jitter / CV)                 |
+-------------------------------------------------------------------+
           | Generación de `SecurityAlert`
           v
+-------------------------------------------------------------------+
| 5. CORRELACIÓN, GRAFOS Y MITRE ATT&CK (`detector/kill_chain.py`)   |
|    - Matriz de Intrusión (Discovery -> C2 -> Exfiltration)       |
|    - Actualización del Grafo de Ataque G=(V,E) (`graph.py`)       |
|    - Trazado de "Patient Zero" y cálculo de "Blast Radius"       |
+-------------------------------------------------------------------+
           | Alerta Correlacionada con Playbook & PCAP Forense
           v
+-------------------------------------------------------------------+
| 6. DESPACHO MULTI-CANAL Y CUMPLIMIENTO REGULATORIO                |
|    |--> SIEM Logs: ArcSight CEF:0 y Syslog RFC 5424               |
|    |--> Cloud Data Lake: OCSF v1.1.0 (AWS Security Lake/Snowflake)|
|    |--> SOAR Webhooks: Firmas HMAC-SHA256 y Auto-Containment     |
|    |--> Auditoría: PCI-DSS v4.0, ISO 27001, NIST CSF, CIS v8     |
|    |--> Frontend Dashboard: WebSockets en vivo + Cytoscape.js UI  |
+-------------------------------------------------------------------+
```

---

## 3. Concurrencia y Filosofía de Diseño en Python

### ¿Por qué Asyncio?
El tráfico de red llega en ráfagas. Si procesáramos cada datagrama de manera síncrona o creáramos un hilo (`threading.Thread`) por paquete, el sistema colapsaría por el costo del cambio de contexto del kernel (*thread context switching overhead*).
NovaFlow utiliza un **bucle de eventos único (`asyncio.get_event_loop()`)** que aprovecha primitivas de E/S no bloqueantes:
- Cuando no hay paquetes, el hilo se suspende sin gastar CPU.
- Cuando llega una ráfaga UDP, el socket `DatagramProtocol` procesa en memoria a velocidad de C subyacente de Python.

### Zero-Copy Ingestion
En lugar de trocear strings o clonar buffers con `data[24:72]`, NovaFlow utiliza `struct.unpack_from(FORMAT, buffer, offset)`. Esto lee los bytes directamente sobre el buffer original en memoria RAM sin instanciar sub-objetos intermedios, reduciendo drásticamente la presión sobre el recolector de basura (*Garbage Collector*).

---

## 4. Preguntas Clave para Repasar
1. **¿Qué diferencia a NetFlow de una captura PCAP tradicional?**
   - *NetFlow* es telemetría estadística agregada (quién habló con quién, cuánto duró, cuántos bytes y paquetes se intercambiaron, qué flags TCP hubo). No contiene el contenido de los paquetes (*payload*). Esto reduce el almacenamiento en un 99%, permitiendo inspeccionar enlaces de 10 Gbps sin llenar petabytes de disco.
2. **¿Por qué NovaFlow no rompe el cifrado TLS?**
   - Romper TLS corporativo (inspección SSL man-in-the-middle) es caro, rompe certificados pinning y viola regulaciones de privacidad (GDPR/HIPAA). NovaFlow utiliza **ETA (Encrypted Traffic Analysis)** inspeccionando metadatos estadísticos (longitud de paquetes y tiempos de arribo) sin necesidad de descifrar.
