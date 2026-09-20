# 📘 Módulo 4: Detecciones de Seguridad y Correlación Cyber Kill Chain

> **Propósito de esta Nota**: Comprender a fondo cada uno de los vectores de ataque detectados por NovaFlow NDR, cómo se modelan en capas L3/L4/L7, y cómo funciona el motor de correlación temporal multietapa (*Kill Chain Correlation*).

---

## 1. Las 7 Categorías de Detección en Red

```
+-----------------------------------------------------------------------------------+
|                         LAS 7 AMENAZAS EN NOVAFLOW NDR                            |
+--------------------+--------------------------+-----------------+-----------------+
| Categoría          | Protocolos / Puertos     | Técnica MITRE   | Método Lógico   |
+--------------------+--------------------------+-----------------+-----------------+
| 1. PORT_SCAN       | TCP SYN / UDP            | T1046           | Fan-out temporal|
| 2. SYN_FLOOD       | TCP Puerto específico    | T1498           | Ratio SYN/ACK   |
| 3. EXFILTRATION    | TCP / UDP (Upload > 85%) | T1048 / T1041   | Bi-Flow + Zscore|
| 4. DNS_TUNNEL      | UDP/TCP 53               | T1071.004       | Entropía Shannon|
| 5. MALICIOUS_C2    | TCP 443 / 80 / 8080      | T1071 / T1571   | Bloom + Jitter  |
| 6. LATERAL_MOVE    | SMB 445, RDP 3389, WinRM | T1021           | Fan-out interno |
| 7. ANOMALOUS_TLS   | TLS / HTTPS 443          | T1573.001       | SPLT Profiler   |
+--------------------+--------------------------+-----------------+-----------------+
```

---

## 2. Detalle Técnico de Cada Heurística

### 1. Escaneo de Puertos y Servicios (PORT_SCAN - MITRE T1046)
- **Comportamiento del Atacante**: Herramientas como Nmap o Masscan envían paquetes TCP con flag SYN (`0x02`) a decenas de puertos para ver cuáles responden con `SYN-ACK`.
- **Lógica de Detección**:
  - NovaFlow mantiene una ventana deslizante de 10 segundos por cada `src_ip`.
  - Si un host contacta $\ge 15$ puertos destino distintos o $\ge 10$ hosts distintos con flag SYN y un promedio menor a 3 paquetes por flujo, se emite alerta `MEDIUM` o `HIGH`.

### 2. Inundación SYN (SYN_FLOOD - MITRE T1498)
- **Comportamiento del Atacante**: Intento de agotar la tabla de conexiones del kernel del servidor (*SYN backlog queue*), enviando ráfagas masivas de paquetes SYN sin completar el handshake con un ACK.
- **Lógica de Detección**:
  - Monitoriza flujos entrantes hacia un mismo `(dst_ip, dst_port)`.
  - Si se reciben $\ge 50$ flujos SYN por segundo con origen en múltiples IPs o con flags anómalos, se emite alerta `HIGH`.

### 3. Exfiltración Volumétrica de Datos (EXFILTRATION - MITRE T1048)
- **Comportamiento del Atacante**: Robo de bases de datos o archivos confidenciales hacia un servidor en la nube (S3, Dropbox, VPS del atacante).
- **Lógica de Detección**:
  - Utiliza el **Bi-Flow Stitcher**: Evalúa la asimetría de bytes.
  - Si un host interno envía $> 25\text{ MB}$ con un ratio de subida $> 85\%$ hacia una IP externa no corporativa, y la transferencia excede su baseline histórico ($Z \ge 3.5$), se emite alerta `HIGH` o `CRITICAL`.

### 4. Túneles DNS y Canales Encubiertos (DNS_TUNNEL - MITRE T1071.004)
- **Comportamiento del Atacante**: Codifica archivos o comandos de shell dentro del prefijo de consultas DNS (`data-en-base64.evil.com`) hacia un servidor DNS controlado por el adversario (herramientas como *iodine* o *dnscat2*).
- **Lógica de Detección**:
  - Inspecciona peticiones hacia el puerto 53 UDP/TCP.
  - Evalúa la longitud del subdominio ($> 35\text{ caracteres}$) y calcula la **Entropía de Shannon** ($H > 3.85$).
  - Si hay ráfagas repetitivas de consultas de alta entropía, se clasifica como túnel encubierto.

### 5. Comando y Control (MALICIOUS_C2 - MITRE T1071)
- **Comportamiento del Atacante**: Comunicación con botnets o frameworks ofensivos (*Cobalt Strike*, *Sliver*, *Brute Ratel*).
- **Lógica de Detección Dual**:
  1. *Cotejo en Cable*: Verificación $O(1)$ en el **Counting Bloom Filter** contra feeds de Feodo Tracker / Abuse.ch.
  2. *Análisis de Periodicidad*: Verificación de intervalos de baliza con bajo Coeficiente de Variación ($CV \le 0.35$).

### 6. Movimiento Lateral Interno (LATERAL_MOVEMENT - MITRE T1021)
- **Comportamiento del Atacante**: Una vez dentro de una workstation, el atacante usa credenciales robadas para saltar hacia Domain Controllers o servidores de base de datos usando protocolos administrativos:
  - `SMB (Puerto 445)`: *PsExec*, *Impacket*, *WMIExec*.
  - `RDP (Puerto 3389)`: Acceso remoto interactivo.
  - `WinRM (Puertos 5985/5986)`: PowerShell Remoting.
- **Lógica de Detección**:
  - Si una IP interna intenta conexiones concurrentes a $\ge 3$ servidores internos en estos puertos dentro de una ventana temporal, se genera alerta `CRITICAL`.

### 7. Encrypted Traffic Analysis (ANOMALOUS_TLS / ETA - MITRE T1573.001)
- **Comportamiento del Atacante**: Cifrar el tráfico con TLS 1.3 para que los firewalls convencionales no puedan leer el payload.
- **Lógica de Detección (SPLT - Sequence of Packet Lengths and Times)**:
  - Sin romper el cifrado, analiza el tamaño de los primeros paquetes:
    * *Exfiltración masiva TLS*: Ráfagas de paquetes de tamaño máximo ($\ge 1400\text{ bytes}$) sin pausas de lectura humana.
    * *C2 HTTPS Beaconing*: Pequeños intercambios simétricos (120-400 bytes) periódicos sobre el puerto 443.

---

## 3. Correlación de la Cyber Kill Chain

Un analista en un SOC recibe cientos de alertas al día (*Alert Fatigue*). Si cada evento se reporta por separado, el atacante pasa desapercibido entre el ruido.

NovaFlow implementa una **Máquina de Estados de Intrusión Causal (`detector/kill_chain.py`)**:

```
+---------------+     Movimiento     +---------------+     Egreso      +---------------+
|  ETAPA 1:     |     Lateral /      |  ETAPA 2:     |   Volumétrico   |  ETAPA 3:     |
| RECONOCIMIENTO| -----------------> | COMANDO & CTRL| --------------> | EXFILTRACIÓN  |
| (Port Scan)   |                    | (C2 Beacon)   |                 | (Data Theft)  |
+---------------+                    +---------------+                 +---------------+
   [MEDIUM - 80%]                       [HIGH - 90%]                      [CRITICAL - 99%]
```

### Reglas de Correlación:
1. Si un mismo host realiza un escaneo de puertos (Reconocimiento), y dentro de las siguientes 4 horas establece un canal C2, la severidad se eleva inmediatamente a **HIGH** y se asigna a la misma campaña de ataque.
2. Si ese mismo host procede a transferir datos masivos al exterior (Exfiltración), la alerta se escala a **CRITICAL con Confianza del 99%**.
3. Se dispara de forma automática la contención SOAR y el trazado de la ruta de intrusión en el Grafo de Ataque.
