# 📘 Módulo 2: Ingestión Binaria, NetFlow y Forense de Paquetes

> **Propósito de esta Nota**: Dominar la decodificación de bajo nivel de protocolos de telemetría (NetFlow v5, NetFlow v9, IPFIX), el ensamblado de flujos bidireccionales (*Bi-Flow*) y la generación binaria de capturas PCAP para análisis pericial en Wireshark.

---

## 1. La Anatomía Binaria de NetFlow v5 (RFC de Cisco)

NetFlow v5 es el protocolo estándar de facto en redes empresariales. Se transmite encapsulado en paquetes **UDP** (habitualmente en el puerto `2055`).

Un datagrama NetFlow v5 consta de **dos partes**:
1. Una **Cabecera Global** fija de **24 bytes**.
2. Una secuencia de **1 a 30 Registros de Flujo (*Flow Records*)**, cada uno de **48 bytes**.

```
+-------------------------------------------------------------+
|               NETFLOW v5 HEADER (24 bytes)                  |
+-------------------------------------------------------------+
| Version (2B) | Count (2B) | SysUptime (4B) | EpochSecs (4B) |
| EpochNano (4B) | FlowSeq (4B) | EngineType (1B) | ID (1B)   |
| SamplingMode (2B)                                           |
+-------------------------------------------------------------+
|               FLOW RECORD 1 (48 bytes)                      |
+-------------------------------------------------------------+
| SrcIP (4B) | DstIP (4B) | NextHop (4B) | InSNMP (2B)        |
| OutSNMP (2B) | Packets (4B) | Octets/Bytes (4B)             |
| FirstSwitched (4B) | LastSwitched (4B)                      |
| SrcPort (2B) | DstPort (2B) | Pad (1B) | TCPFlags (1B)      |
| Protocol (1B) | ToS (1B) | SrcAS (2B) | DstAS (2B)          |
| SrcMask (1B) | DstMask (1B) | Pad2 (2B)                     |
+-------------------------------------------------------------+
```

### Implementación en Python con `struct`:
Para desempaquetar a nivel de bits en formato *Big-Endian* (orden de red estándar `!`):

```python
# Cabecera (24 bytes):
# H = uint16 (2B), I = uint32 (4B), B = uint8 (1B)
HEADER_STRUCT = "!HHIIIIBBH"

# Registro de flujo (48 bytes):
# 4s = 4 bytes crudos de IP, H = uint16, I = uint32, B = uint8
RECORD_STRUCT = "!4s4s4sHHIIIIHHBBBBHHBBH"
```

### El Reto de las Marcas de Tiempo: `sys_uptime` vs Epoch
Un error clásico en implementaciones junior de NetFlow es no entender cómo calcular el timestamp real de inicio y fin de un flujo:
- El router reporta `epoch_secs` (hora Unix del router al emitir el paquete) y `sys_uptime_ms` (milisegundos desde que el router encendió).
- Cada flujo individual reporta `first_switched` y `last_switched` medidos en relación al `sys_uptime_ms`.
- **Fórmula de Reconstrucción Temporal de NovaFlow**:
  $$\text{Flow\_Start\_Epoch} = \text{epoch\_secs} - \frac{\text{sys\_uptime\_ms} - \text{first\_switched}}{1000}$$

---

## 2. NetFlow v9 e IPFIX (RFC 3954 & RFC 7011)

A diferencia de la versión 5 que tiene campos fijos, **NetFlow v9** e **IPFIX (v10)** son **dinámicos y extensibles**:
1. **Template FlowSets**: El router primero envía una "plantilla" que define qué campos vendrán (por ejemplo: `Field 8 = IPv4_SRC`, `Field 12 = IPv4_DST`, `Field 27 = IPv6_SRC`).
2. **Data FlowSets**: Luego envía los datos crudos codificados según la plantilla previamente registrada.
3. **Soporte IPv6**: IPFIX permite nativamente direcciones IPv6 de 128 bits (`Field 27` y `Field 28`), soporte implementado en [`collector/netflow_v9.py`](file:///C:/Users/villa/.gemini/antigravity/scratch/novaflow-ndr/collector/netflow_v9.py).

---

## 3. Bi-Flow Session Stitching (Ensamblado Bidireccional)

Los routers exportan flujos **unidireccionales**. Si la máquina A envía 10 paquetes a la máquina B y B responde con 20 paquetes a A, el router emite **dos flujos separados**.

Un motor NDR no puede tomar decisiones inteligentes analizando solo un sentido (un flujo unidireccional parece una exfiltración cuando en realidad puede ser una simple descarga web).

### Algoritmo de Stitching de NovaFlow (`collector/biflow.py`):
1. **Generación de Clave Canónica Simétrica**:
   Para cualquier conexión entre `(IP_A:Port_A)` e `(IP_B:Port_B)`, la clave de sesión se ordena alfabéticamente:
   ```python
   endpoint_a = (src_ip, src_port)
   endpoint_b = (dst_ip, dst_port)
   session_key = (min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b), protocol)
   ```
2. **Fusión de Métricas**:
   - `forward_bytes` y `reverse_bytes`.
   - `upload_ratio = bytes_sent / (bytes_sent + bytes_received)`.
   - Si `upload_ratio > 0.85` en un host interno hacia el exterior, hay una asimetría sospechosa típica de exfiltración o baliza C2.

---

## 4. Generación Forense de Archivos PCAP sin Dependencias C

Cuando se produce una intrusión, un analista SOC necesita descargar la evidencia en formato `.pcap` para abrirla en **Wireshark**. Típicamente esto requiere instalar librerías pesadas en C como `libpcap` o `Npcap`.

NovaFlow incluye un **sintetizador binario puro (`collector/forensics.py`)**:

### Estructura de un Archivo PCAP Estándar (Global Header 24 bytes):
```python
magic_number = 0xA1B2C3D4  # Identificador formato libpcap (microsegundos)
version_major = 2
version_minor = 4
thiszone = 0
sigfigs = 0
snaplen = 65535            # Longitud máxima capturada
network = 1                # LINKTYPE_ETHERNET (10/100/1000 Mbps Ethernet)
```

Por cada paquete reconstructivo:
1. **Packet Header (16 bytes)**: `ts_sec (4B)`, `ts_usec (4B)`, `incl_len (4B)`, `orig_len (4B)`.
2. **Trama Ethernet II (14 bytes)**: MAC destino (6B), MAC origen (6B), EtherType IPv4 `0x0800` (2B).
3. **Datagrama IPv4 (20 bytes)**: Versión/IHL, Longitud total, TTL=64, Protocolo TCP=6 o UDP=17, IPs de origen y destino.
4. **Cabecera TCP/UDP (20 bytes)**: Puertos, Secuencia, ACK, Flags TCP (SYN, ACK, PSH, FIN).

### Cadena de Custodia Criptográfica (DFIR):
Al sintetizar el archivo, NovaFlow calcula de forma atómica su hash **SHA-256**. Esto permite a un perito informático certificar ante un juez o auditor que la evidencia descargada no ha sufrido alteraciones posteriores.
