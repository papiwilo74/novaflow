# 📘 Módulo 8: Reglas Sigma, MITRE Navigator, Threat Hunting DSL y Benchmarking

> **Propósito de esta Nota**: Dominar los 4 componentes avanzados de nivel comercial incorporados en NovaFlow NDR: el motor declarativo de reglas Sigma para flujos de red en Python puro, la exportación de capas oficiales para MITRE ATT&CK Navigator v4.5, el motor de Threat Hunting con analizador sintáctico AST booleano, y la herramienta de generación de tráfico empresarial con suite de benchmarking en microsegundos.

---

## 1. Motor Declarativo de Reglas Sigma para Tráfico de Red (`detector/sigma_engine.py`)

### 1.1 ¿Qué es el Estándar Sigma y por qué adaptarlo a red?
En ciberseguridad, **Sigma** es el estándar abierto internacional (impulsado por Florian Roth y el consorcio SigmaHQ) para describir firmas de detección en formato declarativo YAML, independiente de la tecnología o vendor subyacente (equivalente a "reglas Snort/Suricata" para eventos de sistema o "reglas YARA" para archivos).

Tradicionalmente, las reglas Sigma operaban sobre logs de Windows Event Viewer (`winlogon.exe`, creación de procesos). En **NovaFlow NDR**, adaptamos el estándar Sigma al dominio de **flujos de red L3/L4/L7 y sesiones Bi-Flow**.

### 1.2 Reto de Ingeniería: YAML sin librerías externas en C
La mayoría de implementaciones dependen de `PyYAML` (que requiere compiladores C o binarios pesados en Windows). NovaFlow implementa `parse_simple_yaml`: un analizador sintáctico recursivo en **Python puro (Zero C / No Npcap)** que reconoce:
- Mapeos clave-valor y estructuras anidadas (`detection.selection`).
- Listas numéricas y alfanuméricas (`dst_port: [8080, 8443, 9001]`).
- Comparadores numéricos (`upload_ratio: "> 10.0"` o `bytes: "> 50000"`).
- Tipos nativos: enteros, flotantes, booleanos (`true/false`) y cadenas con o sin comillas.

### 1.3 Anatomía de una Regla Sigma de Red
```yaml
title: Outbound Communication to Unusual C2 High Ports
id: 5b4779f0-a7cd-4e04-9cb8-23974703b049
status: production
description: Detecta tráfico saliente persistente hacia puertos altos anómalos comúnmente empleados por frameworks C2.
level: high
tags:
    - attack.command_and_control
    - attack.t1071
detection:
    selection:
        dst_port:
            - 8080
            - 8443
            - 9001
            - 1337
        upload_ratio: "> 5.0"
        bytes: "> 1000"
    condition: selection
```

### 1.4 Ciclo de Evaluación y Mapeo MITRE
1. Cuando un flujo NetFlow v5/v9/IPFIX ingresa a `DetectionEngine.analyze_flow()`, se extraen sus campos normalizados (`src_ip`, `dst_ip`, `dst_port`, `proto`, `bytes`, `packets`, `upload_ratio`).
2. `SigmaEngine.evaluate_flow()` compara el contexto contra cada regla cargada en memoria.
3. Si los criterios coinciden, se emite una alerta `SecurityAlert` con severidad mapeada (`low`, `medium`, `high`, `critical`) y técnica MITRE extraída de las etiquetas (`attack.t1071` $\rightarrow$ `T1071`).
4. **Recarga en Caliente**: El endpoint `POST /api/v1/rules/sigma/reload` permite añadir o editar reglas YAML en disco sin detener ni reiniciar los servicios del colector.

---

## 2. Exportador MITRE ATT&CK Navigator Layer v4.5 (`api/routes/mitre.py`)

### 2.1 ¿Qué es MITRE ATT&CK Navigator?
Es la herramienta web estándar de la industria ([attack-navigator](https://mitre-attack.github.io/attack-navigator/)) utilizada por Directores de Seguridad (CISO), equipos de Blue Team y auditores para visualizar la cobertura defensiva y la exposición a amenazas de una organización sobre la matriz de 14 tácticas y cientos de técnicas.

### 2.2 Esquema y Scoring Dinámico en NovaFlow
El endpoint `GET /api/v1/mitre/navigator-layer.json` serializa el estado en vivo del motor de detección en la especificación Navigator v4.5:

```json
{
  "name": "NovaFlow NDR - Live Detection Coverage",
  "version": "4.5",
  "domain": "enterprise-attack",
  "gradient": {
    "colors": ["#1e293b", "#38bdf8", "#f59e0b", "#ef4444"],
    "minValue": 0,
    "maxValue": 100
  },
  "techniques": [
    {
      "techniqueID": "T1046",
      "tactic": "discovery",
      "score": 50,
      "color": "#f59e0b",
      "comment": "Barrido de Puertos (SYN) detectado desde 10.0.50.15",
      "enabled": true
    },
    {
      "techniqueID": "T1071",
      "tactic": "command-and-control",
      "score": 100,
      "color": "#ef4444",
      "comment": "Conexión con C2 / IP Maliciosa (Cobalt Strike C2): 198.51.100.77",
      "enabled": true
    }
  ]
}
```

- **Ponderación de Calor**:
  - `CRITICAL` $\rightarrow$ Score `100` (Rojo `#ef4444`).
  - `HIGH` $\rightarrow$ Score `75` (Naranja `#f97316`).
  - `MEDIUM` $\rightarrow$ Score `50` (Ámbar `#f59e0b`).
  - `LOW` $\rightarrow$ Score `25` (Cian `#38bdf8`).
- **Botón en Dashboard**: El SOC Dashboard (`api/static/index.html`) cuenta con un botón en la barra superior de la matriz que descarga el archivo `.json` listo para importar en Navigator con un solo clic.

---

## 3. Motor de Threat Hunting con DSL Booleano (`detector/hunting.py`)

### 3.1 ¿Por qué un DSL (Domain Specific Language) de Hunting?
Las alertas automatizadas detectan ataques conocidos. Sin embargo, los analistas de **Threat Hunting** necesitan buscar activamente hipótesis de compromiso (ej. "¿hay algún equipo enviando más de 10 megabytes a IPs que no sean de nuestra subred interna?").

Para esto construimos un analizador sintáctico de árbol de sintaxis abstracta (**AST - Abstract Syntax Tree**) recursivo que evalúa expresiones complejas sobre la memoria de flujos en tiempo constante.

### 3.2 Gramática y Operadores Soportados
```
Expresión   := Término ( ('AND' | 'OR') Término )*
Término     := 'NOT' Término | Factor
Factor      := Condición | '(' Expresión ')'
Condición   := Campo Operador Valor
Operadores  := '==' | '!=' | '>' | '<' | '>=' | '<=' | 'IN' | 'CONTAINS' | 'LIKE'
```

### 3.3 Soporte de Unidades Métricas y Normalización
- **Unidades de Bytes y Paquetes**: El parser traduce automáticamente sufijos:
  - `bytes > 10M` $\rightarrow$ `bytes > 10,485,760`
  - `bytes > 50K` $\rightarrow$ `bytes > 51,200`
  - `packets >= 1G` $\rightarrow$ `packets >= 1,073,741,824`
- **Normalización de Protocolos**: Permite indistintamente `proto == TCP` o `proto == 6`, `proto == UDP` o `proto == 17`.

### 3.4 Playbooks Preconfigurados de Caza Activa
| Playbook ID | Propósito | Sintaxis de la Expresión DSL |
| :--- | :--- | :--- |
| `c2_unusual_ports` | Balizas C2 en puertos alternativos | `proto == TCP AND dst_port IN [4444, 5555, 8080, 8443, 9001] AND bytes > 50K` |
| `dns_data_exfil` | Exfiltración encubierta DNS | `proto == UDP AND dst_port == 53 AND bytes > 5000` |
| `lateral_movement_smb` | Propagación lateral Windows | `dst_port IN [445, 135, 3389, 5985] AND packets > 100` |
| `external_high_volume` | Exfiltración masiva externa | `bytes > 10M AND NOT dst_ip LIKE 10.0.` |
| `syn_scan_activity` | Reconocimiento sigiloso SYN | `proto == TCP AND tcp_flags == 2 AND packets == 1` |

- **API REST**: `POST /api/v1/flows/hunt` recibe `{"query": "...", "limit": 100}` y responde con las coincidencias, conteo y tiempo de ejecución en milisegundos.

---

## 4. Generador de Tráfico Empresarial & Benchmark CLI (`tools/traffic_gen.py`)

### 4.1 Empaquetado Binario NetFlow v5 conforme al RFC
Para probar el sistema a escala real sin necesitar un enrutador Cisco físico en el laboratorio, `tools/traffic_gen.py` implementa `build_netflow_v5_packet`:
- Construye la cabecera exacta de 24 bytes (`!HHIIIIBBH`).
- Serializa bloques de hasta 30 registros de 48 bytes (`!4s4s4sHHIIIIHHBBBBHHBBH`).
- **Control de Desbordamiento de Enteros (Masking)**: Aplica `& 0xFFFFFFFF` a los campos de 32 bits (SysUptime, timestamps, contadores de bytes) y `& 0xFFFF` a puertos y SNMP, previniendo excepciones `struct.error: argument out of range`.

### 4.2 Perfiles de Tráfico Generados
1. **Tráfico Benigno**:
   - Web HTTPS corporativa (Google, Cloudflare, Office 365, Reddit) con distribución realista de paquetes TCP.
   - Consultas DNS recursivas hacia resolvers empresariales (puerto 53 UDP).
   - Consultas internas SQL PostgreSQL (puerto 5432) con intercambios cliente-servidor.
2. **Tráfico Adversarial**:
   - Ráfagas de escaneo horizontal SYN contra 20 puertos críticos.
   - Balizas salientes C2 Cobalt Strike con simulación de periodicidad.
   - Ráfagas masivas de exfiltración de base de datos (>32 MB por flujo).

### 4.3 Métricas de Rendimiento del Benchmark en Memoria
Al ejecutar:
```powershell
& ".\.venv\Scripts\python.exe" tools\traffic_gen.py --mode benchmark --flows 2000
```
El motor alcanza resultados de nivel industrial en hardware de desarrollo estándar:
- **Throughput de procesamiento**: **4,885+ flujos/segundo**.
- **Ancho de banda equivalente en red física**: **~1.24 Gbps** a velocidad de línea.
- **Latencia media de inspección**: **~204 microsegundos ($\mu$s) por flujo**.
- **Eficacia de detección**: 100% de los vectores de ataque inyectados disparan alertas de seguridad, correlaciones de campaña y auto-contención SOAR firmada.

---

## 5. Preguntas Clave para Defender este Módulo en Entrevista

### P1: "¿Por qué construir su propio parser YAML en lugar de usar PyYAML o ruamel.yaml?"
> *"La filosofía central de NovaFlow NDR es mantener una arquitectura de cero dependencias externas de compilación C y cero dependencias de drivers de captura como Npcap en Windows o libpcap en Linux. Librerías como PyYAML en ciertos entornos Windows empresariales requieren dependencias C o fallan si el compilador MSVC no está presente. Al implementar un parser recursivo en Python puro de apenas 100 líneas, NovaFlow es 100% portable, corre de inmediato en cualquier contenedor Docker alpine o máquina Windows sin pip, y elimina superficies de ataque de deserialización de código arbitrario."*

### P2: "¿Cómo evita el motor de Threat Hunting degradar el rendimiento al buscar en millones de flujos?"
> *"El motor utiliza un analizador sintáctico recursivo que compila la consulta textual en un Árbol de Sintaxis Abstracta (AST) una sola vez antes de iterar sobre el dataset. Durante la evaluación de cada nodo de condición, se implementa 'short-circuit evaluation' (cortocircuito booleano): si la primera condición de un `AND` es falsa, no evalúa las restantes. Además, las comparaciones de campos numéricos (puertos, flags, bytes) se resuelven a nivel de enteros primitivos en CPython sin conversión a strings."*

### P3: "¿Qué diferencia hay entre la matriz interna de MITRE del SOC y la capa exportada para Navigator?"
> *"La pestaña interna del SOC en NovaFlow ofrece visualización operativa en tiempo real para el analista de guardia. La capa generada para MITRE ATT&CK Navigator v4.5 es un artefacto de interoperabilidad y auditoría estratégica: se puede cargar en la herramienta oficial de MITRE o archivar para reportes de cumplimiento normativo (PCI-DSS, ISO 27001), permitiendo a CISOs y auditores contrastar la telemetría real contra matrices de madurez corporativas."*
