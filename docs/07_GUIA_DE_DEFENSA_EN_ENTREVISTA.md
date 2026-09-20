# 📘 Módulo 7: Guía de Defensa en Entrevistas Técnicas

> **Propósito de esta Nota**: Esta es tu "armadura de combate" para entrevistas de trabajo con Ingenieros de Seguridad Senior, Tech Leads o CISOs. Contiene las preguntas más difíciles que te harán y la forma exacta de responderlas con honestidad técnica, rigor y autoridad.

---

## 1. La Estrategia Maestra: La Matriz de 3 Columnas

En una entrevista, el mayor peligro de un proyecto avanzado es que el evaluador piense:  
❌ *"Esto está inflado, copió y pegó código o usó IA sin entender los retos reales de producción."*

Para neutralizar esa duda en los primeros 2 minutos, di exactamente esto:

> *"Antes de mostrarte el código, quiero ser muy transparente sobre el nivel de madurez del proyecto. He dividido la arquitectura en **3 columnas de ingeniería**:*
> 1. *Columna 1 (Production-Ready)*: El núcleo que implementé desde cero y probé con 137 pruebas automatizadas (el parser binario de NetFlow v5, el algoritmo de Welford en O(1), las heurísticas L4 y el API Gateway).*
> 2. *Columna 2 (Prototipos Funcionales)*: Funcionalidades que operan perfectamente en laboratorio pero cuyos retos de producción en redes de 100 Gbps conozco explícitamente (como el Bi-Flow Stitcher y el sintetizador PCAP en memoria).*
> 3. *Columna 3 (Investigación y Visión)*: Módulos de I+D inspirados en productos enterprise como Darktrace y Vectra (el análisis de tráfico cifrado ETA/SPLT y el grafo de ataque).*

**Efecto en el entrevistador**: Te ganas su respeto inmediato. Demuestras que eres un ingeniero que entiende la diferencia entre un prototipo y el tráfico real a escala de telecomunicaciones.

---

## 2. Preguntas Difíciles y Respuestas Ideales

### Pregunta 1: "¿Por qué implementaste esto en Python y no en Rust, Go o C++?"
**Respuesta Ideal**:
> *"Para el diseño del prototipo y la experimentación algorítmica (Welford, Shannon, grafos BFS), Python ofrece una velocidad de iteración imbatible y una suite de pruebas muy limpia.*  
> *Sin embargo, fui consciente de las limitaciones de rendimiento desde el día 1:*  
> *1. Para la ingesta binaria evité copias innecesarias usando `struct.unpack_from` directo sobre el buffer de memoria.*  
> *2. En un entorno de producción de 10 Gbps con 500,000 flujos por segundo, el cuello de botella sería el GIL (Global Interpreter Lock). En una arquitectura enterprise real, el colector UDP y el descarte inicial se escribirían en **Rust o Go** (o usando **eBPF / XDP** en el kernel de Linux), y se enviarían eventos agregados vía colas Kafka hacia el motor analítico de detección."*

---

### Pregunta 2: "¿Cómo evitas falsos positivos cuando un servidor hace un respaldo legítimo de base de datos a las 2:00 AM (que parece exfiltración)?"
**Respuesta Ideal**:
> *"Ese es uno de los problemas clásicos de los NDR basados solo en umbrales estáticos. En NovaFlow lo abordamos de tres formas:*  
> *1. **Algoritmo de Welford Conductual**: El sistema calcula la media y varianza por host. Si un servidor de base de datos realiza respaldos periódicos, su varianza histórica absorbe ese volumen y el Z-score no se dispara erróneamente.*  
> *2. **Auto-Clasificación de Roles (`AssetRole`)**: Si el profiler detecta que un host tiene puertos de base de datos o almacenamiento masivo y tráfico nocturno recurrente, ajusta automáticamente los umbrales de exfiltración para no alertar operaciones normales de mantenimiento.*  
> *3. **Bi-Flow Ratio**: Un respaldo interno se dirige hacia un servidor de backup corporativo; una exfiltración suele ir hacia una IP pública desconocida con asimetría de subida extrema."*

---

### Pregunta 3: "¿Cómo analizas tráfico cifrado (TLS 1.3 / HTTPS) sin romper el cifrado ni hacer Man-in-the-Middle?"
**Respuesta Ideal**:
> *"Utilizamos la metodología **ETA (Encrypted Traffic Analysis)** desarrollada originalmente por Cisco y la comunidad académica.*  
> *No necesitamos descifrar el payload. Analizamos lo que llamamos **SPLT (Sequence of Packet Lengths and Times)**:*  
> *1. En una navegación web humana sobre HTTPS, ves una petición pequeña, una descarga de HTML, pausas de lectura humana y descargas asimétricas.*  
> *2. En un canal de comando y control (Cobalt Strike o Sliver) sobre HTTPS, observas ráfagas de paquetes idénticos y pequeños (150-300 bytes) con un coeficiente de variación temporal muy bajo ($CV < 0.35$).*  
> *3. En una exfiltración cifrada, observas una saturación continua del MTU (paquetes de $\ge 1400$ bytes) con dirección exclusiva de subida. Los metadatos de transporte revelan el ataque sin violar la privacidad de los usuarios."*

---

### Pregunta 4: "¿Cómo rastrea tu algoritmo el 'Patient Zero' si la intrusión empezó hace varios días?"
**Respuesta Ideal**:
> *"El motor mantiene un historial temporal ordenado de compromisos y una lista de adyacencia de entrada (`in_edges`) en el grafo $G=(V, E)$.*  
> *Cuando un activo crítico (como un Domain Controller) emite una alerta, el algoritmo retrocede cronológicamente en el tiempo:*  
> *Examina qué máquinas internas se comunicaron con el DC en puertos administrativos (SMB 445, RDP 3389) **antes** de la infección. Luego repite el proceso sobre esa máquina previa, hasta llegar al nodo que no recibió movimiento lateral interno, sino que tuvo su primer contacto desde el exterior (vía correo o explotación web).*  
> *En memoria esto opera en milisegundos mediante travesía en grafos; para persistencia a largo plazo, los flujos se almacenarían en un Data Lake como ClickHouse o Snowflake."*

---

## 3. Cheatsheet de Términos Técnicos para Usar en la Conversación

- **Bi-Flow Stitching**: Ensamblar flujos unidireccionales de routers para reconstruir la conversación bidireccional completa.
- **Fan-Out**: Patrón de conexión de un solo origen hacia múltiples destinos o puertos (típico de escaneos y gusanos).
- **Z-Score**: Número de desviaciones estándar que una observación se aleja de la media histórica ($Z \ge 3.5$).
- **Entropía de Shannon**: Grado de aleatoriedad en los caracteres de un dominio DNS ($H > 3.85$ indica túnel o DGA).
- **Counting Bloom Filter**: Estructura de datos probabilística que permite verificar membresía en $O(1)$ con memoria mínima y soporte de borrado dinámico.
- **Patient Zero**: El host que sufrió el compromiso inicial y sirvió de cabeza de playa (*beachhead*) para el adversario.
- **Blast Radius**: El conjunto ponderado de activos alcanzables desde un nodo comprometido y su score de riesgo.
- **OCSF (Open Cybersecurity Schema Framework)**: Estándar abierto respaldado por AWS y Snowflake para normalizar alertas en Category 2 (Findings), Class 2001.
- **Purple Teaming**: Validación cruzada donde los hallazgos del Red Team (OmniBreach) se correlacionan con la telemetría defensiva del Blue Team (NovaFlow).
