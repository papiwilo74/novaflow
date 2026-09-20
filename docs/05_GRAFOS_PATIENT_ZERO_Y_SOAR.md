# 📘 Módulo 5: Grafo de Ataque, Patient Zero, Blast Radius y SOAR

> **Propósito de esta Nota**: Dominar la teoría de grafos aplicada a la respuesta ante incidentes, el algoritmo para encontrar la máquina origen de una intrusión (*Patient Zero*), el cálculo del radio de explosión (*Blast Radius*) y la orquestación activa de contención (*SOAR*).

---

## 1. Modelado de la Red como un Grafo Dirigido $G = (V, E)$

En lugar de ver los flujos como una tabla plana de base de datos, NovaFlow modela la red como un **Grafo Ponderado y Dirigido (`detector/graph.py`)**:

```
+-------------------------------------------------------------+
|                     GRAFO DE RED G = (V, E)                 |
+-------------------------------------------------------------+
| V (Vértices / Nodos):                                       |
|   - Representan direcciones IP (Hosts).                     |
|   - Atributos: Rol del activo, Score de riesgo, Estado      |
|     (Limpio vs Comprometido), In-Degree y Out-Degree.       |
|                                                             |
| E (Aristas / Enlaces):                                      |
|   - Representan flujos de comunicación entre Host A y Host B|
|   - Atributos: Total de bytes, protocolos, marcas temporales|
|     y etiquetas hostiles (Movimiento Lateral, C2).          |
+-------------------------------------------------------------+
```

### Roles y Criticidad de los Activos:
No todas las máquinas tienen el mismo valor en una corporación. NovaFlow asigna ponderaciones según el rol:

| Rol del Activo | Ponderación de Criticidad | Ejemplos |
| :--- | :---: | :--- |
| **`INFRASTRUCTURE_DC`** | **45.0** | Controlador de Dominio de Active Directory |
| **`INTERNAL_SERVER`** | **25.0** | Base de datos PostgreSQL, ERP, Core Bancario |
| **`ADMIN_MANAGEMENT`** | **25.0** | Jump-hosts, consolas de administración |
| **`INFRASTRUCTURE_DNS`**| **15.0** | Servidores DNS corporativos internos |
| **`WORKSTATION`** | **5.0** | Laptops de empleados y clientes DHCP |

---

## 2. El Algoritmo de Rastreo Causal de "Patient Zero"

Cuando un analista del SOC descubre que el **Controlador de Dominio (`10.0.0.10`)** está cifrado por un ransomware o contactando un C2, la pregunta más urgente del CISO es:  
👉 **"¿Cómo entró el atacante a la red y cuál fue la primera máquina infectada?"**

Esa máquina inicial es el **Patient Zero (Paciente Cero)**.

### Funcionamiento del Algoritmo:
1. **Punto de Partida**: El host actualmente comprometido ($H_{\text{target}}$).
2. **Travesía Temporal Inversa**:
   - El motor revisa la lista de adyacencia de entrada (`in_edges`), buscando conexiones previas que involucren técnicas de intrusión (explotación de vulnerabilidades, escaneos o movimiento lateral).
   - Filtra únicamente los eventos que ocurrieron **cronológicamente antes** de la infección de la máquina actual ($t_{\text{prev}} < t_{\text{curr}}$).
3. **Punto de Parada**:
   - Continúa retrocediendo recursivamente hasta encontrar un nodo que **no recibió movimiento lateral de ninguna otra máquina interna**, sino que se infectó directamente desde el exterior (vía correo de phishing, VPN o explotación web).
4. **Resultado**: Retorna la IP del Paciente Cero, el vector inicial de compromiso y la **secuencia exacta de saltos causales** (p. ej. `10.0.50.15 (Phishing) -> 10.0.50.22 -> 10.0.0.10 (DC)`).

---

## 3. El Algoritmo de Cálculo de "Blast Radius" (Radio de Explosión)

Si una máquina de contabilidad está infectada, ¿qué tan grave es el peligro para el resto de la empresa? El **Blast Radius** mide cuántos activos y qué tanto valor corporativo puede destruir el adversario desde su posición actual.

### Funcionamiento del Algoritmo (`calculate_blast_radius`):
1. **Búsqueda en Anchura Hacia Adelante (Forward BFS)**:
   - Partiendo del host infectado hasta una profundidad máxima (típicamente 3 o 4 saltos de red).
2. **Factor de Atenuación por Saltos**:
   - Un activo a 1 salto de distancia está en peligro inminente; a 3 saltos el atacante requiere evadir más controles.
   - Atenuación de NovaFlow:
     $$\text{Factor}(d) = \frac{1}{d^{0.75}}$$
3. **Fórmula del Blast Score (Normalizado 0.0 a 100.0%)**:
   $$\text{Raw\_Risk} = \sum_{v \in \text{Alcanzables}} \frac{\text{Peso\_Rol}(v) \cdot (\text{Riesgo}(v) + 1)}{d(v)^{0.75}}$$
   $$\text{Blast\_Score} = \min\left(100.0, \; \frac{\text{Raw\_Risk}}{120.0} \times 100.0\right)$$

### Clasificación Operativa:
- $\text{Score} < 20\%$: **LOW** (Aislado, solo afecta a PCs secundarias).
- $20\% \le \text{Score} < 45\%$: **MEDIUM** (Puede alcanzar servidores departamentales).
- $45\% \le \text{Score} < 70\%$: **HIGH** (Ruta viable hacia servidores de producción).
- $\text{Score} \ge 70\%$: **CRITICAL** (Acceso directo a Domain Controllers o bases de datos críticas).

---

## 4. Orquestador SOAR, Despacho y Mitigación Activa

Una vez detectada la amenaza, el tiempo de respuesta humano suele ser de horas. NovaFlow implementa un motor SOAR (*Security Orchestration, Automation and Response*, en [`detector/dispatcher.py`](file:///C:/Users/villa/.gemini/antigravity/scratch/novaflow-ndr/detector/dispatcher.py)):

### 1. Despacho Seguro con Firmas Criptográficas (HMAC-SHA256)
Cada webhook enviado a Slack, Splunk o Cortex XSOAR se firma con una clave secreta compartida en la cabecera:
```http
X-NovaFlow-Signature: sha256=a5b6c7d8e9...
```
Esto previene que un atacante envíe webhooks falsos para engañar al equipo de seguridad.

### 2. Resiliencia: Dead-Letter Queue (DLQ) y Reintentos
Si el servidor receptor está caído o la red falla:
- NovaFlow reintenta con retroceso exponencial (*Exponential Backoff*).
- Si tras 3 intentos no responde, el evento se mueve a la cola de mensajes muertos (**DLQ**), garantizando que **ninguna alerta se pierda**.

### 3. Playbooks de Mitigación Activa y Auto-Containment
NovaFlow genera automáticamente comandos de aislamiento específicos para la infraestructura de la empresa:
- **`iptables` / `nftables`**: Para servidores Linux perimetrales.
- **Cisco IOS ACL**: Reglas de filtrado para switches y routers de acceso.
- **AWS Network ACL (NACL)**: Entradas JSON declarativas para AWS VPC.
- **Linux Null-Route**: Descarte directo a nivel de tabla de enrutamiento del kernel (`ip route add blackhole`).

Si un incidente es `CRITICAL` con confianza $\ge 90\%$, el motor puede activar el **Auto-Containment**, aislando de inmediato al atacante antes de que inicie el cifrado de datos.
