# 📘 Módulo 3: Matemáticas y Algoritmos de Detección

> **Propósito de esta Nota**: Dominar los fundamentos matemáticos de NovaFlow NDR. En entrevistas técnicas para roles de Detección, Seguridad de Redes o Data Science, saber explicar estos algoritmos en una pizarra te diferencia inmediatamente del 95% de los candidatos.

---

## 1. Algoritmo de Welford para Baselining en Tiempo Constante $O(1)$

### El Problema en Redes de Alta Velocidad:
Para saber si un servidor está transmitiendo una cantidad anómala de datos, necesitamos conocer su **media ($\mu$)** y su **desviación estándar ($\sigma$)** histórica.

La fórmula de libro de texto es:
$$\sigma = \sqrt{\frac{1}{N} \sum_{i=1}^N (x_i - \mu)^2}$$

**¿Por qué esta fórmula falla en producción?**
1. **Requiere 2 pasadas**: Primero tienes que ver los $N$ flujos para calcular $\mu$, y luego recorrerlos de nuevo para calcular las diferencias al cuadrado.
2. **Agotamiento de memoria ($O(N)$)**: En una red con millones de flujos, tendrías que guardar millones de números en RAM para cada IP.
3. **Inestabilidad numérica (*Catastrophic Cancellation*)**: Si se usa la fórmula simplificada $\sum x^2 - \frac{(\sum x)^2}{N}$, restar dos números gigantes produce pérdida de precisión en coma flotante.

### La Solución de NovaFlow: Algoritmo Online de Welford (1962)
Permite actualizar la media y la varianza **con un solo número a la vez en una única pasada**, usando solo **3 variables por host** ($N$, $\text{mean}$, $M_2$), consumiendo exactamente $O(1)$ de memoria:

```
Para cada nuevo flujo x:
  1. n = n + 1
  2. delta = x - mean
  3. mean = mean + (delta / n)
  4. delta2 = x - mean
  5. M2 = M2 + (delta * delta2)
  6. varianza = M2 / (n - 1)  [si n > 1]
  7. std_dev = sqrt(varianza)
```

En [`detector/profiler.py`](file:///C:/Users/villa/.gemini/antigravity/scratch/novaflow-ndr/detector/profiler.py), esta clase `WelfordAccumulator` calcula el perfil conductual de miles de hosts consumiendo menos de 5 MB de memoria total.

---

## 2. Detección de Anomalías mediante Z-Score Dinámico

Una vez que tenemos $\mu$ y $\sigma$, calculamos la distancia estadística de cualquier nueva transferencia:

$$Z = \frac{x - \mu}{\sigma}$$

- $Z = 0$: Tráfico exactamente idéntico al promedio del host.
- $Z = 1.0$: Variación normal del día a día.
- **$Z \ge 3.5$ (Umbral de NovaFlow)**: Por la regla empírica estadística y la desigualdad de Chebyshev, la probabilidad de que una observación benigna caiga a más de $3.5$ desviaciones estándar es menor al $0.05\%$. Si ocurre, se dispara una alerta de **Exfiltración por Anomalía Conductual**.

---

## 3. Entropía de la Información de Claude Shannon (Túneles DNS y DGA)

Los atacantes utilizan **Túneles DNS** (*DNS Tunneling*, MITRE T1071.004) para robar datos o enviar comandos saltándose el firewall, o algoritmos **DGA** (*Domain Generation Algorithms*, MITRE T1568.002) para generar nombres de dominio aleatorios.

Un dominio legítimo (`google.com`, `banco.com.co`, `portal-empleados.internal`) está compuesto por palabras en lenguaje natural con redundancia y patrones vocálicos repetitivos. Un payload malicioso cifrado en base32/hexadecimal (`a9f8b2c7e1d44.attacker.com`) se parece a ruido blanco aleatorio.

### La Fórmula de Shannon:
$$H(X) = - \sum_{i=1}^{k} P(x_i) \log_2 P(x_i)$$

Donde $P(x_i)$ es la frecuencia de aparición del caracter $x_i$ en la cadena.

```python
import math
from collections import Counter

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())
```

### Escala de Decisión en NovaFlow:
- $H < 2.8$: Dominios naturales y legítimos (`api.service.com`).
- $2.8 \le H \le 3.6$: Dominios con hashes moderados o CDNs.
- **$H > 3.85$**: Característico de cadenas pseudoaleatorias de DGA o datos binarios fragmentados en subdominios DNS.

---

## 4. Análisis de Cadencia Temporal: Jitter y Coeficiente de Variación ($CV$)

Cuando un troyano (como *Cobalt Strike*, *Sliver* o *Metasploit*) infecta una máquina, debe comunicarse periódicamente con su servidor C2 para recibir instrucciones (*Beaconing*).

Los humanos navegando por la web tienen intervalos entre conexiones altamente erráticos (distribución de Pareto o Poisson: hacen clic, leen durante 30 segundos, se van 5 minutos a tomar café). Las balizas de malware se programan con un temporizador (*Sleep Time*, p. ej., cada 60 segundos).

Para no ser descubiertos, los adversarios agregan **Jitter** (una variación aleatoria, p. ej., $\pm 20\%$).

### El Coeficiente de Variación ($CV$):
$$CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$

Donde $\Delta t$ es el intervalo de tiempo entre conexiones sucesivas.

- **Tráfico Humano**: $CV \ge 0.80$ (alta dispersión temporal).
- **Tráfico de Malware con Jitter**: $CV \le 0.35$ (incluso con $30\%$ de jitter sintético, la variabilidad relativa alrededor de la media es extremadamente estrecha y predecible).
- Si NovaFlow observa $CV \le 0.30$ en $\ge 5$ flujos sucesivos hacia una misma IP externa, clasifica la conexión como **MALICIOUS_C2 (Beaconing)**.

---

## 5. Counting Bloom Filter (Filtro de Bloom Contable de 8 Bits)

Para cotejar millones de IPs de Threat Intelligence (como las listas de botnets de *Abuse.ch Feodo Tracker*) en cable a velocidad gigabit:
- Una búsqueda en base de datos toma milisegundos (demasiado lenta).
- Un diccionario `dict` en Python consume megabytes de punteros y memoria.

### La Solución de NovaFlow: Counting Bloom Filter
Un array de contadores enteros de 8 bits con **$k$ funciones de hash independientes**.

### Doble Hashing de Kirsch-Mitzenmacher:
En lugar de calcular $k$ algoritmos criptográficos pesados (SHA, MD5), usamos dos hashes rápidos ($h_1$ y $h_2$) y generamos los $k$ índices con una combinación lineal:
$$g_i(x) = (h_1(x) + i \cdot h_2(x)) \pmod m \quad \text{para } i = 0, \dots, k-1$$

### Ventajas Clave:
1. **Cero Falsos Negativos**: Si una IP maliciosa está en el filtro, el algoritmo **garantiza al 100% que será encontrada**.
2. **Descarte Instantáneo $O(1)$**: Si el filtro dice "No está", el flujo se descarta en microsegundos sin tocar la base de datos.
3. **Eliminación Dinámica**: A diferencia del Bloom Filter clásico (que solo tiene bits `0` o `1` y no permite borrar sin recrearlo todo), el *Counting* Bloom Filter incrementa contadores al agregar (`+1`) y los decrementa al eliminar (`-1`), permitiendo **expirar IOCs en caliente**.
