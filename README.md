# Proyecto IEEE 802.11 — Capa de Enlace Inalámbrica
**Grupo 2**

Análisis, implementación de bajo nivel y detección de ataques sobre el estándar IEEE 802.11 (Wi-Fi). El proyecto se divide en tres componentes independientes y un generador de escenario sintético.

---

## Descripción general


| Componente | Archivo | Propósito |
|---|---|---|
| 1 | `componente_1.py` | Observación de tráfico real — clasificación de tramas por Frame Control |
| 2 | `componente_2.py` | Implementación a bajo nivel — parser propio de bytes crudos |
| 3 | `componente_3.py` | Detección de deauthentication flood — métricas y barrido de umbral |
| — | `simulador_ataque.py` | Generador del escenario de ataque sintético (PCAP + ground-truth) |

---

## Componente 1 — Captura y observación de tráfico real

Carga el archivo público `Network_Join_Nokia_Mobile.pcap` (Wireshark SampleCaptures), que registra el proceso real de asociación de un dispositivo móvil Nokia a una red Wi-Fi.

**Qué hace:**
- Lee el campo **Frame Control** byte a byte (sin usar el disector de alto nivel de Scapy).
- Extrae el tipo (bits 2–3) y el subtipo (bits 4–7) del primer byte del FC.
- Clasifica cada trama en su categoría: Gestión / Control / Datos, con el nombre del subtipo (Beacon, Authentication, Association Request, etc.).
- Imprime un conteo ordenado de mayor a menor frecuencia.

**Validación:** el conteo puede verificarse en Wireshark con *Estadísticas → Jerarquía de protocolos* o con el filtro `wlan.fc.type_subtype`.

---

## Componente 2 — Implementación a bajo nivel

Parser propio que opera directamente sobre los bytes crudos de cada trama, sin delegar en el disector automático de Scapy.

**Qué hace:**
- Extrae de cada trama: tipo, subtipo, MAC destino, MAC origen, BSSID y, si la trama es un Beacon, el SSID.
- Selecciona una trama representativa de **cada etapa** del proceso de asociación 802.11 en orden narrativo:

| # | Etapa | Tipo de trama |
|---|---|---|
| 1 | Descubrimiento | Beacon del AP |
| 2 | Descubrimiento | Probe Request del cliente |
| 3 | Descubrimiento | Probe Response del AP |
| 4 | Autenticación | Authentication |
| 5 | Asociación | Association Request |
| 6 | Asociación | Association Response |
| 7 | Transmisión | Data |

- Para la trama de Datos exige que pertenezca al mismo AP (mismo BSSID que el Beacon), garantizando coherencia narrativa aunque la captura contenga tráfico de múltiples redes.

**Validación:** cada campo mostrado puede compararse contra la disección de Wireshark expandiendo la capa *IEEE 802.11* en la trama correspondiente.

---

## Componente 3 — Detección de deauthentication flood

Detector basado en ventana temporal que identifica un ataque de *deauth flood* (como el que genera `aireplay-ng`) contra el escenario sintético.

**Algoritmo:**
1. Lee el archivo `escenario_deauth.pcap` e identifica las tramas de tipo Deauthentication (tipo=0, subtipo=12) leyendo los bits del Frame Control a mano (salta el header RadioTap cuando está presente).
2. Divide la captura en **ventanas de 1 segundo** y cuenta las deauths en cada ventana.
3. Marca como ataque toda ventana cuyo conteo supere el **umbral** (por defecto 10 deauths/ventana).
4. Compara contra `ground_truth.csv` y calcula la **matriz de confusión** y las métricas:

| Métrica | Significado |
|---|---|
| TPR / Recall | Sensibilidad — porcentaje de ventanas de ataque detectadas |
| FPR | Tasa de falsos positivos |
| Precisión | Exactitud de las alarmas disparadas |
| Exactitud | Porcentaje global de ventanas clasificadas correctamente |
| F1 | Media armónica de precisión y recall |
| Latencia | Tiempo entre el inicio del ataque y la primera alarma correcta |

5. Barre el umbral (1, 2, 3, 5, 10, 25, 50, 100, 150) para mostrar el compromiso TPR/FPR y justificar la elección final.

**Configuración por defecto:**
```
VENTANA_S = 1.0   # segundos por ventana
UMBRAL    = 10    # deauths/ventana para disparar alarma
```

---

## Generador de escenario — `simulador_ataque.py`

Genera de forma **completamente sintética** (sin transmitir tráfico real) el archivo `escenario_deauth.pcap` y el `ground_truth.csv` que consume el Componente 3.

**Línea de tiempo simulada (30 segundos):**

```
t = 0 s    Inicio de beacons periódicos del AP (cada 0.1024 s)
t = 2 s    Handshake de asociación de un cliente legítimo
             Probe Request → Probe Response → Auth → Auth → Assoc Req → Assoc Resp
t = 0–30 s Deauths legítimas dispersas (10 tramas, reason=3 "STA is leaving")
t = 15 s   ⚡ Inicio del deauth flood — 100 tramas/s, suplantando al AP
t = 20 s   ✓ Fin del ataque
```

**Parámetros configurables:**

| Parámetro | Valor por defecto | Descripción |
|---|---|---|
| `SSID` | `RedLab_Grupo2` | Nombre de la red simulada |
| `DURACION_TOTAL_S` | 30 s | Duración total de la captura |
| `BEACON_INTERVALO_S` | 0.1024 s | Intervalo entre beacons |
| `ATAQUE_INICIO_S` | 15 s | Inicio del flood |
| `ATAQUE_FIN_S` | 20 s | Fin del flood |
| `ATAQUE_TASA_HZ` | 100 | Tramas de deauth por segundo |
| `DEAUTHS_LEGITIMOS` | 10 | Deauths de fondo (no ataque) |
| `CON_RADIOTAP` | `True` | Incluir header RadioTap (simula modo monitor) |

Las deauths legítimas se dispersan intencionalmente para que un umbral demasiado bajo produzca falsos positivos, haciendo que el análisis de métricas sea honesto y no trivialmente perfecto.

---

## Archivos de datos

| Archivo | Origen | Descripción |
|---|---|---|
| `Network_Join_Nokia_Mobile.pcap` | Wireshark SampleCaptures (público) | Captura real de asociación Wi-Fi de un Nokia Mobile |
| `escenario_deauth.pcap` | Generado por `simulador_ataque.py` | Escenario sintético con deauth flood |
| `ground_truth.csv` | Generado por `simulador_ataque.py` | Etiqueta real (`es_ataque`) de cada trama |

---

## Requisitos

```bash
pip install scapy
```

Python 3.8 o superior.

---

## Ejecución

```bash
# 1. Generar el escenario de ataque (necesario antes de correr el Componente 3)
python simulador_ataque.py

# 2. Componente 1 — análisis de tráfico real
python componente_1.py

# 3. Componente 2 — parser de bajo nivel
python componente_2.py

# 4. Componente 3 — detección del ataque
python componente_3.py
```

> Los Componentes 1 y 2 requieren que `Network_Join_Nokia_Mobile.pcap` esté en el mismo directorio.  
> El Componente 3 requiere `escenario_deauth.pcap` y `ground_truth.csv` (generados por el simulador).
