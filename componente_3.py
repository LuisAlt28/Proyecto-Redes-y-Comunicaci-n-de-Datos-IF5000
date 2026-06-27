"""
COMPONENTE 3 - Deteccion de un deauthentication flood.

El detector:
  1) Lee el .pcap e identifica las deauth leyendo los BITS del Frame
     Control a mano (mismo enfoque de bajo nivel de modulo_b), NO con
     el disector de alto nivel de scapy.
  2) Cuenta deauth por VENTANA de tiempo y marca como ataque la ventana
     cuya cuenta supera un UMBRAL.
  3) Compara contra ground_truth.csv -> matriz de confusion y metricas
     honestas (TPR, FPR, latencia de deteccion).
  4) Se comparan dos umbrales para mostrar el impacto de la eleccion.
"""

import csv
import math
from scapy.all import rdpcap, RadioTap

# ===================== CONFIGURACION =====================
ARCHIVO_PCAP = "escenario_deauth.pcap"
ARCHIVO_GT   = "ground_truth.csv"

VENTANA_S    = 1.0
UMBRAL_1     = 1    # umbral bajo: detecta todo pero genera falsas alarmas
UMBRAL_2     = 10   # umbral elegido: deteccion precisa sin falsas alarmas
# ========================================================


def es_deauth_bajo_nivel(trama):
    """
    Determina si una trama es Deauthentication (tipo=0 gestion,
    subtipo=12) leyendo los bits del Frame Control directamente sobre
    los bytes crudos. Salta el header RadioTap si esta presente.
    Devuelve True/False.
    """
    raw = bytes(trama)

    # Saltar RadioTap: bytes 2-3 = it_len (longitud del header, LE)
    if trama.haslayer(RadioTap):
        rt_len = int.from_bytes(raw[2:4], "little")
        raw = raw[rt_len:]

    if len(raw) < 2:
        return False

    fc0     = raw[0]
    # Mismo calculo que en componente_2: el primer byte trae el
    # tipo y el subtipo mezclados en sus bits.
    #   >> 2 & 0x03  se queda con el tipo (0=Gestion)
    #   >> 4 & 0x0F  se queda con el subtipo (12 = Deauthentication)
    tipo    = (fc0 >> 2) & 0x03
    subtipo = (fc0 >> 4) & 0x0F

    return tipo == 0 and subtipo == 12


def cargar_tiempos_deauth(pcap):
    """Lee el pcap y devuelve (t_min, lista de tiempos de cada deauth)."""
    paquetes = rdpcap(pcap)
    t_min = min(float(p.time) for p in paquetes)
    tiempos = [float(p.time) for p in paquetes if es_deauth_bajo_nivel(p)]
    return t_min, tiempos, len(paquetes)


def ventana(t, t_min):
    """Indice de ventana al que pertenece el tiempo t."""
    return int((t - t_min) / VENTANA_S)


def conteo_por_ventana(tiempos, t_min, n_ventanas):
    """Cuenta cuantas deauth caen en cada ventana."""
    cuentas = [0] * n_ventanas
    for t in tiempos:
        v = ventana(t, t_min)
        if 0 <= v < n_ventanas:
            cuentas[v] += 1
    return cuentas


def ground_truth_por_ventana(gt_csv, t_min, n_ventanas):
    """
    Ventana = ATAQUE si contiene al menos una trama etiquetada como
    ataque en el ground-truth. Devuelve lista de booleanos.
    """
    gt = [False] * n_ventanas
    with open(gt_csv, newline="") as f:
        for fila in csv.DictReader(f):
            if int(fila["es_ataque"]) == 1:
                v = ventana(float(fila["tiempo"]), t_min)
                if 0 <= v < n_ventanas:
                    gt[v] = True
    return gt


def evaluar(cuentas, gt, umbral):
    """
    Clasifica cada ventana (cuenta >= umbral => ATAQUE) y compara con el
    ground-truth. Devuelve dict con la matriz de confusion y metricas.
    """
    VP = FP = VN = FN = 0
    primera_alarma_correcta = None
    for i, (c, real) in enumerate(zip(cuentas, gt)):
        pred = c >= umbral
        if pred and real:
            VP += 1
            if primera_alarma_correcta is None:
                primera_alarma_correcta = i
        elif pred and not real:
            FP += 1
        elif not pred and real:
            FN += 1
        else:
            VN += 1

    tpr = VP / (VP + FN) if (VP + FN) else 0.0
    fpr = FP / (FP + VN) if (FP + VN) else 0.0

    return {
        "VP": VP, "FP": FP, "VN": VN, "FN": FN,
        "tpr": tpr, "fpr": fpr,
        "primera_alarma": primera_alarma_correcta,
    }


def mostrar_deteccion(m, umbral, onset=15.0):
    """Imprime los resultados de una deteccion con un umbral dado."""
    if m["primera_alarma"] is not None:
        t_alarma = m["primera_alarma"] * VENTANA_S
        latencia = max(0.0, t_alarma - onset)
    else:
        t_alarma = None
        latencia = None

    print("=" * 60)
    print(f"DETECCION  (ventana={VENTANA_S:.0f}s, umbral={umbral} deauth/ventana)")
    print("=" * 60)
    print(f"  Verdaderos Positivos (VP): {m['VP']:>3}")
    print(f"  Falsos Positivos     (FP): {m['FP']:>3}")
    print(f"  Verdaderos Negativos (VN): {m['VN']:>3}")
    print(f"  Falsos Negativos     (FN): {m['FN']:>3}")
    print(f"  ---")
    print(f"  TPR / Recall  : {m['tpr']:.3f}")
    print(f"  FPR           : {m['fpr']:.3f}")
    if latencia is not None:
        print(f"  Latencia de deteccion: {latencia:.2f} s "
              f"(alarma en t={t_alarma:.0f}s, ataque inicia en t={onset:.0f}s)")


def main():
    t_min, tiempos, n_paquetes = cargar_tiempos_deauth(ARCHIVO_PCAP)

    paquetes = rdpcap(ARCHIVO_PCAP)
    t_fin = max(float(p.time) for p in paquetes)
    n_ventanas = int(math.ceil((t_fin - t_min) / VENTANA_S)) + 1

    cuentas = conteo_por_ventana(tiempos, t_min, n_ventanas)
    gt      = ground_truth_por_ventana(ARCHIVO_GT, t_min, n_ventanas)

    # ---------- Validacion contra Wireshark ----------
    print("=" * 60)
    print("VALIDACION DE CONTEO")
    print("=" * 60)
    print(f"  Paquetes totales en pcap : {n_paquetes}")
    print(f"  Deauth detectadas (s.12) : {len(tiempos)}")
    print(f"  (en Wireshark: filtro 'wlan.fc.type_subtype == 12')")
    print()

    # ---------- Deteccion con umbral bajo (genera falsas alarmas) ----------
    m1 = evaluar(cuentas, gt, UMBRAL_1)
    mostrar_deteccion(m1, UMBRAL_1)
    print()

    # ---------- Deteccion con umbral elegido (precisa) ----------
    m2 = evaluar(cuentas, gt, UMBRAL_2)
    mostrar_deteccion(m2, UMBRAL_2)


if __name__ == "__main__":
    main()