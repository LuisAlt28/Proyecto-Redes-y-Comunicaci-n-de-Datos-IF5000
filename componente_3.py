"""
COMPONENTE 3 - Deteccion de un deauthentication flood.

El detector:

  1) Lee el .pcap e identifica las deauth leyendo los BITS del Frame
     Control a mano (mismo enfoque de bajo nivel de modulo_b), NO con
     el disector de alto nivel de scapy.
  2) Cuenta deauth por VENTANA de tiempo y marca como ataque la ventana
     cuya cuenta supera un UMBRAL.
  3) Compara contra ground_truth.csv -> matriz de confusion y metricas
     honestas (TPR, FPR, precision, exactitud, F1, latencia de deteccion).
  4) Barre el umbral para mostrar el compromiso TPR/FPR y justificar la
     eleccion final.

"""

import csv
import math
from scapy.all import rdpcap, RadioTap

# ===================== CONFIGURACION =====================
ARCHIVO_PCAP = "escenario_deauth.pcap"
ARCHIVO_GT   = "ground_truth.csv"

VENTANA_S    = 1.0    
UMBRAL       = 10     
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
    primera_alarma_correcta = None  # indice de ventana del 1er VP
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

    tpr       = VP / (VP + FN) if (VP + FN) else 0.0   # recall / sensibilidad
    fpr       = FP / (FP + VN) if (FP + VN) else 0.0
    precision = VP / (VP + FP) if (VP + FP) else 0.0
    exactitud = (VP + VN) / (VP + VN + FP + FN)
    f1        = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) else 0.0

    return {
        "VP": VP, "FP": FP, "VN": VN, "FN": FN,
        "tpr": tpr, "fpr": fpr, "precision": precision,
        "exactitud": exactitud, "f1": f1,
        "primera_alarma": primera_alarma_correcta,
    }


def main():
    t_min, tiempos, n_paquetes = cargar_tiempos_deauth(ARCHIVO_PCAP)

   
    paquetes = rdpcap(ARCHIVO_PCAP)
    t_fin = max(float(p.time) for p in paquetes)
    n_ventanas = int(math.ceil((t_fin - t_min) / VENTANA_S)) + 1

    cuentas = conteo_por_ventana(tiempos, t_min, n_ventanas)
    gt      = ground_truth_por_ventana(ARCHIVO_GT, t_min, n_ventanas)

    # ---------- Validacion contra Wireshark ----------
    print("=" * 60)
    print("VALIDACION DE CONTEO ")
    print("=" * 60)
    print(f"  Paquetes totales en pcap : {n_paquetes}")
    print(f"  Deauth detectadas (s.12) : {len(tiempos)}")
    print(f"  (en Wireshark: filtro 'wlan.fc.type_subtype == 12')")

    # ---------- Deteccion con el umbral elegido ----------
    m = evaluar(cuentas, gt, UMBRAL)
    onset = 15.0  # inicio del ataque 
    if m["primera_alarma"] is not None:
        t_alarma = m["primera_alarma"] * VENTANA_S
        latencia = max(0.0, t_alarma - onset)
    else:
        t_alarma = None
        latencia = None

    print()
    print("=" * 60)
    print(f"DETECCION  (ventana={VENTANA_S:.0f}s, umbral={UMBRAL} deauth/ventana)")
    print("=" * 60)
    print(f"  Verdaderos Positivos (VP): {m['VP']:>3}")
    print(f"  Falsos Positivos     (FP): {m['FP']:>3}")
    print(f"  Verdaderos Negativos (VN): {m['VN']:>3}")
    print(f"  Falsos Negativos     (FN): {m['FN']:>3}")
    print(f"  ---")
    print(f"  TPR / Recall  : {m['tpr']:.3f}")
    print(f"  FPR           : {m['fpr']:.3f}")
    print(f"  Precision     : {m['precision']:.3f}")
    print(f"  Exactitud     : {m['exactitud']:.3f}")
    print(f"  F1            : {m['f1']:.3f}")
    if latencia is not None:
        print(f"  Latencia de deteccion: {latencia:.2f} s "
              f"(alarma en t={t_alarma:.0f}s, ataque inicia en t={onset:.0f}s)")

    # ---------- Barrido de umbral ----------
    print()
    print("=" * 60)
    print("BARRIDO DE UMBRAL ")
    print("=" * 60)
    print(f"  {'umbral':>6} | {'VP':>3} {'FP':>3} {'FN':>3} | {'TPR':>5} {'FPR':>5} {'F1':>5}")
    print("  " + "-" * 46)
    for u in [1, 2, 3, 5, 10, 25, 50, 100, 150]:
        r = evaluar(cuentas, gt, u)
        print(f"  {u:>6} | {r['VP']:>3} {r['FP']:>3} {r['FN']:>3} | "
              f"{r['tpr']:.2f}  {r['fpr']:.2f}  {r['f1']:.2f}")


if __name__ == "__main__":
    main()