"""
simulador_ataque.py
-------------------------------------------------------------
Grupo 2 - Capa de Enlace inalambrica (IEEE 802.11)
Genera de forma SINTETICA (sin transmitir nada) un archivo .pcap
que contiene una linea de tiempo realista:
 
   1) Fase NORMAL : beacons periodicos del AP + un handshake de
                    asociacion (probe / auth / assoc) de un cliente.
   2) Fase ATAQUE : sobre el trafico normal se inyecta un
                    deauthentication flood (subtipo 12) suplantando
                    al AP, como lo haria aireplay-ng.
 
Como nosotros construimos el archivo, sabemos exactamente que tramas
son ataque -> se escribe ademas un ground-truth (CSV) para poder
calcular Verdaderos/Falsos Positivos en el detector (Componente 3).
 
NO transmite trafico: solo escribe a disco con wrpcap().
Esto es legitimo segun el enunciado ("...pueden ser generados por
nosotros") y no toca infraestructura de terceros.
"""
 
import csv
import random
from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Elt,
    Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq,
    Dot11ProbeResp, Dot11Deauth, wrpcap,
)
 
# ===================== CONFIGURACION =====================
SSID        = "RedLab_Grupo2"
BSSID       = "02:11:22:33:44:55"   # MAC del AP de prueba (localmente administrada)
CLIENTE     = "02:aa:bb:cc:dd:ee"   # MAC de un cliente legitimo
BROADCAST   = "ff:ff:ff:ff:ff:ff"
 
# Si tu captura va a venir de modo monitor, los pcap traen header
# RadioTap. Lo dejamos en True para que el archivo se parezca a una
# captura real y para que el parser (modulo_b) tenga que saltarlo.
CON_RADIOTAP = True
 
DURACION_TOTAL_S   = 30.0   # duracion de toda la simulacion
BEACON_INTERVALO_S = 0.1024 # un AP real emite ~10 beacons/segundo
 
ATAQUE_INICIO_S    = 15.0   # cuando empieza el deauth flood
ATAQUE_FIN_S       = 20.0   # cuando termina
ATAQUE_TASA_HZ     = 100    # tramas de deauth por segundo (flood agresivo)
 
# Deauths LEGITIMOS de fondo: una red real emite alguna deauth de vez en
# cuando (un cliente que se va, roaming, etc.). Los repartimos por la fase
# normal para que el detector PUEDA equivocarse: con un umbral demasiado
# bajo, estas tramas legitimas se convierten en falsos positivos. Asi las
# metricas no salen triviales (100% perfecto) y el analisis es honesto.
DEAUTHS_LEGITIMOS  = 10     # cuantas deauth legitimas dispersas
SEMILLA            = 42     # reproducibilidad
 
ARCHIVO_PCAP = "escenario_deauth.pcap"
ARCHIVO_GT   = "ground_truth.csv"   # etiqueta real de cada trama
# ========================================================
 
 
def _l2(*capas):
    """Antepone RadioTap si la config lo pide y arma la trama."""
    base = capas[0]
    for c in capas[1:]:
        base = base / c
    return (RadioTap() / base) if CON_RADIOTAP else base
 
 
def beacon():
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=BSSID, addr3=BSSID)
    cuerpo = (Dot11Beacon(cap="ESS+privacy")
              / Dot11Elt(ID="SSID", info=SSID)
              / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96"))
    return _l2(dot11, cuerpo)
 
 
def probe_req():
    dot11 = Dot11(type=0, subtype=4, addr1=BROADCAST, addr2=CLIENTE, addr3=BROADCAST)
    return _l2(dot11, Dot11ProbeReq() / Dot11Elt(ID="SSID", info=SSID))
 
 
def probe_resp():
    dot11 = Dot11(type=0, subtype=5, addr1=CLIENTE, addr2=BSSID, addr3=BSSID)
    return _l2(dot11, Dot11ProbeResp() / Dot11Elt(ID="SSID", info=SSID))
 
 
def auth(emisor, receptor, seq):
    dot11 = Dot11(type=0, subtype=11, addr1=receptor, addr2=emisor, addr3=BSSID)
    return _l2(dot11, Dot11Auth(seqnum=seq))
 
 
def assoc_req():
    dot11 = Dot11(type=0, subtype=0, addr1=BSSID, addr2=CLIENTE, addr3=BSSID)
    return _l2(dot11, Dot11AssoReq() / Dot11Elt(ID="SSID", info=SSID))
 
 
def assoc_resp():
    dot11 = Dot11(type=0, subtype=1, addr1=CLIENTE, addr2=BSSID, addr3=BSSID)
    return _l2(dot11, Dot11AssoResp())
 
 
def deauth():
    # El AP "expulsa" al cliente. reason=7 es el que usa aireplay-ng.
    dot11 = Dot11(type=0, subtype=12, addr1=CLIENTE, addr2=BSSID, addr3=BSSID)
    return _l2(dot11, Dot11Deauth(reason=7))
 
 
def deauth_legitimo(cliente):
    # Deauth normal de la red: un cliente se desconecta ordenadamente.
    # reason=3 = "STA is leaving". OJO: el detector NO debe distinguir por
    # reason code (un atacante puede falsificar cualquiera); detecta por
    # TASA. Por eso estas tramas tambien cuentan para el conteo por ventana.
    dot11 = Dot11(type=0, subtype=12, addr1=cliente, addr2=BSSID, addr3=BSSID)
    return _l2(dot11, Dot11Deauth(reason=3))
 
 
def construir_escenario(t0=1_700_000_000.0):
    """
    Devuelve una lista de (paquete, es_ataque) ordenada por tiempo.
    t0 es un timestamp UNIX base arbitrario; lo importante son los
    intervalos relativos.
    """
    eventos = []  # (tiempo_relativo, paquete, es_ataque)
 
    # --- 1) Beacons periodicos durante toda la simulacion ---
    t = 0.0
    while t < DURACION_TOTAL_S:
        eventos.append((t, beacon(), False))
        t += BEACON_INTERVALO_S
 
    # --- 2) Handshake de asociacion de un cliente legitimo (~t=2s) ---
    eventos.append((2.00, probe_req(),            False))
    eventos.append((2.05, probe_resp(),           False))
    eventos.append((2.10, auth(CLIENTE, BSSID, 1), False))  # cliente -> AP
    eventos.append((2.15, auth(BSSID, CLIENTE, 2), False))  # AP -> cliente
    eventos.append((2.20, assoc_req(),            False))
    eventos.append((2.25, assoc_resp(),           False))
 
    # --- 3) Deauths LEGITIMOS dispersos en la fase normal ---
    # Repartidos fuera de la ventana de ataque, en momentos aleatorios pero
    # reproducibles. Etiqueta = False (no son ataque). A veces caen dos en el
    # mismo segundo (cliente reintentando), lo que estresa al detector.
    rnd = random.Random(SEMILLA)
    for _ in range(DEAUTHS_LEGITIMOS):
        # tiempo en [0, ATAQUE_INICIO) U (ATAQUE_FIN, DURACION_TOTAL)
        if rnd.random() < 0.5:
            t = rnd.uniform(0.5, ATAQUE_INICIO_S - 0.5)
        else:
            t = rnd.uniform(ATAQUE_FIN_S + 0.5, DURACION_TOTAL_S - 0.5)
        # cliente legitimo aleatorio que se desconecta
        cliente = "02:cc:%02x:%02x:%02x:%02x" % tuple(rnd.randint(0, 255) for _ in range(4))
        eventos.append((t, deauth_legitimo(cliente), False))
 
    # --- 4) Deauth flood en la ventana de ataque ---
    paso = 1.0 / ATAQUE_TASA_HZ
    t = ATAQUE_INICIO_S
    while t < ATAQUE_FIN_S:
        eventos.append((t, deauth(), True))
        t += paso
 
    # Ordenar cronologicamente y fijar timestamps reales en cada paquete
    eventos.sort(key=lambda e: e[0])
    salida = []
    for t_rel, pkt, es_ataque in eventos:
        pkt.time = t0 + t_rel
        salida.append((pkt, es_ataque))
    return salida
 
 
def main():
    escenario = construir_escenario()
    paquetes  = [p for p, _ in escenario]
 
    wrpcap(ARCHIVO_PCAP, paquetes)
 
    # Ground-truth: indice, tiempo y etiqueta real de cada trama
    with open(ARCHIVO_GT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["indice", "tiempo", "es_ataque"])
        for i, (pkt, es_ataque) in enumerate(escenario):
            w.writerow([i, f"{pkt.time:.4f}", int(es_ataque)])
 
    total   = len(escenario)
    ataques = sum(1 for _, a in escenario if a)
    print(f"Generado: {ARCHIVO_PCAP}")
    print(f"  Tramas totales      : {total}")
    print(f"  Tramas normales     : {total - ataques}")
    print(f"  Deauths legitimos   : {DEAUTHS_LEGITIMOS} (fondo, reason=3)")
    print(f"  Tramas ataque       : {ataques} "
          f"(deauth flood {ATAQUE_INICIO_S:.0f}-{ATAQUE_FIN_S:.0f}s, "
          f"{ATAQUE_TASA_HZ} tramas/s, reason=7)")
    print(f"  RadioTap            : {'si' if CON_RADIOTAP else 'no'}")
    print(f"Ground-truth          : {ARCHIVO_GT}")
 
 
if __name__ == "__main__":
    main()