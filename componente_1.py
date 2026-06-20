"""
Grupo 2 - Capa de Enlace inalambrica (IEEE 802.11)
COMPONENTE 1 - Captura y observacion de trafico real.
 
Carga una captura publica reconocida (Network_Join_Nokia_Mobile.pcap,
Wireshark SampleCaptures) que contiene un proceso real de asociacion
802.11 de un dispositivo movil. Clasifica cada trama por su tipo y
subtipo real, leyendo el Frame Control, para dar una observacion
genuina de la estructura del trafico capturado.
"""
 
from scapy.all import rdpcap
 
ARCHIVO_PCAP = "Network_Join_Nokia_Mobile.pcap"
 
TIPOS = {0: "Gestion", 1: "Control", 2: "Datos", 3: "Reservado"}
SUBTIPOS_GESTION = {
    0: "Association Request", 1: "Association Response",
    2: "Reassociation Request", 3: "Reassociation Response",
    4: "Probe Request", 5: "Probe Response",
    8: "Beacon", 10: "Disassociation",
    11: "Authentication", 12: "Deauthentication",
}
SUBTIPOS_CONTROL = {11: "RTS", 12: "CTS", 13: "ACK"}
SUBTIPOS_DATOS = {
    0: "Data", 4: "Null (sin datos)",
    8: "QoS Data", 12: "QoS Null (sin datos)",
}
 
 
def clasificar(trama):
    """Lee el Frame Control a mano y devuelve 'Tipo / Subtipo'."""
    raw = bytes(trama)
    if len(raw) < 2:
        return "Trama invalida"
 
    fc0     = raw[0]
    # El primer byte del Frame Control trae el tipo y el subtipo
    # mezclados en los mismos bits. Para separarlos:
    #   >> 2  recorre el byte 2 posiciones a la derecha (descarta los
    #         2 bits menos significativos, que son la version del protocolo)
    #   & 0x03  se queda solo con los 2 bits que indican el tipo
    #   >> 4  recorre el byte 4 posiciones (deja solo los 4 bits altos)
    #   & 0x0F  se queda con esos 4 bits, que indican el subtipo
    tipo    = (fc0 >> 2) & 0x03
    subtipo = (fc0 >> 4) & 0x0F
 
    tabla = {0: SUBTIPOS_GESTION, 1: SUBTIPOS_CONTROL, 2: SUBTIPOS_DATOS}.get(tipo, {})
    nombre_subtipo = tabla.get(subtipo, f"Subtipo {subtipo}")
    return f"{TIPOS.get(tipo, 'Desconocido')} / {nombre_subtipo}"
 
 
def main():
    paquetes = rdpcap(ARCHIVO_PCAP)
 
    print(f"Archivo analizado : {ARCHIVO_PCAP}")
    print(f"Tramas capturadas : {len(paquetes)}")
    print("=" * 50)
 
    conteo = {}
    for trama in paquetes:
        nombre = clasificar(trama)
        conteo[nombre] = conteo.get(nombre, 0) + 1
 
    print("Tipos de trama encontrados (por Frame Control):")
    for nombre, cantidad in sorted(conteo.items(), key=lambda x: -x[1]):
        print(f"  {nombre}: {cantidad}")
 
    print()
    print("Validacion: este conteo debe coincidir con Wireshark usando")
    print("Estadisticas > Jerarquia de protocolos, o el filtro wlan.fc.type_subtype")
    print("para cada subtipo individual.")
 
 
if __name__ == "__main__":
    main()