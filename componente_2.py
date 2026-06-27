"""
COMPONENTE 2 - Implementacion a bajo nivel.
Parser propio que opera directamente sobre los bytes crudos de cada
trama (Frame Control, direcciones MAC, SSID), sin delegar en el
disector de alto nivel de Scapy.

Para evidenciar la estructura de las tramas de GESTION y de DATOS, y
el proceso completo de ASOCIACION (descubrimiento, autenticacion,
asociacion) tal como lo pide el enunciado, se selecciona a proposito
una trama representativa de cada etapa, en vez de tomar las primeras
N tramas del archivo (que en una captura real suelen ser todas del
mismo tipo, p. ej. Beacons repetidos).
"""


from scapy.all import rdpcap

ARCHIVO_PCAP = "Network_Join_Nokia_Mobile.pcap"

# Tipos de trama 802.11
TIPOS = {0: "Gestión", 1: "Control", 2: "Datos"}
SUBTIPOS_GESTION = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication"
}
SUBTIPOS_DATOS = {0: "Data", 4: "Null (sin datos)", 8: "QoS Data", 12: "QoS Null (sin datos)"}


# Etapas del proceso de asociacion + una trama de Datos, en el orden en que ocurren realmente en la red. Cada entrada es (tipo, subtipo, etiqueta).
ETAPAS = [
    (0, 8,  "1. Descubrimiento -> Beacon del router"),
    (0, 4,  "2. Descubrimiento -> Solicitud de sondeo del cliente"),
    (0, 5,  "3. Descubrimiento -> Respuesta de sondeo del router"),
    (0, 11, "4. Autenticacion -> Autenticación"),
    (0, 0,  "5. Asociacion -> Solicitud de asociación"),
    (0, 1,  "6. Asociacion -> Respuesta de asociación"),
    (2, 0,  "7. Transmision de datos -> Datos"),
]


def parsear_trama(trama, etiqueta):
    # Obtener bytes crudos
    raw = bytes(trama)
    if len(raw) < 24:
        return

    # Extraer Frame Control (primeros 2 bytes)
    fc = raw[0:2]
    # El primer byte trae el tipo y el subtipo mezclados en sus bits:
    #   >> 2 & 0x03  descarta los 2 bits de version y se queda con
    #                los 2 bits del tipo (0=Gestion, 1=Control, 2=Datos)
    #   >> 4 & 0x0F  se queda con los 4 bits altos, que son el subtipo
    tipo    = (fc[0] >> 2) & 0x03
    subtipo = (fc[0] >> 4) & 0x0F

    # Extraer MACs (bytes 4 al 22)
    mac_dest   = raw[4:10]
    mac_origen = raw[10:16]
    bssid      = raw[16:22]

    # Formatear MACs
    def fmt_mac(m):
        return ":".join(f"{b:02x}" for b in m)

    if tipo == 0:
        subtipo_nombre = SUBTIPOS_GESTION.get(subtipo, f"Subtipo {subtipo}")
    elif tipo == 2:
        subtipo_nombre = SUBTIPOS_DATOS.get(subtipo, f"Subtipo {subtipo}")
    else:
        subtipo_nombre = f"Subtipo {subtipo}"

    tipo_nombre = TIPOS.get(tipo, "Desconocido")

    print(f"\n{'='*55}")
    print(f"{etiqueta}")
    print(f"  Tipo:        {tipo_nombre} ({tipo})")
    print(f"  Subtipo:     {subtipo_nombre} ({subtipo})")
    print(f"  MAC Destino: {fmt_mac(mac_dest)}")
    print(f"  MAC Origen:  {fmt_mac(mac_origen)}")
    print(f"  BSSID:       {fmt_mac(bssid)}")

    # Si es Beacon, extraer SSID
    if tipo == 0 and subtipo == 8 and len(raw) > 36:
        ssid_len = raw[37]
        ssid = raw[38:38+ssid_len].decode("utf-8", errors="ignore")
        print(f"  SSID:        {ssid}")


def main():
    paquetes = rdpcap(ARCHIVO_PCAP)
    print(f"Archivo analizado: {ARCHIVO_PCAP}")
    print(f"Total de tramas en el archivo: {len(paquetes)}\n")
    print("Se selecciona una trama representativa de cada etapa del proceso")
    print("de asociacion, mas una trama de Datos de la MISMA red:\n")

    # --- Paso 1: encontrar el Beacon primero para conocer el BSSID del AP ---
    bssid_ap = None
    for trama in paquetes:
        raw = bytes(trama)
        if len(raw) < 24:
            continue
        tipo, subtipo = (raw[0] >> 2) & 0x03, (raw[0] >> 4) & 0x0F
        if tipo == 0 and subtipo == 8:  # Beacon
            bssid_ap = raw[16:22]
            break

    # --- Paso 2: recorrer el archivo y guardar una trama por etapa ---
    encontradas = {}  # etapa_texto -> trama
    pendientes = list(ETAPAS)

    for trama in paquetes:
        if not pendientes:
            break
        raw = bytes(trama)
        if len(raw) < 24:
            continue
        tipo, subtipo = (raw[0] >> 2) & 0x03, (raw[0] >> 4) & 0x0F
        bssid = raw[16:22]

        for etapa in pendientes:
            if etapa[0] != tipo or etapa[1] != subtipo:
                continue
            # Para la trama de Datos, exigir que sea de la MISMA red que el
            # Beacon (mismo BSSID), para que la narrativa sea coherente y no
            # se mezcle trafico de otra red capturada por interferencia.
            if tipo == 2 and bssid_ap is not None and bssid != bssid_ap:
                continue
            encontradas[etapa[2]] = trama
            pendientes.remove(etapa)
            break

    # --- Paso 3: mostrar en el orden narrativo (1 a 7), no el de llegada ---
    for etapa in ETAPAS:
        trama = encontradas.get(etapa[2])
        if trama is not None:
            parsear_trama(trama, etapa[2])


    faltantes = [e[2] for e in ETAPAS if e[2] not in encontradas]
    if faltantes:
        print(f"\n(No se encontraron en el archivo: {', '.join(faltantes)})")

    print()
    print("Validacion: cada campo mostrado puede compararse contra la")
    print("diseccion de Wireshark abriendo la trama correspondiente y")
    print("expandiendo la capa 'IEEE 802.11'.")


if __name__ == "__main__":
    main()