"""
SOC Automation Toolkit - Módulo principal

Este módulo proporciona una interfaz de línea de comandos para la ingesta, visualización y resumen de logs
de diferentes formatos (CSV, JSON, SYSLOG, EVTX) en un flujo de trabajo de análisis SOC.
Permite cargar eventos desde archivos, normalizarlos y mostrar información relevante para el usuario.

Funciones principales:
- menu_principal: Menú principal de la aplicación.
- menu_ingesta: Menú para seleccionar el tipo de archivo de log a cargar.
- mostrar_eventos: Muestra los primeros eventos cargados.
- resumen_eventos: Muestra un resumen de los eventos cargados.
"""

from parser import (
    guardar_en_temporal,
    procesar_csv,
    procesar_csv_windows,
    procesar_json,
    procesar_syslog,
    procesar_evtx,
    EVTX_SUPPORT
)

def menu_ingesta(datos_cargados):
    """
    Muestra el menú de ingesta de logs y permite al usuario seleccionar el tipo de archivo a cargar.
    Procesa el archivo seleccionado y añade los eventos normalizados a la lista de datos cargados.

    Args:
        datos_cargados (list): Lista donde se almacenan los eventos cargados.
    """
    while True:
        print("\n--- Ingesta de logs ---")
        print("1. CSV (Linux/otros)")
        print("2. JSON / NDJSON")
        print("3. SYSLOG (.log)")
        print("4. CSV Windows")
        print("5. EVTX Windows")
        print("6. Volver al menú principal")

        opcion = input("Seleccione una opción: ")

        if opcion == "6":
            break

        if opcion not in ["1","2","3","4","5"]:
            print("Opción no válida.")
            continue

        ruta = input("Introduzca la ruta absoluta del archivo: ")
        ruta_temp = guardar_en_temporal(ruta)
        if not ruta_temp:
            continue

        if opcion == "1":
            nuevos_datos = procesar_csv(ruta_temp)
            tipo = "CSV_Linux"
        elif opcion == "2":
            nuevos_datos = procesar_json(ruta_temp)
            tipo = "JSON"
        elif opcion == "3":
            nuevos_datos = procesar_syslog(ruta_temp)
            tipo = "SYSLOG"
        elif opcion == "4":
            nuevos_datos = procesar_csv_windows(ruta_temp)
            tipo = "CSV_Windows"
        elif opcion == "5":
            nuevos_datos = procesar_evtx(ruta_temp)
            tipo = "EVTX_Windows"

        if nuevos_datos:
            for evento in nuevos_datos:
                evento["_log_type"] = tipo
            datos_cargados.extend(nuevos_datos)
            print(f"Total eventos cargados hasta ahora: {len(datos_cargados)}")
        else:
            print("No se han cargado eventos de este archivo.")

def mostrar_eventos(datos_cargados):
    """
    Muestra los primeros 3 eventos normalizados de los datos cargados.

    Args:
        datos_cargados (list): Lista de eventos cargados.
    """
    if not datos_cargados:
        print("No hay datos cargados.")
        return
    print("\n=== Primeros 3 eventos normalizados ===")
    for evento in datos_cargados[:3]:
        print(f"timestamp: {evento['timestamp']}, host: {evento['host']}, "
              f"process: {evento['process']}, severity: {evento['severity']}, "
              f"message: {evento['message'][:80]}{'...' if len(evento['message'])>80 else ''}")

def resumen_eventos(datos_cargados):
    """
    Muestra un resumen de la cantidad total de eventos cargados y su distribución por tipo de log.

    Args:
        datos_cargados (list): Lista de eventos cargados.
    """
    if not datos_cargados:
        print("No hay datos cargados.")
        return
    print("\n=== Resumen de eventos cargados ===")
    print(f"Total eventos: {len(datos_cargados)}")
    tipos = {}
    for evento in datos_cargados:
        tipo = evento.get("_log_type", "Desconocido")
        tipos[tipo] = tipos.get(tipo, 0) + 1
    for tipo, cantidad in tipos.items():
        print(f"{tipo}: {cantidad} eventos")

def menu_principal():
    """
    Muestra el menú principal de la aplicación y gestiona la navegación entre las diferentes opciones.
    """
    datos_cargados = []

    while True:
        print("\n=== SOC Automation Toolkit ===")
        print("1. Ingesta de logs")
        print("2. Mostrar primeros 3 eventos cargados")
        print("3. Resumen de eventos cargados")
        print("4. Salir")

        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            menu_ingesta(datos_cargados)
        elif opcion == "2":
            mostrar_eventos(datos_cargados)
        elif opcion == "3":
            resumen_eventos(datos_cargados)
        elif opcion == "4":
            print("Saliendo...")
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    menu_principal()
