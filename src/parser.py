"""
Módulo parser.py

Este módulo proporciona funciones para la ingesta y normalización de logs en diferentes formatos:
- CSV (Linux y Windows)
- JSON / NDJSON
- SYSLOG
- EVTX (si está disponible el soporte)

Incluye utilidades para copiar archivos a una carpeta temporal, normalizar timestamps y severidades,
y convertir los eventos de logs a un formato homogéneo para su posterior análisis.
"""

import os
import shutil
import tempfile
import json
import csv
import re
from datetime import datetime

# Soporte EVTX opcional
try:
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET
    EVTX_SUPPORT = True
except ImportError:
    EVTX_SUPPORT = False

def guardar_en_temporal(ruta_archivo):
    """
    Copia el archivo especificado a la carpeta temporal del sistema.

    Args:
        ruta_archivo (str): Ruta absoluta del archivo a copiar.

    Returns:
        str or None: Ruta del archivo copiado en la carpeta temporal, o None si falla.
    """
    if not os.path.isfile(ruta_archivo):
        print(" Error: la ruta no existe o no es un archivo.")
        return None
    nombre_archivo = os.path.basename(ruta_archivo)
    ruta_temporal = os.path.join(tempfile.gettempdir(), nombre_archivo)
    shutil.copy2(ruta_archivo, ruta_temporal)
    print(f" Log copiado a carpeta temporal: {ruta_temporal}")
    return ruta_temporal

def normalizar_timestamp(ts):
    """
    Convierte un timestamp a formato ISO 8601 si es posible.

    Args:
        ts (str): Timestamp de entrada.

    Returns:
        str: Timestamp en formato ISO 8601 o el valor original si no se puede convertir.
    """
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.isoformat()
    except ValueError:
        try:
            # Intento parseo de syslog (Linux): 'Sep 02 17:23:54'
            dt = datetime.strptime(ts, "%b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            return ts

def normalizar_severity(sev):
    """
    Normaliza el valor de severidad a un entero entre 0 y 10.

    Args:
        sev (str or int): Severidad de entrada.

    Returns:
        int: Severidad normalizada.
    """
    try:
        sev = int(sev)
        return max(0, min(sev, 10))
    except (TypeError, ValueError):
        return 0

def procesar_csv(ruta):
    """
    Procesa un archivo CSV (Linux/otros) y normaliza los eventos.

    Args:
        ruta (str): Ruta del archivo CSV.

    Returns:
        list: Lista de eventos normalizados.
    """
    if not ruta.endswith(".csv"):
        print(" Atención: el archivo no tiene extensión .csv")
    datos = []
    lineas_invalidas = 0
    with open(ruta, newline='', encoding="utf-8", errors="ignore") as f:
        lector = csv.DictReader(f)
        for fila in lector:
            try:
                datos.append({
                    "timestamp": normalizar_timestamp(fila.get("timestamp", "")),
                    "host": fila.get("host", ""),
                    "process": fila.get("process", ""),
                    "message": fila.get("message", ""),
                    "severity": normalizar_severity(fila.get("severity", 0))
                })
            except Exception:
                lineas_invalidas += 1
    print(f" CSV cargado con {len(datos)} eventos normalizados, {lineas_invalidas} líneas inválidas.")
    return datos

def procesar_csv_windows(ruta):
    """
    Procesa un archivo CSV exportado desde Windows Event Viewer y normaliza los eventos.

    Args:
        ruta (str): Ruta del archivo CSV.

    Returns:
        list: Lista de eventos normalizados.
    """
    if not ruta.endswith(".csv"):
        print(" Atención: el archivo no tiene extensión .csv")
    datos = []
    lineas_invalidas = 0
    with open(ruta, newline='', encoding="utf-8", errors="ignore") as f:
        lector = csv.DictReader(f)
        for fila in lector:
            try:
                datos.append({
                    "timestamp": normalizar_timestamp(fila.get("TimeCreated", "")),
                    "host": fila.get("Computer", ""),
                    "process": fila.get("ProviderName", "unknown"),
                    "message": fila.get("Message", ""),
                    "severity": normalizar_severity(fila.get("Level", 0))
                })
            except Exception:
                lineas_invalidas += 1
    print(f" CSV de Windows cargado con {len(datos)} eventos normalizados, {lineas_invalidas} líneas inválidas.")
    return datos

def procesar_json(ruta):
    """
    Procesa un archivo JSON o NDJSON de logs y normaliza los eventos.

    Args:
        ruta (str): Ruta del archivo JSON.

    Returns:
        list: Lista de eventos normalizados.
    """
    if not ruta.endswith(".json"):
        print(" Atención: el archivo no tiene extensión .json")
    datos = []
    lineas_invalidas = 0
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                obj = json.loads(linea)
                datos.append({
                    "timestamp": normalizar_timestamp(obj.get("timestamp", "")),
                    "host": obj.get("agent", {}).get("name", obj.get("manager", {}).get("name", "")),
                    "process": obj.get("predecoder", {}).get("program_name",
                                  obj.get("decoder", {}).get("name", "unknown")),
                    "message": obj.get("full_log", ""),
                    "severity": normalizar_severity(obj.get("rule", {}).get("level", 0))
                })
            except json.JSONDecodeError:
                lineas_invalidas += 1
    print(f" JSON/NDJSON cargado con {len(datos)} eventos normalizados, {lineas_invalidas} líneas inválidas.")
    return datos

def procesar_syslog(ruta):
    """
    Procesa un archivo SYSLOG (.log) y normaliza los eventos.

    Args:
        ruta (str): Ruta del archivo SYSLOG.

    Returns:
        list: Lista de eventos normalizados.
    """
    if not ruta.endswith(".log"):
        print(" Atención: el archivo no tiene extensión .log")
    datos = []
    regex = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)$')
    lineas_invalidas = 0
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            match = regex.match(linea.strip())
            if match:
                datos.append({
                    "timestamp": normalizar_timestamp(match.group(1)),
                    "host": match.group(2),
                    "process": match.group(3),
                    "message": match.group(4),
                    "severity": 0
                })
            else:
                lineas_invalidas += 1
    print(f" SYSLOG cargado con {len(datos)} eventos normalizados, {lineas_invalidas} líneas inválidas.")
    return datos

def procesar_evtx(ruta):
    """
    Procesa un archivo EVTX de Windows y normaliza los eventos.

    Args:
        ruta (str): Ruta del archivo EVTX.

    Returns:
        list: Lista de eventos normalizados.
    """
    if not EVTX_SUPPORT:
        print(" Soporte EVTX no disponible. Instala 'python-evtx'")
        return []
    datos = []
    lineas_invalidas = 0
    try:
        with Evtx(ruta) as evtx:
            for registro in evtx.records():
                try:
                    xml = ET.fromstring(registro.xml())
                    datos.append({
                        "timestamp": normalizar_timestamp(xml.findtext(".//TimeCreated/@SystemTime") or ""),
                        "host": xml.findtext(".//Computer") or "",
                        "process": xml.findtext(".//Provider/@Name") or "unknown",
                        "message": xml.findtext(".//Message") or "",
                        "severity": normalizar_severity(xml.findtext(".//Level") or 0)
                    })
                except Exception:
                    lineas_invalidas += 1
        print(f" EVTX cargado con {len(datos)} eventos normalizados, {lineas_invalidas} líneas inválidas.")
    except Exception as e:
        print(" Error leyendo EVTX:", e)
    return datos