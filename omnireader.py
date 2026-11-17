#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMNIREADER 2.3 CLI — laboratorio didáctico PC/SC para tarjetas RFID.

Alcance de seguridad:
- Consulta UID/ATR y monitoriza presencia de tarjetas.
- Lee y escribe ÚNICAMENTE el bloque de datos 4 de una tarjeta de laboratorio.
- Requiere una clave A/B conocida, introducida manualmente en cada operación.
- No lee tráileres, no modifica el bloque fabricante, no busca claves y no clona tarjetas.
- No persiste claves. Los informes se guardan únicamente cuando el usuario lo solicita.

Compatibilidad: Python 3 + pyscard + lector PC/SC compatible con los APDU del fabricante.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from importlib.metadata import PackageNotFoundError, version as package_version
from getpass import getpass
from pathlib import Path
from typing import Any, Callable, Optional

APP_NAME = "OMNIREADER"
VERSION = "2.3"
LAB_BLOCK = 4
KEY_SLOT = 0
KEY_LENGTH = 6
BLOCK_SIZE = 16
POLL_INTERVAL = 0.5

try:
    from smartcard.System import readers as pcsc_readers
    from smartcard.Exceptions import CardConnectionException, NoCardException
except ImportError:
    print("OMNIREADER necesita pyscard. En Kali ejecuta:\n")
    print("  sudo apt update")
    print("  sudo apt install pcscd libccid python3-pyscard -y")
    print("  sudo systemctl enable --now pcscd")
    sys.exit(1)


class Theme:
    enabled = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    RESET = "\033[0m" if enabled else ""
    BOLD = "\033[1m" if enabled else ""
    DIM = "\033[2m" if enabled else ""
    RED = "\033[91m" if enabled else ""
    GREEN = "\033[92m" if enabled else ""
    YELLOW = "\033[93m" if enabled else ""
    BLUE = "\033[94m" if enabled else ""
    MAGENTA = "\033[95m" if enabled else ""
    CYAN = "\033[96m" if enabled else ""
    WHITE = "\033[97m" if enabled else ""


def paint(value: Any, color: str) -> str:
    return f"{color}{value}{Theme.RESET}"


def rule(char: str = "─", width: int = 72) -> str:
    width = max(40, min(width, shutil.get_terminal_size((80, 24)).columns - 2))
    return char * width


def title(text: str) -> None:
    print("\n" + paint(rule(), Theme.CYAN))
    print(paint(f"  {text}", Theme.BOLD + Theme.WHITE))
    print(paint(rule(), Theme.CYAN))


def ok(message: str) -> None:
    print(f"{paint('[OK]', Theme.GREEN)} {message}")


def info(message: str) -> None:
    print(f"{paint('[i]', Theme.CYAN)} {message}")


def warn(message: str) -> None:
    print(f"{paint('[!]', Theme.YELLOW)} {message}")


def fail(message: str) -> None:
    print(f"{paint('[ERROR]', Theme.RED)} {message}")


class OmniError(Exception):
    """Error operativo mostrado de forma legible en la interfaz."""


def madrid_now() -> datetime:
    """Hora local de Madrid, independiente de la zona horaria del sistema."""
    try:
        return datetime.now(ZoneInfo("Europe/Madrid"))
    except ZoneInfoNotFoundError:
        # Fallback explícito si el sistema no tiene instalada la base tzdata.
        return datetime.now().astimezone()


def timestamp() -> str:
    return madrid_now().isoformat(timespec="seconds")


def sw_description(sw1: int, sw2: int) -> str:
    known = {
        (0x90, 0x00): "Operación correcta",
        (0x63, 0x00): "Autenticación fallida o tarjeta no autenticada",
        (0x69, 0x82): "Condiciones de seguridad no satisfechas",
        (0x69, 0x85): "Condiciones de uso no satisfechas",
        (0x6A, 0x82): "Bloque o dirección no disponible",
        (0x6B, 0x00): "Parámetro o dirección incorrectos",
        (0x67, 0x00): "Longitud APDU incorrecta",
        (0x6D, 0x00): "Instrucción no admitida por lector/firmware",
        (0x6E, 0x00): "Clase APDU no admitida por lector/firmware",
    }
    return known.get((sw1, sw2), "Respuesta no reconocida por OMNIREADER")


def transmit(connection: Any, apdu: list[int]) -> tuple[list[int], int, int]:
    try:
        response, sw1, sw2 = connection.transmit(apdu)
        return list(response), int(sw1), int(sw2)
    except Exception as exc:
        raise OmniError(f"No se pudo enviar el comando PC/SC: {exc}") from exc


def ensure_success(response: list[int], sw1: int, sw2: int, operation: str) -> list[int]:
    if (sw1, sw2) != (0x90, 0x00):
        raise OmniError(
            f"{operation}: SW={sw1:02X} {sw2:02X} — {sw_description(sw1, sw2)}. "
            "Verifica lector, compatibilidad, clave conocida y permisos de la tarjeta de pruebas."
        )
    return response


def get_uid(connection: Any) -> str:
    response, sw1, sw2 = transmit(connection, [0xFF, 0xCA, 0x00, 0x00, 0x00])
    ensure_success(response, sw1, sw2, "Consulta UID")
    if not response:
        raise OmniError("El lector no ha devuelto un UID.")
    return " ".join(f"{byte:02X}" for byte in response)


def uid_to_bytes(uid: str) -> bytes:
    """Parsea el UID devuelto por PC/SC sin inferir formatos de control de acceso."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", uid or "")
    if not compact or len(compact) % 2:
        raise ValueError("UID vacío o con longitud hexadecimal incorrecta.")
    return bytes.fromhex(compact)


def get_atr(connection: Any) -> str:
    try:
        atr = connection.getATR()
        return " ".join(f"{byte:02X}" for byte in atr) if atr else "No disponible"
    except Exception:
        return "No disponible"


# Firma ATR comunicada por el usuario y asociada por pcsc_scan con varias
# referencias de baja frecuencia (HID Proximity / HITAG). Es un indicio,
# no una identificación criptográficamente concluyente del chip.
LOW_FREQUENCY_ATR_PREFIXES = (
    "3B8F8001804F0CA00000030640",
)


def classify_technology(atr: str) -> dict[str, str]:
    """Clasificación conservadora basada en ATR; nunca afirma un modelo exacto."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", atr or "").upper()
    if not compact:
        return {
            "status": "unknown",
            "family": "Tecnología no identificada",
            "confidence": "sin datos",
            "detail": "No hay ATR disponible para comparar.",
        }
    if any(compact.startswith(prefix) for prefix in LOW_FREQUENCY_ATR_PREFIXES):
        return {
            "status": "lf_candidate",
            "family": "Posible HID Proximity / HITAG (baja frecuencia)",
            "confidence": "indicio basado en ATR y lista PC/SC",
            "detail": (
                "La firma coincide con la interpretación que pcsc_scan mostró "
                "para esta tarjeta: RFID de baja frecuencia (<135 kHz), con "
                "HID Proximity y HITAG 1/2 como posibilidades. No distingue "
                "de forma concluyente el modelo exacto."
            ),
        }
    return {
        "status": "unknown",
        "family": "Tecnología no identificada por OMNIREADER",
        "confidence": "indeterminada",
        "detail": (
            "El ATR no coincide con las firmas conservadoras incluidas. "
            "UID y ATR por sí solos no demuestran que sea MIFARE Classic."
        ),
    }


def show_technology_profile(uid: str, atr: str) -> dict[str, str]:
    profile = classify_technology(atr)
    print("\n" + paint("PERFIL TECNOLÓGICO (ORIENTATIVO)", Theme.BOLD + Theme.MAGENTA))
    print(f"  Familia:     {profile['family']}")
    print(f"  Confianza:   {profile['confidence']}")
    print(f"  UID:         {uid}")
    print(f"  ATR:         {atr}")
    if profile["status"] == "lf_candidate":
        warn(profile["detail"])
        warn("Las operaciones MIFARE requieren una confirmación manual adicional para esta firma ATR.")
    else:
        info(profile["detail"])
    return profile


def require_mifare_operations_allowed(atr: str) -> None:
    """Impide enviar APDU MIFARE a la firma ATR LF observada en el laboratorio."""
    profile = classify_technology(atr)
    if profile["status"] == "lf_candidate":
        raise OmniError(
            "Operación bloqueada: el ATR coincide con el perfil LF observado (posible HID Prox/HITAG). "
            "Esa tarjeta no utiliza bloques ni claves A/B de MIFARE Classic."
        )
    warn("La tecnología no se ha podido identificar de forma concluyente por ATR.")
    info("Continúa únicamente si has verificado por documentación que es MIFARE Classic de laboratorio.")
    confirmation = input(
        "Escribe CONFIRMO MIFARE solo si has verificado que es una MIFARE Classic de laboratorio: "
    ).strip().upper()
    if confirmation != "CONFIRMO MIFARE":
        raise OmniError("Operación cancelada: no se ha confirmado que sea MIFARE Classic.")


def list_readers() -> list[Any]:
    try:
        return list(pcsc_readers())
    except Exception as exc:
        raise OmniError(f"No se pudo consultar PC/SC: {exc}") from exc


def select_reader() -> Optional[Any]:
    devices = list_readers()
    if not devices:
        fail("No se detectan lectores PC/SC.")
        info("Comprueba USB y el servicio pcscd: sudo systemctl status pcscd")
        return None
    title("SELECCIÓN DEL LECTOR")
    for index, device in enumerate(devices, 1):
        print(f"  {paint(index, Theme.CYAN)}. {device}")
    if len(devices) == 1:
        ok("Se ha seleccionado el único lector disponible.")
        return devices[0]
    while True:
        choice = input("\nNúmero de lector (0 cancela): ").strip()
        if choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            return devices[int(choice) - 1]
        warn("Selección no válida.")


def connect_card(reader: Optional[Any]) -> Any:
    if reader is None:
        raise OmniError("Primero selecciona un lector en la opción 1.")
    try:
        connection = reader.createConnection()
        connection.connect()
        return connection
    except (NoCardException, CardConnectionException) as exc:
        raise OmniError("No hay tarjeta presente o el lector no puede conectarse.") from exc
    except Exception as exc:
        raise OmniError(f"No se pudo abrir la conexión con el lector: {exc}") from exc


def close_card(connection: Any) -> None:
    if connection is not None:
        try:
            connection.disconnect()
        except Exception:
            pass


def card_identity(connection: Any) -> tuple[str, str]:
    atr = get_atr(connection)
    try:
        uid = get_uid(connection)
        uid_bytes = uid_to_bytes(uid)
        ok(f"UID: {paint(uid, Theme.BOLD + Theme.WHITE)} ({len(uid_bytes)} bytes)")
    except (OmniError, ValueError) as exc:
        uid = "No disponible"
        warn(f"No se pudo consultar el UID por PC/SC: {exc}")
    show_technology_profile(uid, atr)
    info("UID y ATR son identificadores orientativos; no prueban por sí solos el tipo exacto de chip.")
    return uid, atr


def ask_known_key() -> tuple[list[int], int, str]:
    print("\nClave de laboratorio conocida — una sola clave introducida manualmente.")
    info("Formato: 6 bytes / 12 caracteres hexadecimales. No se prueban listas ni combinaciones.")
    info("La clave se carga temporalmente en una ranura del lector para la autenticación PC/SC.")
    while True:
        kind = input("Tipo de clave [A/B]: ").strip().upper()
        if kind in ("A", "B"):
            key_type = 0x60 if kind == "A" else 0x61
            break
        warn("Introduce A o B.")
    while True:
        raw = getpass("Clave (entrada oculta): ").strip().replace(" ", "")
        if re.fullmatch(r"[0-9a-fA-F]{12}", raw):
            return [int(raw[i:i + 2], 16) for i in range(0, 12, 2)], key_type, kind
        warn("La clave debe tener exactamente 12 caracteres hexadecimales.")


def authenticate_lab_block(connection: Any, key: list[int], key_type: int) -> None:
    load = [0xFF, 0x82, 0x00, KEY_SLOT, KEY_LENGTH] + key
    response, sw1, sw2 = transmit(connection, load)
    ensure_success(response, sw1, sw2, "Carga temporal de clave en lector")
    auth = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, LAB_BLOCK, key_type, KEY_SLOT]
    response, sw1, sw2 = transmit(connection, auth)
    ensure_success(response, sw1, sw2, f"Autenticación del bloque de prueba {LAB_BLOCK}")
    ok(f"Autenticación aceptada para el bloque {LAB_BLOCK}.")


def read_lab_block(connection: Any) -> bytes:
    response, sw1, sw2 = transmit(connection, [0xFF, 0xB0, 0x00, LAB_BLOCK, BLOCK_SIZE])
    ensure_success(response, sw1, sw2, f"Lectura del bloque {LAB_BLOCK}")
    if len(response) != BLOCK_SIZE:
        raise OmniError(f"Respuesta inesperada: {len(response)} bytes; se esperaban 16.")
    return bytes(response)


def validate_hex_block(raw: str) -> bytes:
    cleaned = raw.strip().replace(" ", "").replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", cleaned):
        raise ValueError("Se necesitan exactamente 32 caracteres hexadecimales (16 bytes).")
    return bytes.fromhex(cleaned)


def text_to_block(text: str) -> bytes:
    encoded = text.encode("utf-8")
    if not encoded:
        raise ValueError("El texto no puede estar vacío.")
    if len(encoded) > BLOCK_SIZE:
        raise ValueError(f"El texto ocupa {len(encoded)} bytes; el máximo es 16 bytes UTF-8.")
    return encoded.ljust(BLOCK_SIZE, b"\x00")


def display_block(data: bytes, heading: str = "DATOS DEL BLOQUE") -> None:
    print("\n" + paint(heading, Theme.BOLD + Theme.GREEN))
    print(paint("Offset  HEX                                         ASCII", Theme.DIM))
    hex_text = " ".join(f"{byte:02X}" for byte in data)
    ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)
    print(f"  00    {hex_text:<47} {ascii_text}")
    print(f"\n  Longitud: {len(data)} bytes")


def display_analysis(data: bytes) -> None:
    title("ANÁLISIS LOCAL DE LOS 16 BYTES")
    display_block(data, "VISTA HEXADECIMAL")
    try:
        decoded = data.rstrip(b"\x00").decode("utf-8")
        print(f"  Texto UTF-8 (quitando 00 finales): {decoded!r}")
    except UnicodeDecodeError:
        print("  Texto UTF-8: no válido / datos binarios")
    print("  Decimal: " + " ".join(str(value) for value in data))
    print("  Binario: " + " ".join(f"{value:08b}" for value in data))
    print(f"  Bytes nulos: {data.count(0)} | Bytes imprimibles ASCII: "
          f"{sum(32 <= value <= 126 for value in data)}")


def run_with_card(reader: Optional[Any], action: Callable[[Any, str, str], None]) -> None:
    connection = None
    try:
        connection = connect_card(reader)
        uid, atr = card_identity(connection)
        action(connection, uid, atr)
    except OmniError as exc:
        fail(str(exc))
    except KeyboardInterrupt:
        warn("Operación cancelada.")
    except Exception as exc:
        fail(f"Error inesperado controlado: {type(exc).__name__}: {exc}")
    finally:
        close_card(connection)


def identify_card(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("IDENTIFICACIÓN DE TARJETA")
    def action(connection: Any, uid: str, atr: str) -> None:
        state["identity"] = {
            "uid": uid, "atr": atr,
            "technology_profile": classify_technology(atr),
            "timestamp": timestamp(),
        }
        ok("Identificación completada.")
    run_with_card(reader, action)


def read_block_menu(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("LECTURA DEL BLOQUE DE PRUEBA 4")
    def action(connection: Any, uid: str, atr: str) -> None:
        require_mifare_operations_allowed(atr)
        key, key_type, key_kind = ask_known_key()
        authenticate_lab_block(connection, key, key_type)
        data = read_lab_block(connection)
        display_block(data, "LECTURA CORRECTA · BLOQUE 4")
        state["last_data"] = data
        state["last_result"] = {
            "operation": "read", "uid": uid, "atr": atr,
            "block": LAB_BLOCK, "key_type": key_kind,
            "data_hex": data.hex().upper(), "timestamp": timestamp(),
        }
        ok("Lectura finalizada. La clave no se ha guardado.")
    run_with_card(reader, action)


def input_payload() -> bytes:
    print("\nFormato del contenido nuevo:")
    print("  1) HEX   — 32 caracteres hexadecimales (16 bytes exactos)")
    print("  2) TEXTO — UTF-8 de hasta 16 bytes; se rellena con 00 al final")
    while True:
        mode = input("Selecciona [1/2]: ").strip()
        if mode == "1":
            try:
                return validate_hex_block(input("Datos HEX: "))
            except ValueError as exc:
                warn(str(exc))
        elif mode == "2":
            try:
                return text_to_block(input("Texto: "))
            except ValueError as exc:
                warn(str(exc))
        else:
            warn("Selecciona 1 o 2.")


def write_block_menu(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("ESCRITURA CONTROLADA · BLOQUE 4")
    warn("Esta operación modifica físicamente la tarjeta presentada.")
    info("Destino fijo: bloque 4. No hay selector de bloque.")
    info("No se puede escribir en bloque 0 ni en tráileres de sector.")

    def action(connection: Any, uid: str, atr: str) -> None:
        require_mifare_operations_allowed(atr)
        key, key_type, key_kind = ask_known_key()
        authenticate_lab_block(connection, key, key_type)
        before = read_lab_block(connection)
        display_block(before, "CONTENIDO ANTERIOR")
        new_data = input_payload()
        display_block(new_data, "VISTA PREVIA · NUEVO CONTENIDO")
        if new_data == before:
            info("El contenido nuevo es idéntico al actual. No hace falta escribir.")
            return
        print("\n" + paint("DOBLE CONFIRMACIÓN", Theme.BOLD + Theme.YELLOW))
        phrase = input("Escribe exactamente ESCRIBIR BLOQUE 4: ").strip()
        if phrase != "ESCRIBIR BLOQUE 4":
            warn("Cancelado. No se ha enviado ninguna escritura.")
            return
        if input("Confirmación final [s/N]: ").strip().lower() != "s":
            warn("Cancelado. No se ha enviado ninguna escritura.")
            return

        # Revalida el UID justo antes de modificar la tarjeta.
        current_uid = get_uid(connection)
        if current_uid != uid:
            raise OmniError("El UID cambió durante la operación. Escritura abortada.")

        response, sw1, sw2 = transmit(
            connection, [0xFF, 0xD6, 0x00, LAB_BLOCK, BLOCK_SIZE] + list(new_data)
        )
        ensure_success(response, sw1, sw2, "Escritura del bloque 4")
        verified = read_lab_block(connection)
        if verified != new_data:
            display_block(verified, "DATOS DEVUELTOS TRAS LA ESCRITURA")
            raise OmniError("La verificación no coincide. No repitas la operación sin revisar la tarjeta.")

        ok("Escritura completada y verificada byte a byte.")
        display_block(verified, "CONTENIDO FINAL")
        state["last_data"] = verified
        state["last_result"] = {
            "operation": "write_verified", "uid": uid, "atr": atr,
            "block": LAB_BLOCK, "key_type": key_kind,
            "before_hex": before.hex().upper(),
            "data_hex": verified.hex().upper(), "timestamp": timestamp(),
        }
    run_with_card(reader, action)


def compare_block_menu(reader: Optional[Any]) -> None:
    title("COMPARAR BLOQUE 4")
    def action(connection: Any, uid: str, atr: str) -> None:
        require_mifare_operations_allowed(atr)
        key, key_type, _kind = ask_known_key()
        authenticate_lab_block(connection, key, key_type)
        actual = read_lab_block(connection)
        display_block(actual, "CONTENIDO LEÍDO")
        while True:
            try:
                expected = validate_hex_block(input("Valor esperado HEX: "))
                break
            except ValueError as exc:
                warn(str(exc))
        if actual == expected:
            ok("Coincidencia exacta: los 16 bytes son idénticos.")
        else:
            warn("Hay diferencias:")
            for index, (got, want) in enumerate(zip(actual, expected)):
                if got != want:
                    print(f"  Byte {index:02d}: leído {got:02X} | esperado {want:02X}")
    run_with_card(reader, action)


def monitor_cards(reader: Optional[Any]) -> None:
    title("MONITOR DE PRESENCIA")
    if reader is None:
        fail("Selecciona primero un lector en la opción 1.")
        return
    info("Acerca y retira una tarjeta. Ctrl+C detiene el monitor.")
    last_uid: Optional[str] = None
    try:
        while True:
            connection = None
            try:
                connection = reader.createConnection()
                connection.connect()
                uid = get_uid(connection)
                if uid != last_uid:
                    print(f"\n{paint('[PRESENTE]', Theme.GREEN)} UID {paint(uid, Theme.BOLD + Theme.WHITE)}")
                    last_uid = uid
            except (NoCardException, CardConnectionException):
                if last_uid is not None:
                    print(f"\n{paint('[RETIRADA]', Theme.YELLOW)} Tarjeta retirada del campo.")
                    last_uid = None
            except OmniError as exc:
                fail(str(exc))
            finally:
                close_card(connection)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print()
        ok("Monitor detenido.")


def reader_diagnostics(selected_reader: Optional[Any]) -> None:
    title("DIAGNÓSTICO PC/SC")
    try:
        devices = list_readers()
        if devices:
            ok(f"Lectores visibles para PC/SC: {len(devices)}")
            for number, device in enumerate(devices, 1):
                selected = selected_reader is not None and str(device) == str(selected_reader)
                marker = paint("  [SELECCIONADO]", Theme.GREEN) if selected else ""
                print(f"  {number}. {device}{marker}")
        else:
            warn("PC/SC no informa de lectores conectados.")
        if selected_reader is None:
            warn("No hay lector seleccionado en OMNIREADER.")
        else:
            ok(f"Lector seleccionado: {selected_reader}")
    except OmniError as exc:
        fail(str(exc))

    if sys.platform.startswith("linux") and shutil.which("systemctl"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "pcscd"], capture_output=True,
                text=True, timeout=3, check=False,
            )
            status = (result.stdout or result.stderr).strip() or "sin respuesta"
            color = Theme.GREEN if status == "active" else Theme.YELLOW
            print(f"  Servicio pcscd: {paint(status, color)}")
        except (OSError, subprocess.TimeoutExpired):
            warn("No se ha podido consultar el estado de pcscd.")
    info("La detección PC/SC no garantiza compatibilidad con todos los comandos MIFARE.")


def technology_diagnostic(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("ANALIZADOR DE TECNOLOGÍA RFID")
    info("Lee únicamente UID y ATR mediante PC/SC; no autentica ni modifica la tarjeta.")
    def action(connection: Any, uid: str, atr: str) -> None:
        profile = classify_technology(atr)
        state["identity"] = {
            "uid": uid, "atr": atr, "technology_profile": profile,
            "timestamp": timestamp(),
        }
        if profile["status"] == "lf_candidate":
            warn("Resultado: posible tarjeta RFID de baja frecuencia.")
            print("  Recomendación: no utilizar las opciones 05–07 con esta tarjeta.")
            print("  El lector la presenta a PC/SC, pero eso no significa que sea MIFARE.")
        else:
            warn("Resultado: tecnología no identificada de forma concluyente.")
            print("  Recomendación: consulta la referencia del fabricante antes de operar.")
        ok("Diagnóstico de identificación finalizado; no se han escrito datos.")
    run_with_card(reader, action)


def analyze_uid_tool(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("ANÁLISIS DEL IDENTIFICADOR RFID")
    info("Muestra la representación del UID; no deduce números de credencial ni formatos de acceso.")

    def action(connection: Any, uid: str, atr: str) -> None:
        raw = uid_to_bytes(uid)
        profile = classify_technology(atr)
        print(f"\n  UID separado:        {uid}")
        print(f"  UID compacto:        {raw.hex().upper()}")
        print(f"  Longitud:            {len(raw)} bytes ({len(raw) * 8} bits)")
        print("  Bytes decimales:     " + " ".join(str(value) for value in raw))
        print("  Bytes binarios:      " + " ".join(f"{value:08b}" for value in raw))
        print(f"  Familia orientativa: {profile['family']}")
        warn("La representación del UID no revela claves, memoria ni permisos de la tarjeta.")
        warn("No se interpreta como Facility Code/Card Number: depende del formato configurado por el sistema.")
        state["last_uid_analysis"] = {
            "uid": uid, "uid_length_bytes": len(raw), "atr": atr,
            "technology_profile": profile, "timestamp": timestamp(),
        }
        ok("Análisis del identificador terminado.")

    run_with_card(reader, action)


def register_lab_card(reader: Optional[Any]) -> None:
    title("REGISTRO LOCAL DE TARJETA DE LABORATORIO")
    info("El registro se guarda como JSON en este equipo; no se envía a ningún servidor.")
    if input("¿Confirmas que es una tarjeta tuya o autorizada para pruebas? [s/N]: ").strip().lower() != "s":
        warn("Registro cancelado.")
        return

    def action(connection: Any, uid: str, atr: str) -> None:
        alias = input("Alias de laboratorio (ej. LF-PRUEBA-01): ").strip()
        if not alias or len(alias) > 40:
            raise OmniError("El alias debe tener entre 1 y 40 caracteres.")
        include_uid = input("¿Incluir UID en el archivo? [s/N]: ").strip().lower() == "s"
        if include_uid:
            warn("El UID puede ser un identificador estable de una credencial.")
            if input("Para autorizarlo, escribe INCLUIR UID: ").strip() != "INCLUIR UID":
                include_uid = False
                info("UID omitido del registro.")
        profile = classify_technology(atr)
        record: dict[str, Any] = {
            "application": APP_NAME,
            "version": VERSION,
            "alias": alias,
            "timestamp": timestamp(),
            "atr": atr,
            "technology_profile": profile,
            "uid_included": include_uid,
            "note": "Registro local de laboratorio; no contiene claves ni datos de memoria.",
        }
        if include_uid:
            record["uid"] = uid
        record["timezone"] = "Europe/Madrid"
        folder = Path(__file__).resolve().parent / "omnireader_registry"
        folder.mkdir(parents=True, exist_ok=True)
        safe_alias = re.sub(r"[^A-Za-z0-9_-]+", "_", alias).strip("_") or "tarjeta"
        filename = f"{madrid_now().strftime('%Y%m%d_%H%M%S')}_{safe_alias}.json"
        target = folder / filename
        target.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ok(f"Registro guardado: {target}")
        if not include_uid:
            info("El UID no se ha guardado.")

    run_with_card(reader, action)


def verify_one_known_key(reader: Optional[Any]) -> None:
    title("VERIFICAR UNA CLAVE CONOCIDA · BLOQUE 4")
    warn("No es un recuperador de contraseñas ni un ataque de fuerza bruta.")
    info("Realiza una única autenticación en el bloque 4 usando una clave que ya conoces.")
    info("No lee, escribe ni exporta el contenido del bloque.")

    def action(connection: Any, uid: str, atr: str) -> None:
        profile = classify_technology(atr)
        if profile["status"] == "lf_candidate":
            raise OmniError(
                "El ATR coincide con el perfil LF observado. Las claves A/B MIFARE no se aplican a HID Prox/HITAG; "
                "verificación cancelada sin enviar autenticación."
            )
        if input("¿Has confirmado por documentación que es MIFARE Classic de laboratorio? [s/N]: ").strip().lower() != "s":
            raise OmniError("Operación cancelada: tecnología MIFARE no confirmada.")
        key, key_type, kind = ask_known_key()
        authenticate_lab_block(connection, key, key_type)
        ok(f"La clave {kind} introducida autentica el bloque 4 de esta tarjeta.")
        info("Esto solo valida esa clave, ese tipo A/B y ese bloque/sector; no demuestra acceso a otros sectores.")
        info("No se ha leído ni modificado memoria y la clave no se ha guardado en disco.")

    run_with_card(reader, action)


def extended_diagnostics(selected_reader: Optional[Any]) -> None:
    title("DIAGNÓSTICO AMPLIADO DEL ENTORNO")
    print(f"  Aplicación:       {APP_NAME} {VERSION}")
    print(f"  Python:           {sys.version.split()[0]}")
    print(f"  Plataforma:       {sys.platform}")
    print(f"  Codificación:     {getattr(sys.stdout, 'encoding', None) or 'desconocida'}")
    print("  Zona horaria:     Europe/Madrid")
    print(f"  Hora local:       {timestamp()}")

    try:
        pyscard = package_version("pyscard")
        print(f"  PySCard:          {pyscard}")
    except PackageNotFoundError:
        print("  PySCard:          disponible por importación; versión no localizada")
    except Exception:
        print("  PySCard:          versión no disponible")

    try:
        devices = list_readers()
        print(f"  Lectores PC/SC:   {len(devices)}")
        for index, device in enumerate(devices, 1):
            marker = " (seleccionado)" if selected_reader is not None and str(device) == str(selected_reader) else ""
            print(f"    {index}. {device}{marker}")
    except OmniError as exc:
        warn(f"Consulta de lectores: {exc}")

    if sys.platform.startswith("linux") and shutil.which("systemctl"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "pcscd"], capture_output=True,
                text=True, timeout=3, check=False,
            )
            status = (result.stdout or result.stderr).strip() or "sin respuesta"
            print(f"  Servicio pcscd:   {status}")
        except (OSError, subprocess.TimeoutExpired):
            warn("No se ha podido consultar pcscd.")

    info("Este diagnóstico no envía comandos a ninguna tarjeta ni modifica el lector.")


def compatibility_guide() -> None:
    title("GUÍA DE COMPATIBILIDAD RFID")
    print("OMNIREADER usa PC/SC para consultar UID/ATR y comandos específicos del lector.")
    print("La presencia de una tarjeta en PC/SC no significa que sea compatible con MIFARE.")
    print("\nFamilias orientativas:")
    print(f"  {paint('MIFARE Classic 1K', Theme.GREEN)} — 13,56 MHz; sectores, bloques y claves A/B.")
    print(f"  {paint('HID Proximity / HITAG', Theme.YELLOW)} — normalmente baja frecuencia; no usa bloques MIFARE.")
    print(f"  {paint('Desconocida', Theme.CYAN)} — requiere identificar el modelo en la documentación.")
    print("\nLimitaciones:")
    print("  • ATR puede ser genérico o depender del lector/firmware.")
    print("  • Una coincidencia ATR es un indicio, no una prueba definitiva del chip.")
    print("  • UID/ATR no revelan claves ni contenido de memoria.")
    print("  • HID Prox/HITAG LF no utiliza las claves A/B ni los bloques de MIFARE Classic.")
    print("  • El lector 5427 CK admite varias tecnologías, pero no todas comparten comandos.")
    print("  • Las funciones 05–07 permanecen limitadas al bloque de prueba 4.")


def show_memory_map() -> None:
    title("MAPA DE REFERENCIA · MIFARE CLASSIC 1K")
    print("Estructura estándar: 16 sectores × 4 bloques × 16 bytes = 1024 bytes.")
    print("Sectores 1–15: tres bloques de datos y un tráiler por sector.")
    print("Sector 0: bloque fabricante, dos bloques de datos y un tráiler.")
    print("\nSector   Bloque 0   Bloque 1   Bloque 2   Bloque 3")
    print("------   --------   --------   --------   --------")
    for sector in range(16):
        first = sector * 4
        tag = "  <== bloque de pruebas" if first == LAB_BLOCK else ""
        print(f"{sector:>3}      {first:>4}       {first+1:>4}       {first+2:>4}       "
              f"{paint(f'{first+3:>4} [TRÁILER]', Theme.YELLOW)}{tag}")
    print("\nNotas:")
    print("  • Bloque 0: información de fabricante/UID en tarjetas estándar; no tocar.")
    print("  • Bloque 3 de cada sector: claves y condiciones de acceso; no tocar.")
    print("  • OMNIREADER solo accede al bloque 4 (datos de prueba) en esta versión.")
    print("  • El bloque 0 del sector 0 está reservado para datos del fabricante/UID.")


def convert_data_tool() -> None:
    title("CONVERSOR DE DATOS · HEX / TEXTO")
    print("  1) HEX de 16 bytes → texto")
    print("  2) Texto → HEX de bloque de 16 bytes")
    choice = input("Selecciona [1/2]: ").strip()
    if choice == "1":
        try:
            data = validate_hex_block(input("HEX (32 caracteres): "))
            display_analysis(data)
        except ValueError as exc:
            fail(str(exc))
    elif choice == "2":
        try:
            data = text_to_block(input("Texto: "))
            display_block(data, "RESULTADO HEX")
            print("  HEX compacto: " + data.hex().upper())
        except ValueError as exc:
            fail(str(exc))
    else:
        warn("Opción no válida.")


def analyze_last_data(state: dict[str, Any]) -> None:
    title("ANALIZAR ÚLTIMA LECTURA")
    data = state.get("last_data")
    if not isinstance(data, bytes) or len(data) != BLOCK_SIZE:
        warn("No hay una lectura válida en esta sesión. Usa primero la opción 5 o 6.")
        return
    display_analysis(data)


def export_report(state: dict[str, Any]) -> None:
    title("EXPORTAR INFORME JSON")
    result = state.get("last_result")
    if not result:
        warn("Todavía no hay una lectura o escritura verificada que exportar.")
        return
    include_uid = input("¿Incluir UID en el informe? [s/N]: ").strip().lower() == "s"
    report = dict(result)
    if not include_uid:
        report.pop("uid", None)
    report["application"] = APP_NAME
    report["version"] = VERSION
    report["technology_profile"] = classify_technology(str(report.get("atr", "")))
    folder = Path(__file__).resolve().parent / "omnireader_reports"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        report["timezone"] = "Europe/Madrid"
        filename = f"omnireader_{madrid_now().strftime('%Y%m%d_%H%M%S')}.json"
        target = folder / filename
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ok(f"Informe guardado: {target}")
        info("No se incluyen claves A/B. El UID solo se incluye si lo has autorizado.")
    except OSError as exc:
        fail(f"No se pudo guardar el informe: {exc}")


def self_test() -> None:
    title("AUTOPRUEBAS LOCALES · SIN TARJETA")
    tests: list[tuple[str, Callable[[], bool]]] = [
        ("HEX válido (16 bytes)", lambda: len(validate_hex_block("00" * 16)) == 16),
        ("Rechazo de HEX incompleto", lambda: _raises_value_error(lambda: validate_hex_block("AABB"))),
        ("Texto UTF-8 y relleno", lambda: text_to_block("LAB").startswith(b"LAB") and len(text_to_block("LAB")) == 16),
        ("Rechazo de texto >16 bytes", lambda: _raises_value_error(lambda: text_to_block("X" * 17))),
        ("Conversión HEX ida/vuelta", lambda: bytes.fromhex(validate_hex_block("0123456789ABCDEF" * 2).hex()).hex().upper() == "0123456789ABCDEF" * 2),
        ("Identificación indicativa ATR LF", lambda: classify_technology("3B 8F 80 01 80 4F 0C A0 00 00 03 06 40 00 00 00 00 00 00 28")["status"] == "lf_candidate"),
        ("ATR desconocido sin falsa identificación", lambda: classify_technology("3B 00")["status"] == "unknown"),
        ("UID de 5 bytes parseado correctamente", lambda: uid_to_bytes("30 00 45 63 B0") == bytes.fromhex("30004563B0")),
        ("Rechazo de UID hexadecimal irregular", lambda: _raises_value_error(lambda: uid_to_bytes("ABC"))),
        ("Cabecera alineada en terminal estrecho", lambda: len(set(map(len, _banner_lines(40)))) == 1),
        ("Logo adaptable a terminal mediano", lambda: len(set(map(len, _banner_lines(54)))) == 1 and all(len(line) == 54 for line in _banner_lines(54))),
        ("Logo adaptable a terminal ancho", lambda: len(set(map(len, _banner_lines(76)))) == 1 and all(len(line) == 76 for line in _banner_lines(76))),
        ("Zona horaria Europe/Madrid", lambda: madrid_now().tzinfo is not None and madrid_now().strftime("%z") in ("+0100", "+0200")),
    ]
    passed = 0
    for name, test in tests:
        try:
            result = bool(test())
        except Exception:
            result = False
        print(f"  {paint('PASS' if result else 'FAIL', Theme.GREEN if result else Theme.RED)}  {name}")
        passed += int(result)
    print(f"\nResultado: {passed}/{len(tests)} pruebas superadas.")
    info("Estas pruebas validan funciones locales; no prueban lector, tarjeta ni APDU físicos.")


def _raises_value_error(function: Callable[[], Any]) -> bool:
    try:
        function()
    except ValueError:
        return True
    return False


def show_help() -> None:
    title("AYUDA E INSTALACIÓN")
    print("1. Conecta el OMNIKEY y comprueba pcscd.")
    print("2. Selecciona el lector con la opción 1.")
    print("3. Consulta UID/ATR o utiliza el monitor para confirmar presencia.")
    print("4. Para leer/escribir, presenta una tarjeta de laboratorio y proporciona")
    print("   una clave A/B que ya conozcas y estés autorizado a utilizar.")
    print("5. La lectura/escritura se limita al bloque 4 del sector 1.")
    print("6. Usa la opción 14 para analizar la tecnología orientativamente por ATR.")
    print("7. Los informes se exportan manualmente; las claves nunca se guardan en disco.")
    print("8. La opción 18 verifica una única clave A/B conocida en el bloque 4; no adivina claves.")
    print("9. Para tarjetas LF, utiliza identificación/registro/análisis de UID; no uses claves MIFARE.")
    print("10. La opción 19 muestra versiones, zona horaria, lectores y estado de pcscd.")
    print("11. La opción 20 resume la sesión sin mostrar claves ni crear archivos.")
    print("12. Los registros e informes usan hora Europe/Madrid.")
    print("\nInstalación en Kali:")
    print("  sudo apt update")
    print("  sudo apt install pcscd libccid python3-pyscard -y")
    print("  sudo systemctl enable --now pcscd")
    print("  python3 omnireader.py")
    print("\nControles:")
    print("  • Bloque 0 y tráileres: fuera del alcance del programa.")
    print("  • Sin fuerza bruta, diccionarios de claves, clonación ni escritura masiva.")
    print("  • La opción de verificación solo prueba una clave conocida, una vez y en el bloque 4.")
    print("  • Los APDU MIFARE dependen del modelo/firmware del lector.")
    print("  • UID/ATR no prueban por sí solos el tipo de tarjeta.")
    print("  • Para firmas ATR de baja frecuencia o desconocidas, OMNIREADER exige confirmación antes de usar opciones MIFARE.")
    print("  • Trabaja únicamente con tarjetas propias y de laboratorio.")


def session_summary(selected_reader: Optional[Any], state: dict[str, Any]) -> None:
    """Muestra el estado de la sesión sin revelar claves ni exportar datos."""
    title("RESUMEN DE SESIÓN")
    print(f"  Versión:          {APP_NAME} {VERSION} · TERMINAL")
    print(f"  Inicio:           {state.get('started_at', 'No disponible')}")
    if selected_reader is None:
        print(f"  Lector:           {paint('no seleccionado', Theme.YELLOW)}")
    else:
        print(f"  Lector:           {paint(str(selected_reader), Theme.GREEN)}")

    identity = state.get("identity")
    if isinstance(identity, dict):
        print("\n  Última tarjeta identificada:")
        print(f"    UID:            {identity.get('uid', 'No disponible')}")
        print(f"    ATR:            {identity.get('atr', 'No disponible')}")
        profile = identity.get("technology_profile") or classify_technology(str(identity.get("atr", "")))
        print(f"    Familia:        {profile.get('family', 'No identificada')}")
        print(f"    Fecha:          {identity.get('timestamp', 'No disponible')}")
    else:
        info("Todavía no se ha identificado ninguna tarjeta en esta sesión.")

    result = state.get("last_result")
    if isinstance(result, dict):
        operation_names = {
            "read": "Lectura de bloque",
            "write_verified": "Escritura verificada",
        }
        print("\n  Última operación de memoria:")
        print(f"    Operación:      {operation_names.get(result.get('operation'), result.get('operation', 'No disponible'))}")
        print(f"    Bloque:         {result.get('block', 'No disponible')}")
        print(f"    Tipo de clave:  {result.get('key_type', 'No disponible')} (la clave no se conserva)")
        print(f"    Fecha:          {result.get('timestamp', 'No disponible')}")
    else:
        info("No hay operaciones de memoria registradas en esta sesión.")

    cached = state.get("last_data")
    if isinstance(cached, bytes) and len(cached) == BLOCK_SIZE:
        print("\n  Datos de trabajo: última lectura disponible en memoria (16 bytes).")
    else:
        print("\n  Datos de trabajo: ninguna lectura almacenada en memoria.")
    info("El resumen no muestra claves A/B ni escribe archivos.")


def _banner_lines(width: int) -> list[str]:
    """Devuelve líneas de logo con anchura uniforme para terminales variados."""
    return _logo_ascii_lines(width)


def banner() -> None:
    terminal_width = shutil.get_terminal_size((80, 24)).columns
    width = min(76, max(34, terminal_width - 2))
    art = _banner_lines(width)
    print()
    for index, line in enumerate(art):
        if index in (0, len(art) - 1):
            color = Theme.CYAN + Theme.BOLD
        elif index in (2, 3):
            color = Theme.WHITE + Theme.BOLD if index == 2 else Theme.CYAN
        else:
            color = Theme.DIM if index == len(art) - 2 else Theme.WHITE
        print(paint(line, color))
    print(paint("  FIELD NOTES  /  LOCAL PC/SC  /  SAFE LAB OPERATIONS", Theme.DIM))
    warn("Uso exclusivo con tarjetas propias/de laboratorio y operaciones autorizadas.")


def menu(selected_reader: Optional[Any], state: dict[str, Any]) -> None:
    print("\n" + paint("MENÚ PRINCIPAL", Theme.BOLD + Theme.WHITE))
    if selected_reader is None:
        print(f"  Lector: {paint('no seleccionado', Theme.YELLOW)}")
    else:
        print(f"  Lector: {paint(selected_reader, Theme.GREEN)}")
    print(paint("  DISPOSITIVO", Theme.MAGENTA + Theme.BOLD))
    print("  1) Detectar / seleccionar lector")
    print("  2) Diagnóstico PC/SC y pcscd")
    print(paint("  TARJETA", Theme.MAGENTA + Theme.BOLD))
    print("  3) Consultar UID y ATR")
    print("  4) Monitor de presencia en tiempo real")
    print(paint("  MEMORIA · BLOQUE DE LABORATORIO 4", Theme.MAGENTA + Theme.BOLD))
    print("  5) Leer bloque 4 (clave conocida)")
    print("  6) Escribir bloque 4 + verificación (clave conocida)")
    print("  7) Comparar bloque 4 con HEX esperado")
    print(paint("  UTILIDADES", Theme.MAGENTA + Theme.BOLD))
    print("  8) Analizar última lectura (HEX / ASCII / decimal / binario)")
    print("  9) Conversor HEX ↔ texto")
    print(" 10) Exportar informe JSON")
    print(" 11) Ver mapa de memoria MIFARE Classic 1K")
    print(" 12) Ejecutar autopruebas locales")
    print(" 13) Ayuda e instalación")
    print(paint("  IDENTIFICACIÓN RFID", Theme.MAGENTA + Theme.BOLD))
    print(" 14) Analizar tecnología de la tarjeta (UID + ATR; solo lectura)")
    print(" 15) Guía de compatibilidad RFID")
    print(paint("  LABORATORIO LF / GESTIÓN", Theme.MAGENTA + Theme.BOLD))
    print(" 16) Registrar tarjeta de laboratorio en JSON (UID opcional)")
    print(" 17) Analizar UID (longitud / HEX / decimal / binario)")
    print(" 18) Verificar una clave A/B conocida en bloque 4 (una sola prueba)")
    print(" 19) Diagnóstico ampliado del entorno (sin operar sobre tarjetas)")
    print(" 20) Resumen de sesión (sin claves ni exportación)")
    print("  0) Salir")


def cli_main() -> None:
    state: dict[str, Any] = {"last_data": None, "last_result": None, "identity": None, "started_at": timestamp()}
    selected_reader: Optional[Any] = None
    banner()
    actions: dict[str, Callable[[], None]] = {
        "2": lambda: reader_diagnostics(selected_reader),
        "3": lambda: identify_card(selected_reader, state),
        "4": lambda: monitor_cards(selected_reader),
        "5": lambda: read_block_menu(selected_reader, state),
        "6": lambda: write_block_menu(selected_reader, state),
        "7": lambda: compare_block_menu(selected_reader),
        "8": lambda: analyze_last_data(state),
        "9": convert_data_tool,
        "10": lambda: export_report(state),
        "11": show_memory_map,
        "12": self_test,
        "13": show_help,
        "14": lambda: technology_diagnostic(selected_reader, state),
        "15": compatibility_guide,
        "16": lambda: register_lab_card(selected_reader),
        "17": lambda: analyze_uid_tool(selected_reader, state),
        "18": lambda: verify_one_known_key(selected_reader),
        "19": lambda: extended_diagnostics(selected_reader),
        "20": lambda: session_summary(selected_reader, state),
    }
    while True:
        menu(selected_reader, state)
        try:
            choice = input("\n" + paint("omnireader", Theme.CYAN + Theme.BOLD) + " > ").strip()
            if choice == "0":
                print(paint("\nOMNIREADER cerrado.", Theme.CYAN))
                break
            if choice == "1":
                selected = select_reader()
                if selected is not None:
                    selected_reader = selected
                    ok(f"Lector seleccionado: {selected_reader}")
            elif choice in actions:
                actions[choice]()
            else:
                warn("Opción no válida.")
        except (KeyboardInterrupt, EOFError):
            print("\n" + paint("OMNIREADER cerrado.", Theme.CYAN))
            break
        except Exception as exc:
            fail(f"Error controlado: {type(exc).__name__}: {exc}")
        input("\nPulsa ENTER para volver al menú...")


def _logo_ascii_lines(width: int) -> list[str]:
    """Logo CLI adaptable: emblema RFID y wordmark con columnas alineadas."""
    width = max(34, min(76, int(width)))
    inner = width - 2

    def frame(text: str) -> str:
        safe = text[:inner]
        return "║" + safe.center(inner) + "║"

    if width >= 68:
        left = ["  ┌─────────┐", "  │  RFID   │", "  └─────────┘", "       )))"]
        right = [
            "O M N I R E A D E R",
            "TERMINAL LABORATORY",
            "PC/SC · LF / HF · MIFARE",
            "VERSION 2.3 · EUROPE / MADRID",
        ]
        rows = [a.ljust(13) + "  " + b for a, b in zip(left, right)]
    elif width >= 46:
        left = ["  ┌───────┐", "  │ RFID  │", "  └───────┘", "     )))"]
        right = [
            "O M N I R E A D E R",
            "TERMINAL LAB 2.3",
            "PC/SC · LF / HF",
            "EUROPE / MADRID",
        ]
        rows = [a.ljust(11) + "  " + b for a, b in zip(left, right)]
    else:
        rows = [
            "O M N I R E A D E R",
            "RFID LAB · CLI 2.3",
            "PC/SC · LF + HF",
        ]

    content_width = max(len(row) for row in rows)
    rows = [row.ljust(content_width) for row in rows]
    top = "╔" + "═" * inner + "╗"
    bottom = "╚" + "═" * inner + "╝"
    return [top, *(frame(row) for row in rows), bottom]


def main() -> None:
    """Punto de entrada de OMNIREADER 2.3, edición exclusivamente terminal."""
    parser = argparse.ArgumentParser(
        prog="omnireader.py",
        description="OMNIREADER 2.3 — laboratorio RFID PC/SC en terminal.",
        epilog="Ejemplo: python3 omnireader.py --self-test",
    )
    parser.add_argument("--version", action="version", version=f"OMNIREADER {VERSION} · TERMINAL")
    parser.add_argument("--self-test", action="store_true", help="ejecuta las pruebas locales y sale")
    parser.add_argument("--no-color", action="store_true", help="desactiva los colores ANSI")
    args = parser.parse_args()

    if args.no_color:
        for name in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE"):
            setattr(Theme, name, "")

    if args.self_test:
        banner()
        self_test()
        return

    cli_main()


if __name__ == "__main__":
    main()
