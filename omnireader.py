#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMNIREADER 2.0 — entorno didáctico PC/SC para tarjetas MIFARE Classic.

Alcance de seguridad:
- Consulta UID/ATR y monitoriza presencia de tarjetas.
- Lee y escribe ÚNICAMENTE el bloque de datos 4 de una tarjeta de laboratorio.
- Requiere una clave A/B conocida, introducida manualmente en cada operación.
- No lee tráileres, no modifica el bloque fabricante, no busca claves y no clona tarjetas.
- No persiste claves. Los informes se guardan únicamente cuando el usuario lo solicita.

Compatibilidad: Python 3 + pyscard + lector PC/SC compatible con los APDU del fabricante.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Any, Callable, Optional

APP_NAME = "OMNIREADER"
VERSION = "2.0"
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


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


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


def get_atr(connection: Any) -> str:
    try:
        atr = connection.getATR()
        return " ".join(f"{byte:02X}" for byte in atr) if atr else "No disponible"
    except Exception:
        return "No disponible"


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
    uid, atr = get_uid(connection), get_atr(connection)
    ok(f"UID: {paint(uid, Theme.BOLD + Theme.WHITE)}")
    info(f"ATR: {atr}")
    info("El UID/ATR no certifica por sí solo que la tarjeta sea MIFARE Classic 1K.")
    return uid, atr


def ask_known_key() -> tuple[list[int], int, str]:
    print("\nClave de laboratorio conocida — no se guarda en disco.")
    info("Formato: 6 bytes / 12 caracteres hexadecimales.")
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
        state["identity"] = {"uid": uid, "atr": atr, "timestamp": timestamp()}
        ok("Identificación completada.")
    run_with_card(reader, action)


def read_block_menu(reader: Optional[Any], state: dict[str, Any]) -> None:
    title("LECTURA DEL BLOQUE DE PRUEBA 4")
    def action(connection: Any, uid: str, atr: str) -> None:
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


def show_memory_map() -> None:
    title("MAPA DE REFERENCIA · MIFARE CLASSIC 1K")
    print("Estructura estándar: 16 sectores × 4 bloques × 16 bytes = 1024 bytes.")
    print("Cada sector tiene 3 bloques de datos y un tráiler de seguridad.")
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
    folder = Path(__file__).resolve().parent / "omnireader_reports"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        filename = f"omnireader_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
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
    print("6. Los informes se exportan manualmente; las claves nunca se guardan.")
    print("\nInstalación en Kali:")
    print("  sudo apt update")
    print("  sudo apt install pcscd libccid python3-pyscard -y")
    print("  sudo systemctl enable --now pcscd")
    print("  python3 omnireader.py")
    print("\nControles:")
    print("  • Bloque 0 y tráileres: fuera del alcance del programa.")
    print("  • Sin búsqueda automática de claves, clonación ni escritura masiva.")
    print("  • Los APDU MIFARE dependen del modelo/firmware del lector.")
    print("  • UID/ATR no prueban por sí solos el tipo de tarjeta.")
    print("  • Trabaja únicamente con tarjetas propias y de laboratorio.")


def banner() -> None:
    art = [
        "  ____  __  __ _   _ ___ ____  _____    _    ____  _____ ____ ",
        " / __ \\/  \\/  | \\ | |_ _|  _ \\| ____|  / \\  |  _ \\| ____|",
        "| |   | |\\/| |  \\| || || |_) |  _|   / _ \\ | | | |  _|  ",
        "| |___| |  | | |\\  || ||  _ <| |___ / ___ \\| |_| | |___ ",
        " \\____/|_|  |_|_| \\_|___|_| \\_\\_____/_/   \\_\\____/|_____|",
    ]
    print(paint(rule("═"), Theme.CYAN))
    for row in art:
        print(paint(row, Theme.CYAN + Theme.BOLD))
    print(paint(f"  RFID / PC-SC LAB  ·  VERSION {VERSION}", Theme.WHITE + Theme.BOLD))
    print(paint("  OMNIKEY · MIFARE CLASSIC · BLOQUE DE PRUEBA FIJO: 4", Theme.DIM))
    print(paint(rule("═"), Theme.CYAN))
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
    print("  0) Salir")


def main() -> None:
    state: dict[str, Any] = {"last_data": None, "last_result": None, "identity": None}
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


if __name__ == "__main__":
    main()
