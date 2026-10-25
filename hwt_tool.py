#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hwt_tool.py — interactive packer/unpacker/inspector for HUAWEI .hwt themes.

Works with watch faces and band themes shipped by HUAWEI Health / HUAWEI Themes.

What it does
------------
* ``-u/--unpack FILE...``   unpack .hwt into ``<name>_unpacked/``
* ``-p/--pack DIR...``      pack a folder back into .hwt
* ``-i/--info FILE...``     print everything knowable about a .hwt
* no arguments              hot-key interactive mode (see the menus)

Format notes (verified against the open-source MIT project
BlackHatDevX/Huawei-Watchface-Extractor-Python, watchface_extractor.py):
* a .hwt is a ZIP archive whose key entry is ``com.huawei.watchface``;
* the binary starts with the signature ``55 55 55 55``, then 4 skipped bytes,
  then, per image: 4 header bytes, width (uint16 LE), height (uint16 LE),
  and width*height BGRA pixels, RLE-compressed:
  a quad equal to ``89 67 45 23`` (BGRA byte order) introduces a run:
  4 colour bytes (BGRA) plus a run length (uint32 LE); length 0 counts as 1.

Compared to the reference extractor this implementation:
* parses the whole binary in memory with bounds checks (much faster than
  byte-at-a-time file reads) and keeps the unknown prefix / skipped bytes /
  trailing blob, so the repacked file stays structurally faithful;
* can pack as well as unpack (deterministic ZIP: the original entry order,
  timestamps and per-entry compression are preserved);
* guards against ZIP-slip paths, skips desktop junk, and explains every
  extracted file in the log;
* adds a hot-key UI modelled on mozvpn.py (dev3haven/free-mozilla-vpn):
  bold keys in [brackets], token input with Backspace, Esc to cancel,
  Ctrl+C exits immediately.

Dependencies: Pillow (only needed to decode/encode the embedded images).
The tool offers to install it at startup; ZIP-level features work without it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import select
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime

try:
    import msvcrt  # type: ignore
    _HAVE_MSVCRT = True
except ImportError:
    _HAVE_MSVCRT = False
    try:
        import termios
        import tty
        _HAVE_TERMIOS = True
    except ImportError:
        _HAVE_TERMIOS = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
BINARY_NAME = "com.huawei.watchface"
SIG = b"\x55\x55\x55\x55"              # watch-face binary signature
MARKER_BGRA = b"\x89\x67\x45\x23"      # RLE run marker, BGRA byte order
IMG_DIR = "images"                    # decoded PNGs live here
MANIFEST = "manifest.json"             # tool's own manifest, inside IMG_DIR
LANG_FILE = "hwt_tool.lang.json"      # saved UI language, next to the script
DEFAULT_DATE_TIME = (1980, 1, 1, 0, 0, 0)
MAX_DIM = 4096                        # sanity bound for a single image side
FILE_KEYS = [str(d) for d in range(1, 10)] + [
    chr(c) for c in range(ord("a"), ord("z") + 1)
]
PAGE_SIZE = len(FILE_KEYS)            # 35 files per page in the file menu
JUNK_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
JUNK_EXTS = (".pyc", ".log", ".tmp")
REQUIRED_DEPS = [("Pillow", "PIL")]
LANG_NAMES = {"en": "English", "ru": "Русский"}

# Interesting attributes to surface from the small XML files inside .hwt
META_KEYS = [
    "name", "title", "versionName", "version", "packageName", "author",
    "designer", "device", "price", "themeName", "id", "resolution",
]

# ---------------------------------------------------------------------------
# Localization (en + ru), mozvpn.py style: tr("key", ...)
# ---------------------------------------------------------------------------

TEXT = {
    "en": {
        "title": "HUAWEI .hwt theme tool v{v}",
        "dir_label": "Working directory",
        "menu_hint": "Press a key in [brackets]. Ctrl+C exits at any time.",
        "menu_scan": "scan the working directory for .hwt files",
        "menu_dir": "set the working directory",
        "menu_lang": "interface language",
        "menu_deps": "install missing dependencies",
        "menu_quit": "quit",
        "scanning": "Scanning {d} ...",
        "no_files": "No .hwt files found in {d}.",
        "found_n": "Found {n} .hwt file(s):",
        "page": "page {cur}/{total} — Enter: next, Backspace: previous",
        "select_all_hint": "select ALL files",
        "esc_back_hint": "back",
        "all_selected": "Selected all {n} file(s).",
        "action_title": "Selected {n} file(s) — choose an action:",
        "act_unpack": "unpack",
        "act_pack": "pack from the '<name>_unpacked' folder next to the file",
        "act_info": "show all info",
        "esc_cancel_hint": "cancel selection",
        "esc_cancel": "Selection canceled.",
        "unpack_start": "Unpacking {f} ...",
        "unpack_done": "Unpacked into: {d}",
        "unpack_binary_ok": "Decoded {n} watch-face image(s) into {img}/ (manifest: {mf}).",
        "unpacked_files": "Unpacked files:",
        "no_binary": "Archive has no {b} binary — regular theme files only.",
        "no_sig_in_binary": "No watch-face signature (55 55 55 55) in {b}; the file is kept as-is.",
        "pack_start": "Packing {d} ...",
        "pack_done": "Created: {f}",
        "pack_dir_prompt": "Folder with the unpacked theme for {f}",
        "manifest_missing": "No {mf} in {d} — packing the folder as a generic ZIP.",
        "junk_skip": "Skipped junk file: {p}",
        "pack_added": "Added new file: {p}",
        "dim_mismatch": "{p} is {w}x{h}px, but {mf} expects {mw}x{mh}px. Keep the original size.",
        "png_missing": "PNG not found: {p}",
        "px_size_mismatch": "Unexpected pixel data size for {p}.",
        "info_title": "Info: {f}",
        "info_size": "Size",
        "info_mtime": "Modified",
        "info_sha": "SHA-256",
        "info_zip_ok": "ZIP integrity: OK",
        "zip_bad_entry": "ZIP integrity check failed on: {p}",
        "no_zip_info": "Not a ZIP archive — inspected as a raw watch-face binary.",
        "info_entries": "Archive entries ({n}):",
        "info_xml": "XML metadata",
        "info_images": "Watch-face binary {b} — {n} image(s):",
        "info_layout": "Binary layout: prefix {pre} B, signature+skip {sig} B, images {img} B, trailing {post} B.",
        "info_aod": "AOD (always-on display) data detected.",
        "info_no_aod": "No AOD (always-on display) data detected.",
        "info_no_images": "No {b} binary in the archive.",
        "incomplete": "(truncated)",
        "dir_prompt": "Working directory path",
        "dir_changed": "Working directory: {d}",
        "input_cancel": "Input canceled.",
        "dir_not_found": "Directory not found: {d}",
        "lang_menu_title": "Interface language:",
        "lang_saved": "Language saved: {l}",
        "lang_reset": "Language reset to English.",
        "lang_reset_hint": "reset to English",
        "deps_title": "Missing dependencies: {deps}",
        "deps_offer": "Install them now?",
        "yes_no_hint": "y — yes, n — no",
        "deps_installing": "Installing: {deps} ...",
        "deps_ok": "Dependencies installed.",
        "deps_fail": "Dependency installation failed{e}.",
        "deps_skip": "Continuing without Pillow: watch-face images will be skipped, ZIP features still work.",
        "deps_none": "All dependencies are already installed.",
        "bye": "Bye!",
        "interrupt": "Interrupted by Ctrl+C.",
        "err_generic": "Error: {e}",
        "not_found": "File not found: {f}",
        "zip_slip": "Unsafe path in archive: {p}",
        "binary_deps_missing": "Pillow is required to decode watch-face images. Install it and try again.",
        "cli_prog": "Pack/unpack/inspect HUAWEI .hwt watch-face themes. Run without arguments for the interactive menu.",
        "cli_unpack": "unpack .hwt file(s) into '<name>_unpacked' folders",
        "cli_pack": "pack folder(s) back into .hwt",
        "cli_info": "show all available info about .hwt file(s)",
        "cli_dir": "working directory for the interactive mode",
        "cli_out": "output path (file for pack, folder for unpack)",
        "cli_lang": "interface language (en, ru)",
        "cli_install_deps": "install missing dependencies without asking",
        "cli_no_install_deps": "never offer to install dependencies",
        "cli_version": "show the tool version",
        "c_description_xml": "Theme description shown in HUAWEI Themes / Health. You can edit the text inside the tags; keep the XML structure.",
        "c_theme_xml": "Theme manifest: colors and style settings. Edit attribute values, do not rename tags.",
        "c_binary": "Watch-face binary (RLE-BGRA images). The tool decoded it into images/*.png — edit those and pack back.",
        "c_preview": "Preview image shown in the gallery. Replace with a picture of the same size.",
        "c_icon": "Icon shown in the theme/watch-face list. Replace with the same size and format.",
        "c_font": "Embedded font. Keep the file name; replace only for custom fonts.",
        "c_image": "Image asset. Edit or replace, keep the size and format.",
        "c_xml": "XML metadata. Keep the structure; edit values only.",
        "c_other": "Resource file. Keep the original name and format.",
        "c_manifest": "Tool manifest: binary layout info. Do not rename; keep it next to the PNGs. Replace PNGs with the same dimensions.",
        "c_png_dims": "Watch-face image {w}x{h}px.",
    },
    "ru": {
        "title": "Инструмент тем HUAWEI .hwt v{v}",
        "dir_label": "Рабочий каталог",
        "menu_hint": "Нажимайте клавиши в [скобках]. Ctrl+C — немедленный выход.",
        "menu_scan": "сканировать рабочий каталог на файлы .hwt",
        "menu_dir": "сменить рабочий каталог",
        "menu_lang": "язык интерфейса",
        "menu_deps": "установить недостающие зависимости",
        "menu_quit": "выход",
        "scanning": "Сканирую {d} ...",
        "no_files": "В {d} файлы .hwt не найдены.",
        "found_n": "Найдено файлов .hwt: {n}",
        "page": "страница {cur}/{total} — Enter: далее, Backspace: назад",
        "select_all_hint": "выбрать ВСЕ файлы",
        "esc_back_hint": "назад",
        "all_selected": "Выбраны все файлы ({n}).",
        "action_title": "Выбрано файлов: {n} — выберите действие:",
        "act_unpack": "распаковать",
        "act_pack": "запаковать из папки '<имя>_unpacked' рядом с файлом",
        "act_info": "показать все сведения",
        "esc_cancel_hint": "отменить выбор",
        "esc_cancel": "Выбор отменён.",
        "unpack_start": "Распаковываю {f} ...",
        "unpack_done": "Распаковано в: {d}",
        "unpack_binary_ok": "Декодировано изображений циферблата: {n} (в {img}/, манифест: {mf}).",
        "unpacked_files": "Распакованные файлы:",
        "no_binary": "В архиве нет бинарника {b} — только обычные файлы темы.",
        "no_sig_in_binary": "В {b} нет сигнатуры циферблата (55 55 55 55) — файл сохранён как есть.",
        "pack_start": "Запаковываю {d} ...",
        "pack_done": "Создан файл: {f}",
        "pack_dir_prompt": "Папка с распакованной темой для {f}",
        "manifest_missing": "В {d} нет {mf} — запаковываю папку как обычный ZIP.",
        "junk_skip": "Пропущен мусорный файл: {p}",
        "pack_added": "Добавлен новый файл: {p}",
        "dim_mismatch": "Файл {p} имеет размер {w}x{h}px, а {mf} ожидает {mw}x{mh}px. Сохраняйте исходный размер.",
        "png_missing": "Не найден PNG: {p}",
        "px_size_mismatch": "Неверный размер пиксельных данных для {p}.",
        "info_title": "Сведения: {f}",
        "info_size": "Размер",
        "info_mtime": "Изменён",
        "info_sha": "SHA-256",
        "info_zip_ok": "Целостность ZIP: OK",
        "zip_bad_entry": "Ошибка целостности ZIP в записи: {p}",
        "no_zip_info": "Это не ZIP-архив — файл проверен как сырой бинарник циферблата.",
        "info_entries": "Записи архива ({n}):",
        "info_xml": "Метаданные XML",
        "info_images": "Бинарник циферблата {b} — изображений: {n}:",
        "info_layout": "Структура бинарника: префикс {pre} Б, сигнатура+пропуск {sig} Б, изображения {img} Б, хвост {post} Б.",
        "info_aod": "Обнаружены данные AOD (всегда включённый экран).",
        "info_no_aod": "Данные AOD (всегда включённый экран) не обнаружены.",
        "info_no_images": "Бинарник {b} в архиве отсутствует.",
        "incomplete": "(обрезано)",
        "dir_prompt": "Путь к рабочему каталогу",
        "dir_changed": "Рабочий каталог: {d}",
        "input_cancel": "Ввод отменён.",
        "dir_not_found": "Каталог не найден: {d}",
        "lang_menu_title": "Язык интерфейса:",
        "lang_saved": "Язык сохранён: {l}",
        "lang_reset": "Язык сброшен на английский.",
        "lang_reset_hint": "сбросить на английский",
        "deps_title": "Не установлены зависимости: {deps}",
        "deps_offer": "Установить их сейчас?",
        "yes_no_hint": "y — да, n — нет",
        "deps_installing": "Устанавливаю: {deps} ...",
        "deps_ok": "Зависимости установлены.",
        "deps_fail": "Не удалось установить зависимости{e}.",
        "deps_skip": "Продолжаю без Pillow: изображения циферблата будут пропущены, работа с ZIP остаётся доступной.",
        "deps_none": "Все зависимости уже установлены.",
        "bye": "Пока!",
        "interrupt": "Прервано (Ctrl+C).",
        "err_generic": "Ошибка: {e}",
        "not_found": "Файл не найден: {f}",
        "zip_slip": "Небезопасный путь в архиве: {p}",
        "binary_deps_missing": "Для декодирования изображений циферблата нужен Pillow. Установите его и повторите.",
        "cli_prog": "Упаковка/распаковка/просмотр тем HUAWEI .hwt. Без аргументов — интерактивное меню.",
        "cli_unpack": "распаковать файл(ы) .hwt в папки '<имя>_unpacked'",
        "cli_pack": "запаковать папку(и) обратно в .hwt",
        "cli_info": "показать все сведения о файле(ах) .hwt",
        "cli_dir": "рабочий каталог для интерактивного режима",
        "cli_out": "путь вывода (файл для упаковки, папка для распаковки)",
        "cli_lang": "язык интерфейса (en, ru)",
        "cli_install_deps": "установить недостающие зависимости без спроса",
        "cli_no_install_deps": "не предлагать установку зависимостей",
        "cli_version": "показать версию",
        "c_description_xml": "Описание темы, которое показывается в HUAWEI Themes / Health. Текст внутри тегов можно менять, структуру XML — нет.",
        "c_theme_xml": "Манифест темы: цвета и настройки стиля. Меняйте значения атрибутов, теги не переименовывайте.",
        "c_binary": "Бинарник циферблата (изображения в формате RLE-BGRA). Инструмент декодировал его в images/*.png — правьте их и запаковывайте обратно.",
        "c_preview": "Превью темы в галерее. Заменяйте картинкой того же размера.",
        "c_icon": "Иконка в списке тем/циферблатов. Заменяйте тем же размером и форматом.",
        "c_font": "Встроенный шрифт. Имя файла сохраняйте; меняйте только для собственных шрифтов.",
        "c_image": "Графический ресурс. Правьте или заменяйте, сохраняя размер и формат.",
        "c_xml": "XML-метаданные. Структуру сохраняйте, меняйте только значения.",
        "c_other": "Файл ресурса. Сохраняйте исходное имя и формат.",
        "c_manifest": "Манифест инструмента: сведения о структуре бинарника. Не переименовывайте, держите рядом с PNG. PNG заменяйте изображениями тех же размеров.",
        "c_png_dims": "Изображение циферблата {w}x{h}px.",
    },
}

LANG = "en"
WORK_DIR = os.getcwd()
OUT_DIR = None


class ToolError(Exception):
    """A localized, user-facing error."""


def tr(key, **fmt):
    """Translate a key with optional named placeholders."""
    table = TEXT.get(LANG) or TEXT["en"]
    s = table.get(key)
    if s is None:
        s = TEXT["en"].get(key, key)
    if fmt:
        try:
            s = s.format(**fmt)
        except (KeyError, IndexError):
            pass
    return s


# ---------------------------------------------------------------------------
# Language persistence: --lang > saved file > env > default "en"
# ---------------------------------------------------------------------------

def _script_dir():
    """Directory of the script (or of the PyInstaller --onefile executable)."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return base if os.path.isdir(base) else os.getcwd()


def _lang_file():
    return os.path.join(_script_dir(), LANG_FILE)


def detect_lang():
    """Set LANG from the environment, then the saved file, then default."""
    global LANG
    LANG = "en"
    env = os.environ.get("HWT_TOOL_LANG")
    if env in TEXT:
        LANG = env
    saved = None
    try:
        with open(_lang_file(), "r", encoding="utf-8") as fh:
            saved = json.load(fh).get("lang")
    except (OSError, ValueError):
        saved = None
    if saved in TEXT:
        LANG = saved


def _save_lang():
    try:
        with open(_lang_file(), "w", encoding="utf-8") as fh:
            json.dump({"lang": LANG}, fh, indent=2)
            fh.write("\n")
    except OSError:
        pass


def set_lang(code):
    global LANG
    LANG = code
    _save_lang()
    print(c(tr("lang_saved", l=code), "green"))


def reset_lang():
    global LANG
    LANG = "en"
    try:
        os.remove(_lang_file())
    except OSError:
        pass
    print(c(tr("lang_reset"), "green"))


# ---------------------------------------------------------------------------
# Colors, icons and text metrics
# ---------------------------------------------------------------------------

if os.name == "nt":
    os.system("")  # enable ANSI escape sequences on Windows 10+

_STYLES = {
    "bold": "1", "dim": "2", "red": "91", "green": "92",
    "yellow": "93", "blue": "94", "magenta": "95", "cyan": "96", "white": "97",
}


def _color_on():
    if "NO_COLOR" in os.environ:
        return False
    if "FORCE_COLOR" in os.environ:
        return True
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


USE_COLOR = _color_on()


def c(text, style):
    """Wrap text in an ANSI style if colors are enabled."""
    if not USE_COLOR:
        return text
    return "\033[" + _STYLES.get(style, "1") + "m" + text + "\033[0m"


_ICONS = {
    "scan": "🔍", "dir": "📁", "lang": "🌐", "deps": "🧩", "quit": "🚪",
    "unpack": "📤", "pack": "📥", "info": "ℹ️", "file": "⌚",
}


def icon(name):
    return _ICONS.get(name, "•")


def _is_wide(ch):
    o = ord(ch)
    return (
        0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF
        or 0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF
        or 0xFE30 <= o <= 0xFE4F or 0xFF00 <= o <= 0xFF60
        or 0xFFE0 <= o <= 0xFFE6 or 0x1F300 <= o <= 0x1FAFF
        or 0x20000 <= o <= 0x3FFFD
    )


def _disp_width(s):
    return sum(2 if _is_wide(ch) else 1 for ch in s)


def _pad_icon(s, width=2):
    pad = width - _disp_width(s)
    return s + " " * max(pad, 0)


def hint(icon_name, key, text):
    """One menu line: icon + bold [key] + description, mozvpn.py style."""
    print("  " + _pad_icon(icon(icon_name)) + " [" + c(key, "bold") + "] " + text)


def _fmt_size(n):
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0:
            return ("%d %s" % (size, unit)) if unit == "B" else ("%.1f %s" % (size, unit))
        size /= 1024.0
    return "%.1f PiB" % size


def _rel_or_abs(path):
    try:
        rel = os.path.relpath(path, WORK_DIR)
    except ValueError:
        return path
    if rel.startswith(".."):
        return path
    return rel


# ---------------------------------------------------------------------------
# Raw key input
# ---------------------------------------------------------------------------

def _getch():
    """Read a single key press.

    Returns the character, "" for ignored special keys (arrows etc.),
    raises KeyboardInterrupt on Ctrl+C.
    """
    if _HAVE_MSVCRT:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            msvcrt.getwch()  # consume the scan code, ignore the key
            return ""
        if ch == "\x03":
            raise KeyboardInterrupt
        return ch
    if not _HAVE_TERMIOS:
        data = sys.stdin.read(1)
        if data == "\x03":
            raise KeyboardInterrupt
        return data
    try:
        fd = sys.stdin.fileno()
    except (OSError, ValueError, AttributeError):
        data = sys.stdin.read(1)
        if data == "\x03":
            raise KeyboardInterrupt
        return data
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        b1 = os.read(fd, 1)
        if not b1:
            return ""
        if b1 == b"\x1b":
            ready, _, _ = select.select([sys.stdin], [], [], 0.05)
            if not ready:
                return "\x1b"  # a lone Esc
            b2 = os.read(fd, 1)
            if b2 not in (b"[", b"O"):
                return "\x1b"
            while True:  # consume the whole escape sequence, ignore the key
                b = os.read(fd, 1)
                if not b:
                    return ""
                if 0x40 <= b[0] <= 0x7E:
                    return ""
        if b1[0] >= 0x80:
            if b1[0] >= 0xF0:
                need = 4
            elif b1[0] >= 0xE0:
                need = 3
            elif b1[0] >= 0xC0:
                need = 2
            else:
                return ""  # stray UTF-8 continuation byte
            raw = bytes(b1)
            while len(raw) < need:
                chunk = os.read(fd, need - len(raw))
                if not chunk:
                    break
                raw += chunk
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return ""
        if b1 == b"\x03":
            raise KeyboardInterrupt
        return b1.decode("latin-1")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def norm_key(ch):
    """Normalize a key: control characters pass through, letters go lowercase."""
    if not ch or len(ch) != 1:
        return ch
    o = ord(ch)
    if o < 32 or o == 127:
        return ch
    return ch.lower()


def read_line(prompt, default=None):
    """Token input: Enter applies, Backspace deletes, Esc cancels."""
    buf = ""
    suffix = "" if default is None else c(" [" + default + "]", "dim")
    print(c(prompt, "bold") + suffix + ": ", end="", flush=True)
    while True:
        ch = _getch()
        if ch == "":
            continue
        if ch in ("\r", "\n"):
            print()
            if buf:
                return buf
            if default is not None:
                return default
            return ""
        if ch == "\x1b":
            print()
            return None
        if ch in ("\x7f", "\x08"):
            if buf:
                w = _disp_width(buf[-1])
                buf = buf[:-1]
                print("\b \b" * w, end="", flush=True)
            continue
        if ch == "\t":
            continue
        if ch.isprintable():
            buf += ch
            print(ch, end="", flush=True)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def _is_termux():
    return (
        "TERMUX_VERSION" in os.environ
        or "com.termux" in sys.prefix
        or "com.termux" in sys.executable
    )


def missing_deps():
    missing = []
    for pip_name, mod in REQUIRED_DEPS:
        try:
            if importlib.util.find_spec(mod) is None:
                missing.append(pip_name)
        except (ImportError, ValueError):
            missing.append(pip_name)
    return missing


def install_deps(names):
    if not names:
        return True
    print(tr("deps_installing", deps=", ".join(names)))
    try:
        rc = 1
        if _is_termux():
            # Termux ships prebuilt packages; pip wheels are unreliable there.
            pkgs = []
            if "Pillow" in names:
                pkgs.append("python-pillow")
            if pkgs:
                rc = subprocess.call(["pkg", "install", "-y"] + pkgs)
            if rc != 0 or any(n not in ("Pillow",) for n in names):
                env = dict(os.environ, PIP_BREAK_SYSTEM_PACKAGES="1")
                rc = subprocess.call(
                    [sys.executable, "-m", "pip", "install"] + list(names), env=env
                )
        else:
            rc = subprocess.call(
                [sys.executable, "-m", "pip", "install"] + list(names)
            )
        return rc == 0
    except OSError as exc:
        print(c(tr("err_generic", e=exc), "red"))
        return False


def startup_deps():
    """Offer to install missing dependencies at startup."""
    missing = missing_deps()
    if not missing:
        return
    print(c(tr("deps_title", deps=", ".join(missing)), "yellow"))
    try:
        is_tty = bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        is_tty = False
    if not is_tty:
        print(c(tr("deps_skip"), "yellow"))
        return
    print(tr("deps_offer") + "  (" + tr("yes_no_hint") + ")")
    while True:
        ch = norm_key(_getch())
        if ch == "y":
            if install_deps(missing):
                print(c(tr("deps_ok"), "green"))
            else:
                print(c(tr("deps_fail", e=""), "red"))
            return
        if ch == "n":
            print(c(tr("deps_skip"), "yellow"))
            return


# ---------------------------------------------------------------------------
# com.huawei.watchface binary codec
# ---------------------------------------------------------------------------

def decode_watchface(data):
    """Parse the com.huawei.watchface binary.

    Layout (verified against BlackHatDevX/Huawei-Watchface-Extractor-Python):
      signature 55 55 55 55, 4 skipped bytes, then per image:
      4 header bytes, width (uint16 LE), height (uint16 LE),
      then width*height BGRA pixels, RLE-compressed:
      a quad equal to 89 67 45 23 starts a run: 4 BGRA colour bytes
      + run length (uint32 LE); a length of 0 counts as 1 pixel.

    Returns None if the signature is absent; otherwise a dict with the
    prefix, the skipped bytes, the decoded images (RGBA pixel buffers)
    and the trailing blob, so the file can be rebuilt faithfully.
    """
    sig_pos = data.find(SIG)
    if sig_pos < 0:
        return None
    sig_end = sig_pos + len(SIG)
    skip = data[sig_end:sig_end + 4]
    pos = sig_end + 4
    total = len(data)
    images = []
    while pos + 8 <= total:
        img_start = pos
        header = data[pos:pos + 4]
        pos += 4
        width, height = struct.unpack_from("<HH", data, pos)
        pos += 4
        if not (0 < width <= MAX_DIM and 0 < height <= MAX_DIM):
            pos = img_start  # not image data: keep the bytes in the tail
            break
        npix = width * height
        px = bytearray(npix * 4)  # RGBA
        ppos = 0
        ok = True
        while ppos < npix:
            if pos + 4 > total:
                ok = False
                break
            quad = data[pos:pos + 4]
            if quad == MARKER_BGRA:
                if pos + 12 > total:
                    ok = False
                    break
                blue, green, red, alpha = data[pos + 4:pos + 8]
                (count,) = struct.unpack_from("<I", data, pos + 8)
                pos += 12
                if count == 0:
                    count = 1
                run = min(count, npix - ppos)
                px[ppos * 4:(ppos + run) * 4] = bytes((red, green, blue, alpha)) * run
                ppos += run
            else:
                blue, green, red, alpha = quad
                px[ppos * 4:ppos * 4 + 4] = bytes((red, green, blue, alpha))
                ppos += 1
                pos += 4
        if not ok:
            pos = img_start  # truncated image: keep the raw bytes in the tail
            break
        images.append({
            "width": width,
            "height": height,
            "header": header.hex(),
            "pixels": bytes(px),
            "complete": True,
        })
    return {
        "prefix_b64": base64.b64encode(data[:sig_pos]).decode("ascii"),
        "skip_b64": base64.b64encode(skip).decode("ascii"),
        "trailing_b64": base64.b64encode(data[pos:]).decode("ascii"),
        "images": images,
    }


def encode_watchface(manifest, load_png):
    """Rebuild the com.huawei.watchface binary from PNG files + manifest."""
    out = bytearray()
    out += base64.b64decode(manifest.get("prefix_b64", ""))
    out += SIG
    skip = base64.b64decode(manifest.get("skip_b64", "AAAAAA=="))
    out += (skip + b"\x00" * 4)[:4]
    for img in manifest.get("images", []):
        header = bytes.fromhex(img.get("header", "00000000"))
        out += (header + b"\x00" * 4)[:4]
        width = int(img.get("width", 0))
        height = int(img.get("height", 0))
        out += struct.pack("<HH", width, height)
        px = load_png(img)
        if px is None:
            raise ToolError(tr("png_missing", p=img.get("file", "?")))
        if len(px) != width * height * 4:
            raise ToolError(tr("px_size_mismatch", p=img.get("file", "?")))
        n = width * height
        i = 0
        while i < n:
            j = i + 1
            while j < n and px[j * 4:j * 4 + 4] == px[i * 4:i * 4 + 4]:
                j += 1
            run = j - i
            r, g, b, a = px[i * 4:i * 4 + 4]
            bgra = bytes((b, g, r, a))
            if run >= 2 or bgra == MARKER_BGRA:
                # A pixel colored like the marker must always be escaped.
                out += MARKER_BGRA + bgra + struct.pack("<I", run)
            else:
                out += bgra
            i = j
    out += base64.b64decode(manifest.get("trailing_b64", ""))
    return bytes(out)


def _require_pil():
    try:
        from PIL import Image  # noqa: F401
        return Image
    except ImportError as exc:
        raise ToolError(tr("binary_deps_missing")) from exc


def png_save(path, width, height, rgba):
    Image = _require_pil()
    img = Image.frombytes("RGBA", (width, height), rgba)
    img.save(path, "PNG")


def png_load(path):
    Image = _require_pil()
    img = Image.open(path)
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    return img.tobytes(), img.width, img.height


# ---------------------------------------------------------------------------
# .hwt (ZIP) level helpers
# ---------------------------------------------------------------------------

def safe_join(root, name):
    """Join and reject ZIP-slip paths escaping the root."""
    root_abs = os.path.normpath(os.path.abspath(root))
    dest = os.path.normpath(os.path.join(root_abs, name))
    if dest != root_abs and not dest.startswith(root_abs + os.sep):
        raise ToolError(tr("zip_slip", p=name))
    return dest


def xml_meta(data):
    """Best-effort parse of the small XML metadata files inside .hwt."""
    text = None
    for enc in ("utf-8", "gb18030", "utf-16"):
        try:
            text = data.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if text is None:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    found = {}
    for elem in root.iter():
        for key, value in elem.attrib.items():
            short = key.split(":")[-1]
            if short in META_KEYS and short not in found and value:
                found[short] = value
        tag = elem.tag.split(":")[-1]
        inner = (elem.text or "").strip()
        if inner and len(inner) < 128 and ("text_" + tag) not in found:
            found["text_" + tag] = inner
    return found or None


def file_comment(name):
    """Map an archive entry name to a comment key (the knowledge base)."""
    base = os.path.basename(name).lower()
    if base == "description.xml":
        return "c_description_xml"
    if base == "theme.xml":
        return "c_theme_xml"
    if base == BINARY_NAME:
        return "c_binary"
    if base == MANIFEST:
        return "c_manifest"
    if "preview" in base:
        return "c_preview"
    if "icon" in base:
        return "c_icon"
    if base.endswith((".ttf", ".otf")):
        return "c_font"
    if base.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
        return "c_image"
    if base.endswith(".xml"):
        return "c_xml"
    return "c_other"


def _print_entry_comment(rel_path, size=None, dim=None):
    """Log one unpacked file with a comment: what it is and how to edit it."""
    if dim is not None:
        line = tr("c_png_dims", w=dim[0], h=dim[1]) + " " + tr("c_image")
    else:
        line = tr(file_comment(rel_path))
    size_txt = ""
    if size is not None:
        size_txt = c(" (" + _fmt_size(size) + ")", "dim")
    print("  " + c(rel_path, "cyan") + size_txt)
    print("      " + c(line, "dim"))


# ---------------------------------------------------------------------------
# Core operations: unpack / pack / info
# ---------------------------------------------------------------------------

def do_unpack(hwt_path, out_dir=None):
    """Unpack a .hwt into its own folder and explain every extracted file."""
    hwt_path = os.path.abspath(hwt_path)
    if not os.path.isfile(hwt_path):
        raise ToolError(tr("not_found", f=hwt_path))
    stem = os.path.splitext(os.path.basename(hwt_path))[0]
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(hwt_path), stem + "_unpacked")
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    is_zip = zipfile.is_zipfile(hwt_path)
    binary_data = None
    infos = []
    if is_zip:
        with zipfile.ZipFile(hwt_path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                raise ToolError(tr("zip_bad_entry", p=bad))
            infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in infos:
                dest = safe_join(out_dir, info.filename)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
            names = [i.filename for i in infos]
            if BINARY_NAME in names:
                binary_data = zf.read(BINARY_NAME)
    else:
        # Not a ZIP: treat the whole file as a raw watch-face binary.
        with open(hwt_path, "rb") as fh:
            binary_data = fh.read()
        raw_dest = os.path.join(out_dir, BINARY_NAME)
        with open(raw_dest, "wb") as fh:
            fh.write(binary_data)

    decoded = None
    if binary_data is not None:
        decoded = decode_watchface(binary_data)
        if decoded is None:
            if is_zip:
                print(c(tr("no_sig_in_binary", b=BINARY_NAME), "yellow"))
            else:
                print(c(tr("no_sig_in_binary", b=os.path.basename(hwt_path)), "yellow"))
        else:
            img_dir = os.path.join(out_dir, IMG_DIR)
            os.makedirs(img_dir, exist_ok=True)
            for idx, img in enumerate(decoded["images"]):
                fname = "%02d.png" % idx
                png_save(os.path.join(img_dir, fname), img["width"], img["height"], img["pixels"])
                img["file"] = fname
            payload = {
                "tool": "hwt_tool",
                "version": VERSION,
                "binary": BINARY_NAME,
                "prefix_b64": decoded["prefix_b64"],
                "skip_b64": decoded["skip_b64"],
                "trailing_b64": decoded["trailing_b64"],
                "images": [
                    {k: v for k, v in img.items() if k != "pixels"}
                    for img in decoded["images"]
                ],
                "zip_entries": [
                    {
                        "name": i.filename,
                        "date_time": list(i.date_time),
                        "compress_type": i.compress_type,
                    }
                    for i in infos
                ],
                "source": os.path.basename(hwt_path),
            }
            with open(os.path.join(img_dir, MANIFEST), "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            print(c(
                tr("unpack_binary_ok",
                   n=len(decoded["images"]), img=IMG_DIR, mf=MANIFEST),
                "green"))
    elif is_zip:
        print(c(tr("no_binary", b=BINARY_NAME), "yellow"))

    # Requirement: list every unpacked file with a comment.
    print()
    print(c(tr("unpacked_files"), "bold") + " " + c("(" + out_dir + ")", "dim"))
    for info in infos:
        _print_entry_comment(info.filename, size=info.file_size)
    if not is_zip:
        _print_entry_comment(BINARY_NAME, size=len(binary_data))
    if decoded is not None:
        for img in decoded["images"]:
            _print_entry_comment(
                IMG_DIR + "/" + img["file"],
                dim=(img["width"], img["height"]),
            )
        _print_entry_comment(IMG_DIR + "/" + MANIFEST)
    return out_dir


def _load_pack_png(path, img):
    if not os.path.isfile(path):
        raise ToolError(tr("png_missing", p=path))
    data, w, h = png_load(path)
    if (w, h) != (int(img.get("width", 0)), int(img.get("height", 0))):
        raise ToolError(tr(
            "dim_mismatch", p=img.get("file", os.path.basename(path)),
            w=w, h=h, mf=MANIFEST,
            mw=int(img.get("width", 0)), mh=int(img.get("height", 0))))
    return data


def _zip_write(zf, name, data, entry=None):
    """Write a ZIP entry, preserving the original timestamp and compression."""
    date_time = list(DEFAULT_DATE_TIME)
    compress = zipfile.ZIP_DEFLATED
    if entry:
        saved_dt = entry.get("date_time")
        if isinstance(saved_dt, (list, tuple)) and len(saved_dt) == 6:
            date_time = [int(x) for x in saved_dt]
        compress = int(entry.get("compress_type", zipfile.ZIP_DEFLATED))
    info = zipfile.ZipInfo(name, date_time=tuple(date_time))
    info.compress_type = compress
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def do_pack(work_dir, out_path=None, source_hwt=None):
    """Pack an unpacked folder back into a .hwt file."""
    work_dir = os.path.abspath(work_dir)
    if not os.path.isdir(work_dir):
        raise ToolError(tr("dir_not_found", d=work_dir))
    if out_path is None:
        if source_hwt is not None:
            stem = os.path.splitext(os.path.abspath(source_hwt))[0]
            out_path = stem + "_repacked.hwt"
        else:
            out_path = os.path.join(
                os.path.dirname(work_dir), os.path.basename(work_dir) + ".hwt")
    out_path = os.path.abspath(out_path)

    manifest = None
    binary = None
    manifest_path = os.path.join(work_dir, IMG_DIR, MANIFEST)
    if os.path.isfile(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        img_dir = os.path.join(work_dir, IMG_DIR)
        binary = encode_watchface(
            manifest,
            lambda img: _load_pack_png(os.path.join(img_dir, img.get("file", "")), img),
        )
    else:
        print(c(tr("manifest_missing", d=work_dir, mf=MANIFEST), "yellow"))

    written = set()
    with zipfile.ZipFile(out_path, "w") as zf:
        if manifest is not None:
            binary_done = False
            for entry in manifest.get("zip_entries", []):
                nm = entry["name"]
                if nm == BINARY_NAME:
                    _zip_write(zf, nm, binary, entry)
                    binary_done = True
                    written.add(nm)
                    continue
                src = safe_join(work_dir, nm)
                if os.path.isfile(src):
                    with open(src, "rb") as fh:
                        data = fh.read()
                    _zip_write(zf, nm, data, entry)
                    written.add(nm)
            if not binary_done and binary is not None:
                _zip_write(zf, BINARY_NAME, binary, None)
                written.add(BINARY_NAME)
        for root, dirs, files in os.walk(work_dir):
            dirs[:] = [d for d in sorted(dirs) if d != "__pycache__"]
            for fname in sorted(files):
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, work_dir).replace(os.sep, "/")
                if rel in written:
                    continue
                if manifest is not None and rel.startswith(IMG_DIR + "/"):
                    continue  # decoded images and the manifest stay outside the ZIP
                if fname in JUNK_NAMES or fname.lower().endswith(JUNK_EXTS):
                    print(c(tr("junk_skip", p=rel), "yellow"))
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                _zip_write(zf, rel, data, None)
                written.add(rel)
                print(tr("pack_added", p=rel))
    return out_path


def do_info(hwt_path):
    """Print everything knowable about a .hwt file."""
    hwt_path = os.path.abspath(hwt_path)
    if not os.path.isfile(hwt_path):
        raise ToolError(tr("not_found", f=hwt_path))
    print()
    print(c(tr("info_title", f=os.path.basename(hwt_path)), "bold")
          + " " + c("(" + hwt_path + ")", "dim"))
    with open(hwt_path, "rb") as fh:
        data = fh.read()
    size = len(data)
    print("  " + tr("info_size") + ": " + _fmt_size(size) + " (" + str(size) + " B)")
    print("  " + tr("info_mtime") + ": "
          + datetime.fromtimestamp(os.path.getmtime(hwt_path)).strftime("%Y-%m-%d %H:%M:%S"))
    print("  " + tr("info_sha") + ": " + hashlib.sha256(data).hexdigest())

    names = []
    binary = None
    if zipfile.is_zipfile(hwt_path):
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            bad = zf.testzip()
            if bad is None:
                print("  " + c(tr("info_zip_ok"), "green"))
            else:
                print("  " + c(tr("zip_bad_entry", p=bad), "red"))
            infos = [i for i in zf.infolist() if not i.is_dir()]
            names = [i.filename for i in infos]
            print("  " + tr("info_entries", n=len(infos)))
            for i in infos:
                print("    " + c(i.filename, "cyan")
                      + c(" (" + _fmt_size(i.file_size) + ")", "dim"))
            for i in infos:
                if i.filename.lower().endswith(".xml"):
                    meta = xml_meta(zf.read(i.filename))
                    if meta:
                        print("  " + tr("info_xml") + " " + c(i.filename, "cyan") + ":")
                        for k, v in list(meta.items())[:8]:
                            print("      " + k + " = " + str(v))
            if BINARY_NAME in names:
                binary = zf.read(BINARY_NAME)
    else:
        print("  " + c(tr("no_zip_info"), "yellow"))
        binary = data

    if binary is None:
        print("  " + tr("info_no_images", b=BINARY_NAME))
        return
    decoded = decode_watchface(binary)
    if decoded is None:
        print("  " + tr("no_sig_in_binary", b=BINARY_NAME))
        return
    pre_len = len(base64.b64decode(decoded["prefix_b64"]))
    post_len = len(base64.b64decode(decoded["trailing_b64"]))
    images_len = len(binary) - pre_len - len(SIG) - 4 - post_len
    print("  " + tr("info_layout", pre=pre_len, sig=len(SIG) + 4,
                   img=images_len, post=post_len))
    imgs = decoded["images"]
    print("  " + tr("info_images", b=BINARY_NAME, n=len(imgs)))
    for idx, img in enumerate(imgs):
        line = ("    %02d" % idx) + ".png  " + str(img["width"]) + "x" \
            + str(img["height"]) + " px"
        if not img.get("complete", True):
            line += " " + c(tr("incomplete"), "yellow")
        print(line)
    has_aod = any("aod" in nm.lower() for nm in names)
    print("  " + (tr("info_aod") if has_aod else tr("info_no_aod")))


def scan_hwt(directory):
    """Recursively find all .hwt files under a directory."""
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise ToolError(tr("dir_not_found", d=directory))
    found = []
    for root, dirs, files in os.walk(directory):
        dirs.sort()
        for fname in sorted(files):
            if fname.lower().endswith(".hwt"):
                found.append(os.path.join(root, fname))
    return sorted(found)


# ---------------------------------------------------------------------------
# Interactive menus
# ---------------------------------------------------------------------------

def file_list_menu(files):
    """File picker: per-file keys, 0 = all, Esc = back, Enter/Backspace paging."""
    page = 0
    total_pages = max(1, (len(files) + PAGE_SIZE - 1) // PAGE_SIZE)
    while True:
        print()
        print(c(tr("found_n", n=len(files)), "bold"))
        start = page * PAGE_SIZE
        for i, f in enumerate(files[start:start + PAGE_SIZE]):
            try:
                sz = _fmt_size(os.path.getsize(f))
            except OSError:
                sz = "-"
            print("  [" + c(FILE_KEYS[i], "bold") + "] "
                  + _pad_icon(icon("file")) + c(_rel_or_abs(f), "cyan")
                  + c(" (" + sz + ")", "dim"))
        if total_pages > 1:
            print("  " + c(tr("page", cur=page + 1, total=total_pages), "dim"))
        print("  [" + c("0", "bold") + "] " + tr("select_all_hint"))
        print("  [" + c("Esc", "bold") + "] " + tr("esc_back_hint"))
        ch = norm_key(_getch())
        if ch == "\x1b":
            return None
        if ch == "0":
            print(c(tr("all_selected", n=len(files)), "green"))
            return list(files)
        if ch == "\r" and total_pages > 1:
            if page < total_pages - 1:
                page += 1
            continue
        if ch in ("\x7f", "\x08") and total_pages > 1:
            if page > 0:
                page -= 1
            continue
        if ch in FILE_KEYS:
            idx = FILE_KEYS.index(ch) + start
            if idx < len(files):
                return [files[idx]]


def action_menu(selection):
    """Action picker for the selected file(s): 1 unpack, 2 pack, 3 info, Esc."""
    n = len(selection)
    print()
    print(c(tr("action_title", n=n), "bold"))
    for f in selection[:3]:
        print("  " + c(_rel_or_abs(f), "cyan"))
    if n > 3:
        print("  " + c("... +" + str(n - 3), "dim"))
    print()
    hint("unpack", "1", tr("act_unpack"))
    hint("pack", "2", tr("act_pack"))
    hint("info", "3", tr("act_info"))
    print("  [" + c("Esc", "bold") + "] " + tr("esc_cancel_hint"))
    while True:
        ch = norm_key(_getch())
        if ch == "1":
            return "unpack"
        if ch == "2":
            return "pack"
        if ch == "3":
            return "info"
        if ch == "\x1b":
            print(c(tr("esc_cancel"), "yellow"))
            return None


def run_action(action, selection):
    """Run the chosen action over the selected file(s)."""
    single = len(selection) == 1
    for f in selection:
        print()
        stem = os.path.splitext(f)[0]
        try:
            if action == "unpack":
                print(c(tr("unpack_start", f=os.path.basename(f)), "bold"))
                out = None
                if OUT_DIR is not None:
                    if single:
                        out = OUT_DIR
                    else:
                        base = os.path.splitext(os.path.basename(f))[0]
                        out = os.path.join(OUT_DIR, base + "_unpacked")
                out_dir = do_unpack(f, out)
                print(c(tr("unpack_done", d=out_dir), "green"))
            elif action == "pack":
                default_dir = stem + "_unpacked"
                work_dir = default_dir if os.path.isdir(default_dir) else None
                if work_dir is None:
                    work_dir = read_line(tr("pack_dir_prompt", f=os.path.basename(f)))
                    if not work_dir:
                        print(c(tr("input_cancel"), "yellow"))
                        continue
                print(c(tr("pack_start", d=work_dir), "bold"))
                out = None
                if OUT_DIR is not None:
                    if single:
                        out = OUT_DIR
                    else:
                        base = os.path.splitext(os.path.basename(f))[0]
                        out = os.path.join(OUT_DIR, base + "_repacked.hwt")
                out_file = do_pack(work_dir, out, source_hwt=f)
                print(c(tr("pack_done", f=out_file), "green"))
            elif action == "info":
                do_info(f)
        except ToolError as exc:
            print(c(tr("err_generic", e=exc), "red"))
        except OSError as exc:
            print(c(tr("err_generic", e=exc), "red"))


def lang_menu():
    print()
    print(c(tr("lang_menu_title"), "bold"))
    for code in ("en", "ru"):
        mark = c("[x]", "green") if LANG == code else c("[ ]", "dim")
        print("  " + mark + " " + code + " — " + LANG_NAMES[code])
    print()
    hint("lang", "1", "English")
    hint("lang", "2", "Русский")
    hint("lang", "0", tr("lang_reset_hint"))
    print("  [" + c("Esc", "bold") + "] " + tr("esc_back_hint"))
    while True:
        ch = norm_key(_getch())
        if ch == "1":
            set_lang("en")
            return
        if ch == "2":
            set_lang("ru")
            return
        if ch == "0":
            reset_lang()
            return
        if ch == "\x1b":
            return


def run_interactive():
    """Main hot-key loop. Waits for keys; 'q' or Ctrl+C exits."""
    global WORK_DIR
    while True:
        print()
        print(c(tr("title", v=VERSION), "bold"))
        print(c(tr("dir_label") + ": " + WORK_DIR, "dim"))
        print(c(tr("menu_hint"), "dim"))
        print()
        hint("scan", "s", tr("menu_scan"))
        hint("dir", "d", tr("menu_dir"))
        hint("lang", "y", tr("menu_lang"))
        if missing_deps():
            hint("deps", "i", tr("menu_deps"))
        hint("quit", "q", tr("menu_quit"))
        ch = norm_key(_getch())
        if ch == "q":
            print(c(tr("bye"), "green"))
            return 0
        if ch == "s":
            print(tr("scanning", d=WORK_DIR))
            try:
                files = scan_hwt(WORK_DIR)
            except ToolError as exc:
                print(c(tr("err_generic", e=exc), "red"))
                continue
            if not files:
                print(c(tr("no_files", d=WORK_DIR), "yellow"))
                continue
            while True:
                selection = file_list_menu(files)
                if selection is None:
                    break  # Esc: back to the main menu
                while True:
                    action = action_menu(selection)
                    if action is None:
                        break  # Esc: cancel the selection, back to the file list
                    run_action(action, selection)
            continue
        if ch == "d":
            new_dir = read_line(tr("dir_prompt"), default=WORK_DIR)
            if not new_dir:
                print(c(tr("input_cancel"), "yellow"))
            elif os.path.isdir(new_dir):
                WORK_DIR = os.path.abspath(new_dir)
                print(c(tr("dir_changed", d=WORK_DIR), "green"))
            else:
                print(c(tr("dir_not_found", d=new_dir), "red"))
            continue
        if ch == "y":
            lang_menu()
            continue
        if ch == "i":
            missing = missing_deps()
            if missing:
                if install_deps(missing):
                    print(c(tr("deps_ok"), "green"))
                else:
                    print(c(tr("deps_fail", e=""), "red"))
            else:
                print(c(tr("deps_none"), "green"))
            continue
        # any other key (including Esc): stay in the menu


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="hwt_tool",
        description=tr("cli_prog"),
    )
    parser.add_argument("-u", "--unpack", nargs="+", metavar="FILE",
                        help=tr("cli_unpack"))
    parser.add_argument("-p", "--pack", nargs="+", metavar="DIR",
                        help=tr("cli_pack"))
    parser.add_argument("-i", "--info", nargs="+", metavar="FILE",
                        help=tr("cli_info"))
    parser.add_argument("-d", "--dir", metavar="DIR",
                        help=tr("cli_dir"))
    parser.add_argument("-o", "--output", metavar="PATH",
                        help=tr("cli_out"))
    parser.add_argument("--lang", choices=["en", "ru"],
                        help=tr("cli_lang"))
    parser.add_argument("--install-deps", action="store_true",
                        help=tr("cli_install_deps"))
    parser.add_argument("--no-install-deps", action="store_true",
                        help=tr("cli_no_install_deps"))
    parser.add_argument("--version", action="version",
                        version="hwt_tool " + VERSION,
                        help=tr("cli_version"))
    return parser


def run_cli(args):
    rc = 0
    if args.unpack:
        for f in args.unpack:
            out = None
            if OUT_DIR is not None:
                if len(args.unpack) == 1:
                    out = OUT_DIR
                else:
                    base = os.path.splitext(os.path.basename(f))[0]
                    out = os.path.join(OUT_DIR, base + "_unpacked")
            try:
                do_unpack(f, out)
            except (ToolError, OSError) as exc:
                print(c(tr("err_generic", e=exc), "red"))
                rc = 1
    if args.pack:
        for d in args.pack:
            out = OUT_DIR if len(args.pack) == 1 else None
            try:
                created = do_pack(d, out)
                print(c(tr("pack_done", f=created), "green"))
            except (ToolError, OSError) as exc:
                print(c(tr("err_generic", e=exc), "red"))
                rc = 1
    if args.info:
        for f in args.info:
            try:
                do_info(f)
            except (ToolError, OSError) as exc:
                print(c(tr("err_generic", e=exc), "red"))
                rc = 1
    return rc


def main(argv=None):
    global LANG, WORK_DIR, OUT_DIR
    argv = list(sys.argv[1:] if argv is None else argv)

    # Language precedence: --lang > saved file > env > default "en".
    detect_lang()
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv) and argv[i + 1] in TEXT:
            LANG = argv[i + 1]
        elif arg.startswith("--lang=") and arg.split("=", 1)[1] in TEXT:
            LANG = arg.split("=", 1)[1]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.lang:
        LANG = args.lang
        _save_lang()
    if args.dir:
        WORK_DIR = os.path.abspath(args.dir)
    if args.output:
        OUT_DIR = os.path.abspath(args.output)

    # Offer dependency installation at startup (unless suppressed).
    if args.no_install_deps:
        pass
    elif args.install_deps:
        missing = missing_deps()
        if missing:
            if not install_deps(missing):
                print(c(tr("deps_fail", e=""), "red"))
                return 1
            print(c(tr("deps_ok"), "green"))
    else:
        startup_deps()

    has_action = bool(args.unpack or args.pack or args.info)
    if not has_action:
        return run_interactive()
    return run_cli(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print(c(tr("interrupt"), "yellow"))
        sys.exit(130)
