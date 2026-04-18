import base64
import csv
import hashlib
import html as html_module
import io
import json
import os
os.environ['TCL_LIBRARY'] = os.path.join(os.getcwd(), 'python_env', 'tcl', 'tcl8.6')
os.environ['TK_LIBRARY'] = os.path.join(os.getcwd(), 'python_env', 'tcl', 'tk8.6')
import re
import secrets
import shlex
import sys
import subprocess
import threading
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# --- Paths (portable: everything is anchored to this script's directory) ---
APP_ROOT = Path(__file__).resolve().parent
BIN_ROOT = APP_ROOT / "bin"
MEMHUNTER_DATA_ROOT = APP_ROOT / "_memhunter_data"
MEMHUNTER_DATA_ROOT.mkdir(parents=True, exist_ok=True)

STRINGS_EXE = BIN_ROOT / "Strings" / "strings.exe"
VOL2_EXE = BIN_ROOT / "Volatility" / "volatility_2.6_win64_standalone.exe"
VOL3_EXE = BIN_ROOT / "volatility3-win-exes-2.27.0" / "vol.exe"
VOL3_SYMBOLS_DIR = BIN_ROOT / "volatility3-win-exes-2.27.0" / "volatility3" / "symbols"
# Distinct key avoids accidental URL / session collisions with generic names.
MEMORY_IMAGE_PATH_KEY = "mh_memory_image_path"
# Stash dialog result; applied on the *next* run before `st.text_input` (cannot assign widget key after mount).
MEMORY_IMAGE_PATH_PICK_PENDING_KEY = "_mem_path_pick_pending"
# Locked path while analysis_ready (sidebar text_input unmounted — avoids losing the path).
CANONICAL_MEMORY_IMAGE_KEY = "canonical_memory_image_path"
ANALYZED_MEM_NORM_KEY = "_analyzed_memory_path_norm"

# Floating status + deferred blocking work (Volatility / strings) so the UI can paint first.
MH_FLOAT_STATUS_KEY = "_mh_float_status"
MH_PENDING_JOB_KEY = "_mh_pending_blocking_job"

MEMHUNTER_LOGO = APP_ROOT / "assets" / "memhunter_logo.png"
PAGE_ICON = str(MEMHUNTER_LOGO) if MEMHUNTER_LOGO.is_file() else "🧭"
SIDEBAR_LOGO = APP_ROOT / "assets" / "logo.png"
APP_VERSION = "v1.0"


def vol3_symbol_dir_args() -> list[str]:
    """
    Volatility 3 symbol dirs (-s …).

    - Always include the bundled symbols directory under the portable `bin/` tree.
    - If the user selected a custom Linux ISF JSON/ZIP, also include its parent directory.
    """
    args: list[str] = ["-s", str(VOL3_SYMBOLS_DIR)]
    custom_file = st.session_state.get("linux_custom_symbol_file")
    if isinstance(custom_file, str) and custom_file.strip():
        p = Path(custom_file.strip())
        if p.is_file():
            args.extend(["-s", str(p.parent)])
    return args
# Streamlit allows 200–600 px for initial sidebar width (matches fixed CSS below).
MEMHUNTER_SIDEBAR_WIDTH_PX = 300

ENGINE_V2_LABEL = "Volatility 2.6"
ENGINE_V3_LABEL = "Volatility 3"


def missing_required_binaries() -> list[str]:
    missing: list[str] = []
    for p in (STRINGS_EXE, VOL2_EXE, VOL3_EXE):
        if not p.is_file():
            missing.append(str(p))
    return missing

# Vol2: dataframe row selection → focused PID for **Hunt** only (sidebar = global)
PSLIST_SEL_KEY = "pslist_pid_sel"
PSXVIEW_SEL_KEY = "psxview_pid_sel"
PSSCAN_SEL_KEY = "psscan_pid_sel"

# Hunt mode: dashboard tabs (per-process); cleared on analysis reset / new analysis.
HUNT_TABS_SESSION_KEY = "hunt_tab_entries"
# Order of Hunt + global sidebar result tabs (after the four static process tabs), by creation time.
MAIN_TAB_DYNAMIC_ORDER_KEY = "main_tab_dynamic_order"
HUNT_OUTPUT_LOG_MAX = 32
VOL2_DUMP_SUBDIR = "vol2_pid_dumps"
VOL2_DUMPFILES_SUBDIR = "vol2_dumpfiles"

# Vol 2 sidebar: nested accordions. Third column = mode:
# no_profile | profile | profile_opt_pid | pid_dump | printkey_k | hivedump_o | dumpfiles_q | yarascan_y
VOL2_OUTPUT_HISTORY_KEY = "vol2_output_history"
VOL2_OUTPUT_HISTORY_MAX = 24
VOL2_TAB_PARAM_SNIP = 28
# (main_title, "nested", [(sub_title, [(plugin, mode), ...]), ...]) | (main_title, "flat", [(plugin, mode), ...])
VOL2_SIDEBAR_HIERARCHY: list[tuple[str, str, list]] = [
    (
        "OS & PROCESS INFORMATION",
        "nested",
        [
            (
                "IMAGEINFO",
                [("imageinfo", "no_profile"), ("kdbgscan", "profile")],
            ),
            (
                "PROCESS INFORMATION",
                [
                    ("pslist", "profile"),
                    ("psscan", "profile"),
                    ("pstree", "profile"),
                    ("psxview", "profile"),
                ],
            ),
            (
                "CMDLINE & ENVIRONMENT",
                [("cmdline", "profile")],
            ),
        ],
    ),
    (
        "SERVICES & DRIVERS",
        "nested",
        [
            ("SERVICES", [("svcscan", "profile")]),
            (
                "MODULES & DRIVERS",
                [("modules", "profile"), ("modscan", "profile"), ("ssdt", "profile")],
            ),
        ],
    ),
    (
        "REGISTRY",
        "nested",
        [
            (
                "HIVELIST & HIVESCAN",
                [("hivelist", "profile"), ("hivescan", "profile")],
            ),
            (
                "PRINTKEY & HIVEDUMP",
                [("printkey", "printkey_k"), ("hivedump", "hivedump_o")],
            ),
            (
                "REGISTRY ARTIFACTS",
                [
                    ("userassist", "profile"),
                    ("shimcache", "profile"),
                    ("shellbags", "profile"),
                ],
            ),
        ],
    ),
    (
        "FILES & ARTIFACTS",
        "nested",
        [
            (
                "FILESCAN & FILEDUMP",
                [("filescan", "profile"), ("dumpfiles", "dumpfiles_q")],
            ),
            ("MFT", [("mftparser", "profile")]),
        ],
    ),
    (
        "NETWORK INFORMATION",
        "flat",
        [
            ("netscan", "profile"),
            ("connscan", "profile"),
            ("sockets", "profile"),
        ],
    ),
    (
        "CREDENTIALS & SECURITY",
        "flat",
        [("hashdump", "profile"), ("lsadump", "profile")],
    ),
    (
        "MALFIND & MUTANTS",
        "flat",
        [("malfind", "profile"), ("mutantscan", "profile")],
    ),
    ("SEARCH & SCANNING", "flat", [("yarascan", "yarascan_y")]),
    ("CLIPBOARD", "flat", [("clipboard", "profile")]),
]

# Main accordion headers: Streamlit Material Symbols (rounded), monochrome — same family as Google Fonts icons.
VOL2_SIDEBAR_MAIN_MATERIAL_ICON: dict[str, str] = {
    "OS & PROCESS INFORMATION": ":material/monitor:",
    "SERVICES & DRIVERS": ":material/settings:",
    "REGISTRY": ":material/database:",
    "FILES & ARTIFACTS": ":material/folder:",
    "NETWORK INFORMATION": ":material/public:",
    "CREDENTIALS & SECURITY": ":material/shield:",
    "MALFIND & MUTANTS": ":material/bug_report:",
    "SEARCH & SCANNING": ":material/search:",
    "CLIPBOARD": ":material/content_paste:",
}

# Vol 3 sidebar: no --profile; plugins are windows.* (see instructions on Desktop).
VOL3_DUMP_SUBDIR = "vol3_pid_dumps"
VOL3_PHYS_DUMP_SUBDIR = "vol3_phys_dumps"
VOL3_DUMPFILES_PLUGIN_ID = "windows.dumpfiles.DumpFiles"
VOL3_DUMPFILES_RADIO_PHYS = "Physical (--physaddr)"
VOL3_DUMPFILES_RADIO_VIRT = "Virtual (--virtaddr)"
VOL3_DUMPFILES_KIND_PHYS = "phys"
VOL3_DUMPFILES_KIND_VIRT = "virt"
VOL3_OUTPUT_HISTORY_KEY = "vol3_output_history"
# Vol3: use CSV renderer (not "quick") so global scans walk full memory layers — avoids truncated rows.
VOL3_DEFAULT_RENDERER = "csv"
# Hunt cmdline: quick text table matches _extract_hunt_cmdline_display; CSV needs separate parsing.
VOL3_HUNT_CMDLINE_RENDERER = "quick"
# Cap stored sidebar/history text (~8M chars ≈ very large scans); adjust if needed.
OUTPUT_HISTORY_MAX_CHARS = 8_000_000
# Base64 payload above this uses st.code fallback (Streamlit iframe / message size limits).
_SIDEBAR_VIRTUAL_SCROLL_B64_MAX = 4_500_000
# Nested plugin row: (button_label, mode, vol3_plugin_id)
# Modes: v3_plain | v3_pid_opt | v3_dumpfiles_pid | v3_memmap_dump_pid | v3_printkey_key | v3_dumpfiles_addr | v3_yara_string
VOL3_SIDEBAR_HIERARCHY: list[tuple[str, str, list]] = [
    (
        "OS & PROCESS INFORMATION",
        "nested",
        [
            ("OS INFORMATION", [("info", "v3_plain", "windows.info")]),
            (
                "PROCESS INFORMATION",
                [
                    ("pslist", "v3_plain", "windows.pslist"),
                    ("psscan", "v3_plain", "windows.psscan"),
                    ("pstree", "v3_plain", "windows.pstree"),
                ],
            ),
            (
                "CMDLINE & ENVIRONMENT",
                [("cmdline", "v3_plain", "windows.cmdline")],
            ),
        ],
    ),
    (
        "SERVICES & DRIVERS",
        "nested",
        [
            ("SERVICES", [("svcscan", "v3_plain", "windows.svcscan")]),
            (
                "MODULES & DRIVERS",
                [
                    ("modules", "v3_plain", "windows.modules"),
                    ("modscan", "v3_plain", "windows.modscan"),
                    ("ssdt", "v3_plain", "windows.ssdt"),
                ],
            ),
        ],
    ),
    (
        "REGISTRY",
        "nested",
        [
            (
                "HIVELIST & HIVESCAN",
                [
                    ("hivelist", "v3_plain", "windows.registry.hivelist"),
                    ("hivescan", "v3_plain", "windows.registry.hivescan"),
                ],
            ),
            (
                "PRINTKEY & HIVEDUMP",
                [("printkey", "v3_printkey_key", "windows.registry.printkey")],
            ),
            (
                "REGISTRY ARTIFACTS",
                [("userassist", "v3_plain", "windows.registry.userassist")],
            ),
        ],
    ),
    (
        "FILES & ARTIFACTS",
        "nested",
        [
            (
                "FILESCAN & FILEDUMP",
                [
                    ("filescan", "v3_plain", "windows.filescan"),
                    ("dumpfiles", "v3_dumpfiles_addr", VOL3_DUMPFILES_PLUGIN_ID),
                ],
            ),
            ("MFT", [("mftscan", "v3_plain", "windows.mftscan.MFTScan")]),
        ],
    ),
    (
        "NETWORK INFORMATION",
        "flat",
        [
            ("netstat", "v3_plain", "windows.netstat"),
            ("netscan", "v3_plain", "windows.netscan"),
        ],
    ),
    (
        "CREDENTIALS & SECURITY",
        "flat",
        [
            ("hashdump", "v3_plain", "windows.hashdump"),
            ("lsadump", "v3_plain", "windows.lsadump"),
        ],
    ),
    (
        "MALFIND & MUTANTS",
        "flat",
        [
            ("malfind", "v3_plain", "windows.malfind"),
            ("mutantscan", "v3_plain", "windows.mutantscan"),
        ],
    ),
    (
        "SEARCH & SCANNING",
        "flat",
        [("yarascan", "v3_yara_string", "windows.vadyarascan")],
    ),
]

# Tooltips for global sidebar plugin buttons (Vol2/Vol3); key = lowercase button label.
_SIDEBAR_GLOBAL_PLUGIN_HELP: dict[str, str] = {
    "info": (
        "Provides high-level details about the memory image, including OS version, "
        "architecture, and kernel symbols."
    ),
    "pslist": (
        "Lists active processes by walking the doubly-linked list of EPROCESS structures in memory."
    ),
    "psscan": (
        "Scans memory for process objects, including hidden or terminated processes that are "
        "unlinked from the main list."
    ),
    "pstree": (
        "Displays a hierarchical view of processes to reveal parent-child relationships and "
        "suspicious process spawning."
    ),
    "cmdline": (
        "Extracts command-line arguments for all processes, showing how programs were initially executed."
    ),
    "svcscan": (
        "Scans for Windows services, their status, binary paths, and associated PIDs."
    ),
    "modules": (
        "Lists loaded kernel modules and drivers, identifying their base addresses and sizes."
    ),
    "modscan": (
        "Scans for kernel modules, potentially finding hidden or unlinked drivers that were manually mapped."
    ),
    "ssdt": (
        "Lists the System Service Descriptor Table entries to detect kernel-level hooking (rootkits)."
    ),
    "hivelist": (
        "Lists the registry hives currently loaded in memory and their virtual addresses."
    ),
    "hivescan": (
        "Scans memory for registry hive structures that may not be officially linked to the OS."
    ),
    "printkey": (
        "Displays subkeys and values for a specific registry key (requires inputting the key path)."
    ),
    "userassist": (
        "Analyzes UserAssist registry keys to identify which programs were recently executed by users."
    ),
    "filescan": (
        "Scans for FILE_OBJECT structures in memory to identify all files that were open or accessed."
    ),
    "dumpfiles": (
        "Extracts files from memory to disk using their physical or virtual addresses."
    ),
    "mftparser": (
        "Scans memory for Master File Table (MFT) entries, providing metadata about files on the disk."
    ),
    "mftscan": (
        "Scans memory for Master File Table (MFT) entries, providing metadata about files on the disk."
    ),
    "netstat": (
        "Provides a system-wide view of network connections and listening ports "
        "(similar to the live netstat command)."
    ),
    "netscan": (
        "Scans memory for network artifacts to find current and closed connections, including those "
        "hidden by rootkits."
    ),
    "hashdump": (
        "Extracts NTLM/LM password hashes from the SAM and SYSTEM registry hives for offline cracking."
    ),
    "lsadump": (
        "Extracts LSA secrets, such as cleartext passwords and Kerberos tickets, from memory."
    ),
    "malfind": (
        "Performs a global scan for potential code injections across all processes in the system."
    ),
    "mutantscan": (
        "Scans for Mutants (Mutexes), which malware often uses to ensure only one instance of itself is running."
    ),
    "yarascan": (
        "Runs a YARA scan across the entire memory image to find malware signatures or specific strings globally."
    ),
    "clipboard": (
        "Extracts current data stored in the Windows Clipboard, which might contain passwords, URLs, or sensitive text."
    ),
    "connscan": (
        "Scans for TCP connection structures in memory, allowing the recovery of terminated or hidden network connections."
    ),
    "kdbgscan": (
        "Scans for the KDBG (Kernel Debugger Block) structure to identify the correct profile and DTB address for memory analysis."
    ),
    "psxview": (
        "A cross-referencing tool that compares multiple process lists to find hidden processes (rootkits) that don't appear in standard lists."
    ),
    "shellbags": (
        "Parses Shellbag registry keys to track folder access, movements, and user activity within the Windows Explorer."
    ),
    "shimcache": (
        "Analyzes the Application Compatibility Cache (ShimCache) to track previously executed programs and their last modification times."
    ),
    "sockets": (
        "Lists open network sockets for all processes, identifying which processes are listening for incoming traffic."
    ),
}

# Tab key -> (vol2_plugin, vol3_plugin). Vol2 has no windows. prefix.
PLUGIN_NAMES: dict[str, tuple[str, str]] = {
    "pslist": ("pslist", "windows.pslist"),
    "psscan": ("psscan", "windows.psscan"),
    "pstree": ("pstree", "windows.pstree"),
    "psxview": ("psxview", "windows.psxview"),
}

# Sidebar result tabs must not reuse these names (otherwise duplicate tab labels → duplicate widget keys).
STATIC_MAIN_TAB_LABELS: frozenset[str] = frozenset(PLUGIN_NAMES.keys())

st.set_page_config(
    page_title="MemHunter",
    page_icon=PAGE_ICON,
    layout="wide",
    initial_sidebar_state=MEMHUNTER_SIDEBAR_WIDTH_PX,
)

# Inject CSS at the absolute top (prevents FOUC).
st.markdown(
    """
<style>
:root {
  --mh-bg0: #0b0b10;
  --mh-bg1: #12121a;
  --mh-panel: rgba(20, 20, 28, 0.84);
  --mh-panel2: rgba(26, 26, 38, 0.78);
  --mh-fg: #e9e6f7;
  --mh-dim: rgba(233, 230, 247, 0.70);
  --mh-line: rgba(167, 139, 250, 0.22);
  --mh-purple: #a78bfa;
  --mh-purple2: #7c3aed;
  --mh-green: #34d399;
  --mh-salmon: #fb7185;
  --mh-shadow: rgba(0,0,0,0.86);
  --mh-sidebar-top: rgba(18,18,26,0.95);
  --mh-sidebar-bot: rgba(11,11,16,0.96);
  --mh-input-bg: rgba(10, 10, 14, 0.72);
  --mh-btn-bg: rgba(20,20,28,0.88);
  --mh-btn-bg-hover: rgba(26,26,38,0.90);
  --mh-status-bg: rgba(20,20,28,0.92);
  --mh-term: #0b0b0b;
  --mh-term-fg: #d4d4d4;
  --mh-term-dim: #9ca3af;
}
</style>
""",
    unsafe_allow_html=True,
)

# Base layout/theme rules (kept early so the first paint is already on-brand).
st.markdown(
    """
<style>
    /* Hard geometry */
    * { border-radius: 0 !important; }

    /* Sidebar brand (inline logo + title) */
    .mh-sb-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 10px 8px 10px;
        margin: 2px 0 10px 0;
        background: linear-gradient(180deg, var(--mh-sidebar-top), rgba(18,18,26,0.60));
        border: 1px solid rgba(167, 139, 250, 0.18);
        box-shadow: 0 10px 30px rgba(0,0,0,0.35);
    }
    .mh-sb-brand img {
        width: 34px;
        height: 34px;
        object-fit: contain;
        border-radius: 8px !important;
        background: rgba(0,0,0,0.18);
        border: 1px solid rgba(255,255,255,0.06);
    }
    .mh-sb-brand-title {
        font-size: 1.05rem;
        font-weight: 650;
        letter-spacing: 0.2px;
        color: var(--mh-fg);
        line-height: 1.0;
        margin: 0;
        padding: 0;
    }
    .mh-sb-brand-ver {
        font-size: 0.86rem;
        font-weight: 550;
        color: var(--mh-dim);
        margin-left: 6px;
    }
    .mh-sb-divider {
        height: 1px;
        margin: 10px 0 12px 0;
        background: linear-gradient(90deg, rgba(167, 139, 250, 0.35), rgba(167, 139, 250, 0.10), transparent);
    }

    /* App background */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(1200px 780px at 25% -10%, rgba(124,58,237,0.16), transparent 68%),
            radial-gradient(900px 560px at 100% 8%, rgba(251,113,133,0.06), transparent 62%),
            linear-gradient(180deg, var(--mh-bg0), var(--mh-bg1)) !important;
        color: var(--mh-fg) !important;
        opacity: 1 !important;
        filter: none !important;
    }
</style>
""",
    unsafe_allow_html=True,
)


def _sidebar_logo_data_uri() -> str | None:
    p = SIDEBAR_LOGO if SIDEBAR_LOGO.is_file() else MEMHUNTER_LOGO
    if not p.is_file():
        return None
    try:
        raw = p.read_bytes()
        return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    except OSError:
        return None


def _normalize_memory_path(p: str) -> str:
    s = (p or "").strip()
    if not s:
        return ""
    try:
        return os.path.normcase(os.path.normpath(s))
    except (OSError, ValueError):
        return s


def _strip_surrounding_quotes_path(s: str) -> str:
    """Allow pasted paths like `"C:\\image.raw"` or `'C:\\image.raw'`."""
    t = (s or "").strip()
    while len(t) >= 2 and t[0] == t[-1] and t[0] in ('"', "'"):
        t = t[1:-1].strip()
    return t


def _memory_path_from_cli_argv() -> str | None:
    """
    Path from `streamlit run app.py -- … -- --file <path>` (MemHunter.exe launcher),
    optional `MEMHUNTER_IMAGE` env, or `--file=` form. Parsed once per session
    when `_cli_memory_image_seeded` is False.
    """
    envp = (os.environ.get("MEMHUNTER_IMAGE") or "").strip()
    if envp:
        return envp
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--file" and i + 1 < len(args):
            return args[i + 1]
        if isinstance(a, str) and a.startswith("--file="):
            return a.split("=", 1)[1]
    return None


def _pick_memory_file_with_dialog() -> tuple[str | None, bool]:
    """
    Native file picker (tkinter). Returns (path_or_None, dialog_ok).
    dialog_ok False → tkinter unavailable; path None with dialog_ok True → user cancelled.
    """
    # Prefer a Windows-native dialog (doesn't depend on Tk/Tcl, and is more reliable in
    # Streamlit's script runner thread).
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            OFN_EXPLORER = 0x00080000
            OFN_FILEMUSTEXIST = 0x00001000
            OFN_PATHMUSTEXIST = 0x00000800
            OFN_HIDEREADONLY = 0x00000004

            class OPENFILENAMEW(ctypes.Structure):
                _fields_ = [
                    ("lStructSize", wintypes.DWORD),
                    ("hwndOwner", wintypes.HWND),
                    ("hInstance", wintypes.HINSTANCE),
                    ("lpstrFilter", wintypes.LPCWSTR),
                    ("lpstrCustomFilter", wintypes.LPWSTR),
                    ("nMaxCustFilter", wintypes.DWORD),
                    ("nFilterIndex", wintypes.DWORD),
                    ("lpstrFile", wintypes.LPWSTR),
                    ("nMaxFile", wintypes.DWORD),
                    ("lpstrFileTitle", wintypes.LPWSTR),
                    ("nMaxFileTitle", wintypes.DWORD),
                    ("lpstrInitialDir", wintypes.LPCWSTR),
                    ("lpstrTitle", wintypes.LPCWSTR),
                    ("Flags", wintypes.DWORD),
                    ("nFileOffset", wintypes.WORD),
                    ("nFileExtension", wintypes.WORD),
                    ("lpstrDefExt", wintypes.LPCWSTR),
                    ("lCustData", wintypes.LPARAM),
                    ("lpfnHook", wintypes.LPVOID),
                    ("lpTemplateName", wintypes.LPCWSTR),
                    ("pvReserved", wintypes.LPVOID),
                    ("dwReserved", wintypes.DWORD),
                    ("FlagsEx", wintypes.DWORD),
                ]

            # Filter string is a sequence of NUL-separated pairs, ending with double NUL.
            filt = (
                "Memory / dumps\0*.raw;*.vmem;*.mem;*.dmp;*.dump;*.img\0"
                "All files\0*.*\0\0"
            )
            buf = ctypes.create_unicode_buffer(32768)

            ofn = OPENFILENAMEW()
            ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
            ofn.hwndOwner = None
            ofn.lpstrFilter = filt
            ofn.nFilterIndex = 1
            ofn.lpstrFile = ctypes.cast(buf, wintypes.LPWSTR)
            ofn.nMaxFile = ctypes.sizeof(buf) // ctypes.sizeof(wintypes.WCHAR)
            ofn.lpstrTitle = "MemHunter — select memory image"
            ofn.Flags = (
                OFN_EXPLORER
                | OFN_FILEMUSTEXIST
                | OFN_PATHMUSTEXIST
                | OFN_HIDEREADONLY
            )

            comdlg32 = ctypes.WinDLL("comdlg32", use_last_error=True)
            get_open = comdlg32.GetOpenFileNameW
            get_open.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
            get_open.restype = wintypes.BOOL

            # Give the dialog an owner window so Windows keeps it in front.
            try:
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                user32.GetForegroundWindow.restype = wintypes.HWND
                hwnd = user32.GetForegroundWindow()
                if hwnd:
                    ofn.hwndOwner = hwnd
                    try:
                        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
                        user32.SetForegroundWindow.restype = wintypes.BOOL
                        user32.SetForegroundWindow(hwnd)
                    except Exception:
                        pass
            except Exception:
                pass

            ok = bool(get_open(ctypes.byref(ofn)))
            if ok:
                p = (buf.value or "").strip()
                return (p if p else None), True

            # 0 means user cancelled; otherwise dialog error.
            ext_err = comdlg32.CommDlgExtendedError()
            if int(ext_err) == 0:
                return None, True
            return None, False
    except Exception:
        # Fall back to Tk below.
        pass

    # Fallback: Tk dialog (may fail in some packaged/headless setups).
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        return None, False

    root = tk.Tk()
    root.withdraw()
    try:
        root.wm_attributes("-topmost", True)
    except Exception:
        pass
    try:
        root.update()
        path = filedialog.askopenfilename(
            title="MemHunter — select memory image",
            filetypes=[
                ("Memory / dumps", "*.raw *.vmem *.mem *.dmp *.dump *.img"),
                ("All files", "*.*"),
            ],
        )
    except Exception:
        path = ""
    finally:
        try:
            root.destroy()
        except Exception:
            pass

    p = (path or "").strip()
    return (p if p else None), True


def current_memory_image_path() -> str:
    """Path for Volatility `-f`: editor key before analysis; canonical copy after analysis starts."""
    if st.session_state.get("analysis_ready"):
        v = st.session_state.get(CANONICAL_MEMORY_IMAGE_KEY)
        if not isinstance(v, str) or not str(v).strip():
            v = st.session_state.get(MEMORY_IMAGE_PATH_KEY)
    else:
        v = st.session_state.get(MEMORY_IMAGE_PATH_KEY)
    if not isinstance(v, str):
        return ""
    cleaned = _strip_surrounding_quotes_path(v)
    return _normalize_memory_path(cleaned)


def require_memory_image_exists(path: str) -> bool:
    p = (path or "").strip()
    if not p or not os.path.exists(p):
        st.error("Invalid path: File not found.")
        return False
    return True


def _subprocess_run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def run_strings_scan(
    *,
    memory_image_path: str,
    search_term: str,
    min_length: int = 4,
) -> tuple[int, str, str]:
    """
    Sysinternals Strings scan:
    strings.exe -accepteula -n <min_length> "<image>" | findstr /i "<term>"
    Returns (rc, merged_output, display_cmdline).
    """
    mp = (memory_image_path or "").strip()
    term = (search_term or "").strip()
    if not mp:
        return -1, "Memory image path is empty.", ""
    if not os.path.exists(mp):
        return -1, f"Memory image not found: {mp}", ""
    if not STRINGS_EXE.is_file():
        return -1, f"strings.exe not found at: {STRINGS_EXE}", ""
    if not term:
        return -1, "Search term is empty.", ""
    n = int(min_length) if int(min_length) > 0 else 1

    # The pipe (|) needs a shell. Use shell=True, and keep -accepteula to prevent first-run hangs.
    cmdline = f'"{STRINGS_EXE}" -accepteula -n {n} "{mp}" | findstr /i "{term}"'
    proc = subprocess.run(
        cmdline,
        shell=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, _format_vol_subprocess_output(proc).strip(), cmdline


def _mh_float_caption_for_plugin(name: str) -> str:
    """Short status line for the top-right floating indicator."""
    n = (name or "").strip().lower()
    if "yara" in n or "yarascan" in n or "vadyarascan" in n:
        return "Scanning YARA…"
    if "string" in n:
        return "Scanning strings…"
    if any(
        x in n
        for x in (
            "hivelist",
            "hivescan",
            "printkey",
            "hivedump",
            "userassist",
            "shimcache",
            "shellbags",
        )
    ):
        return "Searching registry…"
    if any(x in n for x in ("netscan", "connscan", "socket")):
        return "Scanning network…"
    if any(x in n for x in ("pslist", "psscan", "pstree", "psxview", "pspcid", "psscan")):
        return "Walking processes…"
    if any(x in n for x in ("filescan", "mft", "dumpfiles", "file")):
        return "Scanning files…"
    if any(x in n for x in ("imageinfo", "kdbg")):
        return "Profiling memory image…"
    return f"Running {name}…"


def _render_memhunter_floating_status() -> None:
    """Fixed top-right status (non-blocking); driven by `MH_FLOAT_STATUS_KEY`."""
    raw = st.session_state.get(MH_FLOAT_STATUS_KEY)
    msg = raw.strip() if isinstance(raw, str) else ""
    if not msg:
        st.markdown(
            '<div class="memhunter-float-root memhunter-float-root--hidden" aria-hidden="true"></div>',
            unsafe_allow_html=True,
        )
        return
    safe = html_module.escape(msg)
    st.markdown(
        f'<div class="memhunter-float-root" role="status" aria-live="polite">'
        f'<span class="memhunter-float-text">{safe}</span></div>',
        unsafe_allow_html=True,
    )


def push_strings_scan_results_tab(
    *,
    engine_label: str,
    search_term: str,
    min_length: int,
    rc: int,
    output_text: str,
    cmdline: str,
) -> str:
    """Add Strings output as a dynamic main tab (same viewer as other plugin results)."""
    term = (search_term or "").strip()
    header = f"STRINGS SEARCH RESULTS - {term}" if term else "STRINGS SEARCH RESULTS"
    # Display-only argv (so the command formatter can show something consistent)
    argv = ["cmd.exe", "/c", cmdline] if cmdline else []
    extra = {"search_term": term, "min_length": str(int(min_length))}

    if is_vol3(engine_label):
        return _vol3_push_output_history(
            display_label=header,
            plugin_id="strings",
            category_label="SEARCH & SCANNING",
            mode="strings_scan",
            rc=rc,
            text=output_text,
            argv=argv,
            pid=None,
            append_pid=False,
            extra=extra,
        )
    return _vol2_push_output_history(
        plugin=header,
        category_label="SEARCH & SCANNING",
        mode="strings_scan",
        rc=rc,
        text=output_text,
        argv=argv,
        pid=None,
        append_pid=False,
        extra=extra,
    )


def _format_vol_subprocess_output(proc: subprocess.CompletedProcess) -> str:
    """Join streams for UI/logs: stderr first so VMware / Vol warnings do not corrupt CSV/stdout blocks."""
    out = (proc.stdout or "").rstrip()
    err = (proc.stderr or "").strip()
    if err and out:
        return f"[stderr]\n{err}\n\n[stdout]\n{out}"
    if err:
        return f"[stderr]\n{err}"
    return out


def _tail_history_text(s: str) -> str:
    if len(s) <= OUTPUT_HISTORY_MAX_CHARS:
        return s
    return s[-OUTPUT_HISTORY_MAX_CHARS:]


def _sidebar_output_viewport_height_px(n_lines: int) -> int:
    if n_lines <= 0:
        return 120
    return min(440, max(96, n_lines * 17 + 36))


def _sidebar_output_iframe_outer_height_px(viewport_inner: int) -> int:
    """Top bar + borders + scroll area for sidebar output iframe."""
    return int(viewport_inner) + 96


def _sidebar_output_virtual_pre_html(
    b64: str,
    *,
    download_filename: str,
    viewport_inner_px: int,
) -> str:
    """Monospace <pre> in iframe: search bar, line counts, tiny copy/download, virtualized paint."""
    b64_js = json.dumps(b64)
    dl_js = json.dumps(download_filename)
    vh = max(80, min(int(viewport_inner_px), 900))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
html,body{{margin:0;height:100%;background:#0e1117;}}
#bar{{padding:8px 10px 6px 10px;background:#161b22;border:1px solid #30363d;border-bottom:0;
border-radius:6px 6px 0 0;box-sizing:border-box;}}
#barRow{{display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap;}}
#barLeft{{flex:1 1 160px;min-width:0;}}
#barRight{{flex:0 0 auto;display:flex;gap:2px;align-items:center;padding-top:1px;}}
#q{{width:100%;box-sizing:border-box;padding:6px 10px;border-radius:6px;border:1px solid #30363d;
background:#0d1117;color:#e6edf3;font-size:12px;font-family:system-ui,sans-serif;}}
#info{{margin-top:6px;font-size:11px;color:#8b949e;font-family:system-ui,sans-serif;}}
.iconbtn{{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;padding:0;
margin:0;border:none;border-radius:4px;background:transparent;color:#8b949e;cursor:pointer;
opacity:0.55;line-height:0;}}
.iconbtn:hover{{opacity:1;color:#e6edf3;background:rgba(110,118,129,0.18);}}
.iconbtn svg{{display:block;}}
#vp{{box-sizing:border-box;height:{vh}px;overflow:auto;border:1px solid #30363d;border-radius:0 0 6px 6px;
background:#161b22;margin:0;padding:0;}}
#track{{position:relative;}}
#pre{{position:absolute;left:0;right:0;margin:0;padding:8px 12px;font-family:Consolas,'Cascadia Mono',
'Cascadia Code','Courier New',ui-monospace,monospace;font-size:12px;line-height:17px;white-space:pre;
tab-size:4;-moz-tab-size:4;color:#e6edf3;overflow:hidden;box-sizing:border-box;unicode-bidi:plaintext;}}
#pre mark{{background:rgba(250,204,21,0.35);color:#f8fafc;padding:0;}}
</style></head><body>
<div id="bar">
<div id="barRow">
<div id="barLeft">
<input type="search" id="q" placeholder="Search — filter lines and highlight matches" autocomplete="off"/>
<div id="info"></div>
</div>
<div id="barRight">
<button type="button" class="iconbtn" id="btnCopy" title="Copy to clipboard" aria-label="Copy">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/>
<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
</button>
<button type="button" class="iconbtn" id="btnDl" title="Download as .txt" aria-label="Download">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
<polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
</button>
</div>
</div>
</div>
<div id="vp"><div id="track"><pre id="pre"></pre></div></div>
<script>
(function(){{
const B64 = {b64_js};
const DOWNLOAD_FN = {dl_js};
function decode(b) {{
const bin = atob(b);
const u8 = new Uint8Array(bin.length);
for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
return new TextDecoder("utf-8").decode(u8);
}}
function esc(s) {{
return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}}
function lineHtml(line, q) {{
if (!q) return esc(line);
const ql = q.toLowerCase();
const low = line.toLowerCase();
let out = "";
let i = 0;
while (i < line.length) {{
const j = low.indexOf(ql, i);
if (j < 0) {{ out += esc(line.slice(i)); break; }}
out += esc(line.slice(i, j)) + "<mark>" + esc(line.slice(j, j + q.length)) + "</mark>";
i = j + q.length;
}}
return out;
}}
const text = decode(B64);
const allLines = text.length ? text.split(/\\r?\\n/) : [""];
const N = allLines.length;
const LH = 17;
const vp = document.getElementById("vp");
const track = document.getElementById("track");
const pre = document.getElementById("pre");
const inp = document.getElementById("q");
const info = document.getElementById("info");
const btnCopy = document.getElementById("btnCopy");
const btnDl = document.getElementById("btnDl");
btnCopy.addEventListener("click", function() {{
if (navigator.clipboard && navigator.clipboard.writeText) {{
navigator.clipboard.writeText(text).catch(function(){{}});
}}
}});
btnDl.addEventListener("click", function() {{
try {{
const blob = new Blob([text], {{type: "text/plain;charset=utf-8"}});
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url;
a.download = DOWNLOAD_FN;
document.body.appendChild(a);
a.click();
a.remove();
URL.revokeObjectURL(url);
}} catch (e) {{}}
}});
let viewLines = allLines;
let useHtml = false;
const overscan = 10;
function applyFilter() {{
const q = (inp.value || "").trim();
if (!q) {{
viewLines = allLines;
useHtml = false;
info.textContent = "Total lines: " + N.toLocaleString();
}} else {{
const ql = q.toLowerCase();
viewLines = allLines.filter(function(ln) {{ return ln.toLowerCase().indexOf(ql) >= 0; }});
useHtml = true;
info.textContent = "Showing " + viewLines.length.toLocaleString() + " of " + N.toLocaleString() + " lines";
}}
vp.scrollTop = 0;
paint();
}}
function paint() {{
const n = viewLines.length;
track.style.height = Math.max(n * LH, 1) + "px";
const st = vp.scrollTop;
let i0 = Math.floor(st / LH);
if (i0 < 0) i0 = 0;
let i1 = Math.ceil((st + vp.clientHeight) / LH) + overscan;
if (i1 > n) i1 = n;
if (i0 > i1) i0 = i1;
const slice = viewLines.slice(i0, i1);
const qv = (inp.value || "").trim();
if (useHtml && qv) {{
pre.innerHTML = slice.map(function(ln) {{ return lineHtml(ln, qv); }}).join("\\n");
}} else {{
pre.textContent = slice.join("\\n");
}}
pre.style.top = (i0 * LH) + "px";
}}
inp.addEventListener("input", applyFilter);
vp.addEventListener("scroll", paint, {{passive: true}});
window.addEventListener("resize", paint);
info.textContent = "Total lines: " + N.toLocaleString();
paint();
}})();
</script>
</body></html>"""


def _sidebar_stdout_payload(full_text: str) -> str:
    """Return plugin stdout body (drops leading [stderr] block from _format_vol_subprocess_output)."""
    t = full_text or ""
    mark = "\n[stdout]\n"
    if mark in t:
        return t.split(mark, 1)[-1].strip()
    if t.startswith("[stderr]\n") and "[stdout]" not in t:
        return ""
    return t.strip()


def _sidebar_output_widget_slug(entry: dict) -> str:
    tl = entry.get("tab_label") or entry.get("plugin") or "out"
    s = re.sub(r"[^\w\-]+", "_", str(tl)).strip("_").lower()
    return (s[:44] + "_o") if len(s) > 44 else (s + "_o" if s else "out_o")


def _sidebar_entry_is_mft(entry: dict) -> bool:
    eng = entry.get("engine") or "v2"
    pl = str(entry.get("plugin") or "").strip().lower()
    if eng == "v2":
        return pl == "mftparser"
    plid = str(entry.get("vol3_plugin_id") or "").lower()
    return "mftscan" in plid


def _render_sidebar_clipboard_copy(full_text: str, *, trigger_key: str) -> None:
    """After button sets session flag, inject JS to copy text (best-effort)."""
    if not st.session_state.pop(trigger_key, False):
        return
    safe = json.dumps(full_text)
    components.html(
        f"""<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
const t = {safe};
try {{
navigator.clipboard.writeText(t);
}} catch (e) {{}}
</script></body></html>""",
        height=0,
    )


def _render_sidebar_output_body_code_or_virtual(
    disp: str,
    *,
    entry: dict | None = None,
    widget_slug: str | None = None,
    download_name: str,
) -> None:
    """Single output panel: search bar, line counts, tiny copy/download in iframe (no duplicate Streamlit copy)."""
    if disp == "(empty)":
        st.code(disp, language=None)
        return
    if not widget_slug and entry is None:
        raise ValueError("Provide entry or widget_slug for output widget keys")
    slug = widget_slug if widget_slug else _sidebar_output_widget_slug(entry)
    raw_bytes = disp.encode("utf-8", errors="replace")
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    n_lines = len(disp.splitlines())
    if len(b64) > _SIDEBAR_VIRTUAL_SCROLL_B64_MAX:
        st.caption(
            "Very large output: inline viewer disabled — use the code block’s small **copy** icon; "
            "download is the faint icon on the right."
        )
        qk = f"sb_fallback_q_{slug}"
        st.text_input(
            "Search",
            key=qk,
            placeholder="Search — filter lines and highlight matches",
            label_visibility="collapsed",
        )
        q = str(st.session_state.get(qk, "") or "").strip().lower()
        lines = disp.splitlines()
        n_all = len(lines)
        shown = [ln for ln in lines if not q or q in ln.lower()]
        meta = f'<span class="memhunter-out-linecount">Total lines: **{n_all:,}**</span>'
        if q:
            meta += (
                f'<span class="memhunter-out-filtered"> · Showing **{len(shown):,}**</span>'
            )
        st.markdown(
            '<div class="memhunter-micro-actions-marker"></div>',
            unsafe_allow_html=True,
        )
        c_meta, c_dl = st.columns([0.82, 0.18])
        with c_meta:
            st.markdown(meta, unsafe_allow_html=True)
        with c_dl:
            st.download_button(
                label=":material/download:",
                data=raw_bytes,
                file_name=download_name,
                mime="text/plain; charset=utf-8",
                key=f"sb_fallback_txt_{slug}",
                type="tertiary",
                help="Download full output as .txt",
                width="content",
            )
        st.code("\n".join(shown) if q else disp, language=None)
        return
    vp = _sidebar_output_viewport_height_px(n_lines)
    outer = _sidebar_output_iframe_outer_height_px(vp)
    components.html(
        _sidebar_output_virtual_pre_html(
            b64,
            download_filename=download_name,
            viewport_inner_px=vp,
        ),
        height=outer,
        scrolling=False,
    )


def _parse_suggested_profile(imageinfo_stdout: str) -> str:
    for line in imageinfo_stdout.splitlines():
        if "Suggested Profile" in line and ":" in line:
            m = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)", line, re.IGNORECASE)
            if not m:
                continue
            rest = m.group(1).strip()
            if not rest:
                continue
            first = rest.split(",")[0].strip()
            # "Win7SP1x64 (Instantiated at ..." -> Win7SP1x64
            prof = first.split()[0].strip()
            if prof:
                return prof
    return ""


@st.cache_data(show_spinner=False)
def get_vol2_profile(mem_file: str, vol2_exe: str) -> str:
    """Run imageinfo and return the first suggested profile (cached per image + exe path)."""
    cmd = [str(vol2_exe), "-f", mem_file, "imageinfo"]
    proc = _subprocess_run(cmd)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    prof = _parse_suggested_profile(out)
    return prof


def sync_vol2_profile_to_session(mem_file: str, vol2_exe: str) -> str:
    """Call cached profiler and mirror result into session_state."""
    prof = get_vol2_profile(mem_file, vol2_exe)
    st.session_state["vol2_profile"] = prof if prof else None
    return prof


def is_vol3(engine_label: str) -> bool:
    return engine_label == ENGINE_V3_LABEL


def plugin_for(engine_label: str, tab_key: str) -> str:
    v2p, v3p = PLUGIN_NAMES[tab_key]
    return v3p if is_vol3(engine_label) else v2p


def _is_vol_separator_or_banner_line(line: str) -> bool:
    """Vol2 prints dashed rules between header and data; strip them before CSV/FWF parse."""
    s = line.strip()
    if not s:
        return True
    if s.startswith("Progress:"):
        return True
    if "volware" in s.lower():
        return True
    if s.startswith("WARNING") or "FutureWarning" in s or "DeprecationWarning" in s:
        return True
    if s.startswith("volatility3\\") or "volatility3/" in s:
        return True
    if len(s) >= 16 and re.match(r"^[-_.=\s]+$", s):
        return True
    if s.startswith("***"):
        return True
    return False


def _extract_csv_from_vol_output(raw: str) -> str:
    lines = raw.splitlines()
    start_i = None
    for i, line in enumerate(lines):
        s = line.strip()
        if _is_vol_separator_or_banner_line(line):
            continue
        if "PID" in s and (s.count(",") >= 2 or s.count("\t") >= 2):
            start_i = i
            break
    if start_i is None:
        return ""
    return "\n".join(lines[start_i:])


def _dataframe_from_stdout(stdout: str) -> pd.DataFrame:
    body = _extract_csv_from_vol_output(stdout) or stdout
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return pd.DataFrame()
    try:
        sep = "\t" if any("\t" in ln and ln.count("\t") >= 2 for ln in lines[:3]) else ","
        return pd.read_csv(
            io.StringIO("\n".join(lines)),
            engine="python",
            on_bad_lines="warn",
            sep=sep,
        )
    except Exception:
        return pd.DataFrame()


# Cap filescan rows shown for Streamlit row-selection dump (full output stays in viewer above).
VOL3_FILESCAN_DUMP_UI_MAX_ROWS = 20_000


def _vol3_filescan_row_phys_offset(df: pd.DataFrame, row_pos: int) -> str | None:
    """Physical offset for **windows.dumpfiles --physaddr** from a filescan CSV row."""
    if df.empty or row_pos < 0 or row_pos >= len(df):
        return None
    row = df.iloc[row_pos]

    def cell_str(col: object) -> str | None:
        v = row[col]
        if pd.isna(v):
            return None
        s = str(v).strip()
        return s or None

    def is_virt_col(name: str) -> bool:
        l = str(name).strip().lower()
        return "(v)" in l or "virtual" in l

    cols = list(df.columns)
    for c in cols:
        l = str(c).strip().lower()
        if is_virt_col(c) or "offset" not in l:
            continue
        if "(p)" in l or "phys" in l:
            got = cell_str(c)
            if got:
                return got

    for c in cols:
        l = str(c).strip().lower()
        if is_virt_col(c) or "offset" not in l:
            continue
        got = cell_str(c)
        if got:
            return got

    return cell_str(cols[0])


def _drop_separator_like_rows(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    def row_is_sep(r):
        vals = [str(v).strip() for v in r if pd.notna(v) and str(v).strip() != ""]
        if not vals:
            return True
        return all(re.fullmatch(r"[-_.=\s]+", v) is not None for v in vals)

    m = ~df.apply(row_is_sep, axis=1)
    return df[m].reset_index(drop=True)


def _vol2_df_suspicious(df: pd.DataFrame) -> bool:
    if df.empty:
        return True
    if len(df) == 1:
        if df.shape[1] == 1:
            v = str(df.iloc[0, 0]).strip()
            if re.fullmatch(r"[-_.=\s]+", v) is not None:
                return True
        vals = [str(v).strip() for v in df.iloc[0] if pd.notna(v) and str(v).strip()]
        if vals and all(re.fullmatch(r"[-_.=\s]+", v) is not None for v in vals):
            return True
    if df.shape[1] == 1 and len(df) >= 2:
        return True
    return False


def _vol2_fwf_table(raw: str) -> pd.DataFrame:
    lines_orig = [ln.rstrip() for ln in (raw or "").splitlines()]
    lines = [ln for ln in lines_orig if ln.strip() and not _is_vol_separator_or_banner_line(ln)]
    start = None
    for i, ln in enumerate(lines):
        if not re.search(r"\bPID\b", ln, re.I):
            continue
        stp = ln.lstrip()
        if stp.startswith("."):
            continue
        if re.match(r"^0x[0-9a-fA-F]+\s*:", stp):
            continue
        start = i
        break
    if start is None:
        return pd.DataFrame()
    block = "\n".join(lines[start : start + 50000])
    try:
        df = pd.read_fwf(io.StringIO(block))
    except Exception:
        return pd.DataFrame()
    return _drop_separator_like_rows(df)


def normalize_vol2_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    ren: dict[str, str] = {}
    for c in df.columns:
        key = str(c).strip()
        kl = key.lower().replace(" ", "")
        if kl == "pid" and key != "PID":
            ren[c] = "PID"
        elif kl == "ppid" and key != "PPID":
            ren[c] = "PPID"
        elif kl == "thds" and key != "Threads":
            ren[c] = "Threads"
        elif kl == "hnds" and key != "Handles":
            ren[c] = "Handles"
    return df.rename(columns=ren)


_VOL2_PSTREE_NAME_RE = re.compile(
    r"^(?P<prefix>\s*(?:\.\s*)*)(?P<off>0x[0-9a-fA-F]+):(?P<exe>.*)$",
    re.IGNORECASE,
)


def split_vol2_pstree_name_offset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Vol2 pstree packs tree dots + virtual address + image into one Name cell
    (e.g. '. 0xffff...:lsm.exe'). Split into Offset(V) and Name (dots + exe only).
    """
    if df.empty:
        return df
    if "Offset(V)" in df.columns or "Offset" in df.columns:
        return df
    name_col = next((c for c in df.columns if str(c).strip().lower() == "name"), None)
    if name_col is None:
        return df
    out = df.copy()
    new_names: list[str] = []
    offsets: list[str] = []
    for val in out[name_col].tolist():
        if val is None or (isinstance(val, float) and pd.isna(val)):
            s = ""
        else:
            s = str(val).strip()
        m = _VOL2_PSTREE_NAME_RE.match(s)
        if m:
            prefix = m.group("prefix") or ""
            exe = (m.group("exe") or "").strip()
            offsets.append(m.group("off"))
            new_names.append((prefix + exe).strip() if prefix else exe)
        else:
            offsets.append("")
            new_names.append(s)
    loc = out.columns.get_loc(name_col)
    if isinstance(loc, slice):
        loc = out.columns.get_indexer_for([name_col])[0]
    out.insert(int(loc), "Offset(V)", offsets)
    out[name_col] = new_names
    return out


def _parse_vol2_output_to_df(stdout: str) -> pd.DataFrame:
    raw = stdout or ""
    body = _extract_csv_from_vol_output(raw) or raw
    filtered_lines = [
        ln for ln in body.splitlines() if ln.strip() and not _is_vol_separator_or_banner_line(ln)
    ]
    df_csv = pd.DataFrame()
    if filtered_lines:
        joined = "\n".join(filtered_lines)
        try:
            sample = filtered_lines[: min(8, len(filtered_lines))]
            sep = "\t" if any("\t" in ln and ln.count("\t") >= 2 for ln in sample) else ","
            df_csv = pd.read_csv(
                io.StringIO(joined),
                engine="python",
                on_bad_lines="warn",
                sep=sep,
            )
        except Exception:
            df_csv = pd.DataFrame()
    df_csv = _drop_separator_like_rows(df_csv)
    if not df_csv.empty and not _vol2_df_suspicious(df_csv):
        return normalize_vol2_columns(df_csv)
    df_fwf = _vol2_fwf_table(raw)
    if not df_fwf.empty:
        return normalize_vol2_columns(df_fwf)
    if not df_csv.empty:
        return normalize_vol2_columns(df_csv)
    return pd.DataFrame()


def run_vol(
    engine_label: str,
    mem_file: str,
    plugin: str,
    *,
    vol2_profile: str | None = None,
    prefer_csv: bool = True,
) -> tuple[pd.DataFrame, str]:
    """
    Run Volatility 2 or 3. Returns (dataframe, raw_stdout).
    Vol2: tries --output=csv first; on empty parse, retries without CSV (text-only fallback).
    """
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        st.error("Invalid path: File not found.")
        return pd.DataFrame(), ""

    raw_out = ""
    if is_vol3(engine_label):
        cmd = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            plugin,
        ]
        proc = _subprocess_run(cmd)
        raw_out = proc.stdout or ""
        if proc.returncode != 0 and not raw_out.strip():
            st.error(f"`{plugin}` exited with code {proc.returncode}.")
            if proc.stderr:
                st.code(proc.stderr[-4000:])
            return pd.DataFrame(), _format_vol_subprocess_output(proc)
        merged = _format_vol_subprocess_output(proc)
        return _dataframe_from_stdout(raw_out), merged

    # Volatility 2
    if not vol2_profile:
        st.error("Volatility 2 requires a profile. Run imageinfo / Start Analysis first.")
        return pd.DataFrame(), ""

    if prefer_csv:
        cmd = [str(VOL2_EXE), "-f", mem_file, f"--profile={vol2_profile}", plugin, "--output=csv"]
        proc = _subprocess_run(cmd)
        raw_out = proc.stdout or ""
        err = proc.stderr or ""
        if proc.returncode != 0 and not raw_out.strip():
            if "access" in err.lower() or "denied" in err.lower():
                st.error("Volatility 2 reported an error (e.g. Access Denied). Check paths and permissions.")
            if err.strip():
                st.code(err[-4000:])
        df = _parse_vol2_output_to_df(raw_out)
        if not df.empty:
            return df, _format_vol_subprocess_output(proc)

    # Fallback: text output (no CSV)
    cmd_txt = [str(VOL2_EXE), "-f", mem_file, f"--profile={vol2_profile}", plugin]
    proc2 = _subprocess_run(cmd_txt)
    if proc2.returncode != 0 and not (proc2.stdout or "").strip():
        st.warning(f"`{plugin}` text run exited with code {proc2.returncode}.")
    df2 = _parse_vol2_output_to_df(proc2.stdout or "")
    return df2, _format_vol_subprocess_output(proc2)


def _vol2_dump_dir_for_pid(mem_file: str, pid: int) -> str:
    root = MEMHUNTER_DATA_ROOT / VOL2_DUMP_SUBDIR / f"pid_{pid}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _vol2_dump_dir_for_dumpfiles(mem_file: str) -> str:
    root = MEMHUNTER_DATA_ROOT / VOL2_DUMPFILES_SUBDIR
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


_SIDEBAR_GLOBAL_DUMP_DIR = "global_sidebar"


def _vol2_global_dump_dir(mem_file: str) -> str:
    """Vol2 sidebar: procdump/memdump without -p — output folder under the portable app data dir."""
    root = MEMHUNTER_DATA_ROOT / VOL2_DUMP_SUBDIR / _SIDEBAR_GLOBAL_DUMP_DIR
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _vol3_global_dump_dir(mem_file: str) -> str:
    """Vol3 sidebar: dumpfiles/memmap without --pid — output folder under the portable app data dir."""
    root = MEMHUNTER_DATA_ROOT / VOL3_DUMP_SUBDIR / _SIDEBAR_GLOBAL_DUMP_DIR
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _vol3_dump_dir_for_pid(mem_file: str, pid: int) -> str:
    root = MEMHUNTER_DATA_ROOT / VOL3_DUMP_SUBDIR / f"pid_{pid}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _vol3_dump_dir_phys(mem_file: str) -> str:
    root = MEMHUNTER_DATA_ROOT / VOL3_PHYS_DUMP_SUBDIR
    os.makedirs(str(root), exist_ok=True)
    return str(root)


def _vol3_dumpfiles_addr_kind(extra: dict[str, str] | None) -> str:
    """Return VOL3_DUMPFILES_KIND_PHYS or VOL3_DUMPFILES_KIND_VIRT from sidebar/filescan extra_args."""
    x = extra or {}
    k = (x.get("dumpfiles_addr_mode") or VOL3_DUMPFILES_KIND_PHYS).strip().lower()
    return VOL3_DUMPFILES_KIND_VIRT if k == VOL3_DUMPFILES_KIND_VIRT else VOL3_DUMPFILES_KIND_PHYS


def _extract_pid_from_row(df: pd.DataFrame, row_pos: int) -> int | None:
    if df is None or df.empty or row_pos < 0 or row_pos >= len(df):
        return None
    col = next((c for c in df.columns if str(c).strip().lower() == "pid"), None)
    if col is None:
        return None
    v = pd.to_numeric(df.iloc[row_pos][col], errors="coerce")
    if pd.isna(v):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


_VOL2_NAME_COLUMNS = (
    "name",
    "imagefilename",
    "imagename",
    "process",
    "comm",
    "filename",
)


def _clean_focus_process_display(raw: str) -> str:
    """Strip pstree dot-indent and trailing offset:exe junk for sidebar display."""
    s = (raw or "").strip()
    if not s:
        return ""
    s = re.sub(r"^[\s.]+", "", s)
    if ":" in s and not s.lower().startswith("0x"):
        tail = s.rsplit(":", 1)[-1].strip()
        if tail:
            s = tail
    return s.strip()


def _extract_process_name_from_row(df: pd.DataFrame, row_pos: int) -> str | None:
    if df is None or df.empty or row_pos < 0 or row_pos >= len(df):
        return None
    row = df.iloc[row_pos]
    lower_map = {str(c).strip().lower(): c for c in df.columns}
    for key in _VOL2_NAME_COLUMNS:
        col = lower_map.get(key)
        if col is None:
            continue
        v = row[col]
        if v is None or (isinstance(v, float) and pd.isna(v)):
            continue
        s = _clean_focus_process_display(str(v))
        if s:
            return s[:120]
    return None


def resolve_vol2_focus_meta(*, frames: dict) -> tuple[int | None, str | None]:
    """Return (pid, process name) from the process table the user touched most recently, then fall back."""
    for _sel_key, src in _hunt_selection_checks_ordered():
        pos = _dataframe_selected_row(_sel_key)
        if pos is None:
            continue
        raw = frames.get(src)
        if raw is None:
            continue
        df = raw.reset_index(drop=True)
        if src == "pstree":
            df = split_vol2_pstree_name_offset(df)
        pid = _extract_pid_from_row(df, pos)
        if pid is not None:
            return pid, _extract_process_name_from_row(df, pos)
    return None, None


def resolve_vol2_focus_pid(*, frames: dict) -> int | None:
    pid, _ = resolve_vol2_focus_meta(frames=frames)
    return pid


def _prepare_plugin_frame_for_display(
    frames: dict, source: str, engine_label: str
) -> pd.DataFrame | None:
    raw = frames.get(source)
    if raw is None or raw.empty:
        return None
    df = raw.reset_index(drop=True)
    if source == "pstree" and engine_label == ENGINE_V2_LABEL:
        df = split_vol2_pstree_name_offset(df)
    return df


def resolve_hunt_selection_context(
    *, frames: dict, engine_label: str
) -> tuple[str, int, int, str] | None:
    """
    Which main-table selection drives Hunt: last table where the row selection changed,
    then default order (pstree → pslist → psxview → psscan).
    Returns (source_key, row_pos, pid, display_name) or None.
    """
    for sel_key, src in _hunt_selection_checks_ordered():
        pos = _dataframe_selected_row(sel_key)
        if pos is None:
            continue
        df = _prepare_plugin_frame_for_display(frames, src, engine_label)
        if df is None:
            continue
        pid = _extract_pid_from_row(df, pos)
        if pid is None:
            continue
        name = _extract_process_name_from_row(df, pos) or f"PID {pid}"
        return src, pos, pid, name
    return None


def _hunt_df_find_column(df: pd.DataFrame, *candidates: str) -> str | None:
    if df is None or df.empty:
        return None
    norm_cols = {str(c).strip().lower().replace(" ", ""): c for c in df.columns}
    for cand in candidates:
        k = cand.lower().replace(" ", "")
        if k in norm_cols:
            return norm_cols[k]
    for c in df.columns:
        cl = str(c).strip().lower().replace(" ", "")
        for cand in candidates:
            if cand.lower().replace(" ", "") in cl:
                return c
    return None


def _hunt_relationship_base_df(
    frames: dict,
) -> tuple[pd.DataFrame | None, str | None]:
    """Prefer pslist for PID/PPID graph; else psscan."""
    for key in ("pslist", "psscan"):
        raw = frames.get(key)
        if raw is not None and not raw.empty:
            return raw.reset_index(drop=True), key
    return None, None


def _hunt_format_cell_value(v) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    s = str(v).strip()
    return s if s else ""


def build_hunt_section1_snapshot(
    *,
    frames: dict,
    source: str,
    row_pos: int,
    pid: int,
    name: str,
    engine_label: str,
) -> dict[str, str | list[str]]:
    df_sel = _prepare_plugin_frame_for_display(frames, source, engine_label)
    row = None
    if df_sel is not None and 0 <= row_pos < len(df_sel):
        row = df_sel.iloc[row_pos]

    base_df, _base_key = _hunt_relationship_base_df(frames)
    ppid: int | None = None
    if row is not None and df_sel is not None:
        pp_col = _hunt_df_find_column(df_sel, "ppid", "parentpid", "parent pid")
        if pp_col is not None:
            v = pd.to_numeric(row[pp_col], errors="coerce")
            if not pd.isna(v):
                ppid = int(v)

    parent_display = "None"
    if ppid is not None and base_df is not None:
        pid_col = _hunt_df_find_column(base_df, "pid")
        name_col = _hunt_df_find_column(
            base_df, "name", "imagefilename", "imagename", "process", "comm", "filename"
        )
        if pid_col is not None:
            for _, r in base_df.iterrows():
                pv = pd.to_numeric(r[pid_col], errors="coerce")
                if pd.isna(pv) or int(pv) != ppid:
                    continue
                if name_col is not None:
                    raw_n = _hunt_format_cell_value(r[name_col])
                    pn = _clean_focus_process_display(raw_n) or "?"
                    parent_display = f"{pn} ({ppid})"
                else:
                    parent_display = f"({ppid})"
                break

    children_lines: list[str] = []
    if base_df is not None:
        pid_col = _hunt_df_find_column(base_df, "pid")
        ppid_col = _hunt_df_find_column(base_df, "ppid", "parentpid", "parent pid")
        name_col = _hunt_df_find_column(
            base_df, "name", "imagefilename", "imagename", "process", "comm", "filename"
        )
        if pid_col is not None and ppid_col is not None:
            for _, r in base_df.iterrows():
                ppv = pd.to_numeric(r[ppid_col], errors="coerce")
                if pd.isna(ppv) or int(ppv) != int(pid):
                    continue
                cv = pd.to_numeric(r[pid_col], errors="coerce")
                if pd.isna(cv):
                    continue
                c_pid = int(cv)
                cname = "?"
                if name_col is not None:
                    raw_n = _hunt_format_cell_value(r[name_col])
                    cname = _clean_focus_process_display(raw_n) or "?"
                children_lines.append(f"{cname} ({c_pid})")

    threads_s = "N/A"
    handles_s = "N/A"
    if row is not None and df_sel is not None:
        th_col = _hunt_df_find_column(
            df_sel, "thds", "threads", "numthreads", "threadcount", "# threads"
        )
        if th_col is not None:
            tv = _hunt_format_cell_value(row[th_col])
            threads_s = tv if tv else "N/A"
        h_col = _hunt_df_find_column(
            df_sel, "handles", "handlecount", "# handles", "hnds"
        )
        if h_col is not None:
            hv = _hunt_format_cell_value(row[h_col])
            handles_s = hv if hv else "N/A"

    time_parts: list[str] = []
    if row is not None and df_sel is not None:
        for c in df_sel.columns:
            cl = str(c).strip().lower()
            if not any(
                k in cl for k in ("create", "exit", "time", "started", "exited")
            ):
                continue
            tv = _hunt_format_cell_value(row[c])
            if tv:
                time_parts.append(f"{c}: {tv}")
    times_display = " · ".join(time_parts) if time_parts else "N/A"

    return {
        "process_name": name,
        "pid": str(pid),
        "parent_display": parent_display,
        "children_lines": children_lines if children_lines else [],
        "threads": threads_s,
        "handles": handles_s,
        "times_display": times_display,
    }


def _hunt_tab_label_proposed(process_name: str, pid: int) -> str:
    snip = (process_name or "").strip()[:48]
    return f"Hunt - {snip} ({pid})"


def _hunt_unique_tab_label(existing: list[str], proposed: str) -> str:
    if proposed not in existing:
        return proposed
    n = 2
    while f"{proposed} [{n}]" in existing:
        n += 1
    return f"{proposed} [{n}]"


def run_hunt_cmdline_plugin(
    engine_label: str,
    mem_file: str,
    pid: int,
    *,
    vol2_profile: str | None,
) -> tuple[int, str]:
    """Vol2/Vol3 cmdline for a single PID (text output for Hunt tab)."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid memory image path."
    if is_vol3(engine_label):
        cmd = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_HUNT_CMDLINE_RENDERER,
            "-f",
            mem_file,
            "windows.cmdline",
            "--pid",
            str(pid),
        ]
    else:
        prof = (vol2_profile or "").strip()
        if not prof:
            return -1, "Volatility 2 profile missing — run Start Analysis first."
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "cmdline",
            "-p",
            str(pid),
            "--output=text",
        ]
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    return proc.returncode, text


def run_hunt_yarascan_plugin(
    engine_label: str,
    mem_file: str,
    pid: int,
    yara_string: str,
    *,
    vol2_profile: str | None,
) -> tuple[int, str, list[str]]:
    """Vol2 yarascan -p PID -Y … / Vol3 vadyarascan (Hunt). Returns (rc, merged text, argv)."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid memory image path.", []
    ys = (yara_string or "").strip()
    if not ys:
        return -1, "Empty YARA / search string.", []
    if is_vol3(engine_label):
        cmd = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            "windows.vadyarascan",
            "--yara-string",
            ys,
            "--pid",
            str(pid),
        ]
    else:
        prof = (vol2_profile or "").strip()
        if not prof:
            return -1, "Volatility 2 profile missing — run Start Analysis first.", []
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "yarascan",
            "-p",
            str(pid),
            "-Y",
            ys,
            "--output=text",
        ]
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    return proc.returncode, text, cmd


def run_hunt_pid_text_plugin(
    engine_label: str,
    mem_file: str,
    pid: int,
    vol2_plugin: str,
    vol3_plugin: str,
    *,
    vol2_profile: str | None,
) -> tuple[int, str, list[str]]:
    """Vol2: plugin -p PID · Vol3: plugin --pid (CSV), except threads = full list + findstr-style PID filter."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid memory image path.", []
    if is_vol3(engine_label):
        if vol3_plugin == "windows.threads.Threads":
            base_cmd = [
                str(VOL3_EXE),
                "-q",
                *vol3_symbol_dir_args(),
                "-f",
                mem_file,
                "windows.threads.Threads",
            ]
            proc = _subprocess_run(base_cmd)
            raw = _format_vol_subprocess_output(proc).strip()
            pid_s = str(int(pid))
            if os.name == "nt":
                display_cmd = [*base_cmd, "|", "findstr", pid_s]
            else:
                display_cmd = [*base_cmd, "|", "grep", "-F", "--", pid_s]
            if proc.returncode != 0:
                return proc.returncode, raw, display_cmd
            filt_lines = [ln for ln in raw.splitlines() if pid_s in ln]
            out = "\n".join(filt_lines)
            if not out and raw:
                out = f"(findstr filter: no lines contain PID {pid_s})"
            return 0, out, display_cmd
        cmd = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            vol3_plugin,
            "--pid",
            str(pid),
        ]
    else:
        prof = (vol2_profile or "").strip()
        if not prof:
            return -1, "Volatility 2 profile missing — run Start Analysis first.", []
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            vol2_plugin,
            "-p",
            str(pid),
            "--output=text",
        ]
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    return proc.returncode, text, cmd


def run_hunt_netscan_plugin(
    engine_label: str,
    mem_file: str,
    *,
    vol2_profile: str | None,
) -> tuple[int, str, list[str]]:
    """Full-memory netscan (Vol2 netscan / Vol3 windows.netscan); filter by PID in UI."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid memory image path.", []
    if is_vol3(engine_label):
        cmd = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            "windows.netscan",
        ]
    else:
        prof = (vol2_profile or "").strip()
        if not prof:
            return -1, "Volatility 2 profile missing — run Start Analysis first.", []
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "netscan",
            "--output=text",
        ]
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    return proc.returncode, text, cmd


def _hunt_dump_folder_name(*, pid: int, kind: str) -> str:
    """
    Human-readable per-dump folder name under the PID directory, e.g.:
      `pid 2214 dll dump`
    """
    k = (kind or "").strip().lower()
    label = {
        "exe": "exe dump",
        "dll": "dll dump",
        "mem": "memory dump",
        "vad": "vad dump",
    }.get(k, f"{k} dump" if k else "dump")
    # Keep filesystem-safe-ish (avoid weird punctuation); spaces are OK on Windows.
    safe_label = re.sub(r'[<>:"/\\\\|?*]+', "_", label).strip()
    return f"pid {int(pid)} {safe_label}".strip()


def _hunt_dump_path_vol2(mem_file: str, pid: int, *, dump_kind: str) -> str:
    name = _hunt_dump_folder_name(pid=pid, kind=dump_kind)
    return str(
        MEMHUNTER_DATA_ROOT
        / VOL2_DUMP_SUBDIR
        / f"pid_{pid}"
        / name
    )


def _hunt_dump_path_vol3(mem_file: str, pid: int, *, dump_kind: str) -> str:
    name = _hunt_dump_folder_name(pid=pid, kind=dump_kind)
    return str(
        MEMHUNTER_DATA_ROOT
        / VOL3_DUMP_SUBDIR
        / f"pid_{pid}"
        / name
    )


def _hunt_dump_argv_preview(
    engine_label: str,
    mem_file: str,
    pid: int,
    kind: str,
    *,
    vol2_profile: str | None,
) -> list[str]:
    """Argv list for UI preview (paths match real runs; Vol2 -D dir is created on run)."""
    mem_file = (mem_file or "").strip()
    if not mem_file or pid <= 0:
        return []
    if is_vol3(engine_label):
        out_d = _hunt_dump_path_vol3(mem_file, pid, dump_kind=kind)
        base = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            "-o",
            out_d,
        ]
        if kind == "exe":
            return base + ["windows.dumpfiles", "--pid", str(pid)]
        if kind == "dll":
            return base + ["windows.dlllist.DllList", "--pid", str(pid), "--dump"]
        if kind == "mem":
            return base + ["windows.memmap", "--pid", str(pid), "--dump"]
        if kind == "vad":
            return base + ["windows.vadinfo", "--pid", str(pid), "--dump"]
        return []
    prof = (vol2_profile or "").strip()
    if not prof:
        return []
    d_vol2 = _hunt_dump_path_vol2(mem_file, pid, dump_kind=kind)
    pl = {"exe": "procdump", "dll": "dlldump", "mem": "memdump", "vad": "vaddump"}.get(
        kind
    )
    if not pl:
        return []
    return [
        str(VOL2_EXE),
        "-f",
        mem_file,
        f"--profile={prof}",
        pl,
        "-p",
        str(pid),
        "-D",
        d_vol2,
    ]


def run_hunt_process_dump(
    engine_label: str,
    mem_file: str,
    pid: int,
    kind: str,
    *,
    vol2_profile: str | None,
) -> tuple[int, str, list[str], str | None]:
    """
    PID-scoped dumps for Hunt.
    Vol2: -D under `vol2_pid_dumps/pid_<PID>/pid <PID> <dump label>/`.
    Vol3: -o under `vol3_pid_dumps/pid_<PID>/pid <PID> <dump label>/` (dumpfiles, dlllist --dump, memmap, vadinfo).
    """
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid memory image path.", [], None
    if pid <= 0:
        return -1, "Invalid PID.", [], None

    if is_vol3(engine_label):
        out_d = _hunt_dump_path_vol3(mem_file, pid, dump_kind=kind)
        Path(out_d).mkdir(parents=True, exist_ok=True)
        base = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            "-o",
            out_d,
        ]
        if kind == "exe":
            cmd = base + ["windows.dumpfiles", "--pid", str(pid)]
        elif kind == "dll":
            cmd = base + ["windows.dlllist.DllList", "--pid", str(pid), "--dump"]
        elif kind == "mem":
            cmd = base + ["windows.memmap", "--pid", str(pid), "--dump"]
        elif kind == "vad":
            cmd = base + ["windows.vadinfo", "--pid", str(pid), "--dump"]
        else:
            return -1, f"Unknown dump kind `{kind}`.", [], None
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        note = f"[output_dir] {out_d}\n\n"
        text = note + (text or "(no stdout/stderr)")
        return proc.returncode, text.strip(), cmd, out_d

    prof = (vol2_profile or "").strip()
    if not prof:
        return (
            -1,
            "Volatility 2 profile missing — run Start Analysis first.",
            [],
            None,
        )
    plugin = {"exe": "procdump", "dll": "dlldump", "mem": "memdump", "vad": "vaddump"}.get(
        kind
    )
    if not plugin:
        return -1, f"Unknown dump kind `{kind}`.", [], None
    dump_dir = _hunt_dump_path_vol2(mem_file, pid, dump_kind=kind)
    Path(dump_dir).mkdir(parents=True, exist_ok=True)
    cmd = [
        str(VOL2_EXE),
        "-f",
        mem_file,
        f"--profile={prof}",
        plugin,
        "-p",
        str(pid),
        "-D",
        dump_dir,
    ]
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    prefix = f"[dump_dir] {dump_dir}\n\n"
    text = prefix + (text if text else "(no stdout/stderr)")
    return proc.returncode, text.strip(), cmd, dump_dir


def _hunt_netscan_col_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).lower())


def _hunt_netscan_find_column(df: pd.DataFrame, *parts: str) -> str | None:
    """First column whose normalized header contains every part (substring)."""
    req = [_hunt_netscan_col_key(p) for p in parts]
    for c in df.columns:
        k = _hunt_netscan_col_key(c)
        if all(r in k for r in req):
            return str(c)
    return None


def _hunt_netscan_pid_column(df: pd.DataFrame) -> str | None:
    """Avoid matching PPID: prefer exact 'PID' column name."""
    for c in df.columns:
        if str(c).strip().lower() == "pid":
            return str(c)
    for c in df.columns:
        if _hunt_netscan_col_key(c) == "pid":
            return str(c)
    return None


def _hunt_netscan_resolve_columns(df: pd.DataFrame) -> dict[str, str | None]:
    return {
        "pid": _hunt_netscan_pid_column(df),
        "local": _hunt_netscan_find_column(df, "local", "address")
        or _hunt_netscan_find_column(df, "localaddress")
        or _hunt_netscan_find_column(df, "local", "addr"),
        "remote": _hunt_netscan_find_column(df, "foreign", "address")
        or _hunt_netscan_find_column(df, "remote", "address")
        or _hunt_netscan_find_column(df, "foreignaddr")
        or _hunt_netscan_find_column(df, "remoteaddr"),
        "state": _hunt_netscan_find_column(df, "state"),
        "proto": _hunt_netscan_find_column(df, "proto")
        or _hunt_netscan_find_column(df, "protocol"),
    }


def _hunt_series_pid_int(s: pd.Series) -> pd.Series:
    def to_pid(v: object) -> int | None:
        if pd.isna(v):
            return None
        m = re.match(r"^(\d+)", str(v).strip())
        return int(m.group(1)) if m else None

    return s.map(to_pid)


def _hunt_netscan_filtered_text(
    raw: str, pid: int, *, max_lines: int = 800
) -> str:
    """Raw netscan lines for PID + header row (monospace terminal layout preserved)."""
    if not (raw or "").strip() or pid <= 0:
        return ""
    lines = (raw or "").splitlines()
    pid_pat = re.compile(rf"(?<!\d){int(pid)}(?!\d)")
    header: str | None = None
    for ln in lines[:150]:
        if not ln.strip():
            continue
        if re.search(r"\bPID\b", ln, re.I) and (
            "State" in ln
            or "Proto" in ln
            or "Addr" in ln
            or "Port" in ln
        ):
            header = ln
            break
    body = [ln for ln in lines if pid_pat.search(ln)]
    body = body[:max_lines]
    if header:
        return "\n".join([header] + body)
    return "\n".join(body)


def _hunt_netscan_filtered_frame(
    raw: str, pid: int
) -> tuple[pd.DataFrame, dict[str, str | None], str | None]:
    """Parse netscan stdout, keep rows for pid; return display cols + mapping or error."""
    if not (raw or "").strip() or pid <= 0:
        return pd.DataFrame(), {}, "empty"
    df = _dataframe_from_stdout(raw)
    if df.empty:
        return pd.DataFrame(), {}, "parse"
    cols = _hunt_netscan_resolve_columns(df)
    pid_col = cols.get("pid")
    if not pid_col or pid_col not in df.columns:
        return pd.DataFrame(), cols, "pidcol"
    pids = _hunt_series_pid_int(df[pid_col])
    sub = df.loc[pids == pid].copy()
    if sub.empty:
        return sub, cols, None
    return sub, cols, None


# (state_key_prefix, Vol2 plugin, Vol3 plugin) — Hunt-only PID-scoped blocks
HUNT_EXTRA_PID_PLUGINS: tuple[tuple[str, str, str], ...] = (
    ("dlllist", "dlllist", "windows.dlllist"),
    ("ldrmodules", "ldrmodules", "windows.ldrmodules"),
    ("handles", "handles", "windows.handles"),
    ("threads", "threads", "windows.threads.Threads"),
    ("envars", "envars", "windows.envars"),
    ("privs", "privs", "windows.privileges"),
    ("getsids", "getsids", "windows.getsids"),
    ("malfind", "malfind", "windows.malfind"),
)
HUNT_EXTRA_BY_PREFIX: dict[str, tuple[str, str, str]] = {
    t[0]: t for t in HUNT_EXTRA_PID_PLUGINS
}


def _argv_one_line(argv: list[str]) -> str:
    """Single line for UI (Windows-friendly quoting)."""
    if not argv:
        return ""
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


_HUNT_KNOWN_VOL_PLUGINS = frozenset(
    {
        "yarascan",
        "dlllist",
        "ldrmodules",
        "handles",
        "envars",
        "privs",
        "getsids",
        "malfind",
        "threads",
        "cmdline",
        "pslist",
        "psscan",
        "pstree",
        "filescan",
        "netscan",
        "procdump",
        "dlldump",
        "memdump",
        "vaddump",
        "vadinfo",
        "memmap",
    }
)


def _hunt_vol_argv_syntax_html(argv: list[str] | None) -> str:
    """Syntax-colored argv for Hunt (exe cyan, flags pale, paths green, plugin coral)."""
    if not argv:
        return ""
    bits: list[str] = []
    for i, raw in enumerate(argv):
        a = str(raw)
        low = a.lower()
        cls = "hunt-cmd-txt"
        if i == 0 and (
            low.endswith(".exe")
            or "vol.exe" in low
            or "volatility" in low
            or "python" in low
        ):
            cls = "hunt-cmd-exe"
        elif a.startswith("-") or a.startswith("--"):
            cls = "hunt-cmd-flag"
        elif re.match(r"^[A-Za-z]:\\", a) or (
            "\\" in a
            and any(
                ext in low
                for ext in (".vmem", ".mem", ".raw", ".dmp", ".img", ".dump")
            )
        ):
            cls = "hunt-cmd-path"
        elif (
            "windows." in low
            or low in _HUNT_KNOWN_VOL_PLUGINS
            or (low.startswith("win") and "." in low and i >= 3)
        ):
            cls = "hunt-cmd-plugin"
        elif "/" in a and any(
            ext in low for ext in (".vmem", ".mem", ".raw", ".dmp")
        ):
            cls = "hunt-cmd-path"
        bits.append(f'<span class="{cls}">{html_module.escape(a)}</span>')
    return " ".join(bits)


def _hunt_stdout_for_pre_display(s: str) -> str:
    """Normalize Volatility/CLI output so <pre> shows stable columns (CR / progress lines)."""
    t = s or ""
    t = t.replace("\r\n", "\n")
    lines: list[str] = []
    for line in t.split("\n"):
        if "\r" in line:
            line = line.rsplit("\r", 1)[-1]
        lines.append(line)
    return "\n".join(lines)


def _hunt_widget_slug(tab_label: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", tab_label).strip("_").lower()
    return (s[:40] + "_") if len(s) > 40 else (s + "_" if s else "hunt_")


def _hunt_merge_entry(tab_label: str, **updates: object) -> None:
    lst = list(st.session_state.get(HUNT_TABS_SESSION_KEY) or [])
    for i, e in enumerate(lst):
        if e.get("tab_label") == tab_label:
            lst[i] = {**e, **updates}
            break
    st.session_state[HUNT_TABS_SESSION_KEY] = lst


def _hunt_append_output_block(
    tab_widget_slug: str,
    source_id: str,
    title: str,
    text: str,
    download_name: str,
    argv: list[str] | None,
) -> None:
    """Append a Hunt run to the per-tab log (viewer + optional colored argv like Global)."""
    key = f"hunt_output_log_{tab_widget_slug}"
    log = list(st.session_state.get(key) or [])
    log.append(
        {
            "block_id": f"huntb_{secrets.token_hex(5)}",
            "run_source": (source_id or "").strip()[:48],
            "title": (title or "Results").strip(),
            "text": _hunt_stdout_for_pre_display(text or ""),
            "download_name": (download_name or "hunt_output.txt").strip(),
            "argv": list(argv) if argv else None,
        }
    )
    if len(log) > HUNT_OUTPUT_LOG_MAX:
        log = log[-HUNT_OUTPUT_LOG_MAX:]
    st.session_state[key] = log


def _extract_hunt_cmdline_from_vol3_csv(text: str, pid: int) -> str | None:
    """Parse -r csv style windows.cmdline output (PID, Process, Args, …)."""
    pid_s = str(int(pid))
    try:
        rows = list(
            row
            for row in csv.reader(io.StringIO(text))
            if row and any((c or "").strip() for c in row)
        )
    except csv.Error:
        return None
    args_names = (
        "args",
        "arguments",
        "commandline",
        "command_line",
        "cmdline",
    )
    for i, row in enumerate(rows):
        low = [c.strip().lower() for c in row]
        if not low or low[0] != "pid":
            continue
        if "pid" not in low:
            continue
        pid_idx = low.index("pid")
        args_idx: int | None = None
        for name in args_names:
            if name in low:
                args_idx = low.index(name)
                break
        if args_idx is None and len(low) >= 3:
            args_idx = 2
        if args_idx is None:
            continue
        for data_row in rows[i + 1 :]:
            if len(data_row) <= max(pid_idx, args_idx):
                continue
            if (data_row[pid_idx] or "").strip() == pid_s:
                return (data_row[args_idx] or "").strip()
    return None


HUNT_PID_PLUGIN_LABELS: dict[str, str] = {
    "dlllist": "Dlllist",
    "ldrmodules": "Ldrmodules",
    "handles": "Handles",
    "threads": "Threads",
    "envars": "Envars",
    "privs": "Privileges",
    "getsids": "Getsids",
    "malfind": "Malfind",
}


def _extract_hunt_cmdline_display(raw: str, pid: int) -> str:
    """Pull only the command-line string from Vol2/Vol3 cmdline plugin text output."""
    text = (raw or "").strip()
    if not text:
        return "(empty)"
    # Vol 2 style: "Command line :" or "Command line:"
    for ln in text.splitlines():
        m = re.search(r"Command\s*line\s*:\s*(.+)$", ln, re.IGNORECASE)
        if m:
            s = m.group(1).strip()
            if s:
                return s
    # Vol 3 table row: PID  Process  Args (Args may contain spaces / quotes)
    pid_s = str(int(pid))
    skip_prefixes = (
        "volatility",
        "---",
        "progress:",
        "warning",
        "pid",
    )
    pid_pat = re.compile(
        rf"^{re.escape(pid_s)}(?:\s+|\t+)(\S+)(?:\s+|\t+)(.+)$"
    )
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith(skip_prefixes) and "command" not in low:
            continue
        if "\t" in s and s.split("\t", 1)[0].strip() == pid_s:
            parts = [p for p in s.split("\t") if p.strip()]
            if len(parts) >= 3:
                return parts[2].strip()
        m = pid_pat.match(s)
        if m:
            return m.group(2).strip()
    # Header row heuristic
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith(pid_s):
            continue
        if re.match(rf"^{re.escape(pid_s)}\s+", s):
            tail = s[len(pid_s) :].strip()
            if tail:
                return tail
    from_csv = _extract_hunt_cmdline_from_vol3_csv(text, pid)
    if from_csv:
        return from_csv
    return "(could not parse command line from plugin output)"


def render_hunt_dashboard_tab(entry: dict, *, tab_label: str) -> None:
    """Process overview, categorized Hunt actions (expanders), shared output viewer (Global-style)."""
    s1 = entry.get("section1") or {}
    pname = html_module.escape(str(s1.get("process_name", "?")))
    pid_s = str(s1.get("pid", "?"))
    pid_esc = html_module.escape(pid_s)
    try:
        pid_int = int(str(s1.get("pid", "0")).strip())
    except (TypeError, ValueError):
        pid_int = 0

    _slug = _hunt_widget_slug(tab_label)

    parent_v = html_module.escape(str(s1.get("parent_display", "None")))
    kids = s1.get("children_lines") or []
    if kids:
        kids_inner = "<br/>".join(
            html_module.escape(str(x)) for x in kids
        )
    else:
        kids_inner = html_module.escape("None")

    th = html_module.escape(str(s1.get("threads", "N/A")))
    hd = html_module.escape(str(s1.get("handles", "N/A")))
    tm = html_module.escape(str(s1.get("times_display", "N/A")))

    raw_cmd = entry.get("cmdline_text") or ""
    if pid_int:
        _plain_cmd = _extract_hunt_cmdline_display(raw_cmd, pid_int)
        cmd_display = html_module.escape(_plain_cmd)
    else:
        cmd_display = html_module.escape((raw_cmd or "").strip() or "(empty)")

    rc = entry.get("cmdline_rc")
    rc_note = ""
    if isinstance(rc, int) and rc != 0:
        rc_note = (
            f'<p class="memhunter-hunt-rcnote">cmdline plugin exit code <strong>{rc}</strong></p>'
        )

    _po_l, _po_x = st.columns([0.86, 0.14])
    with _po_l:
        st.markdown(
            '<p class="memhunter-hunt-sectionlabel">Process overview</p>',
            unsafe_allow_html=True,
        )
    with _po_x:
        _render_tab_close_x_button(tab_label)

    st.markdown(
        '<div class="memhunter-hunt-sheet">'
        '<div class="memhunter-hunt-hero">'
        f'<div class="memhunter-hunt-title">{pname}</div>'
        f'<div class="memhunter-hunt-pid">PID <span class="memhunter-hunt-pid-num">{pid_esc}</span></div>'
        "</div>"
        '<div class="memhunter-hunt-kvgrid">'
        '<div class="memhunter-hunt-kv">'
        '<span class="memhunter-hunt-lbl">Threads</span>'
        f'<span class="memhunter-hunt-val">{th}</span>'
        "</div>"
        '<div class="memhunter-hunt-kv">'
        '<span class="memhunter-hunt-lbl">Handles</span>'
        f'<span class="memhunter-hunt-val">{hd}</span>'
        "</div>"
        '<div class="memhunter-hunt-kv memhunter-hunt-kv-wide">'
        '<span class="memhunter-hunt-lbl">Times</span>'
        f'<span class="memhunter-hunt-val">{tm}</span>'
        "</div>"
        '<div class="memhunter-hunt-kv memhunter-hunt-kv-wide memhunter-hunt-kv-parent">'
        '<span class="memhunter-hunt-lbl">Parent process</span>'
        f'<div class="memhunter-hunt-highlight-parent">{parent_v}</div>'
        "</div>"
        '<div class="memhunter-hunt-kv memhunter-hunt-kv-wide memhunter-hunt-kv-child">'
        '<span class="memhunter-hunt-lbl">Child processes</span>'
        f'<div class="memhunter-hunt-highlight-child">{kids_inner}</div>'
        "</div>"
        '<div class="memhunter-hunt-kv memhunter-hunt-kv-wide memhunter-hunt-kv-cmd">'
        '<span class="memhunter-hunt-lbl">Command line</span>'
        f'<div class="memhunter-hunt-cmdline">{cmd_display}</div>'
        "</div>"
        "</div>"
        f"{rc_note}"
        "</div>",
        unsafe_allow_html=True,
    )

    _mem_for_vol = current_memory_image_path()
    if _mem_for_vol:
        st.caption(f"**Memory image:** `{_mem_for_vol}`")
    else:
        st.caption(
            "**Memory image:** _(not set — enter the full path in the sidebar)_"
        )

    st.markdown('<hr class="memhunter-hunt-sep"/>', unsafe_allow_html=True)
    st.markdown(
        '<p class="memhunter-hunt-sectionlabel memhunter-hunt-acc-strip">Focused process actions</p>',
        unsafe_allow_html=True,
    )

    _prof_h = st.session_state.get("vol2_profile")
    _dump_btn_dis = pid_int <= 0
    _extra_map = HUNT_EXTRA_BY_PREFIX

    def _fire_pid_plugin(pfx: str, panel_title: str, file_stem: str) -> None:
        if pid_int <= 0:
            st.warning("Invalid PID for this Hunt tab.")
            return
        _mp = current_memory_image_path()
        if not require_memory_image_exists(_mp):
            return
        t3 = _extra_map.get(pfx)
        if not t3:
            return
        _, v2p, v3p = t3
        _eng = st.session_state.vol_engine
        _plab = HUNT_PID_PLUGIN_LABELS.get(pfx, pfx)
        with st.spinner(f"Running {_plab}…"):
            prc, ptxt, pargv = run_hunt_pid_text_plugin(
                _eng,
                _mp,
                pid_int,
                v2p,
                v3p,
                vol2_profile=_prof_h,
            )
        _hunt_merge_entry(
            tab_label,
            **{
                f"hunt_{pfx}_output": _tail_history_text(ptxt or ""),
                f"hunt_{pfx}_rc": prc,
                f"hunt_{pfx}_argv": pargv,
            },
        )
        _hunt_append_output_block(
            _slug,
            pfx,
            f"{panel_title} · PID {pid_int} · exit {prc}",
            ptxt or "",
            f"{file_stem}_pid{pid_int}.txt",
            pargv,
        )
        st.rerun()

    def _fire_netscan() -> None:
        if pid_int <= 0:
            st.warning("Invalid PID for this Hunt tab.")
            return
        _mp = current_memory_image_path()
        if not require_memory_image_exists(_mp):
            return
        _eng = st.session_state.vol_engine
        with st.spinner("Running netscan (full memory image)…"):
            nrc, ntxt, nargv = run_hunt_netscan_plugin(
                _eng,
                _mp,
                vol2_profile=_prof_h,
            )
        _hunt_merge_entry(
            tab_label,
            hunt_netscan_raw=_tail_history_text(ntxt or ""),
            hunt_netscan_rc=nrc,
            hunt_netscan_argv=nargv,
        )
        _nraw = _tail_history_text(ntxt or "")
        _nview = _hunt_netscan_filtered_text(_nraw, pid_int)
        _nsub, _, nerr = _hunt_netscan_filtered_frame(_nraw, pid_int)
        if not _nview.strip() and not _nsub.empty:
            _nview = _nsub.to_string(index=False)
        if _nview.strip():
            dl_body, dl_name = _nview, f"netscan_pid{pid_int}.txt"
        elif not _nsub.empty:
            dl_body = _nsub.to_csv(sep="\t", index=False)
            dl_name = f"netscan_pid{pid_int}_filtered.tsv"
        else:
            dl_body = _nraw or ""
            dl_name = f"netscan_raw_{pid_int}.txt"
        hdr_lines: list[str] = []
        if nerr == "empty":
            hdr_lines.append("[Note: no netscan table data]")
        elif nerr == "parse":
            hdr_lines.append(
                "[Warning: could not parse netscan as a table — showing truncated raw]"
            )
            dl_body = (_nraw or "")[:120_000]
        elif nerr == "pidcol":
            hdr_lines.append(
                "[Note: no PID column — showing lines mentioning this PID]"
            )
        elif not _nview.strip() and _nsub.empty:
            hdr_lines.append("[Note: no matching rows for this PID]")
        hdr = ("\n".join(hdr_lines) + "\n\n") if hdr_lines else ""
        _hunt_append_output_block(
            _slug,
            "netscan",
            f"Netscan (filtered for this PID) · exit {nrc}",
            hdr + dl_body,
            dl_name,
            nargv,
        )
        st.rerun()

    _dump_spin = {
        "exe": "Dumping executable (procdump / dumpfiles)…",
        "dll": "Dumping DLL modules (dlldump / dlllist --dump)…",
        "mem": "Dumping full process memory…",
        "vad": "Dumping VAD sections…",
    }

    with st.expander(":material/public: Identity & Network", expanded=False):
        ec1, ec2, ec3, ec4 = st.columns(4, gap="small")
        with ec1:
            if st.button(
                "netscan",
                key=f"hunt_run_netscan_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Shows active network connections, IP addresses, and open ports for this process.",
            ):
                _fire_netscan()
        with ec2:
            if st.button(
                "privileges",
                key=f"hunt_run_privs_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Displays enabled process privileges (e.g., SeDebugPrivilege) to identify potential privilege escalation.",
            ):
                _fire_pid_plugin("privs", "Privileges", "privs")
        with ec3:
            if st.button(
                "envars",
                key=f"hunt_run_envars_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Shows environment variables for the process, revealing potential paths, API keys, or execution parameters.",
            ):
                _fire_pid_plugin("envars", "Envars", "envars")
        with ec4:
            if st.button(
                "getsids",
                key=f"hunt_run_getsids_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Displays the Security Identifiers (SIDs) associated with the process to determine its user context.",
            ):
                _fire_pid_plugin("getsids", "Getsids", "getsids")

    with st.expander(":material/bug_report: Malware Hunting", expanded=False):
        hm1, hm2, hm3, hm4 = st.columns(4, gap="small")
        with hm1:
            if st.button(
                "malfind",
                key=f"hunt_run_malfind_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Locates potential code injections by searching for hidden or RWX (Read-Write-Execute) memory segments.",
            ):
                _fire_pid_plugin("malfind", "Malfind", "malfind")
        with hm2:
            st.caption("yarascan — rule / string below")
        with hm3:
            st.empty()
        with hm4:
            st.empty()
        _yq_key = f"hunt_yara_q_{_slug}"
        _yr_key = f"hunt_yara_run_{_slug}"
        st.text_input(
            "YARA",
            key=_yq_key,
            placeholder=r'wide ascii "suspicious" or plain text',
            label_visibility="collapsed",
        )
        yb1, yb2, yb3, yb4 = st.columns(4, gap="small")
        with yb1:
            if st.button(
                "yarascan",
                key=_yr_key,
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Scans the process memory space using YARA rules or strings to identify malware signatures.",
            ):
                _q = str(st.session_state.get(_yq_key, "") or "").strip()
                if not _q:
                    st.warning("Enter a search string or YARA snippet first.")
                elif pid_int <= 0:
                    st.warning("Invalid PID for this Hunt tab.")
                else:
                    _mp_y = current_memory_image_path()
                    if require_memory_image_exists(_mp_y):
                        _eng_y = st.session_state.vol_engine
                        st.session_state[MH_FLOAT_STATUS_KEY] = "Scanning process memory (YARA)…"
                        st.session_state[MH_PENDING_JOB_KEY] = {
                            "kind": "hunt_yara",
                            "slug": _slug,
                            "tab_label": tab_label,
                            "pid": pid_int,
                            "q": _q,
                            "mp_y": _mp_y,
                            "vol_engine": _eng_y,
                            "vol2_profile": ("" if _prof_h is None else str(_prof_h)).strip(),
                        }
                        st.rerun()
        with yb2:
            st.empty()
        with yb3:
            st.empty()
        with yb4:
            st.empty()

    with st.expander(":material/account_tree: Resource Analysis", expanded=False):
        ra1, ra2, ra3, ra4 = st.columns(4, gap="small")
        with ra1:
            if st.button(
                "dlllist",
                key=f"hunt_run_dlllist_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Lists all dynamically loaded libraries (DLLs) and their absolute paths for the process.",
            ):
                _fire_pid_plugin("dlllist", "Dlllist", "dlllist")
        with ra2:
            if st.button(
                "handles",
                key=f"hunt_run_handles_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Lists open handles (files, registry keys, mutexes, etc.) currently accessed by the process.",
            ):
                _fire_pid_plugin("handles", "Handles", "handles")
        with ra3:
            if st.button(
                "ldrmodules",
                key=f"hunt_run_ldrmodules_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Cross-references DLL lists to find unlinked or hidden modules that bypass standard API tracking (DLL hiding).",
            ):
                _fire_pid_plugin("ldrmodules", "Ldrmodules", "ldrmodules")
        with ra4:
            if st.button(
                "threads",
                key=f"hunt_run_threads_{_slug}",
                type="tertiary",
                disabled=_dump_btn_dis,
                use_container_width=True,
                help="Displays active execution threads within the process, useful for finding unbacked injected code.",
            ):
                _fire_pid_plugin("threads", "Threads", "threads")

    with st.expander(":material/download: Dumps & Extraction", expanded=False):
        st.caption(
            "Vol 2: **-D** → `…\\\\vol2_pid_dumps\\\\pid_<PID>\\\\pid <PID> <dump type>\\\\` · Vol 3: **-o** → "
            "`…\\\\vol3_pid_dumps\\\\pid_<PID>\\\\pid <PID> <dump type>\\\\` "
            "(e.g. `pid 2214 dll dump`, `pid 2214 exe dump`)."
        )
        with st.expander("Command reference", expanded=False, key=f"hunt_dump_ref_{_slug}"):
            _mp_ref = current_memory_image_path()
            for _dk, _dlab in (
                ("exe", "EXE"),
                ("dll", "DLL"),
                ("mem", "Full memory"),
                ("vad", "VAD"),
            ):
                _pv = _hunt_dump_argv_preview(
                    st.session_state.vol_engine,
                    _mp_ref,
                    pid_int,
                    _dk,
                    vol2_profile=_prof_h,
                )
                if _pv:
                    st.markdown(
                        f'<p class="memhunter-hunt-dump-ref-label">{html_module.escape(_dlab)}</p>'
                        '<div class="memhunter-hunt-dump-cmd-wrap memhunter-hunt-vol-cmd-wrap">'
                        f"{_hunt_vol_argv_syntax_html(_pv)}</div>",
                        unsafe_allow_html=True,
                    )
                else:
                    st.caption(f"{_dlab} — set memory path / Vol 2 profile to preview argv.")
        d1, d2, d3, d4 = st.columns(4, gap="small")
        for _col, (_kind, _short, _htip) in zip(
            (d1, d2, d3, d4),
            (
                (
                    "exe",
                    "EXE dump",
                    "Extracts and reconstructs the main executable file of the process from memory to disk.",
                ),
                (
                    "dll",
                    "DLL dump",
                    "Extracts a specific loaded DLL from the process memory to disk for further static analysis.",
                ),
                (
                    "mem",
                    "Memory dump",
                    "Dumps the entire memory address space of the process into a single file.",
                ),
                (
                    "vad",
                    "VAD dump",
                    "Extracts specific Virtual Address Descriptor (VAD) segments, ideal for dumping injected shellcode or unbacked memory.",
                ),
            ),
            strict=True,
        ):
            with _col:
                if st.button(
                    _short,
                    key=f"hunt_dump_{_kind}_{_slug}",
                    type="tertiary",
                    disabled=_dump_btn_dis,
                    use_container_width=True,
                    help=_htip,
                ):
                    if pid_int <= 0:
                        st.warning("Invalid PID for this Hunt tab.")
                    else:
                        _mp_d = current_memory_image_path()
                        if require_memory_image_exists(_mp_d):
                            _eng_d = st.session_state.vol_engine
                            _dump_title = (
                                _dump_spin.get(_kind, "Process dump").rstrip("…").strip()
                                or "Process dump"
                            )
                            st.session_state[MH_FLOAT_STATUS_KEY] = (
                                f"{_dump_title} (extracting)…"
                            )
                            st.session_state[MH_PENDING_JOB_KEY] = {
                                "kind": "hunt_dump",
                                "slug": _slug,
                                "tab_label": tab_label,
                                "pid": pid_int,
                                "dump_kind": _kind,
                                "dump_short": _short,
                                "mp_d": _mp_d,
                                "vol_engine": _eng_d,
                                "vol2_profile": ("" if _prof_h is None else str(_prof_h)).strip(),
                            }
                            st.rerun()

    st.markdown('<hr class="memhunter-hunt-sep"/>', unsafe_allow_html=True)
    st.markdown(
        '<p class="memhunter-hunt-sectionlabel">Hunt output log</p>',
        unsafe_allow_html=True,
    )
    _hunt_log = list(st.session_state.get(f"hunt_output_log_{_slug}") or [])
    if not _hunt_log:
        st.caption(
            "Each run adds a foldable block (oldest at top). Only the **latest** opens expanded; "
            "expand any row for colored command line + the same search / copy / download viewer as Global."
        )
    else:
        _n_blk = len(_hunt_log)
        for _hi, _blk in enumerate(_hunt_log):
            _title_raw = str(_blk.get("title", "Results")).strip() or "Results"
            _exp_label = _title_raw if len(_title_raw) <= 140 else _title_raw[:137] + "…"
            _bid = str(_blk.get("block_id") or f"huntx_{_hi}")
            _exp_key = f"huntoutex_{_slug}_{_hi}_{re.sub(r'[^0-9a-zA-Z_-]', '_', _bid)[:48]}"
            with st.expander(
                _exp_label,
                expanded=(_hi == _n_blk - 1),
                key=_exp_key,
            ):
                _argv_b = _blk.get("argv")
                if isinstance(_argv_b, list) and len(_argv_b) > 0:
                    st.markdown(
                        '<div class="memhunter-hunt-vol-cmd-wrap memhunter-hunt-out-argv">'
                        f"{_hunt_vol_argv_syntax_html(_argv_b)}</div>",
                        unsafe_allow_html=True,
                    )
                _txt = str(_blk.get("text") or "")
                _dn = str(_blk.get("download_name") or "hunt_output.txt")
                _render_sidebar_output_body_code_or_virtual(
                    _txt.strip() if _txt.strip() else "(empty)",
                    entry=None,
                    widget_slug=_bid[:96],
                    download_name=_dn,
                )


def execute_hunt_for_current_selection() -> None:
    """Run cmdline and append a Hunt tab (sidebar button handler)."""
    eng = st.session_state.vol_engine
    frames_hf: dict = st.session_state.get("plugin_frames") or {}
    hctx = resolve_hunt_selection_context(frames=frames_hf, engine_label=eng)
    if hctx is None:
        return
    _h_src, _h_row, _h_pid, _h_name = hctx
    _h_snap = build_hunt_section1_snapshot(
        frames=frames_hf,
        source=_h_src,
        row_pos=_h_row,
        pid=_h_pid,
        name=_h_name,
        engine_label=eng,
    )
    _h_mp = current_memory_image_path()
    if not require_memory_image_exists(_h_mp):
        return
    with st.spinner("Running cmdline for Hunt…"):
        _h_crc, _h_ctxt = run_hunt_cmdline_plugin(
            eng,
            _h_mp,
            _h_pid,
            vol2_profile=st.session_state.get("vol2_profile"),
        )
    if eng == ENGINE_V2_LABEL:
        _hist = list(st.session_state.get(VOL2_OUTPUT_HISTORY_KEY) or [])
    elif eng == ENGINE_V3_LABEL:
        _hist = list(st.session_state.get(VOL3_OUTPUT_HISTORY_KEY) or [])
    else:
        _hist = []
    _hunt_entries: list[dict] = list(st.session_state.get(HUNT_TABS_SESSION_KEY) or [])
    _h_prop = _hunt_tab_label_proposed(_h_name, _h_pid)
    _h_taken_names = (
        list(STATIC_MAIN_TAB_LABELS)
        + [e.get("tab_label") for e in _hunt_entries if e.get("tab_label")]
        + [h.get("tab_label") for h in _hist if h.get("tab_label")]
    )
    _h_tlab = _hunt_unique_tab_label([x for x in _h_taken_names if x], _h_prop)
    _hunt_entries.append(
        {
            "tab_label": _h_tlab,
            "hunt_pid": _h_pid,
            "section1": _h_snap,
            "cmdline_text": _h_ctxt,
            "cmdline_rc": _h_crc,
        }
    )
    st.session_state[HUNT_TABS_SESSION_KEY] = _hunt_entries
    _append_main_tab_dynamic_order(_h_tlab)
    st.rerun()


def _vol2_sidebar_cat_slug(category: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", category).strip("_").lower()
    return (s[:28] + "_") if len(s) > 28 else (s + "_")


def _vol2_snip_param(s: str, max_len: int = VOL2_TAB_PARAM_SNIP) -> str:
    t = (s or "").strip().replace("\n", " ")
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _vol2_tab_label_proposed(
    plugin: str,
    mode: str,
    *,
    pid: int | None,
    append_pid: bool,
    extra: dict[str, str],
) -> str:
    if mode == "pid_dump":
        if pid is not None:
            return f"{plugin} · PID {pid}"
        return f"{plugin} · global"
    if mode == "profile_opt_pid" and append_pid and pid is not None:
        return f"{plugin} · PID {pid}"
    if mode == "printkey_k":
        return f"{plugin} · {_vol2_snip_param(extra.get('K', ''))}"
    if mode == "hivedump_o":
        return f"{plugin} · {_vol2_snip_param(extra.get('o', ''), 24)}"
    if mode == "dumpfiles_q":
        return f"{plugin} · {_vol2_snip_param(extra.get('Q', ''), 24)}"
    if mode == "yarascan_y":
        return f"{plugin} · {_vol2_snip_param(extra.get('Y', ''))}"
    return plugin


def _vol2_unique_tab_label(existing: list[str], proposed: str) -> str:
    if proposed not in existing:
        return proposed
    n = 2
    while f"{proposed} ({n})" in existing:
        n += 1
    return f"{proposed} ({n})"


def _vol2_push_output_history(
    *,
    plugin: str,
    category_label: str,
    mode: str,
    rc: int,
    text: str,
    argv: list[str],
    pid: int | None,
    append_pid: bool,
    extra: dict[str, str],
) -> str:
    hist = list(st.session_state.get(VOL2_OUTPUT_HISTORY_KEY) or [])
    taken = [h.get("tab_label") for h in hist if h.get("tab_label")]
    prop = _vol2_tab_label_proposed(
        plugin, mode, pid=pid, append_pid=append_pid, extra=extra
    )
    tab_label = _vol2_unique_tab_label(
        [x for x in taken if x] + list(STATIC_MAIN_TAB_LABELS),
        prop,
    )
    hist.append(
        {
            "engine": "v2",
            "plugin": plugin,
            "category": category_label,
            "mode": mode,
            "rc": rc,
            "text": _tail_history_text(text or ""),
            "cmd": " ".join(argv) if argv else "",
            "argv": list(argv) if argv else [],
            "tab_label": tab_label,
            "pid": pid,
            "extra": dict(extra),
        }
    )
    if len(hist) > VOL2_OUTPUT_HISTORY_MAX:
        hist = hist[-VOL2_OUTPUT_HISTORY_MAX :]
    st.session_state[VOL2_OUTPUT_HISTORY_KEY] = hist
    _append_main_tab_dynamic_order(tab_label)
    return tab_label


def _vol3_tab_label_proposed(
    display_label: str,
    mode: str,
    *,
    pid: int | None,
    append_pid: bool,
    extra: dict[str, str],
) -> str:
    if mode in ("v3_dumpfiles_pid", "v3_memmap_dump_pid"):
        if pid is not None:
            return f"{display_label} · PID {pid}"
        return f"{display_label} · global"
    if mode == "v3_pid_opt" and append_pid and pid is not None:
        return f"{display_label} · PID {pid}"
    if mode == "v3_printkey_key":
        return f"{display_label} · {_vol2_snip_param(extra.get('key', ''))}"
    if mode == "v3_dumpfiles_addr":
        tag = (
            "virt"
            if _vol3_dumpfiles_addr_kind(extra) == VOL3_DUMPFILES_KIND_VIRT
            else "phys"
        )
        return (
            f"{display_label} · {tag} · "
            f"{_vol2_snip_param(extra.get('dumpfiles_address', ''), 24)}"
        )
    if mode == "v3_yara_string":
        return f"{display_label} · {_vol2_snip_param(extra.get('Y', ''))}"
    return display_label


def _vol3_push_output_history(
    *,
    display_label: str,
    plugin_id: str,
    category_label: str,
    mode: str,
    rc: int,
    text: str,
    argv: list[str],
    pid: int | None,
    append_pid: bool,
    extra: dict[str, str],
) -> str:
    hist = list(st.session_state.get(VOL3_OUTPUT_HISTORY_KEY) or [])
    taken = [h.get("tab_label") for h in hist if h.get("tab_label")]
    prop = _vol3_tab_label_proposed(
        display_label, mode, pid=pid, append_pid=append_pid, extra=extra
    )
    tab_label = _vol2_unique_tab_label(
        [x for x in taken if x] + list(STATIC_MAIN_TAB_LABELS),
        prop,
    )
    hist.append(
        {
            "engine": "v3",
            "plugin": display_label,
            "vol3_plugin_id": plugin_id,
            "category": category_label,
            "mode": mode,
            "rc": rc,
            "text": _tail_history_text(text or ""),
            "cmd": " ".join(argv) if argv else "",
            "argv": list(argv) if argv else [],
            "tab_label": tab_label,
            "pid": pid,
            "extra": dict(extra),
        }
    )
    if len(hist) > VOL2_OUTPUT_HISTORY_MAX:
        hist = hist[-VOL2_OUTPUT_HISTORY_MAX :]
    st.session_state[VOL3_OUTPUT_HISTORY_KEY] = hist
    _append_main_tab_dynamic_order(tab_label)
    return tab_label


def _append_main_tab_dynamic_order(tab_label: str) -> None:
    """Append a Hunt or global sidebar result tab label in creation order (deduped)."""
    if not tab_label:
        return
    cur = list(st.session_state.get(MAIN_TAB_DYNAMIC_ORDER_KEY) or [])
    cur = [x for x in cur if x != tab_label]
    cur.append(tab_label)
    st.session_state[MAIN_TAB_DYNAMIC_ORDER_KEY] = cur


def _dynamic_tab_close_button_key(tab_label: str) -> str:
    """Stable Streamlit widget key from tab label (labels may contain punctuation)."""
    h = hashlib.sha256((tab_label or "").encode("utf-8")).hexdigest()[:32]
    return f"memh_close_mtab_{h}"


def _remove_dynamic_main_tab(tab_label: str) -> None:
    """Drop a Hunt or Vol2/Vol3 results tab from session (history + order + Hunt log)."""
    lab = (tab_label or "").strip()
    if not lab:
        return
    hunt = list(st.session_state.get(HUNT_TABS_SESSION_KEY) or [])
    new_hunt = [e for e in hunt if (e.get("tab_label") or "") != lab]
    if len(new_hunt) < len(hunt):
        st.session_state[HUNT_TABS_SESSION_KEY] = new_hunt
        st.session_state.pop(f"hunt_output_log_{_hunt_widget_slug(lab)}", None)
    for hist_key in (VOL2_OUTPUT_HISTORY_KEY, VOL3_OUTPUT_HISTORY_KEY):
        hist = list(st.session_state.get(hist_key) or [])
        new_hist = [h for h in hist if (h.get("tab_label") or "") != lab]
        if len(new_hist) < len(hist):
            st.session_state[hist_key] = new_hist
    order = list(st.session_state.get(MAIN_TAB_DYNAMIC_ORDER_KEY) or [])
    st.session_state[MAIN_TAB_DYNAMIC_ORDER_KEY] = [x for x in order if x != lab]


def _render_tab_close_x_button(tab_label: str) -> None:
    """3D “CLOSE” block for dynamic tabs (Hunt Process overview, Vol output tabs)."""
    lab = (tab_label or "").strip()
    if not lab:
        return
    st.markdown(
        '<span class="mh-tab-close-slot" aria-hidden="true"></span>',
        unsafe_allow_html=True,
    )
    if st.button(
        "CLOSE",
        key=_dynamic_tab_close_button_key(lab),
        type="primary",
        help="Close this tab",
        use_container_width=True,
    ):
        _remove_dynamic_main_tab(lab)
        st.rerun()


def _ordered_dynamic_sidebar_tab_labels(
    hunt_entries: list[dict],
    hist: list[dict],
) -> list[str]:
    """Stable order: creation order from session, then any new tabs (Hunt list, then history)."""
    hunt_labels = [e.get("tab_label") for e in hunt_entries if e.get("tab_label")]
    hist_labels = [h.get("tab_label") for h in hist if h.get("tab_label")]
    known = frozenset(l for l in hunt_labels + hist_labels if l)
    stored = list(st.session_state.get(MAIN_TAB_DYNAMIC_ORDER_KEY) or [])
    out: list[str] = []
    seen: set[str] = set()
    for lab in stored:
        if lab in known and lab not in seen:
            out.append(lab)
            seen.add(lab)
    for lab in hunt_labels + hist_labels:
        if lab and lab not in seen:
            out.append(lab)
            seen.add(lab)
    st.session_state[MAIN_TAB_DYNAMIC_ORDER_KEY] = out
    return out


def _vol2_format_commandline_html(argv: list[str]) -> str:
    """Token-colored one-line style command (Vol2 argv list)."""
    if not argv:
        return ""
    parts: list[str] = []

    def gap() -> None:
        parts.append('<span class="memhunter-cmd-gap"> </span>')

    def span(text: str, cls: str) -> None:
        parts.append(
            f'<span class="{cls}">{html_module.escape(text)}</span>'
        )

    i = 0
    n = len(argv)
    span(argv[0], "memhunter-cmd-exe")
    i = 1
    while i < n:
        t = argv[i]
        if t == "-f" and i + 1 < n:
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-path")
            i += 2
        elif t.startswith("--profile="):
            gap()
            span(t, "memhunter-cmd-profile")
            i += 1
        elif t == "--profile" and i + 1 < n:
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-profile")
            i += 2
        elif t in ("-p", "-D", "-Q", "-K", "-o", "-Y") and i + 1 < n:
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-value")
            i += 2
        elif t == "--output=text" or (t.startswith("--output") and "=" in t):
            gap()
            span(t, "memhunter-cmd-flag")
            i += 1
        elif t.startswith("-") and len(t) > 1:
            gap()
            span(t, "memhunter-cmd-flag")
            i += 1
        else:
            gap()
            span(t, "memhunter-cmd-plugin")
            i += 1
    return "".join(parts)


def _vol3_format_commandline_html(argv: list[str]) -> str:
    """Token-colored argv for Vol3 (vol.exe -q -r csv -f … -o … windows.* …)."""
    if not argv:
        return ""
    parts: list[str] = []

    def gap() -> None:
        parts.append('<span class="memhunter-cmd-gap"> </span>')

    def span(text: str, cls: str) -> None:
        parts.append(
            f'<span class="{cls}">{html_module.escape(text)}</span>'
        )

    i = 0
    n = len(argv)
    span(argv[0], "memhunter-cmd-exe")
    i = 1
    while i < n:
        t = argv[i]
        if t == "-f" and i + 1 < n:
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-path")
            i += 2
        elif t == "-o" and i + 1 < n:
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-path")
            i += 2
        elif t in ("-q", "-r") and i + 1 < n and argv[i + 1] in (
            "quick",
            "csv",
            "json",
        ):
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-value")
            i += 2
        elif t in ("-q", "-r"):
            gap()
            span(t, "memhunter-cmd-flag")
            i += 1
        elif t.startswith("windows.") or t.startswith("linux.") or t.startswith("mac."):
            gap()
            span(t, "memhunter-cmd-plugin")
            i += 1
        elif t.startswith("--") and i + 1 < n and not argv[i + 1].startswith("-"):
            gap()
            span(t, "memhunter-cmd-flag")
            gap()
            span(argv[i + 1], "memhunter-cmd-value")
            i += 2
        elif t.startswith("-") and len(t) > 1:
            gap()
            span(t, "memhunter-cmd-flag")
            i += 1
        else:
            gap()
            span(t, "memhunter-cmd-value")
            i += 1
    return "".join(parts)


SIDEBAR_DUMP_UI_MODES: frozenset[str] = frozenset(
    {
        "pid_dump",
        "dumpfiles_q",
        "v3_dumpfiles_pid",
        "v3_memmap_dump_pid",
        "v3_dumpfiles_addr",
    }
)


def _sidebar_dump_output_dir(entry: dict) -> str | None:
    """Folder written by procdump/memdump/dumpfiles (Vol2 -D) or Vol3 -o."""
    text = entry.get("text") or ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[dump_dir] "):
            return s[len("[dump_dir] ") :].strip()
        if s.startswith("[output_dir] "):
            return s[len("[output_dir] ") :].strip()
    argv = entry.get("argv")
    if not isinstance(argv, list):
        return None
    mode = entry.get("mode") or ""
    eng = entry.get("engine") or "v2"
    if eng == "v2" and mode in ("pid_dump", "dumpfiles_q"):
        for i, t in enumerate(argv):
            if t == "-D" and i + 1 < len(argv):
                return str(argv[i + 1])
    if eng == "v3" and mode in (
        "v3_dumpfiles_pid",
        "v3_memmap_dump_pid",
        "v3_dumpfiles_addr",
    ):
        for i, t in enumerate(argv):
            if t == "-o" and i + 1 < len(argv):
                return str(argv[i + 1])
    return None


def _render_sidebar_dump_result(entry: dict) -> None:
    pl = entry.get("plugin") or "?"
    rc = entry.get("rc")
    if not isinstance(rc, int):
        rc = -1
    eng = entry.get("engine") or "v2"
    _dump_tl = str(entry.get("tab_label") or "").strip()
    _sh_l, _sh_x = st.columns([0.86, 0.14])
    with _sh_l:
        st.subheader(str(pl), anchor=False)
    with _sh_x:
        if _dump_tl:
            _render_tab_close_x_button(_dump_tl)
    argv = entry.get("argv")
    cmd = entry.get("cmd") or ""
    if isinstance(argv, list) and len(argv) > 0:
        st.caption("Command")
        inner = (
            _vol3_format_commandline_html(argv)
            if eng == "v3"
            else _vol2_format_commandline_html(argv)
        )
        st.markdown(
            f'<div class="memhunter-cmdline-wrap">{inner}</div>',
            unsafe_allow_html=True,
        )
    elif cmd:
        st.caption("Command")
        st.code(cmd, language=None)
    dump_dir = _sidebar_dump_output_dir(entry)
    if dump_dir:
        if rc == 0:
            st.success(f"**Saved under:** `{dump_dir}`")
        else:
            st.info(
                f"**Output folder:** `{dump_dir}`  \n"
                f"Volatility exit code **{rc}** — the dump may still be OK; expand **details** if you need the raw log."
            )
    else:
        st.warning(f"Could not detect output folder (exit code **{rc}**).")
    raw = (entry.get("text") or "").strip()
    if raw and rc != 0:
        with st.expander("Volatility output (details)"):
            st.code(raw, language=None)


def _safe_sidebar_download_stem(entry: dict) -> str:
    p = str(entry.get("plugin") or "output")
    s = re.sub(r"[^\w\-.]+", "_", p).strip("_").strip(".")
    return s[:48] if s else "output"


def render_volatility_sidebar_output_entry(entry: dict) -> None:
    """Single saved Vol2/Vol3 sidebar run inside a dynamic main tab."""
    _tl_close = str(entry.get("tab_label") or "").strip()
    mode = entry.get("mode") or ""
    if mode in SIDEBAR_DUMP_UI_MODES:
        _render_sidebar_dump_result(entry)
        return

    pl = entry.get("plugin") or "?"
    eng = entry.get("engine") or "v2"
    _hd_l, _hd_x = st.columns([0.86, 0.14])
    with _hd_l:
        st.subheader(str(pl), anchor=False)
    with _hd_x:
        if _tl_close:
            _render_tab_close_x_button(_tl_close)
    argv = entry.get("argv")
    cmd = entry.get("cmd") or ""
    if isinstance(argv, list) and len(argv) > 0:
        st.caption("Command")
        inner = (
            _vol3_format_commandline_html(argv)
            if eng == "v3"
            else _vol2_format_commandline_html(argv)
        )
        st.markdown(
            f'<div class="memhunter-cmdline-wrap">{inner}</div>',
            unsafe_allow_html=True,
        )
    elif cmd:
        st.caption("Command")
        st.code(cmd, language=None)
    st.markdown("**Output**")
    raw_full = str(entry.get("text") or "")
    payload = _sidebar_stdout_payload(raw_full)
    # Prefer stdout (same as non-MFT): full raw is huge for MFT and forces the st.code fallback.
    disp_all = (payload or "").strip() or raw_full.strip()
    if not disp_all:
        disp_all = "(empty)"

    is_mft = _sidebar_entry_is_mft(entry)
    rc_e = entry.get("rc")
    stem = _safe_sidebar_download_stem(entry)
    dl_name = f"{stem}_mft_raw.txt" if is_mft else f"{stem}_output.txt"
    if disp_all == "(empty)":
        st.info("No output was captured for this run.")
    else:
        if is_mft and isinstance(rc_e, int) and rc_e != 0:
            st.caption(
                "Volatility reported a non-zero exit code — expand **Diagnostics** for full stderr/stdout."
            )
        _render_sidebar_output_body_code_or_virtual(
            disp_all,
            entry=entry,
            download_name=dl_name,
        )

    is_v3_filescan = (
        eng == "v3"
        and str(entry.get("vol3_plugin_id") or "").strip().lower() == "windows.filescan"
    )
    if is_v3_filescan and disp_all != "(empty)":
        fs_df = _dataframe_from_stdout(disp_all)
        if not fs_df.empty:
            st.markdown("**Dump file from table**")
            if len(fs_df) > VOL3_FILESCAN_DUMP_UI_MAX_ROWS:
                st.caption(
                    f"**{len(fs_df):,}** rows — interactive selection is disabled above "
                    f"**{VOL3_FILESCAN_DUMP_UI_MAX_ROWS:,}**. Copy an offset from the output and use sidebar "
                    "**dumpfiles** (**Physical** or **Virtual** addressing)."
                )
            else:
                st.caption(
                    "Select a row. The physical offset is taken from **Offset(P)** / **Offset** when present, "
                    "otherwise from the **first column**."
                )
                slug_fs = _sidebar_output_widget_slug(entry)
                fs_sel_key = f"{slug_fs}_filescan_phys_sel"
                st.dataframe(
                    fs_df,
                    use_container_width=True,
                    hide_index=True,
                    height=table_height(len(fs_df)),
                    on_select="rerun",
                    selection_mode="single-row",
                    key=fs_sel_key,
                )
                if st.button(
                    "Dump selected file (physical offset)",
                    key=f"{slug_fs}_filescan_phys_dump",
                    type="secondary",
                ):
                    pos = _dataframe_selected_row(fs_sel_key)
                    if pos is None:
                        st.warning("Select a row in the table above.")
                    else:
                        off = _vol3_filescan_row_phys_offset(fs_df, pos)
                        if not off:
                            st.warning("Could not read an offset from the selected row.")
                        else:
                            mem = current_memory_image_path()
                            if require_memory_image_exists(mem):
                                with st.spinner(
                                    "Running windows.dumpfiles.DumpFiles (--physaddr)…"
                                ):
                                    d_rc, d_txt, d_argv = run_vol3_sidebar_plugin(
                                        mem,
                                        "v3_dumpfiles_addr",
                                        VOL3_DUMPFILES_PLUGIN_ID,
                                        pid=None,
                                        append_pid_when_optional=False,
                                        extra_args={
                                            "dumpfiles_address": off,
                                            "dumpfiles_addr_mode": VOL3_DUMPFILES_KIND_PHYS,
                                        },
                                    )
                                d_extra = {
                                    "dumpfiles_address": off,
                                    "dumpfiles_addr_mode": VOL3_DUMPFILES_KIND_PHYS,
                                }
                                new_tab = _vol3_push_output_history(
                                    display_label="dumpfiles",
                                    plugin_id=VOL3_DUMPFILES_PLUGIN_ID,
                                    category_label=str(
                                        entry.get("category") or "FILESCAN & FILEDUMP"
                                    ),
                                    mode="v3_dumpfiles_addr",
                                    rc=d_rc,
                                    text=d_txt,
                                    argv=d_argv,
                                    pid=None,
                                    append_pid=False,
                                    extra=d_extra,
                                )
                                if hasattr(st, "toast"):
                                    st.toast(
                                        f"Added results tab: {new_tab}", icon="📋"
                                    )
                                st.rerun()

    if is_mft and isinstance(rc_e, int) and rc_e != 0 and raw_full.strip():
        with st.expander("Diagnostics (stderr + stdout)", expanded=False):
            st.code(raw_full, language=None)


def run_vol2_sidebar_plugin(
    mem_file: str,
    profile: str | None,
    plugin: str,
    mode: str,
    *,
    pid: int | None,
    append_pid_when_optional: bool,
    extra_args: dict[str, str] | None = None,
) -> tuple[int, str, list[str]]:
    """Build argv per cheatsheet; returns (returncode, merged_output, argv)."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid path: File not found.", []

    x = extra_args or {}

    if mode == "no_profile":
        cmd = [str(VOL2_EXE), "-f", mem_file, plugin, "--output=text"]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        return proc.returncode, text, cmd

    prof = (profile or "").strip()
    if not prof:
        return (
            -1,
            "Profile required — run **Start Analysis** (imageinfo) or use **imageinfo** above first.",
            [],
        )

    if mode == "pid_dump":
        if pid is not None:
            dump_dir = _vol2_dump_dir_for_pid(mem_file, pid)
            cmd = [
                str(VOL2_EXE),
                "-f",
                mem_file,
                f"--profile={prof}",
                plugin,
                "-p",
                str(pid),
                "-D",
                dump_dir,
            ]
        else:
            dump_dir = _vol2_global_dump_dir(mem_file)
            cmd = [
                str(VOL2_EXE),
                "-f",
                mem_file,
                f"--profile={prof}",
                plugin,
                "-D",
                dump_dir,
            ]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        if text:
            text = f"[dump_dir] {dump_dir}\n\n{text}"
        else:
            text = f"[dump_dir] {dump_dir}\n(no stdout/stderr)"
        return proc.returncode, text, cmd

    if mode == "printkey_k":
        k = (x.get("K") or "").strip()
        if not k:
            return (
                -1,
                "Enter a registry key path for **printkey -K** (e.g. `Software\\Microsoft\\Windows\\CurrentVersion\\Run`).",
                [],
            )
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "printkey",
            "-K",
            k,
            "--output=text",
        ]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        return proc.returncode, text, cmd

    if mode == "hivedump_o":
        off = (x.get("o") or "").strip()
        if not off:
            return (
                -1,
                "Enter a hive **offset** for **hivedump -o** (from **hivelist**).",
                [],
            )
        # No --output=text; hive body may be mostly binary (UTF-8 replace via subprocess text mode).
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "hivedump",
            "-o",
            off,
        ]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        if not text:
            text = (
                "(No captured text; **hivedump** often writes binary. "
                "Use a shell redirect to a `.hive` file if the UI output is unusable.)"
            )
        return proc.returncode, text, cmd

    if mode == "dumpfiles_q":
        q = (x.get("Q") or "").strip()
        if not q:
            return (
                -1,
                "Enter a physical offset for **dumpfiles -Q** (e.g. from **filescan**).",
                [],
            )
        dump_dir = _vol2_dump_dir_for_dumpfiles(mem_file)
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "dumpfiles",
            "-Q",
            q,
            "-D",
            dump_dir,
        ]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        if text:
            text = f"[dump_dir] {dump_dir}\n\n{text}"
        else:
            text = f"[dump_dir] {dump_dir}\n(no stdout/stderr)"
        return proc.returncode, text, cmd

    if mode == "yarascan_y":
        y = (x.get("Y") or "").strip()
        if not y:
            return (
                -1,
                "Enter a YARA rule or search string for **yarascan -Y**.",
                [],
            )
        cmd = [
            str(VOL2_EXE),
            "-f",
            mem_file,
            f"--profile={prof}",
            "yarascan",
            "-Y",
            y,
            "--output=text",
        ]
        proc = _subprocess_run(cmd)
        text = _format_vol_subprocess_output(proc).strip()
        return proc.returncode, text, cmd

    cmd = [str(VOL2_EXE), "-f", mem_file, f"--profile={prof}"]
    if mode == "profile_opt_pid" and append_pid_when_optional and pid is not None:
        cmd.extend(["-p", str(pid)])
    out_fmt = "--output=csv" if plugin == "mftparser" else "--output=text"
    cmd.extend([plugin, out_fmt])
    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    return proc.returncode, text, cmd


def run_vol3_sidebar_plugin(
    mem_file: str,
    mode: str,
    plugin_id: str,
    *,
    pid: int | None,
    append_pid_when_optional: bool,
    extra_args: dict[str, str] | None = None,
) -> tuple[int, str, list[str]]:
    """Vol3: vol.exe -q -r csv -f <mem> … — no --profile."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        return -1, "Invalid path: File not found.", []

    x = extra_args or {}
    base = [
        str(VOL3_EXE),
        "-q",
        *vol3_symbol_dir_args(),
        "-r",
        VOL3_DEFAULT_RENDERER,
        "-f",
        mem_file,
    ]

    if mode == "v3_plain":
        cmd = base + [plugin_id]
    elif mode == "v3_pid_opt":
        cmd = base + [plugin_id]
        if append_pid_when_optional and pid is not None:
            cmd.extend(["--pid", str(pid)])
    elif mode == "v3_dumpfiles_pid":
        if pid is not None:
            out_d = _vol3_dump_dir_for_pid(mem_file, pid)
            cmd = base + ["-o", out_d, plugin_id, "--pid", str(pid)]
        else:
            out_d = _vol3_global_dump_dir(mem_file)
            cmd = base + ["-o", out_d, plugin_id]
    elif mode == "v3_memmap_dump_pid":
        if pid is not None:
            out_d = _vol3_dump_dir_for_pid(mem_file, pid)
            cmd = base + ["-o", out_d, plugin_id, "--dump", "--pid", str(pid)]
        else:
            out_d = _vol3_global_dump_dir(mem_file)
            cmd = base + ["-o", out_d, plugin_id, "--dump"]
    elif mode == "v3_printkey_key":
        key = (x.get("key") or "").strip()
        if not key:
            return (
                -1,
                "Enter a registry key for **--key** (e.g. `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`).",
                [],
            )
        cmd = base + [plugin_id, "--key", key]
    elif mode == "v3_dumpfiles_addr":
        addr = (x.get("dumpfiles_address") or "").strip()
        if not addr:
            return (
                -1,
                "Enter an offset for **dumpfiles** (use Physical or Virtual mode above).",
                [],
            )
        out_d = _vol3_dump_dir_phys(mem_file)
        os.makedirs(out_d, exist_ok=True)
        if _vol3_dumpfiles_addr_kind(x) == VOL3_DUMPFILES_KIND_VIRT:
            cmd = base + ["-o", out_d, plugin_id, "--virtaddr", addr]
        else:
            cmd = base + ["-o", out_d, plugin_id, "--physaddr", addr]
    elif mode == "v3_yara_string":
        ys = (x.get("Y") or "").strip()
        if not ys:
            return (
                -1,
                "Enter a YARA rule or string for **--yara-string**.",
                [],
            )
        cmd = base + [plugin_id, "--yara-string", ys]
        if append_pid_when_optional and pid is not None:
            cmd.extend(["--pid", str(pid)])
    else:
        return -1, f"Unknown Vol3 sidebar mode `{mode}`.", []

    proc = _subprocess_run(cmd)
    text = _format_vol_subprocess_output(proc).strip()
    note = ""
    if mode in ("v3_dumpfiles_pid", "v3_memmap_dump_pid"):
        out_note = (
            _vol3_dump_dir_for_pid(mem_file, int(pid))
            if pid is not None
            else _vol3_global_dump_dir(mem_file)
        )
        note = f"[output_dir] {out_note}\n\n"
    elif mode == "v3_dumpfiles_addr":
        note = f"[output_dir] {_vol3_dump_dir_phys(mem_file)}\n\n"
    if note:
        text = note + (text or "(no stdout/stderr)")
    return proc.returncode, text.strip(), cmd


def _vol2_sidebar_plugin_row(
    mem: str,
    prof,
    plugin: str,
    mode: str,
    key_base: str,
    category_label: str,
) -> None:
    """One plugin row: optional text inputs, then run button (always global; no table PID)."""
    inp_k = f"v2arg_{key_base}_{plugin}_K"
    inp_o = f"v2arg_{key_base}_{plugin}_o"
    inp_q = f"v2arg_{key_base}_{plugin}_Q"
    inp_y = f"v2arg_{key_base}_{plugin}_Y"

    dis = False
    if mode != "no_profile" and not prof:
        dis = True

    if mode == "printkey_k":
        st.text_input(
            f"`{plugin}` · registry key (-K)",
            key=inp_k,
            placeholder=r"Software\Microsoft\Windows\CurrentVersion\Run",
        )
    elif mode == "hivedump_o":
        st.text_input(
            f"`{plugin}` · hive virtual offset (-o)",
            key=inp_o,
            placeholder="0x... (from hivelist)",
        )
    elif mode == "dumpfiles_q":
        st.caption(
            f"`{plugin}` · files written under `…\\_memhunter_data\\{VOL2_DUMPFILES_SUBDIR}\\` (next to the app)."
        )
        st.text_input(
            f"`{plugin}` · physical offset (-Q)",
            key=inp_q,
            placeholder="0x... (from filescan)",
        )
    elif mode == "yarascan_y":
        st.text_input(
            f"`{plugin}` · YARA rule or string (-Y)",
            key=inp_y,
            placeholder='wide ascii "suspicious"',
        )

    _v2_plk = (plugin or "").strip().lower()
    _v2_btn_kw: dict = {
        "key": f"v2sb_{key_base}_{plugin}",
        "disabled": dis,
        "use_container_width": True,
    }
    _v2_h = _SIDEBAR_GLOBAL_PLUGIN_HELP.get(_v2_plk)
    if _v2_h:
        _v2_btn_kw["help"] = _v2_h
    if st.button(plugin, **_v2_btn_kw):
        extra: dict[str, str] = {}
        if mode == "printkey_k":
            extra["K"] = str(st.session_state.get(inp_k, "") or "")
        elif mode == "hivedump_o":
            extra["o"] = str(st.session_state.get(inp_o, "") or "")
        elif mode == "dumpfiles_q":
            extra["Q"] = str(st.session_state.get(inp_q, "") or "")
        elif mode == "yarascan_y":
            extra["Y"] = str(st.session_state.get(inp_y, "") or "")

        if require_memory_image_exists(mem):
            _cap = _mh_float_caption_for_plugin(plugin)
            if plugin == "mftparser":
                st.session_state[MH_FLOAT_STATUS_KEY] = f"{_cap} (large MFT — may take a while)…"
            else:
                st.session_state[MH_FLOAT_STATUS_KEY] = _cap
            st.session_state[MH_PENDING_JOB_KEY] = {
                "kind": "vol2_sidebar",
                "mem": mem,
                "prof": str(prof) if prof else "",
                "plugin": plugin,
                "mode": mode,
                "extra": dict(extra),
                "category_label": category_label,
            }
            st.rerun()


def render_vol2_sidebar_plugin_library() -> None:
    """Nested accordions + one-off Vol2 runs; each run adds a main-area results tab."""
    st.markdown(
        '<p class="memhunter-sidebar-heading" title="Global Analysis — runs on entire memory image">'
        "Vol 2 plugin library</p>",
        unsafe_allow_html=True,
    )
    st.caption(
        "**Global analysis** — runs on the **entire memory image** (ignores table selection). "
        "Use **Hunt** for PID-targeted runs. Each button opens a new **results** tab."
    )
    mem = current_memory_image_path()
    prof = st.session_state.get("vol2_profile")

    for main_title, kind, payload in VOL2_SIDEBAR_HIERARCHY:
        mslug = _vol2_sidebar_cat_slug(main_title)
        _main_icon = VOL2_SIDEBAR_MAIN_MATERIAL_ICON.get(main_title)
        with st.expander(
            main_title,
            expanded=False,
            icon=_main_icon,
            key=f"v2sidebar_main_{mslug}",
        ):
            if kind == "nested":
                for sub_title, items in payload:
                    sslug = _vol2_sidebar_cat_slug(sub_title)
                    key_base = f"{mslug}{sslug}"[:56]
                    cat_label = f"{main_title} › {sub_title}"
                    with st.expander(sub_title, expanded=False):
                        for pl, mode in items:
                            _vol2_sidebar_plugin_row(
                                mem,
                                prof,
                                pl,
                                mode,
                                key_base,
                                cat_label,
                            )
            elif kind == "flat":
                key_base = f"{mslug}flat"[:56]
                for pl, mode in payload:
                    _vol2_sidebar_plugin_row(
                        mem,
                        prof,
                        pl,
                        mode,
                        key_base,
                        main_title,
                    )
                if main_title == "SEARCH & SCANNING":
                    st.markdown("---")
                    st.markdown("**Strings Scan**")
                    q = st.text_input(
                        "Search Term",
                        key="sb_strings_scan_search_term_v2",
                        placeholder="Enter string, IP, or domain",
                    )
                    min_len = st.slider(
                        "Min Length",
                        min_value=1,
                        max_value=32,
                        value=4,
                        step=1,
                        key="sb_strings_scan_min_length_v2",
                    )
                    if st.button(
                        "RUN STRINGS SEARCH",
                        key="sb_strings_scan_run_v2",
                        type="secondary",
                        help="Sysinternals Strings + findstr filter.",
                    ):
                        if not q.strip():
                            st.warning("Enter a search term first.")
                        elif not require_memory_image_exists(mem):
                            pass
                        else:
                            st.session_state[MH_FLOAT_STATUS_KEY] = "Scanning strings…"
                            st.session_state[MH_PENDING_JOB_KEY] = {
                                "kind": "strings",
                                "engine_label": ENGINE_V2_LABEL,
                                "mem": mem,
                                "q": q,
                                "min_len": int(min_len),
                            }
                            st.rerun()


def _vol3_sidebar_plugin_row(
    mem: str,
    display_label: str,
    mode: str,
    plugin_id: str,
    key_base: str,
    category_label: str,
) -> None:
    """One Vol3 plugin row — global run only (no `--pid` from table selection)."""
    inp_key = f"v3arg_{key_base}_{display_label}_key"
    inp_addr_kind = f"v3arg_{key_base}_{display_label}_addr_kind"
    inp_addr = f"v3arg_{key_base}_{display_label}_addr"
    inp_y = f"v3arg_{key_base}_{display_label}_Y"

    dis = False

    if mode == "v3_printkey_key":
        st.text_input(
            f"`{display_label}` · registry key (--key)",
            key=inp_key,
            placeholder=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        )
    elif mode == "v3_dumpfiles_addr":
        st.radio(
            "Addressing",
            options=[VOL3_DUMPFILES_RADIO_PHYS, VOL3_DUMPFILES_RADIO_VIRT],
            key=inp_addr_kind,
            horizontal=True,
            help="Physical: **--physaddr** (offset in image). Virtual: **--virtaddr**.",
        )
        st.text_input(
            f"`{display_label}` · offset",
            key=inp_addr,
            placeholder="0x... (from filescan or your notes)",
        )
    elif mode == "v3_yara_string":
        st.text_input(
            f"`{display_label}` · YARA (--yara-string)",
            key=inp_y,
            placeholder='wide ascii "suspicious"',
        )

    _v3_lbk = (display_label or "").strip().lower()
    _v3_btn_kw: dict = {
        "key": f"v3sb_{key_base}_{display_label}",
        "disabled": dis,
        "use_container_width": True,
    }
    _v3_h = _SIDEBAR_GLOBAL_PLUGIN_HELP.get(_v3_lbk)
    if _v3_h:
        _v3_btn_kw["help"] = _v3_h
    if st.button(display_label, **_v3_btn_kw):
        extra: dict[str, str] = {}
        if mode == "v3_printkey_key":
            extra["key"] = str(st.session_state.get(inp_key, "") or "")
        elif mode == "v3_dumpfiles_addr":
            _rad = str(
                st.session_state.get(inp_addr_kind) or VOL3_DUMPFILES_RADIO_PHYS
            )
            extra["dumpfiles_addr_mode"] = (
                VOL3_DUMPFILES_KIND_VIRT
                if _rad == VOL3_DUMPFILES_RADIO_VIRT
                else VOL3_DUMPFILES_KIND_PHYS
            )
            extra["dumpfiles_address"] = str(st.session_state.get(inp_addr, "") or "")
        elif mode == "v3_yara_string":
            extra["Y"] = str(st.session_state.get(inp_y, "") or "")

        if require_memory_image_exists(mem):
            _cap = _mh_float_caption_for_plugin(display_label)
            if "mftscan" in (plugin_id or "").lower():
                st.session_state[MH_FLOAT_STATUS_KEY] = f"{_cap} (large MFT — may take a while)…"
            else:
                st.session_state[MH_FLOAT_STATUS_KEY] = _cap
            st.session_state[MH_PENDING_JOB_KEY] = {
                "kind": "vol3_sidebar",
                "mem": mem,
                "display_label": display_label,
                "mode": mode,
                "plugin_id": plugin_id,
                "category_label": category_label,
                "extra": dict(extra),
            }
            st.rerun()


def render_vol3_sidebar_plugin_library() -> None:
    """Nested Vol3 sidebar — same layout as Vol2; no profile; results tabs on the right."""
    st.markdown(
        '<p class="memhunter-sidebar-heading" title="Global Analysis — runs on entire memory image">'
        "Vol 3 plugin library</p>",
        unsafe_allow_html=True,
    )
    st.caption(
        "**Global analysis** — runs on the **entire memory image**"
    )
    mem = current_memory_image_path()

    for main_title, kind, payload in VOL3_SIDEBAR_HIERARCHY:
        mslug = _vol2_sidebar_cat_slug(main_title)
        _main_icon = VOL2_SIDEBAR_MAIN_MATERIAL_ICON.get(main_title)
        with st.expander(
            main_title,
            expanded=False,
            icon=_main_icon,
            key=f"v3sidebar_main_{mslug}",
        ):
            if kind == "nested":
                for sub_title, items in payload:
                    sslug = _vol2_sidebar_cat_slug(sub_title)
                    key_base = f"v3{mslug}{sslug}"[:56]
                    cat_label = f"{main_title} › {sub_title}"
                    with st.expander(sub_title, expanded=False):
                        for display_label, mode, plugin_id in items:
                            _vol3_sidebar_plugin_row(
                                mem,
                                display_label,
                                mode,
                                plugin_id,
                                key_base,
                                cat_label,
                            )
            elif kind == "flat":
                key_base = f"v3{mslug}flat"[:56]
                for display_label, mode, plugin_id in payload:
                    _vol3_sidebar_plugin_row(
                        mem,
                        display_label,
                        mode,
                        plugin_id,
                        key_base,
                        main_title,
                    )
                if main_title == "SEARCH & SCANNING":
                    st.markdown("---")
                    st.markdown("**Strings Scan**")
                    q = st.text_input(
                        "Search Term",
                        key="sb_strings_scan_search_term_v3",
                        placeholder="Enter string, IP, or domain",
                    )
                    min_len = st.slider(
                        "Min Length",
                        min_value=1,
                        max_value=32,
                        value=4,
                        step=1,
                        key="sb_strings_scan_min_length_v3",
                    )
                    if st.button(
                        "RUN STRINGS SEARCH",
                        key="sb_strings_scan_run_v3",
                        type="secondary",
                        help="Sysinternals Strings + findstr filter.",
                    ):
                        if not q.strip():
                            st.warning("Enter a search term first.")
                        elif not require_memory_image_exists(mem):
                            pass
                        else:
                            st.session_state[MH_FLOAT_STATUS_KEY] = "Scanning strings…"
                            st.session_state[MH_PENDING_JOB_KEY] = {
                                "kind": "strings",
                                "engine_label": ENGINE_V3_LABEL,
                                "mem": mem,
                                "q": q,
                                "min_len": int(min_len),
                            }
                            st.rerun()


def run_vol_live(
    engine_label: str,
    mem_file: str,
    plugin: str,
    log_lines: list[str],
    refresh,
    *,
    vol2_profile: str | None = None,
) -> pd.DataFrame:
    """Streaming run (startup): Vol3 uses CSV stream; Vol2 uses CSV attempt without -q on vol3 only."""
    mem_file = (mem_file or "").strip()
    if not mem_file or not os.path.exists(mem_file):
        st.error("Invalid path: File not found.")
        return pd.DataFrame()

    if is_vol3(engine_label):
        command = [
            str(VOL3_EXE),
            "-q",
            *vol3_symbol_dir_args(),
            "-r",
            VOL3_DEFAULT_RENDERER,
            "-f",
            mem_file,
            plugin,
        ]
        log_lines.append(f"$ {' '.join(command)}")
        refresh()
        out_buf: list[str] = []
        err_buf: list[str] = []
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            if proc.stdout is None or proc.stderr is None:
                return pd.DataFrame()

            def _drain_stderr() -> None:
                try:
                    for line in proc.stderr:
                        err_buf.append(line.rstrip("\n"))
                except Exception:
                    pass

            t_err = threading.Thread(target=_drain_stderr, daemon=True)
            t_err.start()
            for line in proc.stdout:
                line = line.rstrip("\n")
                out_buf.append(line)
                log_lines.append(line)
                refresh()
            proc.wait()
            t_err.join(timeout=30)
            err_txt = "\n".join(err_buf).strip()
            if err_txt:
                log_lines.append("[stderr]")
                log_lines.extend(err_txt.splitlines())
                refresh()
            raw = "\n".join(out_buf)
            csv_text = _extract_csv_from_vol_output(raw)
            if not csv_text.strip():
                return pd.DataFrame()
            return pd.read_csv(io.StringIO(csv_text), engine="python", on_bad_lines="warn")
        except Exception as e:
            st.error(f"Error running `{plugin}`: {e}")
            log_lines.append(str(e))
            refresh()
            return pd.DataFrame()

    # Vol2: no line-buffered live CSV easily — run batched subprocess.run inside spinner path instead
    df, raw = run_vol(engine_label, mem_file, plugin, vol2_profile=vol2_profile, prefer_csv=True)
    log_lines.append(f"$ vol2 … {plugin} --output=csv")
    log_lines.extend(raw.splitlines()[-40:])
    refresh()
    return df


def table_height(row_count: int) -> int:
    # Extra vertical budget so the horizontal scrollbar does not sit on the last row (selection checkboxes).
    return min(740, 120 + min(row_count, 500) * 35) + 24


PSTREE_TABLE_KEY = "pstree_interactive"
PSTREE_STYLER_UUID = "pstree_hl_v1"
PSXVIEW_STYLER_UUID = "psxview_pslist_v1"

# Last-interaction focus for Hunt / sidebar PID: avoids pslist/pstree shadowing psxview.
_MEMHUNT_FOCUS_SEL_KEY = "_memhunt_focus_sel_key"
_MEMHUNT_SEL_POS_PREV = "_memhunt_sel_pos_prev"
_HUNT_SEL_TABLE_ORDER: list[tuple[str, str]] = [
    (PSTREE_TABLE_KEY, "pstree"),
    (PSLIST_SEL_KEY, "pslist"),
    (PSXVIEW_SEL_KEY, "psxview"),
    (PSSCAN_SEL_KEY, "psscan"),
]


def _hunt_selection_checks_ordered() -> list[tuple[str, str]]:
    mem = st.session_state.setdefault(_MEMHUNT_SEL_POS_PREV, {})
    focused = st.session_state.get(_MEMHUNT_FOCUS_SEL_KEY)

    for sel_key, _src in _HUNT_SEL_TABLE_ORDER:
        prev = mem.get(sel_key)
        current_row = _dataframe_selected_row(sel_key)
        if current_row is not None and prev != current_row:
            mem[sel_key] = current_row
            st.session_state[_MEMHUNT_FOCUS_SEL_KEY] = sel_key
            focused = sel_key
        elif current_row is None and prev is not None:
            mem.pop(sel_key, None)
            if st.session_state.get(_MEMHUNT_FOCUS_SEL_KEY) == sel_key:
                st.session_state.pop(_MEMHUNT_FOCUS_SEL_KEY, None)
            focused = st.session_state.get(_MEMHUNT_FOCUS_SEL_KEY)

    _src_by_key = dict(_HUNT_SEL_TABLE_ORDER)
    if focused in _src_by_key:
        return [(focused, _src_by_key[focused])] + [
            (k, s) for k, s in _HUNT_SEL_TABLE_ORDER if k != focused
        ]
    return list(_HUNT_SEL_TABLE_ORDER)


def _dataframe_selected_row(key: str) -> int | None:
    raw = st.session_state.get(key)
    if raw is None:
        return None
    try:
        if isinstance(raw, dict):
            rows = raw.get("selection", {}).get("rows", [])
        else:
            sel = getattr(raw, "selection", None)
            rows = list(getattr(sel, "rows", [])) if sel is not None else []
    except (AttributeError, KeyError, TypeError):
        return None
    if not rows:
        return None
    try:
        return int(rows[0])
    except (TypeError, ValueError):
        return None


def _pstree_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").astype("Float64")


def _pstree_relation_sets(df: pd.DataFrame, selected_pos: int | None) -> tuple[set[int], set[int]]:
    if selected_pos is None or df.empty or selected_pos < 0 or selected_pos >= len(df):
        return set(), set()
    if "PID" not in df.columns or "PPID" not in df.columns:
        return set(), set()
    pids = _pstree_numeric(df["PID"])
    ppids = _pstree_numeric(df["PPID"])
    sel_pid = pids.iloc[selected_pos]
    sel_ppid = ppids.iloc[selected_pos]
    parent_idxs = set()
    child_idxs = set()
    if pd.notna(sel_ppid):
        match_p = (pids == sel_ppid) & pids.notna()
        parent_idxs = set(df.index[match_p].tolist())
    if pd.notna(sel_pid):
        match_c = (ppids == sel_pid) & ppids.notna()
        child_idxs = set(df.index[match_c].tolist())
    parent_idxs.discard(selected_pos)
    child_idxs.discard(selected_pos)
    return parent_idxs, child_idxs


def _style_pstree_row(
    selected_pos: int | None,
    parent_idxs: set[int],
    child_idxs: set[int],
    row: pd.Series,
):
    i = int(row.name) if row.name is not None else -1
    if selected_pos is not None and i == selected_pos:
        style = (
            "background-color: rgba(14, 165, 233, 0.35); color: #f0f9ff; "
            "font-weight: 600; border-left: 4px solid #38bdf8; box-shadow: inset 0 0 0 1px rgba(56, 189, 248, 0.45)"
        )
    elif i in parent_idxs:
        style = (
            "background-color: rgba(250, 204, 21, 0.22); color: #fffbeb; "
            "font-weight: 500; border-left: 4px solid #fbbf24"
        )
    elif i in child_idxs:
        style = (
            "background-color: rgba(52, 211, 153, 0.22); color: #ecfdf5; "
            "font-weight: 500; border-left: 4px solid #34d399"
        )
    else:
        style = ""
    return [style] * len(row)


def style_pstree_dataframe(df: pd.DataFrame, selected_pos: int | None):
    styler = df.style.hide(axis="index")
    styler.set_uuid(PSTREE_STYLER_UUID)
    if selected_pos is None:
        return styler
    parent_idxs, child_idxs = _pstree_relation_sets(df, selected_pos)
    return styler.apply(
        lambda row: _style_pstree_row(selected_pos, parent_idxs, child_idxs, row),
        axis=1,
    )


def _psxview_pslist_is_false(v) -> bool:
    """True when psxview marks the process as absent from pslist (unchecked / False)."""
    if pd.isna(v):
        return False
    if isinstance(v, str):
        s = v.strip().upper()
        return s in ("FALSE", "F", "NO", "OFF", "0")
    if v in (0, 0.0):
        return True
    if v in (1, 1.0):
        return False
    if v is True or v is False:
        return v is False
    try:
        return not bool(v)
    except Exception:
        return False


def style_psxview_pslist_false(df: pd.DataFrame):
    """Highlight full row red when the pslist column is False (not on EPROCESS list)."""
    ps_col = next((c for c in df.columns if str(c).lower() == "pslist"), None)
    styler = df.style.hide(axis="index")
    styler.set_uuid(PSXVIEW_STYLER_UUID)
    if ps_col is None:
        return styler

    red = (
        "background-color: rgba(220, 38, 38, 0.42); color: #fecaca; font-weight: 500"
    )

    def apply_row(row: pd.Series):
        n = len(row)
        if _psxview_pslist_is_false(row[ps_col]):
            return [red] * n
        return [""] * n

    return styler.apply(apply_row, axis=1)


VOL_PENDING_KEY = "maor_vol_pending"


def _memhunter_logo_data_uri() -> str | None:
    if not MEMHUNTER_LOGO.is_file():
        return None
    try:
        raw = MEMHUNTER_LOGO.read_bytes()
        return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    except OSError:
        return None


def analysis_brand():
    uri = _memhunter_logo_data_uri()
    if uri:
        st.markdown(
            '<div class="analysis-brand-row">'
            f'<img class="analysis-brand-logo" src="{uri}" alt="" />'
            '<div class="analysis-brand-text">'
            "<h1>MemHunter</h1>"
            '<p class="analysis-by">by Maor Lankry</p>'
            "</div></div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="analysis-brand-block">'
            "<h1>MemHunter</h1>"
            '<p class="analysis-by">by Maor Lankry</p>'
            "</div>",
            unsafe_allow_html=True,
        )


LOADING_ORBIT_HTML = """
<style>
.maor-dock {
    text-align: center;
    padding: 0.25rem 0 0.1rem 0;
    opacity: 0.88;
}
.maor-orbit-wrap {
    position: relative;
    width: 92px;
    height: 92px;
    margin: 0.2rem auto 0.35rem auto;
}
.maor-orbit {
    position: absolute;
    inset: 0;
    border-radius: 9999px !important;
    border: 1px solid transparent;
    border-top-color: rgba(125, 211, 252, 0.75);
    border-right-color: rgba(167, 139, 250, 0.45);
    animation: maor-spin 1.75s linear infinite;
    opacity: 0.92;
}
.maor-orbit2 {
    position: absolute;
    inset: 18px;
    border-radius: 9999px !important;
    border: 1px solid transparent;
    border-bottom-color: rgba(52, 211, 153, 0.35);
    border-left-color: rgba(52, 211, 153, 0.2);
    animation: maor-spin 1.35s linear infinite reverse;
    opacity: 0.85;
}
.maor-hex {
    position: absolute;
    inset: 28px;
    width: 36px;
    height: 36px;
    margin: auto;
    background: rgba(15, 23, 42, 0.6);
    border-radius: 9999px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.72rem;
    color: rgba(186, 230, 253, 0.9);
    border: 1px solid rgba(56, 189, 248, 0.22);
}
@keyframes maor-spin {
    to { transform: rotate(360deg); }
}
</style>
<div class="maor-dock">
  <div class="maor-orbit-wrap">
    <div class="maor-orbit"></div>
    <div class="maor-orbit2"></div>
    <div class="maor-hex">▶</div>
  </div>
</div>
"""


def _render_mini_fog_terminal(log_lines: list[str]) -> str:
    tail = log_lines[-26:]
    body = "\n".join(tail)
    safe = html_module.escape(body)
    return (
        '<div class="maor-mini-cli-wrap">'
        '<div class="maor-mini-cli-fog">'
        f'<pre class="maor-mini-cli">{safe}</pre>'
        "</div></div>"
    )


if False:
    st.markdown(
        f"""
<style>
:root {{
  --mh-bg0: #0b0b10;
  --mh-bg1: #12121a;
  --mh-panel: rgba(20, 20, 28, 0.84);
  --mh-panel2: rgba(26, 26, 38, 0.78);
  --mh-fg: #e9e6f7;
  --mh-dim: rgba(233, 230, 247, 0.70);
  --mh-line: rgba(167, 139, 250, 0.22);
  --mh-purple: #a78bfa;
  --mh-purple2: #7c3aed;
  --mh-green: #34d399;
  --mh-salmon: #fb7185;
  --mh-shadow: rgba(0,0,0,0.86);
  --mh-sidebar-top: rgba(18,18,26,0.95);
  --mh-sidebar-bot: rgba(11,11,16,0.96);
  --mh-input-bg: rgba(10, 10, 14, 0.72);
  --mh-btn-bg: rgba(20,20,28,0.88);
  --mh-btn-bg-hover: rgba(26,26,38,0.90);
  --mh-status-bg: rgba(20,20,28,0.92);
  --mh-term: #0b0b0b;
  --mh-term-fg: #d4d4d4;
  --mh-term-dim: #9ca3af;
}}
</style>
""",
        unsafe_allow_html=True,
    )

st.markdown(
    """
<style>
    /* Theme vars are injected above (dark/light) */
    /* Hard geometry */
    * { border-radius: 0 !important; }

    /* App background: neutral + purple glow (not suffocating) */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(1200px 780px at 25% -10%, rgba(124,58,237,0.16), transparent 68%),
            radial-gradient(900px 560px at 100% 8%, rgba(251,113,133,0.06), transparent 62%),
            linear-gradient(180deg, var(--mh-bg0), var(--mh-bg1)) !important;
        color: var(--mh-fg) !important;
        opacity: 1 !important;
        filter: none !important;
    }
    /* Keep UI fully bright during reruns (spinner / st.status / long Volatility runs). */
    [data-testid="stMain"],
    [data-testid="stMain"] > div,
    section.stMain,
    section.stMain > div,
    [data-testid="stSidebar"],
    .stApp,
    .stMain,
    .main .block-container {
        opacity: 1 !important;
        filter: none !important;
    }
    [data-testid="stMain"],
    [data-testid="stSidebar"],
    section.stMain {
        pointer-events: auto !important;
    }
    /* Nuclear override: keep every Streamlit shell + descendants bright (global plugins). */
    .stApp,
    .stApp > div,
    [data-testid="stAppViewContainer"],
    [data-testid="stAppViewContainer"] > div,
    [data-testid="stVerticalBlock"],
    [data-testid="stVerticalBlock"] > div,
    [data-testid="stHorizontalBlock"],
    [data-testid="stHorizontalBlock"] > div,
    [data-testid="stSidebar"] > div,
    [data-testid="stHeader"],
    [data-testid="stToolbar"],
    [data-testid="stBottom"],
    section.main,
    section.main > div,
    .main,
    .main > div,
    .block-container {
        opacity: 1 !important;
        filter: none !important;
    }

    /* Top-right floating status (deferred blocking jobs) */
    .memhunter-float-root {
        position: fixed !important;
        top: 0.42rem !important;
        right: 3.1rem !important;
        z-index: 2147483000 !important;
        max-width: min(440px, 46vw) !important;
        padding: 0.26rem 0.62rem !important;
        font-size: 0.76rem !important;
        line-height: 1.28 !important;
        font-weight: 500 !important;
        letter-spacing: 0.02em !important;
        color: var(--mh-fg) !important;
        background: rgba(15, 23, 42, 0.82) !important;
        border: 1px solid rgba(167, 139, 250, 0.32) !important;
        box-shadow: 0 8px 28px rgba(0, 0, 0, 0.5) !important;
        pointer-events: none !important;
    }
    .memhunter-float-root--hidden {
        display: none !important;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--mh-sidebar-top), var(--mh-sidebar-bot)) !important;
        border-right: 1px solid rgba(167,139,250,0.14) !important;
    }

    /* Panels / containers */
    div[data-testid="stVerticalBlock"] > div:has(> div[data-testid="stMarkdownContainer"]),
    div[data-testid="stVerticalBlock"] > div:has(div[data-testid="stDataFrame"]) {
        background: var(--mh-panel);
        border: 1px solid rgba(167,139,250,0.18);
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
    }

    /* Inputs */
    input, textarea, select, [data-baseweb="input"] input {
        background: var(--mh-input-bg) !important;
        border: 1px solid rgba(167,139,250,0.22) !important;
        color: var(--mh-fg) !important;
    }
    input:focus, textarea:focus, select:focus, [data-baseweb="input"] input:focus {
        outline: none !important;
        border-color: rgba(167,139,250,0.50) !important;
        box-shadow: 0 0 0 1px rgba(124,58,237,0.24) !important;
    }

    /* Base buttons: 3D block style */
    button[kind="primary"], button[kind="secondary"], button[kind="tertiary"] {
        border: 1px solid rgba(167,139,250,0.38) !important;
        background: var(--mh-btn-bg) !important;
        color: var(--mh-fg) !important;
        font-weight: 750 !important;
        letter-spacing: 0.10em !important;
        text-transform: uppercase !important;
        box-shadow: 4px 4px 0px var(--mh-shadow) !important;
    }

    /* Hunt action buttons: uniform size + sensible spacing */
    section.main div[data-testid="stVerticalBlock"]:has(p.memhunter-hunt-acc-strip) div[data-testid="stButton"] button {
        min-height: 2.25rem !important;
        padding: 0.25rem 0.85rem !important;
        font-size: 0.82rem !important;
    }
    button[kind="primary"]:active, button[kind="secondary"]:active, button[kind="tertiary"]:active {
        transform: translate(2px,2px) !important;
        box-shadow: 2px 2px 0px var(--mh-shadow) !important;
    }
    button[kind="primary"]:hover, button[kind="secondary"]:hover, button[kind="tertiary"]:hover {
        border-color: rgba(233,230,247,0.34) !important;
        background: var(--mh-btn-bg-hover) !important;
    }

    /* Hunt button coloring (JS tags stButton wrappers) */
    section.main div[data-testid="stButton"].mh-btn-net button { border-color: rgba(52,211,153,0.85) !important; }
    section.main div[data-testid="stButton"].mh-btn-mal button { border-color: rgba(251,113,133,0.90) !important; }
    section.main div[data-testid="stButton"].mh-btn-yara button { border-color: rgba(167,139,250,0.86) !important; }
    section.main div[data-testid="stButton"].mh-btn-strings button { border-color: rgba(52,211,153,0.86) !important; }
    section.main div[data-testid="stButton"].mh-btn-res button { border-color: rgba(52,211,153,0.80) !important; }
    section.main div[data-testid="stButton"].mh-btn-ids button { border-color: rgba(167,139,250,0.80) !important; }
    section.main div[data-testid="stButton"].mh-btn-dll button { border-color: rgba(167,139,250,0.82) !important; }
    section.main div[data-testid="stButton"].mh-btn-dump-exe button { border-color: rgba(251,113,133,0.86) !important; }
    section.main div[data-testid="stButton"].mh-btn-dump-dll button { border-color: rgba(167,139,250,0.86) !important; }
    section.main div[data-testid="stButton"].mh-btn-dump-mem button { border-color: rgba(52,211,153,0.86) !important; }
    section.main div[data-testid="stButton"].mh-btn-dump-vad button { border-color: rgba(233,230,247,0.30) !important; }

    /* Sidebar Hunt CTA: extra special */
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-btn-hunt-cta button {
        background: var(--mh-btn-bg) !important;
        border-color: rgba(52,211,153,0.88) !important;
        box-shadow: 5px 5px 0px var(--mh-shadow) !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-btn-hunt-cta button:hover {
        background: var(--mh-btn-bg-hover) !important;
        border-color: rgba(52,211,153,1) !important;
    }

    /* Output/code blocks: classic terminal */
    pre, code, .stCodeBlock, .stMarkdown code {
        background: var(--mh-term) !important;
        color: var(--mh-term-fg) !important;
        border: 1px solid rgba(233,230,247,0.10) !important;
    }
    .memhunter-out-linecount { color: var(--mh-term-fg) !important; }
    .memhunter-out-filtered { color: rgba(52,211,153,0.95) !important; }

    /* Streamlit spinner (plugin loading): force circular spinner */
    div[data-testid="stSpinner"] {
        display: inline-flex !important;
        align-items: center !important;
        gap: 0.55rem !important;
        color: var(--mh-fg) !important;
    }
    div[data-testid="stSpinner"] svg {
        display: none !important;
    }
    /* Some Streamlit versions render a rotating square via non-SVG nodes */
    div[data-testid="stSpinner"] [data-testid*="stSpinner"] {
        display: none !important;
    }
    div[data-testid="stSpinner"]::before {
        content: "";
        width: 16px;
        height: 16px;
        border: 2px solid rgba(167,139,250,0.28);
        border-top-color: rgba(52,211,153,0.92);
        border-radius: 9999px !important;
        animation: memhunter-orbit-spin 0.9s linear infinite;
        box-shadow: 2px 2px 0px var(--mh-shadow);
        display: inline-block;
        flex: 0 0 auto;
    }

    /* Status widget (Stop / Running): remove any square icon, keep circular ::before */
    div[data-testid="stStatusWidget"] svg,
    div[data-testid="stStatusWidget"] [data-testid*="Icon"] {
        display: none !important;
    }
    /* Hide any leftover “square” glyphs inside the status widget button */
    div[data-testid="stStatusWidget"] [role="img"],
    div[data-testid="stStatusWidget"] img {
        display: none !important;
    }

    /* Light theme: force “text on light background” correctness */
    [data-testid="stAppViewContainer"] h1,
    [data-testid="stAppViewContainer"] h2,
    [data-testid="stAppViewContainer"] h3,
    [data-testid="stAppViewContainer"] p,
    [data-testid="stAppViewContainer"] label,
    [data-testid="stAppViewContainer"] span {
        color: var(--mh-fg);
    }

    /* DataFrame: readable + reserve space below grid so horizontal scrollbar does not cover last row */
    div[data-testid="stDataFrame"] {
        background: var(--mh-panel) !important;
        border: 1px solid rgba(167,139,250,0.18) !important;
        padding-bottom: 22px !important;
        box-sizing: border-box !important;
    }
    div[data-testid="stDataFrame"] > div {
        padding-bottom: 18px !important;
        box-sizing: border-box !important;
    }
    /* Glide Data Grid (Streamlit dataframe): keep last row above horizontal scrollbar */
    div[data-testid="stDataFrame"] .dvn-scroller {
        padding-bottom: 20px !important;
        box-sizing: border-box !important;
    }
    div[data-testid="stDataFrame"] [role="grid"],
    div[data-testid="stDataFrame"] [role="rowgroup"],
    div[data-testid="stDataFrame"] [role="columnheader"],
    div[data-testid="stDataFrame"] [role="gridcell"] {
        color: var(--mh-fg) !important;
        border-color: rgba(167,139,250,0.14) !important;
    }

    @keyframes memhunter-orbit-spin {
        to {
            transform: rotate(360deg);
        }
    }
    /* Streamlit main menu (⋯): hide “System” theme — keep Light / Dark only (Base Web popover). */
    div[data-baseweb="popover"] [data-baseweb="segmented-control"] > div:first-child,
    div[data-baseweb="popover"] [data-baseweb="segmented-control"] > button:first-child {
        display: none !important;
    }
    div[data-baseweb="popover"] [role="listbox"] > div[role="option"]:first-child {
        display: none !important;
    }
    /* Keep header alive so the sidebar can be reopened after collapsing.
       We'll make it minimal/transparent instead of removing it. */
    header[data-testid="stHeader"] {
        display: block !important;
        background: transparent !important;
        height: 0 !important;
    }
    div[data-testid="stToolbar"] {
        display: block !important;
        background: transparent !important;
        height: 0 !important;
    }
    div[data-testid="stDecoration"] {
        display: none !important;
    }

    /* Ensure sidebar expand/collapse buttons are clickable/visible */
    button[data-testid="stSidebarExpandButton"],
    button[data-testid="stSidebarCollapseButton"] {
        display: inline-flex !important;
        pointer-events: auto !important;
        opacity: 0.92 !important;
        z-index: 100000 !important;
        box-shadow: 4px 4px 0px var(--mh-shadow) !important;
        border: 1px solid rgba(167,139,250,0.28) !important;
        background: var(--mh-btn-bg) !important;
        color: var(--mh-fg) !important;
    }
    /* Streamlit header “Running / Stop” pill — replace default running-man with orbit spinner (like first-load UI) */
    div[data-testid="stStatusWidget"] {
        display: inline-flex !important;
        align-items: center !important;
        gap: 0.4rem !important;
        background: var(--mh-status-bg) !important;
        border: 1px solid rgba(167,139,250,0.22) !important;
        box-shadow: 0 8px 26px rgba(0, 0, 0, 0.28) !important;
        backdrop-filter: blur(10px);
        color: var(--mh-fg) !important;
        padding: 0.28rem 0.75rem !important;
    }
    div[data-testid="stStatusWidget"] * {
        text-shadow: none !important;
    }
    div[data-testid="stStatusWidgetRunningManIcon"],
    div[data-testid="stStatusWidgetRunningIcon"],
    div[data-testid="stStatusWidgetNewYearsIcon"] {
        display: none !important;
    }
    div[data-testid="stStatusWidget"]::before {
        content: "";
        width: 14px;
        height: 14px;
        flex-shrink: 0;
        border: 2px solid rgba(167, 139, 250, 0.28);
        border-top-color: rgba(167, 139, 250, 0.85);
        border-radius: 9999px !important;
        animation: memhunter-orbit-spin 0.88s linear infinite;
    }
    div[data-testid="stStatusWidget"] [data-testid="stToolbarActionButtonLabel"] {
        color: var(--mh-fg) !important;
        font-weight: 500 !important;
        letter-spacing: 0.04em !important;
    }
    /* Top padding: browser chrome only (in-app header bar hidden above). */
    .block-container {
        max-width: 88rem;
        padding-top: 1.45rem !important;
        padding-bottom: 2rem !important;
    }
    /* Avoid overflow:visible on stMain — breaks Streamlit main scroll / mouse wheel. */
    section.main > div,
    .stMain > div {
        padding-top: 0.75rem !important;
    }
    [data-testid="stAppViewContainer"] > .main {
        scroll-margin-top: 0;
    }
    /* Sidebar: disable drag-resize only (show/hide chevron still works).
       Default width: st.set_page_config(initial_sidebar_state=MEMHUNTER_SIDEBAR_WIDTH_PX). */
    [data-testid="stSidebar"] {
        resize: none !important;
    }
    /* Do NOT target [data-testid="stSidebar"] + div — in Streamlit that sibling is often the
       main content column; collapsing it hides the logo and Start Analysis button. */
    /* Do not disable pointer-events on the sidebar toggle handle.
       Some Streamlit builds reuse ew/col-resize styles for the collapse/expand control,
       and disabling pointer events makes the sidebar impossible to reopen. */
    /* Sidebar: less top padding (content sits higher) */
    [data-testid="stSidebar"] .block-container {
        padding-top: 0.35rem !important;
        padding-bottom: 1rem !important;
    }
    [data-testid="stSidebar"] [data-testid="stSidebarHeader"] {
        margin-bottom: 0.15rem !important;
    }
    [data-testid="stSidebar"] h3 {
        margin-top: 0 !important;
        margin-bottom: 0.35rem !important;
    }
    /* Vol2 main category icons (Material SVG) — muted gray, match sidebar text */
    [data-testid="stSidebar"] [data-testid="stExpander"] svg {
        color: #94a3b8 !important;
        opacity: 0.88;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="collapsedControl"] svg {
        color: #94a3b8 !important;
    }
    .memhunter-sidebar-heading {
        font-size: 0.82rem;
        font-weight: 650;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #7dd3fc;
        margin: 0.5rem 0 0.35rem 0;
        opacity: 0.92;
    }
    /* Compact “terminal line” for Vol2 argv (not full-width st.code block) */
    .memhunter-cmdline-wrap {
        display: block;
        width: fit-content;
        max-width: min(100%, 52rem);
        margin: 0 0 0.55rem 0;
        padding: 0.48rem 0.72rem;
        border-radius: 8px;
        background: rgba(15, 23, 42, 0.78);
        border: 1px solid rgba(71, 85, 105, 0.38);
        font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
        font-size: 0.73rem;
        line-height: 1.48;
        letter-spacing: 0.015em;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.035);
        white-space: pre-wrap;
        word-break: break-word;
    }
    .memhunter-cmdline-wrap .memhunter-cmd-exe {
        color: rgba(147, 197, 253, 0.88);
        font-weight: 500;
    }
    .memhunter-cmdline-wrap .memhunter-cmd-flag {
        color: rgba(165, 180, 252, 0.76);
    }
    .memhunter-cmdline-wrap .memhunter-cmd-path {
        color: rgba(110, 231, 183, 0.7);
    }
    .memhunter-cmdline-wrap .memhunter-cmd-profile {
        color: rgba(251, 191, 36, 0.72);
    }
    .memhunter-cmdline-wrap .memhunter-cmd-value {
        color: rgba(196, 181, 253, 0.76);
    }
    .memhunter-cmdline-wrap .memhunter-cmd-plugin {
        color: rgba(232, 189, 246, 0.74);
        font-weight: 500;
    }
    .memhunter-cmdline-wrap .memhunter-cmd-gap {
        white-space: pre;
    }
    .memhunter-out-linecount,
    .memhunter-out-filtered {
        font-size: 0.9rem;
        color: rgba(226, 232, 240, 0.92);
    }
    .memhunter-out-filtered {
        color: rgba(110, 231, 183, 0.88);
    }
    /* Tiny copy / download icons (Volatility + Hunt): faint until hover; overrides Hunt purple chrome */
    [data-testid="stSidebar"] .memhunter-micro-actions-marker + div button[kind="tertiary"] {
        background: transparent !important;
        background-color: transparent !important;
        background-image: none !important;
        color: rgba(148, 163, 184, 0.85) !important;
        border: none !important;
        box-shadow: none !important;
        font-weight: 400 !important;
        min-height: 1.35rem !important;
        max-height: 2rem !important;
        padding: 0.04rem 0.18rem !important;
        opacity: 0.35 !important;
    }
    [data-testid="stSidebar"] .memhunter-micro-actions-marker + div button[kind="tertiary"] p {
        font-size: 1rem !important;
        margin: 0 !important;
    }
    [data-testid="stSidebar"] .memhunter-micro-actions-marker + div button[kind="tertiary"]:hover {
        filter: none !important;
        opacity: 0.92 !important;
        color: rgba(226, 232, 240, 0.95) !important;
    }
    /* Main tabs: separator before first sidebar-results tab (5th: after pslist/psscan/pstree/psxview) */
    section.main [data-testid="stTabs"] [role="tablist"] button:nth-child(5) {
        margin-left: 0.75rem !important;
        padding-left: 0.75rem !important;
        border-left: 1px solid rgba(148, 163, 184, 0.48) !important;
        border-radius: 0 !important;
    }
    /* Hunt — sidebar only: styling handled by JS class mh-btn-hunt-cta (avoid :has dependency) */
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button[kind="primary"],
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button[kind="secondary"],
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button[kind="tertiary"] {
        background: transparent !important;
        background-color: transparent !important;
        background-image: none !important;
        border: none !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button:not(:disabled) {
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button:not(:disabled):hover {
        filter: none !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] div[data-testid="column"]:has(.memhunter-hunt-sidebar-slot) button:disabled {
        opacity: 0.42 !important;
        filter: grayscale(0.35) !important;
        box-shadow: none !important;
    }
    .memhunter-hunt-sheet {
        background: rgba(15, 23, 42, 0.78);
        border: 1px solid rgba(148, 163, 184, 0.38);
        border-radius: 14px;
        padding: 1.15rem 1.35rem 1.25rem 1.35rem;
        margin: 0.35rem 0 0.75rem 0;
    }
    .memhunter-hunt-sectionlabel {
        margin: 0 0 0.65rem 0;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #bae6fd;
        text-shadow: 0 0 18px rgba(56, 189, 248, 0.45);
    }
    .memhunter-hunt-hero {
        margin-bottom: 1.1rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.28);
    }
    .memhunter-hunt-title {
        font-size: 1.85rem;
        font-weight: 700;
        line-height: 1.2;
        color: #f8fafc;
        letter-spacing: -0.02em;
    }
    .memhunter-hunt-pid {
        margin-top: 0.35rem;
        font-size: 1.2rem;
        font-weight: 600;
        color: rgba(186, 230, 253, 0.92);
    }
    .memhunter-hunt-pid-num {
        color: #7dd3fc;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
    }
    .memhunter-hunt-kvgrid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.85rem 1.5rem;
    }
    .memhunter-hunt-kv {
        display: flex;
        flex-direction: column;
        gap: 0.28rem;
    }
    .memhunter-hunt-kv-wide {
        grid-column: 1 / -1;
    }
    .memhunter-hunt-lbl {
        font-size: 0.82rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #e0f2fe;
        text-shadow:
            0 0 14px rgba(125, 211, 252, 0.55),
            0 0 28px rgba(56, 189, 248, 0.25);
    }
    .memhunter-hunt-val {
        font-size: 1.08rem;
        font-weight: 500;
        line-height: 1.45;
        color: #e2e8f0;
    }
    .memhunter-hunt-highlight-parent {
        margin-top: 0.28rem;
        padding: 0.5rem 0.7rem;
        background: rgba(250, 204, 21, 0.14);
        border-left: 3px solid rgba(250, 204, 21, 0.72);
        border-radius: 10px;
        font-size: 1.08rem;
        font-weight: 500;
        line-height: 1.45;
        color: #f8fafc;
    }
    .memhunter-hunt-highlight-child {
        margin-top: 0.28rem;
        padding: 0.5rem 0.7rem;
        background: rgba(74, 222, 128, 0.12);
        border-left: 3px solid rgba(74, 222, 128, 0.68);
        border-radius: 10px;
        font-size: 1.08rem;
        font-weight: 500;
        line-height: 1.45;
        color: #f8fafc;
    }
    .memhunter-hunt-kv-cmd {
        margin-top: 0.35rem;
    }
    .memhunter-hunt-cmdline {
        margin-top: 0.35rem;
        padding: 0.75rem 0.95rem;
        background: var(--mh-panel2);
        border: 1px solid rgba(167,139,250,0.18);
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.98rem;
        line-height: 1.5;
        color: var(--mh-fg);
        word-break: break-word;
    }
    .memhunter-hunt-rcnote {
        margin: 0.75rem 0 0 0;
        font-size: 0.85rem;
        color: rgba(251, 191, 36, 0.95);
    }
    .memhunter-hunt-acc-strip {
        letter-spacing: 0.1em;
        opacity: 0.92;
    }
    .memhunter-hunt-out-argv {
        margin: 0 0 0.45rem 0 !important;
        font-size: 0.68rem !important;
        line-height: 1.34 !important;
        opacity: 0.97;
    }
    .memhunter-hunt-yara-cmdline {
        margin: 0.15rem 0 0.65rem 0;
        padding: 0.35rem 0.5rem;
        font-size: 0.76rem;
        line-height: 1.4;
        font-family: ui-monospace, Consolas, monospace;
        color: rgba(148, 163, 184, 0.95);
        background: rgba(15, 23, 42, 0.55);
        border: 1px solid rgba(51, 65, 85, 0.45);
        border-radius: 8px;
        word-break: break-all;
    }
    .memhunter-hunt-vol-cmd-wrap {
        margin: 0.05rem 0 0.2rem 0;
        padding: 0.2rem 0.32rem;
        font-size: 0.62rem;
        line-height: 1.32;
        font-family: ui-monospace, Consolas, monospace;
        background: rgba(2, 6, 23, 0.78);
        border: 1px solid rgba(51, 65, 85, 0.55);
        border-radius: 6px;
        word-break: break-all;
    }
    .memhunter-hunt-vol-cmd-wrap .hunt-cmd-exe {
        color: #7dd3fc;
    }
    .memhunter-hunt-vol-cmd-wrap .hunt-cmd-flag {
        color: #e2e8f0;
    }
    .memhunter-hunt-vol-cmd-wrap .hunt-cmd-path {
        color: #86efac;
    }
    .memhunter-hunt-vol-cmd-wrap .hunt-cmd-plugin {
        color: #fb7185;
    }
    .memhunter-hunt-vol-cmd-wrap .hunt-cmd-txt {
        color: #cbd5e1;
    }
    p.memhunter-hunt-dump-heading {
        margin: 0.1rem 0 0.2rem 0 !important;
    }
    .memhunter-hunt-dump-cmd-wrap.memhunter-hunt-vol-cmd-wrap {
        margin: 0 0 0.12rem 0 !important;
        padding: 0.14rem 0.28rem !important;
        font-size: 0.58rem !important;
        line-height: 1.28 !important;
    }
    p.memhunter-hunt-dump-ref-label {
        margin: 0.25rem 0 0.05rem 0 !important;
        font-size: 0.62rem !important;
        font-weight: 650;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: rgba(125, 211, 252, 0.78);
    }
    p.memhunter-hunt-dump-status {
        margin: 0.12rem 0 0.05rem 0 !important;
        font-size: 0.68rem !important;
        line-height: 1.35;
    }
    p.memhunter-hunt-dump-status--ok {
        color: rgba(134, 239, 172, 0.92);
    }
    p.memhunter-hunt-dump-status--err {
        color: rgba(252, 165, 165, 0.95);
    }
    p.memhunter-hunt-dump-status code {
        font-size: 0.62rem !important;
        word-break: break-all;
    }
    .memhunter-yara-output-label {
        display: inline-block;
        margin-top: 0.12rem;
        font-size: 0.72rem;
        font-weight: 550;
        letter-spacing: 0.03em;
        color: rgba(203, 213, 225, 0.88);
    }
    /* Hunt plugin output (expander) — small, transparent toolbar; hover only */
    div[data-testid="stHorizontalBlock"]:has(.memhunter-hunt-toolbar-slot) {
        align-items: center;
        gap: 0.1rem;
        margin-bottom: 0.04rem;
    }
    div[data-testid="stHorizontalBlock"]:has(.memhunter-hunt-toolbar-slot) button {
        min-width: 1.05rem;
        padding: 0.05rem 0.12rem;
        border-radius: 6px;
        font-size: 0.7rem;
        line-height: 1;
        background: transparent;
        border: 1px solid transparent;
        color: rgba(148, 163, 184, 0.88);
        box-shadow: none;
    }
    div[data-testid="stHorizontalBlock"]:has(.memhunter-hunt-toolbar-slot) button:hover {
        background: rgba(51, 65, 85, 0.5);
        border-color: rgba(100, 116, 139, 0.35);
        color: #e2e8f0;
    }
    hr.memhunter-hunt-sep {
        border: none;
        border-top: 1px solid rgba(51, 65, 85, 0.42);
        margin: 0.28rem 0 0.32rem 0;
    }
    p.memhunter-hunt-plugin-h {
        margin: 0 0 0.12rem 0;
        line-height: 1.3;
        letter-spacing: 0.02em;
        font-size: 1.02rem;
        font-weight: 700;
    }
    p.memhunter-hunt-plugin-h .memhunter-hunt-plugin-h-name {
        color: #f0f9ff;
        text-shadow:
            0 0 14px rgba(125, 211, 252, 0.55),
            0 0 26px rgba(56, 189, 248, 0.28);
    }
    p.memhunter-hunt-plugin-h .memhunter-hunt-plugin-h-pid {
        font-weight: 700;
        font-variant-numeric: tabular-nums;
        color: #7dd3fc;
        text-shadow:
            0 0 12px rgba(125, 211, 252, 0.65),
            0 0 22px rgba(56, 189, 248, 0.32);
    }
    /* Hunt plugin Run + tertiary controls: single line, low height (inside Hunt tab only) */
    section.main div[data-testid="stVerticalBlock"]:has(p.memhunter-hunt-plugin-h) div[data-testid="stButton"] button {
        white-space: nowrap !important;
        width: auto !important;
        min-height: 1.6rem !important;
        max-height: 1.95rem !important;
        padding: 0.12rem 0.55rem !important;
        font-size: 0.75rem !important;
        line-height: 1.2 !important;
        border-radius: 6px !important;
    }
    /* Expander: minimal footprint when closed; compact body when open (main column only) */
    section.main div[data-testid="stExpander"] details > summary {
        padding-top: 0.18rem !important;
        padding-bottom: 0.18rem !important;
        font-size: 0.78rem !important;
        min-height: 0 !important;
    }
    section.main div[data-testid="stExpander"] div[data-testid="stExpanderContent"] {
        padding: 0.22rem 0.3rem 0.4rem 0.3rem !important;
    }
    div[data-testid="stVerticalBlock"] > div:has(div[data-testid="stDataFrame"]) {
        border: 1px solid rgba(148, 163, 184, 0.35);
        border-radius: 10px;
        padding: 0.6rem 0.6rem 1.1rem 0.6rem;
    }
    .analysis-brand-row {
        display: flex;
        align-items: center;
        gap: 1.1rem;
        margin: 0.65rem 0 0.55rem 0;
        padding-top: 0.35rem;
        padding-bottom: 0.1rem;
        overflow: visible;
    }
    /* Logo: no “card” frame — the PNG already has its own art; extra border/shadow read as a pasted box */
    .analysis-brand-logo {
        width: 84px;
        height: 84px;
        object-fit: contain;
        flex-shrink: 0;
        display: block;
        border: none;
        outline: none;
        box-shadow: none;
        border-radius: 0;
        background: transparent;
        opacity: 0.97;
    }
    .analysis-brand-text {
        display: flex;
        flex-direction: column;
        justify-content: center;
        min-height: 84px;
        padding: 0.1rem 0 0 0;
    }
    .analysis-brand-text h1 {
        font-size: 2.15rem;
        font-weight: 700;
        letter-spacing: -0.03em;
        margin: 0 0 0.02rem 0;
        line-height: 1.15;
        padding-top: 0.04em;
        color: #f1f5f9;
        opacity: 0.92;
        overflow: visible;
    }
    .analysis-brand-text .analysis-by {
        font-size: 1.28rem;
        font-weight: 550;
        color: #a8b7d0;
        margin: 0;
        margin-top: -0.04rem;
        letter-spacing: 0.04em;
        opacity: 0.78;
        line-height: 1.2;
    }
    /* Fallback when logo file is missing */
    .analysis-brand-block {
        margin: 0.55rem 0 0.5rem 0;
        padding-top: 0.25rem;
        overflow: visible;
    }
    .analysis-brand-block h1 {
        font-size: 2.15rem;
        font-weight: 700;
        letter-spacing: -0.03em;
        margin: 0.35rem 0 0.02rem 0;
        line-height: 1.15;
        padding-top: 0.18em;
        color: #f1f5f9;
        opacity: 0.92;
        overflow: visible;
    }
    .analysis-brand-block .analysis-by {
        font-size: 1.28rem;
        font-weight: 550;
        color: #a8b7d0;
        margin: 0;
        margin-top: -0.04rem;
        letter-spacing: 0.04em;
        opacity: 0.78;
        line-height: 1.2;
    }
    [data-testid="stVerticalBlock"] [data-testid="stCaptionContainer"] p,
    [data-testid="stVerticalBlock"] [data-testid="stCaptionContainer"] {
        opacity: 0.68 !important;
    }
    .maor-mini-cli-wrap {
        max-width: none;
        width: 100%;
        margin: 0.55rem 0 0 0;
    }
    .maor-mini-cli-fog {
        position: relative;
        border: 1px solid rgba(148, 163, 184, 0.14);
        background: var(--mh-panel2);
        backdrop-filter: blur(10px);
        overflow: hidden;
        height: 128px;
        box-shadow: 0 8px 36px rgba(0, 0, 0, 0.35);
        opacity: 0.9;
    }
    .maor-mini-cli-fog::after {
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        height: 88%;
        pointer-events: none;
        background: linear-gradient(
            to bottom,
            rgba(0,0,0,0) 0%,
            rgba(0,0,0,0.10) 12%,
            rgba(0,0,0,0.28) 28%,
            rgba(0,0,0,0.55) 48%,
            rgba(0,0,0,0.78) 72%,
            rgba(0,0,0,0.92) 100%
        );
    }
    .maor-mini-cli {
        margin: 0;
        padding: 10px 14px 48px 14px;
        font-size: 11px;
        line-height: 1.38;
        color: #cbd5e1;
        font-family: ui-monospace, Consolas, monospace;
        white-space: pre-wrap;
        word-break: break-word;
        overflow: hidden;
        max-height: 128px;
        opacity: 0.92;
        -webkit-mask-image: linear-gradient(
            to bottom,
            rgba(0,0,0,1) 0%,
            rgba(0,0,0,0.92) 18%,
            rgba(0,0,0,0.35) 62%,
            rgba(0,0,0,0) 100%
        );
        mask-image: linear-gradient(
            to bottom,
            rgba(0,0,0,1) 0%,
            rgba(0,0,0,0.92) 18%,
            rgba(0,0,0,0.35) 62%,
            rgba(0,0,0,0) 100%
        );
    }
    button[kind="tertiary"] {
        border-radius: 9999px !important;
        border: 1px solid rgba(148, 163, 184, 0.32) !important;
        background: rgba(30, 41, 59, 0.4) !important;
        color: #f1f5f9 !important;
        font-weight: 500 !important;
        letter-spacing: 0.04em !important;
        font-size: 0.9rem !important;
        padding: 0.55rem 1.4rem !important;
        text-transform: none !important;
        transition: border-color 0.2s ease, background 0.2s ease, box-shadow 0.2s ease !important;
    }
    button[kind="tertiary"]:hover {
        border-color: rgba(56, 189, 248, 0.5) !important;
        background: rgba(30, 41, 59, 0.72) !important;
        box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.12), 0 10px 28px rgba(0, 0, 0, 0.25) !important;
    }
    button[kind="secondary"] {
        background: rgba(14, 165, 233, 0.11) !important;
        border: 1px solid rgba(56, 189, 248, 0.42) !important;
        color: #bae6fd !important;
        font-weight: 500 !important;
        border-radius: 12px !important;
        letter-spacing: 0.02em !important;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06) !important;
    }
    button[kind="secondary"]:hover {
        background: rgba(14, 165, 233, 0.2) !important;
        border-color: rgba(56, 189, 248, 0.58) !important;
        color: #e0f2fe !important;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.18) !important;
    }
    /* Sidebar: Vol3 dumpfiles — purple geometric border (JS class mh-btn-dump-files) */
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-btn-dump-files button {
        border-color: rgba(167, 139, 250, 0.82) !important;
        box-shadow: 0 0 0 1px rgba(167, 139, 250, 0.12), 0 6px 22px rgba(0, 0, 0, 0.22) !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-btn-dump-files button:hover {
        border-color: rgba(196, 181, 253, 0.9) !important;
        box-shadow: 0 0 0 1px rgba(196, 181, 253, 0.2), 0 8px 26px rgba(0, 0, 0, 0.28) !important;
    }
    /* Sidebar: radios — grayscale labels, violet accent (addressing + engine) */
    [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stWidgetLabel"] p {
        color: rgba(148, 163, 184, 0.92) !important;
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.04em !important;
        text-transform: uppercase !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {
        gap: 0.5rem !important;
        flex-wrap: wrap !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label {
        color: rgba(226, 232, 240, 0.9) !important;
        border: 1px solid rgba(167, 139, 250, 0.32) !important;
        border-radius: 10px !important;
        padding: 0.28rem 0.55rem !important;
        background: rgba(15, 23, 42, 0.5) !important;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04) !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover {
        border-color: rgba(196, 181, 253, 0.55) !important;
        background: rgba(30, 27, 46, 0.55) !important;
    }
    /* Dynamic tab close: rectangular 3D “CLOSE” block (marker .mh-tab-close-slot + JS .mh-tab-close-x) */
    .mh-tab-close-slot {
        display: none !important;
    }
    section.main div[data-testid="column"]:has(span.mh-tab-close-slot) div[data-testid="stButton"],
    section.main div[data-testid="column"]:has(span.mh-tab-close-slot) div[data-testid="stButton"] > div,
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"],
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        > div,
    section.main div[data-testid="stButton"].mh-tab-close-x,
    section.main div[data-testid="stButton"].mh-tab-close-x > div,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x > div {
        background: transparent !important;
        background-color: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
        width: 100% !important;
        max-width: 100% !important;
        margin-left: auto !important;
    }
    section.main
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"],
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"],
    section.main div[data-testid="stButton"].mh-tab-close-x button,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x button {
        box-sizing: border-box !important;
        width: 100% !important;
        min-width: 120px !important;
        height: auto !important;
        min-height: 2.4rem !important;
        padding: 0.5rem 0.85rem !important;
        margin: 0 !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        border-radius: 0 !important;
        border: 1px solid rgba(167, 139, 250, 0.55) !important;
        background: rgba(46, 16, 101, 0.94) !important;
        background-color: rgba(46, 16, 101, 0.94) !important;
        color: #34d399 !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace !important;
        font-size: 0.88rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.1em !important;
        text-transform: none !important;
        line-height: 1.2 !important;
        box-shadow: 4px 4px 0 #000000 !important;
        outline: none !important;
    }
    section.main
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"]:hover,
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"]:hover,
    section.main div[data-testid="stButton"].mh-tab-close-x button:hover,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x button:hover {
        background: rgba(76, 29, 149, 0.96) !important;
        background-color: rgba(76, 29, 149, 0.96) !important;
        color: #6ee7b7 !important;
        border-color: rgba(196, 181, 253, 0.75) !important;
        box-shadow: 4px 4px 0 #000000 !important;
    }
    section.main
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"]:active,
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button[kind="primary"]:active,
    section.main div[data-testid="stButton"].mh-tab-close-x button:active,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x button:active {
        transform: translate(2px, 2px) !important;
        box-shadow: 2px 2px 0 #000000 !important;
        color: #a7f3d0 !important;
    }
    section.main
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button
        p,
    [data-testid="stAppViewContainer"]
        :is(.main, .stMain)
        div[data-testid="column"]:has(span.mh-tab-close-slot)
        div[data-testid="stButton"]
        button
        p,
    section.main div[data-testid="stButton"].mh-tab-close-x button p,
    [data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"].mh-tab-close-x button p {
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1 !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        color: inherit !important;
    }
    /* Sidebar: “Browse” — text link, square (no pill / ellipse) */
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-mem-browse-lite,
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-mem-browse-lite > div {
        width: fit-content !important;
        max-width: 100% !important;
        border-radius: 0 !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-mem-browse-lite button {
        background: transparent !important;
        background-color: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0.12rem 0.1rem !important;
        min-height: 0 !important;
        height: auto !important;
        width: auto !important;
        border-radius: 2px !important;
        color: rgba(125, 211, 252, 0.85) !important;
        font-size: 0.74rem !important;
        font-weight: 400 !important;
        text-decoration: underline !important;
        text-underline-offset: 0.15em;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-mem-browse-lite button:hover {
        color: rgba(224, 242, 254, 0.95) !important;
        border: none !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"].mh-mem-browse-lite button p {
        font-size: 0.74rem !important;
        margin: 0 !important;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Visual-only: tag Streamlit button containers for stable coloring (Hunt dashboard + sidebar Hunt CTA)
components.html(
    """
<!doctype html><html><head><meta charset="utf-8"/></head><body>
<script>
(function(){
  function txt(el){ try { return (el.innerText||el.textContent||"").trim().toLowerCase(); } catch(e){ return ""; } }
  function tag(){
    // Main column (tabs + hunt): tag “CLOSE” tab control for .mh-tab-close-x (backup if :has(slot) CSS misses an edge case)
    var wraps = document.querySelectorAll(
      '[data-testid="stAppViewContainer"] :is(.main, .stMain) div[data-testid="stButton"], ' +
      'section.main div[data-testid="stButton"]'
    );
    for (var i=0;i<wraps.length;i++){
      var w = wraps[i];
      var b = w.querySelector('button');
      if(!b) continue;
      var t = txt(b);
      if(!t) continue;
      var cls = null;
      if (t === "netscan") cls = "mh-btn-net";
      else if (t === "dlllist") cls = "mh-btn-dll";
      else if (t === "malfind") cls = "mh-btn-mal";
      else if (t === "yarascan") cls = "mh-btn-yara";
      else if (t === "run strings search") cls = "mh-btn-strings";
      else if (t === "handles" || t === "threads" || t === "ldrmodules") cls = "mh-btn-res";
      else if (t === "privileges" || t === "envars" || t === "getsids") cls = "mh-btn-ids";
      else if (t.indexOf("exe dump") >= 0) cls = "mh-btn-dump-exe";
      else if (t.indexOf("dll dump") >= 0) cls = "mh-btn-dump-dll";
      else if (t.indexOf("memory dump") >= 0) cls = "mh-btn-dump-mem";
      else if (t.indexOf("vad dump") >= 0) cls = "mh-btn-dump-vad";
      else if (t === "close") cls = "mh-tab-close-x";
      if (cls) w.classList.add(cls);
    }
    // Sidebar hunt CTA (button label starts with Hunt)
    var sb = document.querySelector('[data-testid="stSidebar"]');
    if(sb){
      var sbw = sb.querySelectorAll('div[data-testid="stButton"]');
      for (var j=0;j<sbw.length;j++){
        var w2 = sbw[j];
        var b2 = w2.querySelector('button');
        if(!b2) continue;
        var t2 = txt(b2);
        if (t2 === "hunt" || t2.indexOf("hunt (pid") === 0) w2.classList.add("mh-btn-hunt-cta");
        else if (t2 === "dumpfiles") w2.classList.add("mh-btn-dump-files");
        else if (t2 === "browse") w2.classList.add("mh-mem-browse-lite");
      }
    }
  }
  tag();
  setInterval(tag, 600);
})();
</script>
</body></html>
""",
    height=0,
)


def _mh_process_pending_blocking_job() -> None:
    """Run one deferred blocking job (after a fast `st.rerun` so the float status can paint)."""
    job = st.session_state.get(MH_PENDING_JOB_KEY)
    if not isinstance(job, dict) or not job.get("kind"):
        return
    st.session_state.pop(MH_PENDING_JOB_KEY, None)
    try:
        kind = job["kind"]
        if kind == "strings":
            rc, out, cmdline = run_strings_scan(
                memory_image_path=str(job["mem"]),
                search_term=str(job["q"]),
                min_length=int(job["min_len"]),
            )
            new_tab = push_strings_scan_results_tab(
                engine_label=str(job["engine_label"]),
                search_term=str(job["q"]),
                min_length=int(job["min_len"]),
                rc=rc,
                output_text=out,
                cmdline=cmdline,
            )
            if hasattr(st, "toast"):
                st.toast(f"Added results tab: {new_tab}", icon="📋")

        elif kind == "vol2_sidebar":
            extra = job.get("extra") if isinstance(job.get("extra"), dict) else {}
            rc, txt, argv = run_vol2_sidebar_plugin(
                str(job["mem"]),
                str(job["prof"]) if job.get("prof") else None,
                str(job["plugin"]),
                str(job["mode"]),
                pid=None,
                append_pid_when_optional=False,
                extra_args=extra if extra else None,
            )
            pl = str(job["plugin"])
            if pl == "imageinfo" and rc == 0 and txt:
                parsed = _parse_suggested_profile(txt)
                if parsed:
                    st.session_state["vol2_profile"] = parsed
            new_tab = _vol2_push_output_history(
                plugin=pl,
                category_label=str(job["category_label"]),
                mode=str(job["mode"]),
                rc=rc,
                text=txt,
                argv=argv,
                pid=None,
                append_pid=False,
                extra=extra,
            )
            if hasattr(st, "toast"):
                st.toast(f"Added results tab: {new_tab}", icon="📋")

        elif kind == "vol3_sidebar":
            extra = job.get("extra") if isinstance(job.get("extra"), dict) else {}
            rc, txt, argv = run_vol3_sidebar_plugin(
                str(job["mem"]),
                str(job["mode"]),
                str(job["plugin_id"]),
                pid=None,
                append_pid_when_optional=False,
                extra_args=extra if extra else None,
            )
            new_tab = _vol3_push_output_history(
                display_label=str(job["display_label"]),
                plugin_id=str(job["plugin_id"]),
                category_label=str(job["category_label"]),
                mode=str(job["mode"]),
                rc=rc,
                text=txt,
                argv=argv,
                pid=None,
                append_pid=False,
                extra=extra,
            )
            if hasattr(st, "toast"):
                st.toast(f"Added results tab: {new_tab}", icon="📋")

        elif kind == "hunt_yara":
            _slug = str(job["slug"])
            tab_label = str(job["tab_label"])
            pid_i = int(job["pid"])
            _q = str(job["q"])
            _mp_y = str(job["mp_y"])
            _eng_y = str(job["vol_engine"])
            _vprof = str(job.get("vol2_profile") or "").strip() or None
            _yrc, _yout, _yargv = run_hunt_yarascan_plugin(
                _eng_y,
                _mp_y,
                pid_i,
                _q,
                vol2_profile=_vprof,
            )
            _hunt_merge_entry(
                tab_label,
                yara_query=_q,
                yara_output=_tail_history_text(_yout or ""),
                yara_rc=_yrc,
                yara_argv=_yargv,
            )
            _fn_snip = re.sub(r"[^\w\-.]+", "_", _q).strip("_")[:28] or "query"
            _q_show = _q if len(_q) <= 72 else _q[:69] + "…"
            _hunt_append_output_block(
                _slug,
                "yarascan",
                f"Yarascan · PID {pid_i} · exit {_yrc} · {_q_show}",
                _yout or "",
                f"yarascan_pid{pid_i}_{_fn_snip}.txt",
                _yargv,
            )

        elif kind == "hunt_dump":
            _slug = str(job["slug"])
            tab_label = str(job["tab_label"])
            pid_i = int(job["pid"])
            _dk = str(job["dump_kind"])
            _short = str(job["dump_short"])
            _mp_d = str(job["mp_d"])
            _eng_d = str(job["vol_engine"])
            _vprof = str(job.get("vol2_profile") or "").strip() or None
            _drc, _dtxt, _dargv, _ddir = run_hunt_process_dump(
                _eng_d,
                _mp_d,
                pid_i,
                _dk,
                vol2_profile=_vprof,
            )
            _hunt_merge_entry(
                tab_label,
                **{
                    f"hunt_dump_{_dk}_rc": _drc,
                    f"hunt_dump_{_dk}_text": _tail_history_text(_dtxt or ""),
                    f"hunt_dump_{_dk}_argv": _dargv,
                    f"hunt_dump_{_dk}_dir": _ddir,
                },
            )
            _body = (
                f"Exit code: {_drc}\n"
                f"Output directory: {_ddir or '(none)'}\n\n"
            )
            _body += (_dtxt or "").strip()
            _hunt_append_output_block(
                _slug,
                f"dump_{_dk}",
                f"{_short} · PID {pid_i} · exit {_drc}",
                _body,
                f"dump_{_dk}_pid{pid_i}.txt",
                _dargv,
            )
    except Exception:
        st.session_state.pop(MH_FLOAT_STATUS_KEY, None)
        raise
    st.session_state.pop(MH_FLOAT_STATUS_KEY, None)
    st.rerun()


def reset_analysis_data():
    st.session_state.analysis_ready = False
    st.session_state.plugin_frames = {}
    st.session_state[VOL_PENDING_KEY] = False
    st.session_state.pop(MH_PENDING_JOB_KEY, None)
    st.session_state.pop(MH_FLOAT_STATUS_KEY, None)
    st.session_state.pop(_MEMHUNT_FOCUS_SEL_KEY, None)
    st.session_state.pop(_MEMHUNT_SEL_POS_PREV, None)
    st.session_state.pop(PSTREE_TABLE_KEY, None)
    st.session_state.pop(ANALYZED_MEM_NORM_KEY, None)
    st.session_state.pop(VOL2_OUTPUT_HISTORY_KEY, None)
    st.session_state.pop(VOL3_OUTPUT_HISTORY_KEY, None)
    st.session_state.pop(HUNT_TABS_SESSION_KEY, None)
    st.session_state.pop(MAIN_TAB_DYNAMIC_ORDER_KEY, None)
    st.session_state.pop(CANONICAL_MEMORY_IMAGE_KEY, None)
    for _k in list(st.session_state.keys()):
        if isinstance(_k, str) and (
            _k.startswith("hunt_active_out_") or _k.startswith("hunt_output_log_")
        ):
            st.session_state.pop(_k, None)


# --- Session defaults ---
if "analysis_ready" not in st.session_state:
    st.session_state.analysis_ready = False
if "plugin_frames" not in st.session_state:
    st.session_state.plugin_frames = {}
if VOL_PENDING_KEY not in st.session_state:
    st.session_state[VOL_PENDING_KEY] = False
if "vol_engine" not in st.session_state:
    st.session_state.vol_engine = ENGINE_V3_LABEL
if "_cli_memory_image_seeded" not in st.session_state:
    st.session_state._cli_memory_image_seeded = False
if MEMORY_IMAGE_PATH_KEY not in st.session_state:
    _legacy_path = None
    if "memory_image_path" in st.session_state:
        _legacy_path = st.session_state.pop("memory_image_path")
    _cli0 = _memory_path_from_cli_argv()
    if _cli0 and not st.session_state.get("analysis_ready"):
        _s0 = _strip_surrounding_quotes_path(_cli0)
        st.session_state[MEMORY_IMAGE_PATH_KEY] = (
            _normalize_memory_path(_s0) or _s0.strip()
        )
        st.session_state._cli_memory_image_seeded = True
    elif isinstance(_legacy_path, str) and _legacy_path.strip():
        _ls = _strip_surrounding_quotes_path(_legacy_path)
        st.session_state[MEMORY_IMAGE_PATH_KEY] = (
            _normalize_memory_path(_ls) or _ls.strip()
        )
    else:
        st.session_state[MEMORY_IMAGE_PATH_KEY] = ""
_cli_mem = _memory_path_from_cli_argv()
if (
    _cli_mem
    and not st.session_state._cli_memory_image_seeded
    and not st.session_state.get("analysis_ready")
):
    _seed = _strip_surrounding_quotes_path(_cli_mem)
    st.session_state[MEMORY_IMAGE_PATH_KEY] = (
        _normalize_memory_path(_seed) or _seed.strip()
    )
    st.session_state._cli_memory_image_seeded = True

# If the field was cleared or session was migrated from an older widget key, refill from launcher.
if not st.session_state.get("analysis_ready"):
    _cur_mem = st.session_state.get(MEMORY_IMAGE_PATH_KEY)
    if not (isinstance(_cur_mem, str) and _cur_mem.strip()):
        _again = _memory_path_from_cli_argv()
        if _again:
            _s2 = _strip_surrounding_quotes_path(_again)
            st.session_state[MEMORY_IMAGE_PATH_KEY] = (
                _normalize_memory_path(_s2) or _s2.strip()
            )
            st.session_state._cli_memory_image_seeded = True

_render_memhunter_floating_status()
_mh_process_pending_blocking_job()

# While analysis is active, the engine radio is not mounted. Some Streamlit versions can
# leave `vol_engine` stale or revert it toward the first radio option on rerun, which
# then differs from `_vol_engine_lock` and triggers a false "engine switch" → full reset
# → back to Start Analysis on every dataframe/plugin click.
if st.session_state.get("analysis_ready"):
    if "_vol_engine_lock" not in st.session_state:
        st.session_state._vol_engine_lock = st.session_state.vol_engine
    st.session_state.vol_engine = st.session_state._vol_engine_lock

with st.sidebar:
    _sb_uri = _sidebar_logo_data_uri()
    if _sb_uri:
        st.markdown(
            '<div class="mh-sb-brand">'
            f'<img src="{_sb_uri}" alt="MemHunter logo" />'
            f'<div class="mh-sb-brand-title">MemHunter<span class="mh-sb-brand-ver">[{APP_VERSION}]</span></div>'
            "</div>"
            '<div class="mh-sb-divider"></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="mh-sb-brand"><div class="mh-sb-brand-title">MemHunter<span class="mh-sb-brand-ver">[{APP_VERSION}]</span></div></div>'
            '<div class="mh-sb-divider"></div>',
            unsafe_allow_html=True,
        )

    _missing_bins = missing_required_binaries()
    if _missing_bins:
        st.warning("Warning: Binaries not found in /bin/ folder.")
        with st.expander("Missing binary paths"):
            st.code("\n".join(_missing_bins))

    if not st.session_state.get("analysis_ready"):
        _pend = st.session_state.pop(MEMORY_IMAGE_PATH_PICK_PENDING_KEY, None)
        if isinstance(_pend, str) and _pend.strip():
            st.session_state[MEMORY_IMAGE_PATH_KEY] = _normalize_memory_path(
                _strip_surrounding_quotes_path(_pend)
            ) or _pend.strip()
        st.text_input(
            "Memory image",
            key=MEMORY_IMAGE_PATH_KEY,
            help="Path to the memory dump file. **MemHunter.exe** passes it at launch (`--file` / "
            "`MEMHUNTER_IMAGE`); you can edit it here. On **Start Analysis**, Volatility uses this path as **`-f`**.",
        )
        if st.session_state.get("_cli_memory_image_seeded"):
            st.caption("Path was set at launch (MemHunter.exe). Edit above if you need a different image.")
        if st.button(
            "Browse",
            key="memhunter_mem_browse",
            type="tertiary",
            help="Native file picker (tkinter).",
        ):
            _picked, _dlg_ok = _pick_memory_file_with_dialog()
            if not _dlg_ok:
                st.error(
                    "File picker failed to open. "
                    "If you're running via the portable launcher, try starting without elevated privileges, "
                    "or run `MemHunter.bat` to see any startup errors."
                )
            if _picked:
                # Can't assign to a widget-backed key after instantiation in the same run.
                # Stash the result and apply it at the top of the next run (before `st.text_input`).
                st.session_state[MEMORY_IMAGE_PATH_PICK_PENDING_KEY] = _picked
                st.rerun()
    else:
        _mem_locked = current_memory_image_path()
        if _mem_locked:
            st.caption(f"**Memory image:** `{_mem_locked}`")
        else:
            st.caption("**Memory image:** _(not set)_")

    if not st.session_state.get("analysis_ready"):
        st.radio(
            "Engine",
            [ENGINE_V3_LABEL, ENGINE_V2_LABEL],
            key="vol_engine",
        )
    eng = st.session_state.vol_engine
    if eng == ENGINE_V2_LABEL:
        prof = st.session_state.get("vol2_profile")
        # Profile display is not operationally relevant during navigation; keep sidebar minimal.

    if st.session_state.get("analysis_ready"):
        st.markdown(
            '<p class="memhunter-sidebar-heading">Hunt</p>',
            unsafe_allow_html=True,
        )
        st.caption("Chose a process to Hunt")
        _hsc = st.columns([1])
        with _hsc[0]:
            st.markdown(
                '<span class="memhunter-hunt-sidebar-slot"></span>',
                unsafe_allow_html=True,
            )
            _frames_sb = st.session_state.get("plugin_frames") or {}
            _hctx_sb = resolve_hunt_selection_context(
                frames=_frames_sb, engine_label=eng
            )
            _hunt_btn_label = (
                f"Hunt (PID {_hctx_sb[2]})" if _hctx_sb is not None else "Hunt"
            )
            if st.button(
                _hunt_btn_label,
                key="memhunter_hunt_sidebar_cta",
                type="secondary",
                use_container_width=True,
                disabled=_hctx_sb is None,
                help="Dashboard for the selected process (runs cmdline for that PID).",
            ):
                execute_hunt_for_current_selection()

    if st.session_state.get("analysis_ready"):
        if eng == ENGINE_V2_LABEL:
            render_vol2_sidebar_plugin_library()
        elif eng == ENGINE_V3_LABEL:
            render_vol3_sidebar_plugin_library()

# Changing engine must clear loaded results only when something engine-specific is in play.
# On the welcome screen (no analysis yet), switching Vol3 ↔ Vol2 should not run a full reset +
# rerun — that felt like being kicked back before Start Analysis and could interrupt a pending run
# only in edge cases; when idle, just track the new engine.
if "_vol_engine_lock" not in st.session_state:
    st.session_state._vol_engine_lock = st.session_state.vol_engine
elif st.session_state._vol_engine_lock != st.session_state.vol_engine:
    st.session_state._vol_engine_lock = st.session_state.vol_engine
    _engine_switch_needs_reset = (
        st.session_state.get("analysis_ready")
        or st.session_state.get(VOL_PENDING_KEY)
        or bool(st.session_state.get("plugin_frames"))
    )
    if _engine_switch_needs_reset:
        reset_analysis_data()
        st.rerun()

if not st.session_state.analysis_ready:
    _, center, _ = st.columns([0.12, 5.76, 0.12])
    with center:
        analysis_brand()

        if not st.session_state[VOL_PENDING_KEY]:
            st.caption(
                f"**{st.session_state.vol_engine}** — **Start Analysis** runs profiling (Vol2 only), "
                "then loads **pslist**, **psscan**, and **pstree**. Open the **psxview** tab and click **Run psxview** when you need it (slower)."
            )
            _, btn_col, _ = st.columns([1.35, 1.15, 1.35])
            with btn_col:
                start = st.button(
                    "Start Analysis",
                    type="tertiary",
                    use_container_width=True,
                )
            if start:
                mp = current_memory_image_path()
                if not require_memory_image_exists(mp):
                    pass
                else:
                    cur_n = _normalize_memory_path(mp)
                    an_n = st.session_state.get(ANALYZED_MEM_NORM_KEY)
                    if (
                        st.session_state.analysis_ready
                        and an_n is not None
                        and cur_n != an_n
                    ):
                        reset_analysis_data()
                        st.session_state.pop("vol2_profile", None)
                    st.session_state[VOL_PENDING_KEY] = True
                    st.rerun()
        else:
            eng_run = st.session_state.vol_engine
            mem_path_run = current_memory_image_path()
            if not require_memory_image_exists(mem_path_run):
                st.session_state[VOL_PENDING_KEY] = False
                st.rerun()

            st.caption("Running")
            st.markdown(LOADING_ORBIT_HTML, unsafe_allow_html=True)
            term_ph = st.empty()
            log_lines: list[str] = []

            def refresh_term():
                term_ph.markdown(_render_mini_fog_terminal(log_lines), unsafe_allow_html=True)

            profile = None
            if eng_run == ENGINE_V2_LABEL:
                with st.spinner("Volatility 2: running imageinfo for profile…"):
                    profile = sync_vol2_profile_to_session(mem_path_run, str(VOL2_EXE))
                if not profile:
                    st.error("Could not parse a suggested profile from imageinfo. Check the image and Vol2 path.")
                    st.session_state[VOL_PENDING_KEY] = False
                    st.rerun()
                log_lines.append(f"[Vol2] profile = {profile}")
                refresh_term()

            frames: dict[str, pd.DataFrame] = {}
            for tab_key in ("pslist", "psscan", "pstree"):
                pl = plugin_for(eng_run, tab_key)
                log_lines.append(f"\n── {tab_key} ({pl}) ──")
                refresh_term()
                frames[tab_key] = run_vol_live(
                    eng_run, mem_path_run, pl, log_lines, refresh_term, vol2_profile=profile
                )

            refresh_term()
            st.session_state.plugin_frames = frames
            st.session_state[VOL_PENDING_KEY] = False
            st.session_state.analysis_ready = True
            st.session_state[CANONICAL_MEMORY_IMAGE_KEY] = _normalize_memory_path(mem_path_run)
            st.session_state[ANALYZED_MEM_NORM_KEY] = _normalize_memory_path(mem_path_run)
            st.session_state._vol_engine_lock = eng_run
            st.rerun()
else:
    analysis_brand()
    eng = st.session_state.vol_engine
    _an = st.session_state.get(ANALYZED_MEM_NORM_KEY)
    if _an is not None and _normalize_memory_path(current_memory_image_path()) != _an:
        reset_analysis_data()
        st.session_state._vol_engine_lock = st.session_state.vol_engine
        st.rerun()

    st.caption(f"**{eng}** · `{current_memory_image_path()}`")

    _static_tabs = ("pslist", "psscan", "pstree", "psxview")
    if eng == ENGINE_V2_LABEL:
        _hist = list(st.session_state.get(VOL2_OUTPUT_HISTORY_KEY) or [])
    elif eng == ENGINE_V3_LABEL:
        _hist = list(st.session_state.get(VOL3_OUTPUT_HISTORY_KEY) or [])
    else:
        _hist = []

    _hunt_entries: list[dict] = list(st.session_state.get(HUNT_TABS_SESSION_KEY) or [])
    _hunt_labels = [e.get("tab_label") for e in _hunt_entries if e.get("tab_label")]
    _hunt_label_set = frozenset(_hunt_labels)
    _dynamic_tab_labels = _ordered_dynamic_sidebar_tab_labels(_hunt_entries, _hist)
    tab_order = list(_static_tabs) + _dynamic_tab_labels
    tabs = st.tabs(tab_order)
    tab_map = dict(zip(tab_order, tabs))

    for label in tab_order:
        with tab_map[label]:
            if label in _static_tabs:
                pl = plugin_for(eng, label)
                if label == "psxview" and "psxview" not in st.session_state.plugin_frames:
                    st.caption(
                        "**psxview** cross-checks listing sources and takes longer than **pslist** / **psscan**. "
                        "Run it from this tab when you need it."
                    )
                    _bcol, _ = st.columns([1.05, 5])
                    with _bcol:
                        _run_psx = st.button(
                            "Run psxview",
                            key="lazy_run_psxview_main",
                            type="secondary",
                            help="Load psxview for the current image (Vol 2 or Vol 3).",
                        )
                    if _run_psx:
                        _mp = current_memory_image_path()
                        if require_memory_image_exists(_mp):
                            _prof = (
                                st.session_state.get("vol2_profile")
                                if eng == ENGINE_V2_LABEL
                                else None
                            )
                            with st.spinner("Running psxview…"):
                                df_px, _ = run_vol(
                                    eng,
                                    _mp,
                                    pl,
                                    vol2_profile=_prof,
                                    prefer_csv=True,
                                )
                            st.session_state.plugin_frames["psxview"] = df_px
                            st.rerun()
                else:
                    df = st.session_state.plugin_frames.get(label)
                    if df is None or df.empty:
                        st.warning(f"No rows for **{label}** (`{pl}`).")
                    elif label == "pstree":
                        tree = df.reset_index(drop=True)
                        if eng == ENGINE_V2_LABEL:
                            tree = split_vol2_pstree_name_offset(tree)
                        sel = _dataframe_selected_row(PSTREE_TABLE_KEY)
                        styled = style_pstree_dataframe(tree, sel)
                        st.dataframe(
                            styled,
                            use_container_width=True,
                            hide_index=True,
                            height=table_height(len(tree)),
                            on_select="rerun",
                            selection_mode="single-row",
                            key=PSTREE_TABLE_KEY,
                        )
                        st.caption(
                            f"{len(tree):,} rows · `{pl}` · **Cyan** selected · **amber** parent · **green** children"
                        )
                    else:
                        view = df.reset_index(drop=True)
                        if label == "psxview":
                            styled_ps = (
                                view
                                if eng == ENGINE_V3_LABEL
                                else style_psxview_pslist_false(view)
                            )
                            psx_kwargs = dict(
                                use_container_width=True,
                                hide_index=True,
                                height=table_height(len(view)),
                            )
                            if eng in (ENGINE_V2_LABEL, ENGINE_V3_LABEL):
                                st.dataframe(
                                    styled_ps,
                                    on_select="rerun",
                                    selection_mode="single-row",
                                    key=PSXVIEW_SEL_KEY,
                                    **psx_kwargs,
                                )
                            else:
                                st.dataframe(styled_ps, **psx_kwargs)
                            if eng == ENGINE_V3_LABEL:
                                st.caption(
                                    f"{len(view):,} rows · `{pl}` · **Select a row** for **Hunt** (PID-targeted)"
                                )
                            else:
                                st.caption(
                                    f"{len(view):,} rows · `{pl}` · **Red row** = not listed by **pslist** (hiding / DKOM / etc.)"
                                )
                        else:
                            list_kwargs = dict(
                                use_container_width=True,
                                hide_index=True,
                                height=table_height(len(view)),
                            )
                            _sel_key = (
                                PSLIST_SEL_KEY
                                if label == "pslist"
                                else PSSCAN_SEL_KEY
                            )
                            if eng in (ENGINE_V2_LABEL, ENGINE_V3_LABEL):
                                st.dataframe(
                                    view,
                                    on_select="rerun",
                                    selection_mode="single-row",
                                    key=_sel_key,
                                    **list_kwargs,
                                )
                            else:
                                st.dataframe(view, **list_kwargs)
                            st.caption(
                                f"{len(view):,} rows · `{pl}`"
                                + (
                                    " · **Select a row** for **Hunt** (PID-targeted)"
                                    if eng == ENGINE_V3_LABEL
                                    else ""
                                )
                            )

            elif label in _hunt_label_set:
                _he = next(
                    (e for e in _hunt_entries if e.get("tab_label") == label),
                    None,
                )
                if _he is not None:
                    render_hunt_dashboard_tab(_he, tab_label=label)
                else:
                    st.warning("Could not find Hunt tab data.")
            else:
                entry = next(
                    (h for h in _hist if h.get("tab_label") == label),
                    None,
                )
                if entry is not None:
                    render_volatility_sidebar_output_entry(entry)
                else:
                    st.warning("Could not find saved output for this tab.")

