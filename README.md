## MemHunter

MemHunter is a standalone, portable Digital Forensics and Incident Response (DFIR) memory forensics workstation built around **Volatility 3** (with **Volatility 2.6** support), **Pandas**, and a **Streamlit** UI.

It is designed for offline investigations: **no installation**, **no internet**, and **no system-wide Python** are required. The tool ships with its own embedded runtime and binaries.

## Key Features

- **Portable execution**: double-click `MemHunter.exe` to launch the UI.
- **Dual engine support**:
  - **Volatility 3** (primary)
  - **Volatility 2.6** (compatibility / legacy workflows)
- **Structured, analyst-friendly results**: tabular outputs via Pandas, designed for quick pivoting and filtering.
- **Two analysis modes**:
  - **Global Mode** (whole-image analysis)
  - **Hunt Mode** (rapid, single-PID deep-dive driven by previously extracted data)
- **Offline by design**: no telemetry, no remote dependencies.

## What’s Included

The repository/package is typically laid out as follows:

- `app.py`: Streamlit application implementing the UI and workflow orchestration.
- `bin/`: bundled forensic binaries (Volatility executables, Sysinternals Strings, etc.).
- `assets/`: branding assets (logo and application icon).
- `requirements.txt`: Python dependency list for running MemHunter from source (developer workflow).
- `_memhunter_data/`: working directory created during analysis (see “Data Folder Notes”).

Distribution model:

- **Source repository (GitHub)**: contains the code and supporting assets (`app.py`, `bin/`, `assets/`, `requirements.txt`, etc.).
- **Portable Release ZIP (GitHub Releases)**: contains the full offline portable package, including:
  - `MemHunter.exe`: silent Windows launcher (C#) that starts the application.
  - `python_env/`: embedded Python runtime and dependencies.

## System Requirements

- **Operating system**: Windows 10/11 (x64 recommended)
- **Browser**: any modern browser (the UI opens automatically)
- **Permissions**: standard user permissions are typically sufficient; some environments may restrict local process execution or browser loopback.

## Getting Started

MemHunter is distributed in two forms: a portable offline package for investigators, and source code for developers.

### Option 1: Portable Release (Recommended for Investigators)

1. Go to the project’s **Releases** page on GitHub.
2. Download the pre-packaged ZIP (for example: `MemHunter_vX.X.zip`).
3. Extract the ZIP locally (avoid running directly from within the archive).
4. Double-click:

```text
MemHunter.exe
```

`MemHunter.exe` is a silent C# wrapper that:

- sets `PYTHONPATH` to the embedded `python_env\Lib\site-packages`
- launches the Streamlit application
- opens the browser to the local UI automatically

### Option 2: Running from Source (For Developers)

1. Clone the repository.
2. Create and activate a Python environment of your choice.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Launch the UI:

```bash
streamlit run app.py
```

### Selecting a Memory Image

MemHunter selects the memory image **inside the web UI**:

- Click **Browse** next to “Memory image”
- Choose the memory dump file
- Click **Start Analysis**

Supported extensions commonly include: `.raw`, `.vmem`, `.mem`, `.dmp`, `.dump`, `.img` (and any other file you select explicitly).

## Core Workflow (Critical): The Two Analysis Modes

MemHunter implements two distinct modes with different performance and intent characteristics.

### Global Mode (Whole Image Analysis)

Global Mode is the broad, whole-memory baseline. It runs plugins and workflows that operate on the entire memory image and generates foundational datasets used throughout the investigation.

Typical Global Mode capabilities include:

- **Process discovery and validation**
  - `pslist`, `psscan`, `pstree`, `psxview`
- **System-wide artifact enumeration**
  - examples: `filescan` (and other global scanners depending on engine and OS)
- **Global YARA scanning**
  - scanning across the image (rules and scope depend on the selected engine/workflow)
- **Strings extraction**
  - bulk string extraction and searching (useful for triage and quick pivots)

Output from Global Mode is loaded into memory (Pandas dataframes) and becomes the primary source for navigation, filtering, and downstream targeting.

### Hunt Mode (Single Process Analysis)

Hunt Mode is a targeted deep-dive into a **single PID**.

Its architecture is explicitly optimized for investigative speed:

- **Hunt Mode prioritizes reuse of Global Mode data already extracted and kept in memory.**
- Instead of repeatedly spawning new, expensive Volatility processes for every interaction, Hunt Mode:
  - **cross-references** results already collected during the Global scan
  - **filters** and **profiles** the selected process rapidly
  - surfaces process-centric insights (e.g., loaded modules/DLLs, handles, relevant memory regions, and related artifacts) without redoing the full-image work

This model enables efficient iterative analysis on suspicious processes while preserving the analyst’s context and reducing overall runtime.

## Engines

MemHunter supports two forensic execution engines:

- **Volatility 3 (default)**: primary analysis engine.
- **Volatility 2.6 (optional)**: provided for legacy compatibility and workflows where Vol2 plugins are preferred or required.

Engine selection is performed in the sidebar prior to starting analysis.

## Data Folder Notes (`_memhunter_data`)

During analysis MemHunter creates and uses a working directory:

```text
_memhunter_data\
```

This folder may contain temporary artifacts, cached outputs, exported files, and intermediate results used to accelerate the current investigation session.

- You can safely **delete `_memhunter_data` between distinct investigations** to ensure a clean workspace.
- Do not delete it while an analysis is actively running.

## Troubleshooting

- **Browse button does not open a file dialog**:
  - Ensure MemHunter is not running in a restricted desktop/session context (e.g., some remote execution policies).
  - Try launching MemHunter normally (non-elevated) and ensure your browser window is visible.
- **Missing binaries warning**:
  - Verify the `bin/` folder exists and contains the required executables.
- **Port conflicts / UI not opening**:
  - Close other Streamlit sessions, then relaunch `MemHunter.exe`.

## Security and Operational Notes

- MemHunter is intended to run **locally** and **offline**.
- Investigators should validate evidence handling practices, including write-blocking and secure storage, according to their organizational procedures.

## License and Third-Party Components

MemHunter bundles third-party tools and libraries (including Volatility components). Each third-party component is governed by its own license terms. Refer to the relevant files in `bin/` and the embedded Python packages for applicable notices.

