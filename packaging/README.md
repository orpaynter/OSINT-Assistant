# Packaging (PyInstaller)

## Quick Start (Windows)
1. Add your icon: place `icon.ico` under `packaging/assets/` (convert from PNG with ImageMagick: `magick icon.png -define icon:auto-resize=256,128,64,48,32,16 packaging/assets/icon.ico`).
2. From repo root, run: `powershell -ExecutionPolicy Bypass -File packaging/pyinstaller-win.ps1`.
3. Collect outputs from `dist/`:
   - `OSINT-Assistant.exe` (windowed Flask UI)
   - `OSINT-Assistant-CLI.exe` (console CLI)
4. Copy `.env` (based on `.env.example`) next to the exe and set `PERPLEXITY_API_KEY` before launching.

## Notes
- Script creates an isolated `.venv-pyinstaller` and installs `pyinstaller` plus runtime deps.
- Omit `--windowed` by passing `-Console` if you want console output for the web app bundle.
- The web app serves on `http://127.0.0.1:5000`; the script leaves debug enabled as in `osint_web_app.py`.
