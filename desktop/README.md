# Desktop (Electron Wrapper)

Electron shell that boots the OSINT Assistant backend (PyInstaller exe or Python) and loads it in a native window.

## Prerequisites
- Node.js 18+
- Backend built with PyInstaller (`packaging/pyinstaller-win.ps1`) **or** Python available to run `osint_web_app.py`
- Icon copied to `desktop/icon.ico` (reuse `packaging/assets/icon.ico`)
- `.env` with `PERPLEXITY_API_KEY` accessible to the backend (place beside the exe in `desktop/backend/` or set env vars before launching)

## Dev Run
1. Build/copy backend: `powershell -ExecutionPolicy Bypass -File desktop/prepare-backend.ps1` (expects `dist/OSINT-Assistant.exe`). If you skip this, Electron will try `python ../osint_web_app.py`.
2. Install deps: `cd desktop && npm install`.
3. Launch Electron: `npm start` (starts backend, then opens window to `http://127.0.0.1:5000`).

## Package Installer (Windows)
1. Ensure `desktop/backend/osint_web_app.exe` exists (use `prepare-backend.ps1`).
2. Ensure `desktop/icon.ico` is present (copy from `packaging/assets/icon.ico`).
3. From `desktop/`: `npm install` (first time), then `npm run pack` to build an NSIS installer under `desktop/dist/`.

## Notes
- Backend runs in the Electron process environment; set `PERPLEXITY_API_KEY` (and other settings) in your shell before launching, or drop a `.env` next to `osint_web_app.exe`.
- Logs stream to the Electron console and `electron-log` files in `%APPDATA%/osint-assistant-desktop/logs/`.
- The backend listens on port 5000 (as defined in `osint_web_app.py`). If that port is in use, stop the other service before launching.
