# Repository Guidelines

## Project Structure & Module Organization
- `osint_assistant.py` powers the CLI workflow; `osint_web_app.py` serves the Flask API on port 5000 for the React client.
- `client/` holds the CRA + Tailwind UI; `public/` for static assets, `src/` for components and styling.
- `desktop/` is the Electron wrapper; expects a packaged backend under `desktop/backend/` (see `packaging/pyinstaller-win.ps1`).
- `.env.example`, `dotenv.py`, and `fix_*.sh`/`fix_*.bat` handle configuration; run scripts (`run.sh`, `run_windows.bat`) orchestrate installs, build, and launch.

## Build, Test, and Development Commands
- Python setup (3.11+): `python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt`; copy `.env.example` to `.env`.
- CLI smoke: `python osint_assistant.py --query "quantum computing" --json`.
- Full stack dev: Windows `run_windows.bat`; Linux/Mac `bash run.sh` (builds client, ensures `.env`, starts Flask at http://localhost:5000).
- Frontend only: `cd client && npm install && npm start`; production build `npm run build`.
- Electron dev: `cd desktop && npm install && npm start`; Windows installer `npm run pack` after preparing backend via `packaging/pyinstaller-win.ps1` or `desktop/prepare-backend.ps1`.

## Coding Style & Naming Conventions
- Python: PEP 8, 4-space indent, ~100-char lines; snake_case for functions/vars, PascalCase for classes; guard entrypoints with `if __name__ == "__main__"`.
- React: functional components, PascalCase files, camelCase props/state; keep styles in Tailwind utility classes and `client/src/index.css`.
- Keep secrets in `.env`; avoid committing `client/build`, `dist/`, or packaged binaries.

## Testing Guidelines
- Add pytest coverage alongside new Python code under `tests/` (e.g., `tests/test_osint_assistant.py`); cover API routes, parsing, and fallback behavior without an API key.
- Frontend: `cd client && npm test` (CRA/Jest/RTL); prioritize search flows, loading/error states, and API integration.
- Keep fixtures small and document sample inputs in test docstrings.

## Commit & Pull Request Guidelines
- Commits: imperative, present tense, <=72-char subject (e.g., `Add retries for Perplexity client`); keep changes scoped.
- PRs: describe intent, link issues, list commands/tests run, and include screenshots for UI changes; update `.env.example` and docs when configs shift.
- Avoid committing generated assets (`client/build`, `dist/`, `desktop/dist`, packaged executables).

## Security & Configuration Tips
- Require `PERPLEXITY_API_KEY`; place it in `.env` or set env vars before launching CLI/web/desktop bundles.
- If `python-dotenv` fails, use bundled `dotenv.py` or the `fix_*` scripts; verify `.env` sits beside packaged executables.
- Review logs and exported reports before sharing to prevent leaking queries or URLs.
