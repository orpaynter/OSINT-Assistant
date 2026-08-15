# OSINT Assistant

Local-first OSINT assistant for public-source research. This version uses a **local LLM**, connects to the **internet**, supports **Tor/.onion dark-web source access**, and can send governed verification/signal receipts to **local AIA**.

## Local architecture

```text
OSINT Assistant
  -> clearnet fetch / optional local SearXNG search
  -> Tor SOCKS proxy for .onion URLs
  -> local OpenAI-compatible LLM endpoint
  -> local AIA /verify and /signals/ingest
  -> JSON report with source fetches + provider status + AIA receipt
```

Defaults:

```env
LOCAL_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=llama3.1
SEARXNG_URL=http://localhost:8080
TOR_PROXY=socks5h://127.0.0.1:9050
AIA_BASE_URL=http://localhost:3001
```

## Evidence and safety rule

Local model output is **analysis**, not proof. Internet or .onion access is for authorized public-source research only. Do not use this tool to buy, sell, access stolen data, bypass authentication, exploit systems, or facilitate illegal activity. AIA capture makes runs governable; it does not make unverified sources true.

## Installation

```bash
git clone https://github.com/orpaynter/OSINT-Assistant.git
cd OSINT-Assistant
pip install -r requirements.txt
cp .env.example .env
```

Start local model server first. Example with Ollama:

```bash
ollama serve
ollama pull llama3.1
```

Start local AIA separately:

```bash
cd /path/to/AIA
uvicorn agsi.api.main:app --port 3001
```

Optional: start local SearXNG for clearnet search:

```bash
docker run --rm -p 8080:8080 searxng/searxng
```

Optional: start Tor for .onion access:

```bash
# Linux/macOS example
 tor
# Windows: run Tor Browser or Tor Expert Bundle and expose SOCKS on 127.0.0.1:9050
```

## CLI usage

List providers. It should only return `local`:

```bash
python osint_assistant.py --list-providers
```

Run local OSINT against a topic:

```bash
python osint_assistant.py --query "roofing claims AI governance" --results 10
```

Fetch/analyze a direct internet URL:

```bash
python osint_assistant.py --query "https://example.com/report" --json
```

Fetch/analyze a direct .onion URL through Tor:

```bash
python osint_assistant.py --query "http://exampleonionaddress.onion/path" --json
```

Override local endpoints:

```bash
python osint_assistant.py \
  --query "roofing claims AI governance" \
  --model llama3.1 \
  --llm-base-url http://localhost:11434/v1 \
  --aia-base-url http://localhost:3001 \
  --json
```

Disable AIA for a run:

```bash
python osint_assistant.py --query "example" --skip-aia
```

## Web application

Start the local web app:

```bash
bash run.sh
# or on Windows
run_windows.bat
```

The Flask API uses `.env` by default. `/api/search` accepts optional local fields:

```json
{
  "query": "roofing claims AI governance",
  "num_results": 10,
  "model": "llama3.1",
  "llm_base_url": "http://localhost:11434/v1",
  "searxng_url": "http://localhost:8080",
  "tor_proxy": "socks5h://127.0.0.1:9050",
  "allow_onion": true,
  "aia_base_url": "http://localhost:3001",
  "skip_aia": false
}
```

## AIA behavior

By default, AIA is enabled and uses `AIA_BASE_URL=http://localhost:3001` unless you explicitly skip it (`skip_aia: true` in API payloads or `--skip-aia` in CLI). When enabled, the assistant:

1. Calls `POST /verify` with a bounded statement summarizing the local OSINT run.
2. Calls `POST /signals/ingest` with one signal per collected source.
3. Records the result in `aia_receipt`.

If local AIA is unavailable, the OSINT run still completes and the integration error is recorded.

## Security notes

- No cloud model providers are configured.
- Tor/.onion support requires a local Tor proxy; it is not bundled.
- Keep local API tokens and `.env` out of Git.
- Treat all local LLM outputs and fetched source text as untrusted until independently verified.
- Review logs and exported reports before sharing.

## Development smoke checks

```bash
python osint_assistant.py --list-providers
python osint_assistant.py --query "https://example.com" --json --skip-aia
python osint_web_app.py
```

## Disclaimer

This tool is for educational, research, and authorized intelligence workflows only. Always comply with applicable laws, contracts, platform terms, and privacy obligations.
