# OSINT Assistant

Local-first OSINT assistant for gathering, analyzing, and reporting on public-source intelligence. This version is configured for **local LLM + local AIA only** — no Perplexity, OpenAI, Anthropic, or other external model providers by default.

## Local architecture

```text
OSINT Assistant
  -> local OpenAI-compatible LLM endpoint
  -> local AIA /verify and /signals/ingest
  -> JSON report with local provider status + AIA receipt
```

Default local endpoints:

```env
LOCAL_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=llama3.1
AIA_BASE_URL=http://localhost:3001
```

The local LLM endpoint can be Ollama, LM Studio, vLLM, llama.cpp server, or any local OpenAI-compatible `/chat/completions` server.

## Important evidence rule

Local model output is **analysis**, not proof. AIA verification/signal capture makes OSINT runs governable inside the OrPaynter stack, but it does not automatically make model output true, production-ready, or field-validated.

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

Start local AIA separately, typically:

```bash
cd /path/to/AIA
uvicorn agsi.api.main:app --port 3001
```

## CLI usage

List providers. It should only return `local`:

```bash
python osint_assistant.py --list-providers
```

Run local OSINT:

```bash
python osint_assistant.py --query "roofing claims AI governance" --results 10
```

Override local model or endpoint:

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

Save output:

```bash
python osint_assistant.py --query "example" --save
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
  "aia_base_url": "http://localhost:3001",
  "aia_api_key": "optional-local-token",
  "skip_aia": false
}
```

## AIA behavior

When `AIA_BASE_URL` is set, the assistant:

1. Calls `POST /verify` with a bounded statement summarizing the local OSINT run.
2. Calls `POST /signals/ingest` with one signal per collected source.
3. Records the result in `aia_receipt`.

If local AIA is unavailable, the OSINT run still completes and the integration error is recorded.

## Security notes

- No cloud model providers are configured by default.
- Keep local API tokens and `.env` out of Git.
- Treat all local LLM outputs as untrusted analysis until sources are independently verified.
- Review logs and exported reports before sharing.

## Development smoke checks

```bash
python osint_assistant.py --list-providers
python osint_assistant.py --query "quantum computing" --json --skip-aia
python osint_web_app.py
```

## Disclaimer

This tool is for educational, research, and authorized intelligence workflows only. Always comply with applicable laws, contracts, platform terms, and privacy obligations.
