# OSINT Assistant

An AI-enhanced OSINT (Open Source Intelligence) tool for gathering, analyzing, and reporting on information from public sources. The assistant now supports **multi-LLM routing** and optional **AIA governed verification / signal ingest** instead of being locked to Perplexity only.

## Features

- 🔍 **OSINT search:** collect candidate public sources for a query
- 🧠 **Multi-LLM analysis:** route across Perplexity, OpenAI, Anthropic, Google, Groq, Mistral, xAI, DeepSeek, OpenRouter, Together, Fireworks, Cohere, or local OpenAI-compatible models
- 🛡️ **AIA integration:** optionally call AIA `/verify` and ingest collected sources into AIA `/signals/ingest`
- 📊 **Entity and relationship extraction:** identify key entities, sentiment, credibility, and connections
- 📝 **Structured reports:** export Pydantic-backed JSON including provider status and AIA receipt
- 🌐 **CLI + Flask web app:** use the terminal or the local web interface

## Important evidence rule

LLM output is **analysis**, not proof. AIA verification/signal capture makes OSINT runs governable inside the OrPaynter stack, but it does not automatically make a model output true, production-ready, or field-validated.

## Installation

```bash
git clone https://github.com/orpaynter/OSINT-Assistant.git
cd OSINT-Assistant
pip install -r requirements.txt
cp .env.example .env
```

Fill only the provider keys you actually use. Never commit `.env`.

## Configuration

Provider routing is controlled by `OSINT_LLM_PROVIDERS`:

```env
OSINT_LLM_PROVIDERS=perplexity,openai,anthropic,local
PERPLEXITY_API_KEY=...
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
LOCAL_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=llama3.1
AIA_BASE_URL=http://localhost:3001
```

Supported provider names:

```text
perplexity, openai, anthropic, google, groq, mistral, xai, deepseek,
openrouter, together, fireworks, cohere, local
```

Providers are tried in order. Missing keys are skipped. Provider errors fail over to the next configured provider and are recorded in `provider_runs`.

## CLI usage

List providers:

```bash
python osint_assistant.py --list-providers
```

Run with `.env` configuration:

```bash
python osint_assistant.py --query "roofing claims AI governance" --results 10
```

Override providers and connect AIA for a run:

```bash
python osint_assistant.py \
  --query "roofing claims AI governance" \
  --providers perplexity,openai,anthropic,local \
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

The Flask API uses `.env` by default. `/api/search` accepts optional fields:

```json
{
  "query": "roofing claims AI governance",
  "num_results": 10,
  "providers": "perplexity,openai,anthropic",
  "model": "sonar-pro",
  "llm_base_url": "https://api.perplexity.ai",
  "aia_base_url": "http://localhost:3001",
  "aia_api_key": "optional-bearer-token",
  "skip_aia": false
}
```

## AIA behavior

When `AIA_BASE_URL` is set, the assistant:

1. Calls `POST /verify` with a bounded statement summarizing the OSINT run.
2. Calls `POST /signals/ingest` with one signal per collected source.
3. Records the result in `aia_receipt`.

If AIA is unavailable, the OSINT run still completes and the integration error is recorded.

## Security notes

- Never commit real provider keys, AIA tokens, or `.env`.
- Treat all LLM outputs as untrusted analysis until sources are independently verified.
- Do not send restricted or secret-bearing context to a provider unless that provider is approved for the data class.
- Review logs and exported reports before sharing.

## Development

Python setup:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

CLI smoke:

```bash
python osint_assistant.py --list-providers
python osint_assistant.py --query "quantum computing" --json --skip-aia
```

Frontend/web smoke:

```bash
python osint_web_app.py
```

## Disclaimer

This tool is for educational, research, and authorized intelligence workflows only. Always comply with applicable laws, contracts, platform terms, and privacy obligations.
