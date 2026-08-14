import os
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, render_template_string, request

from osint_assistant import OSINTAssistant, SourceClient, model_dump, redact_secrets, split_csv

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CORS — same-origin by default; opt-in allowlist via OSINT_CORS_ORIGINS
# ---------------------------------------------------------------------------
_cors_origins_env = os.getenv("OSINT_CORS_ORIGINS", "").strip()
if _cors_origins_env:
    from flask_cors import CORS
    _allowed = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
    CORS(app, origins=_allowed, supports_credentials=False)
# No CORS is applied when OSINT_CORS_ORIGINS is unset — same-origin only.

# ---------------------------------------------------------------------------
# Inline self-contained CSS (no third-party CDN)
# ---------------------------------------------------------------------------
_INLINE_CSS = """
*,::before,::after{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#0a0a0a;color:#e5e5e5;font-family:system-ui,sans-serif}
a{color:#fb923c}a:hover{color:#fdba74}
input[type=text],input[type=number],input[type=url]{background:#0a0a0a;border:1px solid #404040;border-radius:.75rem;color:#e5e5e5;padding:.75rem;width:100%}
input[type=checkbox]{accent-color:#f97316;width:1.1rem;height:1.1rem}
button[type=submit]{background:#f97316;border:0;border-radius:.75rem;color:#000;cursor:pointer;font-weight:900;padding:.75rem 1.25rem;width:100%}
button[type=submit]:hover{background:#fb923c}
.wrap{max-width:960px;margin:0 auto;padding:1.5rem}
.card{background:#171717;border:1px solid rgba(249,115,22,.3);border-radius:1rem;padding:1.5rem;box-shadow:0 25px 50px rgba(0,0,0,.5)}
.label{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.15em;color:#e5e5e5;display:block;margin-bottom:.4rem}
.grid2{display:grid;gap:1rem}@media(min-width:640px){.grid2{grid-template-columns:1fr 1fr}}
.result{background:#0a0a0a;border:1px solid #262626;border-radius:.75rem;padding:1rem;margin-top:.75rem}
.result-meta{font-size:.75rem;color:#737373;margin-top:.25rem}
.result-snippet{margin-top:.5rem;color:#d4d4d4}
.alert-error{background:rgba(127,29,29,.3);border:1px solid #ef4444;border-radius:.75rem;padding:1rem;color:#fca5a5;margin-top:1.5rem}
.alert-warn{background:rgba(120,53,15,.3);border:1px solid #f97316;border-radius:.75rem;padding:1rem;color:#fdba74;margin-top:1rem;font-size:.85rem}
.badge{display:inline-block;font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:.4rem;margin-left:.5rem}
.badge-tor{background:#7c3aed;color:#ede9fe}
.badge-direct{background:#b45309;color:#fef3c7}
.badge-local{background:#065f46;color:#d1fae5}
"""

APP_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Local OSINT Assistant</title>
  <style>{{ css }}</style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <p style="font-size:.75rem;text-transform:uppercase;letter-spacing:.3em;color:#fb923c">Local OSINT Assistant</p>
      <h1 style="margin:.5rem 0 0;font-size:2rem;font-weight:900">Local LLM + Source Fetch + Tor + Local AIA</h1>
      <p style="margin:.75rem 0 0;color:#a3a3a3">
        Authorized public-source research only. Tor reduces direct source exposure but
        <strong>does not guarantee anonymity</strong>.
      </p>

      {% if privacy_mode == 'direct' %}
      <div class="alert-warn">
        ⚠ <strong>Direct mode active</strong> — outbound requests are NOT routed through Tor.
        Set <code>PRIVACY_MODE=strict</code> (default) for Tor-routed privacy.
      </div>
      {% endif %}
      {% if bind_warning %}
      <div class="alert-warn">
        ⚠ <strong>Remote binding active</strong> — this server is reachable beyond localhost.
        Only run on a trusted network.
      </div>
      {% endif %}

      <form style="margin-top:1.5rem;display:grid;gap:1rem" method="post" action="/search">
        <label>
          <span class="label">Search query or direct URL</span>
          <input type="text" name="query" required value="{{ query or '' }}"
            placeholder="topic, https://..., or http://example.onion/...">
        </label>
        <div class="grid2">
          <label><span class="label">Local model</span><input type="text" name="model" placeholder="llama3.1"></label>
          <label><span class="label">Local LLM base URL</span><input type="text" name="llm_base_url" placeholder="http://localhost:11434/v1"></label>
          <label><span class="label">SearXNG URL</span><input type="text" name="searxng_url" placeholder="http://localhost:8080"></label>
          <label><span class="label">Tor proxy</span><input type="text" name="tor_proxy" placeholder="socks5h://127.0.0.1:9050"></label>
          <label><span class="label">AIA base URL</span><input type="text" name="aia_base_url" placeholder="http://localhost:3001"></label>
          <label><span class="label">Results</span><input type="number" name="num_results" min="1" max="50" value="10"></label>
          <label style="display:flex;align-items:center;gap:.75rem">
            <input name="allow_onion" type="checkbox">
            <span class="label" style="margin:0">.onion via Tor</span>
          </label>
          <label style="display:flex;align-items:center;gap:.75rem">
            <input name="skip_aia" type="checkbox">
            <span class="label" style="margin:0">Skip AIA</span>
          </label>
        </div>
        <button type="submit">Run OSINT</button>
      </form>
    </section>

    {% if error %}
    <section class="alert-error">{{ error }}</section>
    {% endif %}

    {% if report %}
    <section class="card" style="margin-top:1.5rem">
      <h2 style="font-size:1.5rem;font-weight:900;margin:0">Run result</h2>
      <p style="color:#a3a3a3;margin:.5rem 0 0">Found {{ report.query_info.results_found }} results.</p>

      {% set pr = report.privacy_receipt %}
      {% if pr %}
      <p style="font-size:.8rem;color:#737373;margin:.5rem 0 0">
        Privacy mode: <strong>{{ pr.privacy_mode }}</strong> |
        Route: <strong>{{ pr.route }}</strong> |
        Remote DNS via Tor: <strong>{{ pr.remote_dns_via_tor }}</strong> |
        Fail-closed: <strong>{{ pr.fail_closed_on_proxy_error }}</strong>
        <br><em>{{ pr.anonymity_disclaimer }}</em>
      </p>
      {% endif %}

      {% if report.aia_receipt %}
      <p style="font-size:.8rem;color:#fb923c;margin:.5rem 0 0">
        AIA: {{ 'enabled' if report.aia_receipt.enabled else 'disabled' }}
        {% if report.aia_receipt.error %} — {{ report.aia_receipt.error }}{% endif %}
      </p>
      {% endif %}

      <div style="margin-top:1rem">
        {% for item in report.collected_data %}
        <article class="result">
          <a href="{{ item.url }}" target="_blank" rel="noreferrer noopener">{{ item.title }}</a>
          <p class="result-meta">{{ item.source_type }} · {{ item.timestamp }}</p>
          <p class="result-snippet">{{ item.snippet }}</p>
        </article>
        {% endfor %}
      </div>
    </section>
    {% endif %}
  </main>
</body>
</html>
"""


def run_search(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = payload.get("query")
    if not query:
        raise ValueError("No query provided")
    source_client = SourceClient(
        allow_onion=payload.get("allow_onion", False) not in {False, "false", "False", "0", "off"},
        tor_proxy=payload.get("tor_proxy") or None,
        searxng_url=payload.get("searxng_url") or None,
    )
    assistant = OSINTAssistant(
        api_key=payload.get("api_key") or None,
        providers=split_csv(payload.get("providers")) or ["local"],
        model=payload.get("model") or None,
        llm_base_url=payload.get("llm_base_url") or None,
        aia_base_url=payload.get("aia_base_url") or None,
        aia_api_key=payload.get("aia_api_key") or None,
        enable_aia=not bool(payload.get("skip_aia")),
        source_client=source_client,
    )
    num_results = int(payload.get("num_results", 10))
    assistant.search_web(query, num_results)
    for item in assistant.collected_data:
        assistant.analyze_content(item["url"])
    return model_dump(assistant.build_report(query, num_results))


def _safe_error(exc: Exception) -> str:
    return redact_secrets(str(exc))


@app.route("/", methods=["GET"])
def index():
    privacy_mode = os.getenv("PRIVACY_MODE", SourceClient.STRICT)
    bind_host = os.getenv("OSINT_BIND_HOST", "127.0.0.1")
    bind_warning = bind_host not in ("127.0.0.1", "::1", "localhost")
    return render_template_string(
        APP_HTML,
        css=_INLINE_CSS,
        query=None,
        report=None,
        error=None,
        privacy_mode=privacy_mode,
        bind_warning=bind_warning,
        current_year=datetime.now().year,
    )


@app.route("/search", methods=["POST"])
def search():
    payload = dict(request.form)
    payload["skip_aia"] = "skip_aia" in request.form
    payload["allow_onion"] = "allow_onion" in request.form
    privacy_mode = os.getenv("PRIVACY_MODE", SourceClient.STRICT)
    bind_host = os.getenv("OSINT_BIND_HOST", "127.0.0.1")
    bind_warning = bind_host not in ("127.0.0.1", "::1", "localhost")
    try:
        report = run_search(payload)
        return render_template_string(
            APP_HTML,
            css=_INLINE_CSS,
            query=payload.get("query"),
            report=report,
            error=None,
            privacy_mode=privacy_mode,
            bind_warning=bind_warning,
            current_year=datetime.now().year,
        )
    except Exception as exc:  # noqa: BLE001
        return render_template_string(
            APP_HTML,
            css=_INLINE_CSS,
            query=payload.get("query"),
            report=None,
            error=_safe_error(exc),
            privacy_mode=privacy_mode,
            bind_warning=bind_warning,
            current_year=datetime.now().year,
        )


@app.route("/api/search", methods=["POST"])
def api_search():
    try:
        return jsonify(run_search(request.json or {}))
    except ValueError as exc:
        return jsonify({"error": _safe_error(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": _safe_error(exc)}), 500


if __name__ == "__main__":
    bind_host = os.getenv("OSINT_BIND_HOST", "127.0.0.1")
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    if bind_host not in ("127.0.0.1", "::1", "localhost"):
        import sys
        print(
            f"WARNING: Binding to {bind_host} — server will be reachable beyond localhost. "
            "Only do this on a trusted, isolated network.",
            file=sys.stderr,
        )
    if debug_mode:
        import sys
        print("WARNING: Flask debug mode is enabled (FLASK_DEBUG=true).", file=sys.stderr)
    app.run(debug=debug_mode, host=bind_host, port=int(os.getenv("OSINT_PORT", "5000")))
