from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, redirect, render_template_string, request
from flask_cors import CORS

from osint_assistant import OSINTAssistant, model_dump, split_csv

app = Flask(__name__)
CORS(app)

APP_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OSINT Assistant</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-neutral-950 text-neutral-100">
  <main class="mx-auto max-w-5xl p-6">
    <section class="rounded-2xl border border-orange-500/30 bg-neutral-900 p-6 shadow-2xl">
      <p class="text-sm uppercase tracking-[0.3em] text-orange-400">OrPaynter OSINT</p>
      <h1 class="mt-2 text-4xl font-black">AIA + Multi-LLM Intelligence Search</h1>
      <p class="mt-3 text-neutral-300">Routes through configured LLM providers, then optionally verifies and captures signals in AIA.</p>
      <form class="mt-6 grid gap-4" method="post" action="/search">
        <label class="grid gap-2">
          <span class="text-sm font-semibold">Search query</span>
          <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="query" required value="{{ query or '' }}">
        </label>
        <div class="grid gap-4 md:grid-cols-2">
          <label class="grid gap-2">
            <span class="text-sm font-semibold">Providers</span>
            <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="providers" placeholder="perplexity,openai,anthropic,local">
          </label>
          <label class="grid gap-2">
            <span class="text-sm font-semibold">Model override</span>
            <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="model" placeholder="optional">
          </label>
          <label class="grid gap-2">
            <span class="text-sm font-semibold">First-provider API key</span>
            <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="api_key" type="password" placeholder="optional; env fallback preferred">
          </label>
          <label class="grid gap-2">
            <span class="text-sm font-semibold">AIA base URL</span>
            <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="aia_base_url" placeholder="http://localhost:3001">
          </label>
          <label class="grid gap-2">
            <span class="text-sm font-semibold">Results</span>
            <input class="rounded-xl border border-neutral-700 bg-neutral-950 p-3" name="num_results" type="number" min="1" max="50" value="10">
          </label>
          <label class="flex items-center gap-3 pt-7">
            <input name="skip_aia" type="checkbox">
            <span class="text-sm">Skip AIA for this run</span>
          </label>
        </div>
        <button class="rounded-xl bg-orange-500 px-5 py-3 font-black text-black hover:bg-orange-400" type="submit">Run OSINT</button>
      </form>
    </section>

    {% if error %}
      <section class="mt-6 rounded-xl border border-red-500 bg-red-950/50 p-4 text-red-200">{{ error }}</section>
    {% endif %}

    {% if report %}
      <section class="mt-6 rounded-2xl border border-neutral-800 bg-neutral-900 p-6">
        <h2 class="text-2xl font-black">Run result</h2>
        <p class="mt-2 text-neutral-300">Found {{ report.query_info.results_found }} results.</p>
        {% if report.aia_receipt %}
          <p class="mt-2 text-sm text-orange-300">AIA: {{ 'enabled' if report.aia_receipt.enabled else 'disabled' }}{% if report.aia_receipt.error %} — {{ report.aia_receipt.error }}{% endif %}</p>
        {% endif %}
        <div class="mt-4 grid gap-3">
          {% for item in report.collected_data %}
            <article class="rounded-xl border border-neutral-800 bg-neutral-950 p-4">
              <a class="font-bold text-orange-300" href="{{ item.url }}" target="_blank" rel="noreferrer">{{ item.title }}</a>
              <p class="mt-1 text-sm text-neutral-400">{{ item.source_type }} · {{ item.timestamp }}</p>
              <p class="mt-2 text-neutral-200">{{ item.snippet }}</p>
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
    assistant = OSINTAssistant(
        api_key=payload.get("api_key") or None,
        providers=split_csv(payload.get("providers")),
        model=payload.get("model") or None,
        llm_base_url=payload.get("llm_base_url") or None,
        aia_base_url=payload.get("aia_base_url") or None,
        aia_api_key=payload.get("aia_api_key") or None,
        enable_aia=not bool(payload.get("skip_aia")),
    )
    num_results = int(payload.get("num_results", 10))
    assistant.search_web(query, num_results)
    for item in assistant.collected_data:
        assistant.analyze_content(item["url"])
    return model_dump(assistant.build_report(query, num_results))


@app.route("/", methods=["GET"])
def index():
    return render_template_string(APP_HTML, query=None, report=None, error=None, current_year=datetime.now().year)


@app.route("/search", methods=["POST"])
def search():
    payload = dict(request.form)
    payload["skip_aia"] = "skip_aia" in request.form
    try:
        report = run_search(payload)
        return render_template_string(APP_HTML, query=payload.get("query"), report=report, error=None, current_year=datetime.now().year)
    except Exception as exc:  # noqa: BLE001
        return render_template_string(APP_HTML, query=payload.get("query"), report=None, error=str(exc), current_year=datetime.now().year)


@app.route("/api/search", methods=["POST"])
def api_search():
    try:
        return jsonify(run_search(request.json or {}))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


@app.route("/results/<session_id>")
def legacy_results(session_id: str):
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
