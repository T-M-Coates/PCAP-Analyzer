"""
Self-contained HTML export.

Takes a fully-rendered report HTML string (from Flask's render_template) and
produces a single portable .html file that works offline:

  • Local static files (report.css, report.js) are read from disk and inlined
  • CDN resources (Bootstrap CSS/JS, Chart.js) are fetched once from the
    internet, cached in memory for the server session, and inlined
  • If a CDN fetch fails the original <link>/<script> tag is left intact, so
    the file still works whenever an internet connection is available

Usage:
    from export.html_export import build_standalone_html
    standalone = build_standalone_html(rendered_html, app.static_folder)
"""
from __future__ import annotations
import os

# ── In-process cache for CDN resources (keyed by URL) ─────────────
_cdn_cache: dict[str, str] = {}

_CDN = {
    "bootstrap_css": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
    "bootstrap_js":  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
    "chartjs":       "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js",
    "chartjs_geo":   "https://cdn.jsdelivr.net/npm/chartjs-chart-geo@4.3.0/build/index.umd.min.js",
}


def _fetch_cdn(url: str) -> str:
    """Download a CDN resource once, cache for the life of the process."""
    if url in _cdn_cache:
        return _cdn_cache[url]
    try:
        import requests
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            _cdn_cache[url] = resp.text
            return resp.text
    except Exception:
        pass
    return ""   # caller keeps the original tag on failure


def _read_static(static_folder: str, rel_path: str) -> str:
    """Read a file from the static folder; return empty string on error."""
    try:
        path = os.path.join(static_folder, *rel_path.split("/"))
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def build_standalone_html(rendered_html: str, static_folder: str) -> str:
    """
    Inline all external resources into a rendered report HTML string.

    Args:
        rendered_html:  Output of Flask's render_template('report.html', ...)
        static_folder:  Absolute path to the Flask app's /static directory

    Returns:
        A self-contained HTML string suitable for saving as a .html file.
    """
    html = rendered_html

    # ── 1. Inline local CSS (/static/css/report.css) ──────────────
    report_css = _read_static(static_folder, "css/report.css")
    if report_css:
        # The rendered tag looks like: href="/static/css/report.css"
        old = '<link rel="stylesheet" href="/static/css/report.css">'
        new = f"<style>/* report.css */\n{report_css}\n</style>"
        html = html.replace(old, new)

    # ── 2. Inline local JS (/static/js/report.js) ─────────────────
    report_js = _read_static(static_folder, "js/report.js")
    if report_js:
        old = '<script src="/static/js/report.js"></script>'
        new = f"<script>/* report.js */\n{report_js}\n</script>"
        html = html.replace(old, new)

    # ── 3. Inline Bootstrap CSS ───────────────────────────────────
    bs_css = _fetch_cdn(_CDN["bootstrap_css"])
    if bs_css:
        old = (
            '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/'
            'bootstrap@5.3.3/dist/css/bootstrap.min.css">'
        )
        new = f"<style>/* bootstrap.min.css */\n{bs_css}\n</style>"
        html = html.replace(old, new)

    # ── 4. Inline Bootstrap JS bundle ────────────────────────────
    bs_js = _fetch_cdn(_CDN["bootstrap_js"])
    if bs_js:
        old = (
            '<script src="https://cdn.jsdelivr.net/npm/'
            'bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>'
        )
        new = f"<script>/* bootstrap.bundle.min.js */\n{bs_js}\n</script>"
        html = html.replace(old, new)

    # ── 5. Inline Chart.js ────────────────────────────────────────
    cjs = _fetch_cdn(_CDN["chartjs"])
    if cjs:
        old = (
            '<script src="https://cdn.jsdelivr.net/npm/'
            'chart.js@4.4.4/dist/chart.umd.min.js"></script>'
        )
        new = f"<script>/* chart.umd.min.js */\n{cjs}\n</script>"
        html = html.replace(old, new)

    # ── 6. Inline chartjs-chart-geo ───────────────────────────────
    geo_js = _fetch_cdn(_CDN["chartjs_geo"])
    if geo_js:
        old = (
            '<script src="https://cdn.jsdelivr.net/npm/'
            'chartjs-chart-geo@4.3.0/build/index.umd.min.js"></script>'
        )
        new = f"<script>/* chartjs-chart-geo */\n{geo_js}\n</script>"
        html = html.replace(old, new)

    return html
