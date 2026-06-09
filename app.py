import json as _json
import os
import threading
import uuid
import webbrowser
from datetime import datetime, timezone

from flask import Flask, Response, abort, jsonify, render_template, request
from werkzeug.utils import secure_filename

import database
from config import Config
from analyzer.runner import analyze as run_analysis
from analyzer.utils import pcap_magic_valid
from export.csv_export import iocs_to_csv
from export.html_export import build_standalone_html

app = Flask(__name__)
app.config.from_object(Config)

# In-memory job state: {job_id: {"status", "progress", "error", "filename",
#                                "file_size", "uploaded_at"}}
jobs: dict[str, dict] = {}


# ── Jinja2 helpers ────────────────────────────────────────────────
def _flag_emoji(iso_code: str) -> str:
    """Convert a 2-letter ISO country code to a flag emoji."""
    if not iso_code or len(iso_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso_code.upper())

app.jinja_env.globals["flag_emoji"] = _flag_emoji


def _validate_pcap(path: str) -> bool:
    return pcap_magic_valid(path)


def _run_analysis(pcap_path: str, job_id: str) -> None:
    """Background thread: run analysis then save record to database."""
    run_analysis(pcap_path, job_id, jobs, app.config["DATA_FOLDER"])

    job = jobs.get(job_id, {})
    if job.get("status") == "complete":
        try:
            data_path = os.path.join(app.config["DATA_FOLDER"], f"{job_id}.json")
            with open(data_path) as f:
                results = _json.load(f)
            ioc_data = results.get("iocs", {})
            database.save_analysis(
                db_path=app.config["DATABASE_PATH"],
                job_id=job_id,
                filename=job.get("filename", ""),
                file_size=job.get("file_size", 0),
                uploaded_at=job.get("uploaded_at", ""),
                critical=ioc_data.get("critical_count", 0),
                high=ioc_data.get("high_count", 0),
                medium=ioc_data.get("medium_count", 0),
                info=ioc_data.get("info_count", 0),
                json_path=data_path,
            )
        except Exception:
            pass   # DB failure never kills a report


# ── Helper: load results JSON (works even after server restart) ────
def _load_results(job_id: str) -> dict | None:
    data_path = os.path.join(app.config["DATA_FOLDER"], f"{job_id}.json")
    if not os.path.exists(data_path):
        return None
    try:
        with open(data_path) as f:
            return _json.load(f)
    except Exception:
        return None


def _get_filename(job_id: str) -> str:
    """Return filename from in-memory job or database."""
    job = jobs.get(job_id)
    if job:
        return job.get("filename", "report")
    rec = database.get_analysis(app.config["DATABASE_PATH"], job_id)
    return rec["filename"] if rec else "report"


# ── Core routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload/init", methods=["POST"])
def upload_init():
    """Phase 1: register the upload, return a job_id immediately."""
    body     = request.get_json(silent=True) or {}
    filename = secure_filename(body.get("filename", ""))
    if not filename:
        return jsonify({"error": "filename required"}), 400

    job_id    = str(uuid.uuid4())
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{job_id}_{filename}")

    jobs[job_id] = {
        "status":          "uploading",
        "upload_progress": 0,
        "progress":        0,
        "error":           None,
        "filename":        filename,
        "file_size":       None,
        "uploaded_at":     None,
        "_save_path":      save_path,
    }
    return jsonify({"job_id": job_id})


@app.route("/upload/<job_id>", methods=["POST"])
def upload_stream(job_id: str):
    """Phase 2: receive raw octet-stream body, write to disk in chunks."""
    job = jobs.get(job_id)
    if job is None or job["status"] != "uploading":
        abort(404)

    save_path      = job["_save_path"]
    max_bytes      = app.config["MAX_FILE_BYTES"]
    chunk_size     = app.config["STREAM_CHUNK_SIZE"]
    content_length = request.content_length  # may be None if client omits header

    if content_length and content_length > max_bytes:
        jobs.pop(job_id, None)
        return jsonify({"error": f"File exceeds {app.config['MAX_UPLOAD_MB']} MB limit"}), 413

    written = 0
    try:
        with open(save_path, "wb") as fout:
            while True:
                chunk = request.stream.read(chunk_size)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    fout.close()
                    os.remove(save_path)
                    job["status"] = "error"
                    job["error"]  = f"File exceeds {app.config['MAX_UPLOAD_MB']} MB limit"
                    return jsonify({"error": job["error"]}), 413
                fout.write(chunk)
                if content_length:
                    job["upload_progress"] = min(99, round(written / content_length * 100))
    except Exception as exc:
        job["status"] = "error"
        job["error"]  = str(exc)
        try:
            os.remove(save_path)
        except OSError:
            pass
        return jsonify({"error": "Upload failed"}), 500

    if not _validate_pcap(save_path):
        os.remove(save_path)
        job["status"] = "error"
        job["error"]  = "File does not appear to be a valid PCAP or PCAPNG (bad magic bytes)"
        return jsonify({"error": job["error"]}), 400

    job["upload_progress"] = 100
    job["file_size"]       = written
    job["uploaded_at"]     = datetime.now(timezone.utc).isoformat(timespec="seconds")
    job["status"]          = "pending"

    thread = threading.Thread(target=_run_analysis, args=(save_path, job_id), daemon=True)
    thread.start()

    return jsonify({"ok": True})


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    job_id   = str(uuid.uuid4())
    filename = secure_filename(f.filename)
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{job_id}_{filename}")
    f.save(save_path)

    if not _validate_pcap(save_path):
        os.remove(save_path)
        return jsonify({"error": "File does not appear to be a valid PCAP or PCAPNG (bad magic bytes)"}), 400

    file_size   = os.path.getsize(save_path)
    uploaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    jobs[job_id] = {
        "status":          "pending",
        "upload_progress": 100,
        "progress":        0,
        "error":           None,
        "filename":        filename,
        "file_size":       file_size,
        "uploaded_at":     uploaded_at,
    }
    thread = threading.Thread(target=_run_analysis, args=(save_path, job_id), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/status/<job_id>")
def status(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        abort(404)
    return jsonify({
        "status":          job["status"],
        "upload_progress": job.get("upload_progress", 100),
        "progress":        job["progress"],
        "status_label":    job.get("status_label", ""),
    })


@app.route("/report/<job_id>")
def report(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        abort(404)
    if job["status"] == "error":
        return render_template("error.html", message=job.get("error", "Unknown error"))
    if job["status"] != "complete":
        return render_template("error.html", message="Analysis not yet complete.")

    results = _load_results(job_id)
    if results is None:
        abort(404)

    return render_template(
        "report.html",
        results=results,
        job_id=job_id,
        filename=job.get("filename", ""),
    )


# ── History ───────────────────────────────────────────────────────
@app.route("/history")
def history():
    analyses = database.list_analyses(app.config["DATABASE_PATH"])
    return jsonify(analyses)


# ── Export routes ─────────────────────────────────────────────────
@app.route("/export/html/<job_id>")
def export_html(job_id: str):
    """Render a self-contained offline-capable HTML report."""
    results = _load_results(job_id)
    if results is None:
        abort(404)

    filename = _get_filename(job_id)
    rendered = render_template(
        "report.html",
        results=results,
        job_id=job_id,
        filename=filename,
    )
    standalone = build_standalone_html(rendered, app.static_folder)

    safe_name = secure_filename(filename).rsplit(".", 1)[0] or "report"
    return Response(
        standalone,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}_report.html"'
        },
    )


@app.route("/export/iocs/<job_id>")
def export_iocs_txt(job_id: str):
    """Download the IOC list as plain text."""
    results = _load_results(job_id)
    if results is None:
        abort(404)

    lines: list[str] = []
    for ioc in results.get("iocs", {}).get("iocs", []):
        lines.append(
            f"[{ioc['severity']}] {ioc['type']}: {ioc['value']} — {ioc['description']}"
        )

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="iocs_{job_id[:8]}.txt"'
        },
    )


@app.route("/export/csv/<job_id>")
def export_iocs_csv(job_id: str):
    """Download the IOC list as CSV."""
    results = _load_results(job_id)
    if results is None:
        abort(404)

    return Response(
        iocs_to_csv(results),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="iocs_{job_id[:8]}.csv"'
        },
    )


# ── Delete ────────────────────────────────────────────────────────
@app.route("/analysis/<job_id>", methods=["DELETE"])
def delete_analysis(job_id: str):
    """Remove an analysis from the database and delete its files."""
    database.delete_analysis(app.config["DATABASE_PATH"], job_id)

    # Remove JSON result
    data_path = os.path.join(app.config["DATA_FOLDER"], f"{job_id}.json")
    try:
        if os.path.exists(data_path):
            os.remove(data_path)
    except OSError:
        pass

    # Remove upload file (if still present)
    upload_dir = app.config["UPLOAD_FOLDER"]
    for fname in os.listdir(upload_dir):
        if fname.startswith(job_id):
            try:
                os.remove(os.path.join(upload_dir, fname))
            except OSError:
                pass

    jobs.pop(job_id, None)
    return jsonify({"ok": True})


# ── Browser auto-open ─────────────────────────────────────────────
def _open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["DATA_FOLDER"], exist_ok=True)
    database.init_db(app.config["DATABASE_PATH"])
    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(debug=False, host="127.0.0.1", port=5000)
