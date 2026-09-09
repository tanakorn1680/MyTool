import sys, io
from pathlib import Path

ROOT = Path(__file__).parent.parent if (Path(__file__).parent.parent / "luar_obfuscate.py").exists() \
       else Path(__file__).parent
sys.path.insert(0, str(ROOT))

from flask import Flask, request, send_file, jsonify
from luar_obfuscate import obfuscate_bytecode

STATIC = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")


def _do_protect():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file uploaded."), 400

    raw = f.read()
    if len(raw) == 0:
        return jsonify(error="File is empty."), 400

    try:
        result = obfuscate_bytecode(raw)
    except Exception as e:
        return jsonify(error=f"Protection error: {e}"), 400

    stem = Path(f.filename).stem if f.filename else "protected"
    out_name = stem + "_protected.lua"
    resp = send_file(
        io.BytesIO(result),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=out_name,
    )
    resp.headers["Content-Disposition"] = f'attachment; filename="{out_name}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _serve_index():
    index_file = STATIC / "index.html"
    if not index_file.exists():
        return jsonify(error="index.html not found"), 500
    return send_file(str(index_file))


def _dispatch():
    path = (
        request.environ.get("HTTP_X_ORIGINAL_URL") or
        request.environ.get("HTTP_X_REWRITE_URL") or
        request.headers.get("X-Original-URL") or
        request.headers.get("X-Rewrite-URL") or
        request.environ.get("PATH_INFO") or "/"
    ).split("?")[0].rstrip("/") or "/"

    try:
        if path == "/api/protect" and request.method == "POST":
            return _do_protect()
        elif path == "/api/protect":
            return jsonify(error="Method not allowed"), 405
        else:
            return _serve_index()
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/protect", methods=["POST"])
def protect():
    try:
        return _do_protect()
    except Exception as e:
        return jsonify(error=str(e)), 400

@app.route("/api/index", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def vercel_entry():
    return _dispatch()

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    return _serve_index()
