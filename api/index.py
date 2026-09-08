import sys, io, tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, request, send_file, jsonify
from luar_compiler import compile_lua
from luar_crypto import protect_payload, unprotect_payload, AuthenticationError
from luar_format import pack_luar, unpack_luar, FormatError
from luar_runtime import execute_instructions, LuaRuntimeError

STATIC = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")


# ── Helpers ───────────────────────────────────────────────────────────────────
def _do_protect():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file uploaded."), 400
    source = f.read().decode("utf-8", errors="replace")
    payload = compile_lua(source)
    ct, salt, nonce, tag, seed_hex = protect_payload(payload)
    with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        pack_luar(tmp_path, salt, nonce, ct, tag, seed_hex)
        data = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)
    stem = Path(f.filename).stem if f.filename else "protected"
    resp = send_file(
        io.BytesIO(data),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=stem + ".luar",
    )
    # Force download — ป้องกัน Android Chrome render เป็น HTML
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.luar"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _do_run():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file uploaded."), 400
    with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp_path.write_bytes(f.read())
    try:
        salt, nonce, ct, tag, seed_hex = unpack_luar(tmp_path)
    except FormatError as e:
        return jsonify(error=f"Format error: {e}"), 400
    finally:
        tmp_path.unlink(missing_ok=True)
    try:
        payload = unprotect_payload(ct, salt, nonce, tag, seed_hex)
    except AuthenticationError:
        return jsonify(error="Authentication failed."), 403
    buf = io.StringIO()
    sys.stdout, old = buf, sys.stdout
    try:
        execute_instructions(payload)
    except LuaRuntimeError as e:
        sys.stdout = old
        return jsonify(error=f"Runtime error: {e}"), 400
    finally:
        sys.stdout = old
    return jsonify(output=buf.getvalue())


def _serve_index():
    index_file = STATIC / "index.html"
    if not index_file.exists():
        return jsonify(error="index.html not found"), 500
    return send_file(str(index_file))


# ── Main dispatcher — handles Vercel calling /api/index for everything ────────
def _dispatch():
    # Vercel preserves the original path in PATH_INFO or these headers
    path = (
        request.environ.get("HTTP_X_ORIGINAL_URL") or
        request.environ.get("HTTP_X_REWRITE_URL") or
        request.environ.get("PATH_INFO") or
        "/"
    ).split("?")[0].rstrip("/") or "/"

    method = request.method

    try:
        if path == "/api/protect" and method == "POST":
            return _do_protect()
        elif path == "/api/run" and method == "POST":
            return _do_run()
        elif path in ("/api/protect", "/api/run"):
            return jsonify(error="Method not allowed"), 405
        else:
            return _serve_index()
    except Exception as e:
        return jsonify(error=str(e)), 500


# ── Routes ────────────────────────────────────────────────────────────────────
# Real Flask routes (work locally and on some Vercel configs)
@app.route("/api/protect", methods=["POST"])
def protect():
    try:
        return _do_protect()
    except Exception as e:
        return jsonify(error=str(e)), 400

@app.route("/api/run", methods=["POST"])
def run():
    try:
        return _do_run()
    except Exception as e:
        return jsonify(error=str(e)), 500

# Vercel entry point — called with ANY path rewritten to /api/index
@app.route("/api/index", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def vercel_entry():
    return _dispatch()

# Catch-all for local dev
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    return _serve_index()
