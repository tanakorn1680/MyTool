import sys, io, tempfile
from pathlib import Path

# ── path setup ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, request, send_file, jsonify
from luar_compiler import compile_lua
from luar_crypto import protect_payload, unprotect_payload, AuthenticationError
from luar_format import pack_luar, unpack_luar, FormatError
from luar_runtime import execute_instructions, LuaRuntimeError

# ── Flask: explicit static folder so Vercel serverless finds it ─────────────
STATIC = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")


# ── Error handlers: always return JSON, never HTML ──────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not found"), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify(error="Method not allowed"), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error=f"Internal server error: {e}"), 500


# ── /api/protect ─────────────────────────────────────────────────────────────
@app.route("/api/protect", methods=["POST"])
def protect():
    try:
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
        return send_file(
            io.BytesIO(data),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=stem + ".luar",
        )

    except Exception as e:
        return jsonify(error=str(e)), 400


# ── /api/run (kept for internal use, not shown in UI) ────────────────────────
@app.route("/api/run", methods=["POST"])
def run():
    try:
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

    except Exception as e:
        return jsonify(error=str(e)), 500


# ── Catch-all → serve index.html ─────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    # Never let Flask 404 bubble up as HTML
    index_file = STATIC / "index.html"
    if not index_file.exists():
        return jsonify(error="index.html not found in static folder"), 500
    return send_file(str(index_file))
