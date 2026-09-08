import sys, io, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, request, send_file, jsonify
from luar_compiler import compile_lua
from luar_crypto import protect_payload, unprotect_payload, AuthenticationError
from luar_format import pack_luar, unpack_luar, FormatError
from luar_runtime import execute_instructions, LuaRuntimeError

app = Flask(__name__)


@app.route("/api/protect", methods=["POST"])
def protect():
    f    = request.files.get("file")
    seed = request.form.get("seed", "").strip()
    if not f:    return jsonify(error="No file uploaded."), 400
    if not seed: return jsonify(error="Seed is required."), 400

    source = f.read().decode("utf-8", errors="replace")
    try:
        payload = compile_lua(source)
        ct, salt, nonce, tag = protect_payload(payload, seed)
    except Exception as e:
        return jsonify(error=str(e)), 400

    with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    pack_luar(tmp_path, salt, nonce, ct, tag)
    data = tmp_path.read_bytes()
    tmp_path.unlink(missing_ok=True)

    return send_file(
        io.BytesIO(data),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=Path(f.filename).stem + ".luar",
    )


@app.route("/api/run", methods=["POST"])
def run():
    f    = request.files.get("file")
    seed = request.form.get("seed", "").strip()
    if not f:    return jsonify(error="No file uploaded."), 400
    if not seed: return jsonify(error="Seed is required."), 400

    with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp_path.write_bytes(f.read())

    try:
        salt, nonce, ct, tag = unpack_luar(tmp_path)
    except FormatError as e:
        return jsonify(error=f"Format error: {e}"), 400
    finally:
        tmp_path.unlink(missing_ok=True)

    try:
        payload = unprotect_payload(ct, salt, nonce, tag, seed)
    except AuthenticationError:
        return jsonify(error="Authentication failed — wrong seed or corrupted file."), 403

    buf = io.StringIO()
    sys.stdout, old = buf, sys.stdout
    try:
        execute_instructions(payload)
    except LuaRuntimeError as e:
        sys.stdout = old
        return jsonify(error=f"Runtime error: {e}"), 400
    except Exception as e:
        sys.stdout = old
        return jsonify(error=f"Unexpected error: {e}"), 500
    finally:
        sys.stdout = old

    return jsonify(output=buf.getvalue())


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    return app.send_static_file("index.html")
