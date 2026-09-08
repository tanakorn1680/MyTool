import sys, io, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, request, jsonify
from luar_crypto import unprotect_payload, AuthenticationError
from luar_format import unpack_luar, FormatError
from luar_runtime import execute_instructions, LuaRuntimeError

app = Flask(__name__)

@app.route("/api/run", methods=["POST", "OPTIONS"])
def run():
    if request.method == "OPTIONS":
        return "", 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

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
    old_out = sys.stdout
    sys.stdout = buf
    try:
        execute_instructions(payload)
    except LuaRuntimeError as e:
        sys.stdout = old_out
        return jsonify(error=f"Runtime error: {e}"), 400
    except Exception as e:
        sys.stdout = old_out
        return jsonify(error=f"Unexpected error: {e}"), 500
    finally:
        sys.stdout = old_out

    return jsonify(output=buf.getvalue())

handler = app
