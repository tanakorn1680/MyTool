import sys, io, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, request, send_file, jsonify
from luar_compiler import compile_lua
from luar_crypto import protect_payload
from luar_format import pack_luar

app = Flask(__name__)

@app.route("/api/protect", methods=["POST", "OPTIONS"])
def protect():
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

    out_name = Path(f.filename).stem + ".luar"
    return send_file(
        io.BytesIO(data),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=out_name,
    )

handler = app
