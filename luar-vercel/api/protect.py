import sys, io, tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(Path(__file__).parent.parent))

from luar_compiler import compile_lua
from luar_crypto import protect_payload
from luar_format import pack_luar


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        import cgi, json

        ctype, pdict = cgi.parse_header(self.headers.get("Content-Type", ""))
        if ctype != "multipart/form-data":
            self._json(400, {"error": "multipart/form-data required"})
            return

        pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
        pdict["CONTENT-LENGTH"] = int(self.headers.get("Content-Length", 0))
        fields = cgi.parse_multipart(self.rfile, pdict)

        seed_list = fields.get("seed")
        file_list = fields.get("file")
        fname_list = fields.get("filename")

        if not seed_list or not file_list:
            self._json(400, {"error": "Missing file or seed."})
            return

        seed = seed_list[0] if isinstance(seed_list[0], str) else seed_list[0].decode()
        raw  = file_list[0] if isinstance(file_list[0], bytes) else file_list[0].encode()
        fname = (fname_list[0] if fname_list else b"script.lua")
        if isinstance(fname, bytes): fname = fname.decode()

        source = raw.decode("utf-8", errors="replace")

        try:
            payload = compile_lua(source)
            ct, salt, nonce, tag = protect_payload(payload, seed)
        except Exception as e:
            self._json(400, {"error": str(e)})
            return

        with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        pack_luar(tmp_path, salt, nonce, ct, tag)
        data = tmp_path.read_bytes()
        tmp_path.unlink(missing_ok=True)

        out_name = Path(fname).stem + ".luar"
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{out_name}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, code, obj):
        import json
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_): pass
