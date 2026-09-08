import sys, io, tempfile, json
from pathlib import Path
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(Path(__file__).parent.parent))

from luar_crypto import unprotect_payload, AuthenticationError
from luar_format import unpack_luar, FormatError
from luar_runtime import execute_instructions, LuaRuntimeError


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        import cgi

        ctype, pdict = cgi.parse_header(self.headers.get("Content-Type", ""))
        if ctype != "multipart/form-data":
            self._json(400, {"error": "multipart/form-data required"})
            return

        pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
        pdict["CONTENT-LENGTH"] = int(self.headers.get("Content-Length", 0))
        fields = cgi.parse_multipart(self.rfile, pdict)

        seed_list = fields.get("seed")
        file_list = fields.get("file")

        if not seed_list or not file_list:
            self._json(400, {"error": "Missing file or seed."})
            return

        seed = seed_list[0] if isinstance(seed_list[0], str) else seed_list[0].decode()
        raw  = file_list[0] if isinstance(file_list[0], bytes) else file_list[0].encode()

        with tempfile.NamedTemporaryFile(suffix=".luar", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp_path.write_bytes(raw)

        try:
            salt, nonce, ct, tag = unpack_luar(tmp_path)
        except FormatError as e:
            tmp_path.unlink(missing_ok=True)
            self._json(400, {"error": f"Format error: {e}"})
            return
        finally:
            tmp_path.unlink(missing_ok=True)

        try:
            payload = unprotect_payload(ct, salt, nonce, tag, seed)
        except AuthenticationError:
            self._json(403, {"error": "Authentication failed — wrong seed or corrupted file."})
            return

        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            execute_instructions(payload)
        except LuaRuntimeError as e:
            sys.stdout = old_stdout
            self._json(400, {"error": f"Runtime error: {e}"})
            return
        except Exception as e:
            sys.stdout = old_stdout
            self._json(500, {"error": f"Unexpected error: {e}"})
            return
        finally:
            sys.stdout = old_stdout

        self._json(200, {"output": buf.getvalue()})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_): pass
