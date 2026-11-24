"""Local fixture server for detonator tests. Fictional brand "Sandbox Bank / بنك التجربة" only."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGIN_PAGE = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>Sandbox Bank | بنك التجربة - تسجيل الدخول</title><link rel="icon" href="/favicon.png"></head>
<body><h1>بنك التجربة - Sandbox Bank</h1>
<p>تم تعليق حسابك. يرجى تسجيل الدخول للتحقق. Your account is suspended, log in to verify.</p>
<form action="/nowhere" method="post">
<label for="u">اسم المستخدم / Username</label><input id="u" name="username" type="text" placeholder="Username">
<label for="p">كلمة المرور / Password</label><input id="p" name="password" type="password">
<input name="otp" type="text" autocomplete="one-time-code" placeholder="OTP رمز التحقق">
<button type="submit">دخول</button></form></body></html>"""

BENIGN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Gardening tips blog</title></head>
<body><h1>Gardening tips</h1><p>Water your tomatoes early in the morning and mulch the beds to keep
the soil moist during the hot summer months. Compost improves soil structure.</p></body></html>"""

META_PAGE = """<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/final"><title>wait</title></head>
<body>Redirecting...</body></html>"""

JS_PAGE = """<!doctype html><html><head><title>loading</title></head><body>Loading...
<script>setTimeout(function(){ location.href = '/final'; }, 300);</script></body></html>"""

FP_PAGE = """<!doctype html><html><head><title>fp</title></head><body><pre id="o">hdr=__HDR__</pre><script>
document.getElementById('o').textContent += ' webdriver=' + navigator.webdriver + ' langs=' + navigator.languages.join(',') +
 ' touch=' + navigator.maxTouchPoints + ' chrome=' + (typeof window.chrome) + ' platform=' + navigator.platform +
 ' brands=' + (navigator.userAgentData ? navigator.userAgentData.brands.map(b => b.brand).join(',') : '') +
 ' st=' + String(setTimeout).indexOf('[native code]');
</script></body></html>"""

SHADOW_PAGE = """<!doctype html><html><head><title></title></head><body><div id="h"></div><script>
const r = document.getElementById('h').attachShadow({mode: 'closed'});
r.innerHTML = '<p>Sandbox Bank login - verify your account now</p><label for="p">Password</label>' +
  '<input id="p" name="password" type="password">';
</script></body></html>"""

BLANK_PAGE = "<!doctype html><html><head><title></title></head><body></body></html>"

# 1x1 PNG
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: str | bytes = b"", ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        try:
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        ua = self.headers.get("User-Agent", "")
        if p == "/r1":
            return self._send(302, headers={"Location": "/r2"})
        if p in ("/r2", "/r3", "/r4"):
            return self._send(301 if p == "/r3" else 302, headers={"Location": f"/r{int(p[2]) + 1}"})
        if p == "/r5":
            return self._send(302, headers={"Location": "/final"})
        if p == "/meta":
            return self._send(200, META_PAGE)
        if p == "/js":
            return self._send(200, JS_PAGE)
        if p == "/final":
            return self._send(200, LOGIN_PAGE)
        if p == "/cloak":
            return self._send(200, BENIGN_PAGE if "Googlebot" in ua else LOGIN_PAGE)
        if p == "/blank":
            return self._send(200, BLANK_PAGE)
        if p == "/slow":
            time.sleep(30)
            return self._send(200, BENIGN_PAGE)
        if p == "/js5":
            return self._send(200, JS_PAGE.replace("300", "4500"))
        if p == "/meta4":
            return self._send(200, META_PAGE.replace('content="0;', 'content="4;'))
        if p == "/fp":  # fingerprint echo: what a cloaker would see
            hdr = (self.headers.get("sec-ch-ua", "") + " | " + ua).replace("<", "")
            return self._send(200, FP_PAGE.replace("__HDR__", hdr))
        if p == "/shadow":
            return self._send(200, SHADOW_PAGE)
        if p == "/tall":
            return self._send(200, "<html><body><h1>Sandbox Bank tall page</h1>"
                              "<div style='height:30000px;background:linear-gradient(#fff,#00f)'>long</div></body></html>")
        if p == "/favicon.png":
            return self._send(200, PNG, ctype="image/png")
        return self._send(404, "<html><body>not found</body></html>")


def start() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
