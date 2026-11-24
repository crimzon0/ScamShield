"""Breaker fixture server: adversarial delivery mechanics. Fictional brand "Sandbox Bank / بنك التجربة" only.

Routes
  /phish                 Sandbox Bank login (username, password, OTP) - the payload
  /benign                unrelated gardening page
  /chain/<n>             12-hop chain mixing 302 / 301 / meta refresh / JS -> /phish
  /loop/a, /loop/b       infinite 302 loop
  /cloak                 Googlebot / desktop en-US -> benign; mobile + ar-AE -> phish
  /refgate               Referer from google -> phish; otherwise benign
  /jsonly                empty HTML; the phishing form is built by JavaScript
  /delayed               form inserted 3 s after load
  /blank                 empty body
  /huge                  ~6 MB of text followed by the phishing form
  /slow                  sleeps 60 s before answering
  /iframe                benign shell that embeds /phish in a full-size iframe
  /shadow                phishing form inside a closed shadow root
  /jsdelay               benign "checking your browser" page, JS redirect to /phish after 4 s
  /aronly                Arabic-only phishing page (brand named only as بنك التجربة)
  /shared/sandboxbank-login/   phish served under a path (shared-host-like)
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FORM = """<form action="/nowhere" method="post" onsubmit="return false">
<label for="u">اسم المستخدم / Username</label><input id="u" name="username" type="text">
<label for="p">كلمة المرور / Password</label><input id="p" name="password" type="password">
<label for="o">رمز التحقق / OTP</label><input id="o" name="otp" type="text" autocomplete="one-time-code">
<button type="submit">دخول</button></form>"""

PHISH = f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>Sandbox Bank | بنك التجربة - تسجيل الدخول</title></head>
<body><h1>بنك التجربة - Sandbox Bank</h1>
<p>تم تعليق حسابك. Your account is suspended. Verify your account within 24 hours.</p>{FORM}</body></html>"""

BENIGN = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Gardening tips blog</title></head>
<body><h1>Gardening tips</h1><p>Water your tomatoes early in the morning and mulch the beds to keep
the soil moist during the hot summer months. Compost improves soil structure and feeds worms.</p></body></html>"""

JSONLY = """<!doctype html><html><head><meta charset="utf-8"><title></title></head><body><div id="app"></div>
<script>
var t = ['Sandbox Bank', ' | ', 'بنك التجربة'];
document.title = t.join('') + ' - Login';
document.getElementById('app').innerHTML = '<h1>' + t[0] + ' - ' + t[2] + '</h1>' +
  '<p>Your account is suspended. Verify your account now.</p>' + atob('__FORM_B64__');
</script></body></html>"""

DELAYED = """<!doctype html><html><head><meta charset="utf-8"><title>Loading...</title></head><body>
<div id="app">Loading, please wait...</div>
<script>setTimeout(function(){
 document.title = 'Sandbox Bank | بنك التجربة - Login';
 document.getElementById('app').innerHTML = '<h1>Sandbox Bank - بنك التجربة</h1>' +
  '<p>Your account is suspended. Verify your account.</p>' + atob('__FORM_B64__');
}, 3000);</script></body></html>"""

SHADOW = """<!doctype html><html><head><meta charset="utf-8"><title>Sandbox Bank Online</title></head><body>
<div id="host"></div><script>
var r = document.getElementById('host').attachShadow({mode: 'closed'});
r.innerHTML = '<h1>Sandbox Bank - بنك التجربة</h1>' +
  '<p>Your account is suspended. Verify your account.</p>' + atob('__FORM_B64__');
</script></body></html>"""

ARONLY = f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>بنك التجربة - الخدمات المصرفية عبر الإنترنت</title></head>
<body><h1>بنك التجربة</h1><p>تم إيقاف حسابك مؤقتاً. يرجى تحديث بياناتك وإدخال رمز التحقق المرسل إلى هاتفك خلال 24 ساعة.</p>
<form onsubmit="return false"><label>رقم الهوية الإماراتية</label><input name="eid" type="text">
<label>كلمة المرور</label><input name="pw" type="password"><label>رمز التحقق</label><input name="code" type="text">
<button>متابعة</button></form></body></html>"""

BLANK = "<!doctype html><html><head><title></title></head><body></body></html>"

CHAIN_LEN = 12
# hop kind per index: h=302, p=301 (permanent), m=meta refresh, j=JS location
CHAIN_KINDS = "hpmjhmjhpjmh"


def _b64_form() -> str:
    import base64

    return base64.b64encode(FORM.encode("utf-8")).decode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body: str | bytes = b"", headers=None, ctype="text/html; charset=utf-8"):
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

    def _redir(self, to, code=302):
        self._send(code, f"<a href='{to}'>moved</a>", {"Location": to})

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        ua = self.headers.get("User-Agent", "")
        lang = self.headers.get("Accept-Language", "")
        ref = self.headers.get("Referer", "")
        if p in ("/phish", "/shared/sandboxbank-login/"):
            return self._send(200, PHISH)
        if p == "/benign":
            return self._send(200, BENIGN)
        if p.startswith("/chain/"):
            try:
                i = int(p.rsplit("/", 1)[1])
            except ValueError:
                return self._send(404, "nf")
            nxt = "/phish" if i + 1 >= CHAIN_LEN else f"/chain/{i + 1}"
            k = CHAIN_KINDS[i % len(CHAIN_KINDS)]
            if k == "h":
                return self._redir(nxt, 302)
            if k == "p":
                return self._redir(nxt, 301)
            if k == "m":
                return self._send(200, f"<html><head><meta http-equiv='refresh' content='0;url={nxt}'>"
                                       f"<title>.</title></head><body>...</body></html>")
            return self._send(200, f"<html><head><title>.</title></head><body>...<script>"
                                   f"setTimeout(function(){{location.replace('{nxt}')}},100)</script></body></html>")
        if p == "/loop/a":
            return self._redir("/loop/b")
        if p == "/loop/b":
            return self._redir("/loop/a")
        if p == "/cloak":
            bot = "googlebot" in ua.lower() or "bot" in ua.lower()
            mobile = "Mobile" in ua or "Android" in ua or "iPhone" in ua
            if not bot and mobile and lang.lower().startswith("ar"):
                return self._send(200, PHISH)
            return self._send(200, BENIGN)
        if p == "/refgate":
            return self._send(200, PHISH if "google." in ref else BENIGN)
        if p == "/jsonly":
            return self._send(200, JSONLY.replace("__FORM_B64__", _b64_form()))
        if p == "/delayed":
            return self._send(200, DELAYED.replace("__FORM_B64__", _b64_form()))
        if p == "/blank":
            return self._send(200, BLANK)
        if p == "/huge":
            filler = ("<p>" + "lorem ipsum dolor sit amet " * 40 + "</p>\n") * 5500  # ~6 MB
            return self._send(200, PHISH.replace("<body>", "<body>" + filler, 1))
        if p == "/slow":
            time.sleep(60)
            return self._send(200, BENIGN)
        if p == "/iframe":
            return self._send(200, "<!doctype html><html><head><meta charset='utf-8'><title>Secure portal</title></head>"
                                   "<body style='margin:0'><iframe src='/phish' style='border:0;width:100vw;height:100vh'>"
                                   "</iframe></body></html>")
        if p == "/shadow":
            return self._send(200, SHADOW.replace("__FORM_B64__", _b64_form()))
        if p == "/jsdelay":
            return self._send(200, "<!doctype html><html><head><title>Just a moment...</title></head><body>"
                                   "Checking your browser before accessing the site.<script>setTimeout(function(){"
                                   "location.href='/phish'},4000)</script></body></html>")
        if p == "/aronly":
            return self._send(200, ARONLY)
        return self._send(404, "<html><body>not found</body></html>")


def start(host: str = "127.0.0.1") -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer((host, 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
