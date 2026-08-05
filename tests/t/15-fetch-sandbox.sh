#!/bin/sh
# libfetch sandbox broker tests.  fetch(1) enters the path-scoped
# sandbox (cwd+TMPDIR rw) and all connects go through the broker
# process; parsing happens fully confined.

. "$CU_LIB/lib.sh"

group "libfetch sandbox: availability"

# Same capability detection as 14-sandbox: qemu-user lacks Landlock.
sandbox_available=1
if have shimtest; then
    "$(tool shimtest)" >/dev/null 2>&1
    [ $? -eq 77 ] && sandbox_available=0
fi
[ "${ASTROUTILS_SANDBOX:-}" = "NONE" ] && sandbox_available=0

if [ "$sandbox_available" = 0 ]; then
    skip "libfetch sandbox" "sandbox not enforcing on this runtime"
    cu_finish
    exit 0
fi

group "libfetch sandbox: HTTP via broker"

if ! require "fetch" fetch || ! have_host python3; then
    skip "fetch sandbox tests" "fetch or python3 unavailable"
    cu_finish
    exit 0
fi

mkdir -p srv
printf 'fetch-sandbox-fixture\n' > srv/real.txt

# unique ports per run: parallel suites must not collide
http_port=$((18000 + ($$ % 2000)))
tls_port=$((20000 + ($$ % 2000)))

cat > srv/server.py <<EOF
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redir':
            self.send_response(302)
            self.send_header('Location', '/real.txt')
            self.end_headers()
            return
        if self.path == '/redir-badport':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:6666/real.txt')
            self.end_headers()
            return
        try:
            with open('srv/real.txt', 'rb') as f:
                data = f.read()
        except OSError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('127.0.0.1', $http_port), H).serve_forever()
EOF
python3 srv/server.py &
srv_pid=$!
trap 'kill $srv_pid 2>/dev/null' EXIT
sleep 1

assert_ok "fetch over brokered HTTP" \
    "$(tool fetch)" -q -o direct.out http://127.0.0.1:$http_port/real.txt
assert_out "direct content correct" "fetch-sandbox-fixture" \
    "$(tool cat)" direct.out

assert_ok "fetch follows a brokered redirect" \
    "$(tool fetch)" -q -o redir.out http://127.0.0.1:$http_port/redir
assert_out "redirect content correct" "fetch-sandbox-fixture" \
    "$(tool cat)" redir.out

assert_ok "fetch -o outside cwd registers the directory" \
    "$(tool fetch)" -q -o srv/outside.out \
    http://127.0.0.1:$http_port/real.txt

# file:// outside the allowed roots must fail under Landlock
assert_contains "file:// outside roots denied" "Permission denied" \
    "$(tool fetch)" -q file:///etc/passwd

# broker port policy: the run's first port is pinned; a redirect to a
# different custom port fails closed
assert_contains "redirect to unpinned port denied by broker" \
    "Permission denied" \
    "$(tool fetch)" -q http://127.0.0.1:$http_port/redir-badport

group "libfetch sandbox: TLS with preloaded CA store"

if have_host openssl; then
    openssl req -x509 -newkey rsa:2048 -keyout srv/key.pem \
        -out srv/cert.pem -days 1 -nodes -subj '/CN=localhost' \
        >/dev/null 2>&1
    cat > srv/tlsserver.py <<EOF
import http.server, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open('srv/real.txt', 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(('127.0.0.1', $tls_port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('srv/cert.pem', 'srv/key.pem')
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
    python3 srv/tlsserver.py &
    tls_pid=$!
    sleep 1
    assert_ok "fetch over HTTPS with preloaded CA store" \
        env SSL_CA_CERT_FILE="$CU_WORK/srv/cert.pem" \
        "$(tool fetch)" -q -o tls.out https://localhost:$tls_port/real.txt
    assert_out "HTTPS content correct" "fetch-sandbox-fixture" \
        "$(tool cat)" tls.out
    kill $tls_pid 2>/dev/null
else
    skip "TLS with preloaded CA store" "openssl unavailable"
fi

group "libfetch sandbox: escape hatch"

assert_out "ASTROUTILS_SANDBOX=NONE goes direct" \
    "fetch-sandbox-fixture" \
    env ASTROUTILS_SANDBOX=NONE "$(tool fetch)" -q -o /dev/stdout \
    http://127.0.0.1:$http_port/real.txt

cu_finish
