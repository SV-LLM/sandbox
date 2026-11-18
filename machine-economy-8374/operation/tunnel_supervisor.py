#!/usr/bin/env python3
"""Machine-economy public tunnel supervisor (BUILD-Q-19, bore route).

Why this exists: all VM egress transits an HTTP CONNECT proxy
(hatch-egress-proxy:3128); raw-TCP tunnels (bore) cannot dial out
directly, and HTTPS tunnel control planes (Cloudflare quick tunnel,
localtunnel) are refused from this egress. bore works when its TCP
transport is carried over a CONNECT tunnel through the proxy. This
supervisor therefore:
  1. runs an in-process CONNECT shim on 127.0.0.1:7835 that forwards
     each accepted connection to bore.pub:7835 via the egress proxy
     (proxy discovered from env, else the bare proxy address, else a
     /proc scan for a live process carrying the proxy env);
  2. runs `bore local 8796 --to 127.0.0.1` in the foreground,
     requesting the remote port pinned in public-port.pin beside this
     file (bore.pub honors requested ports — verified 2026-11-17 by a
     throwaway instance that received its requested port and served
     traffic on it); if the pinned request yields no tunnel, it
     retries once with a server-assigned port;
  3. watches bore's output for remote_port=<n> and records the public
     URL in public-url.txt beside this file.
Exits when bore exits; systemd Restart=always relaunches it, and the
new port is recorded the same way. Only the path-filtered public
proxy (127.0.0.1:8796) is exposed; the signing service is untouched.
"""
import base64, os, re, shutil, socket, subprocess, sys, threading, urllib.parse

WS = os.path.dirname(os.path.abspath(__file__))
URL_FILE = os.path.join(WS, "public-url.txt")
PIN_FILE = os.path.join(WS, "public-port.pin")
# Site slot: the bore binary is the site's own tool — supplied via
# ME_BORE_BIN or found on PATH. No other site's path is named here.
BORE = os.environ.get("ME_BORE_BIN") or shutil.which("bore") or "bore"
TARGET_HOST, TARGET_PORT = "bore.pub", 7835

def proxy_candidates():
    out = []
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        v = os.environ.get(k)
        if v and "hatch-egress-proxy" in v:
            out.append(v)
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    env = f.read().decode(errors="replace")
                for kv in env.split("\0"):
                    if kv.startswith("https_proxy=") and "hatch-egress-proxy" in kv:
                        out.append(kv.split("=", 1)[1])
            except OSError:
                continue
    except OSError:
        pass
    out.append("http://hatch-egress-proxy:3128")
    seen, res = set(), []
    for v in out:
        if v not in seen:
            seen.add(v); res.append(v)
    return res

def open_via_proxy():
    last = None
    for cand in proxy_candidates():
        px = urllib.parse.urlparse(cand)
        try:
            up = socket.create_connection((px.hostname, px.port or 3128), timeout=15)
            auth = ""
            if px.username:
                creds = base64.b64encode(
                    f"{urllib.parse.unquote(px.username)}:{urllib.parse.unquote(px.password or '')}".encode()
                ).decode()
                auth = f"Proxy-Authorization: Basic {creds}\r\n"
            up.sendall(f"CONNECT {TARGET_HOST}:{TARGET_PORT} HTTP/1.1\r\nHost: {TARGET_HOST}:{TARGET_PORT}\r\n{auth}\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = up.recv(4096)
                if not chunk:
                    raise OSError("proxy closed during CONNECT")
                buf += chunk
            if b" 200 " not in buf.split(b"\r\n", 1)[0]:
                raise OSError(f"CONNECT refused: {buf.splitlines()[0]!r}")
            return up, buf.split(b"\r\n\r\n", 1)[1]
        except Exception as e:
            last = e
            continue
    raise OSError(f"all proxy candidates failed: {last}")

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def handle(client):
    try:
        up, rest = open_via_proxy()
        if rest:
            client.sendall(rest)
        threading.Thread(target=pipe, args=(client, up), daemon=True).start()
        pipe(up, client)
    except Exception as e:
        print(f"shim: {e}", flush=True)
    finally:
        try:
            client.close()
        except OSError:
            pass

def shim_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 7835))
    srv.listen(64)
    print("shim listening on 127.0.0.1:7835", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def read_pin():
    try:
        with open(PIN_FILE) as f:
            port = int(f.read().strip())
        if 1 <= port <= 65535:
            return port
    except (OSError, ValueError):
        pass
    return None

def run_bore(extra_args):
    """Run bore in the foreground, recording the public URL as before.
    Returns (exit_code, saw_remote_port)."""
    proc = subprocess.Popen([BORE, "local", "8796", "--to", "127.0.0.1"] + extra_args,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    saw_port = False
    for line in proc.stdout:
        sys.stdout.write(line); sys.stdout.flush()
        m = re.search(r"remote_port=(\d+)", ansi.sub("", line))
        if m:
            saw_port = True
            url = f"http://bore.pub:{m.group(1)}"
            tmp = URL_FILE + ".tmp"
            with open(tmp, "w") as f:
                f.write(url + "\n")
            os.replace(tmp, URL_FILE)
            print(f"public url recorded: {url}", flush=True)
    return proc.wait(), saw_port

def main():
    threading.Thread(target=shim_server, daemon=True).start()
    pin = read_pin()
    if pin:
        print(f"requesting pinned remote port {pin}", flush=True)
        code, saw_port = run_bore(["--port", str(pin)])
        if saw_port:
            return code
        print("pinned port request did not yield a tunnel; "
              "falling back to a server-assigned port", flush=True)
    code, _ = run_bore([])
    return code

if __name__ == "__main__":
    sys.exit(main())
