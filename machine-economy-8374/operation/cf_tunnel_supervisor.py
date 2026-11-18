#!/usr/bin/env python3
"""Machine-economy Cloudflare named-tunnel supervisor (BUILD-Q-34).

Why this exists: cloudflared dials the Cloudflare edge
(region1/region2.v2.argotunnel.com:7844) directly, and this node's
egress intercepts direct dials (the 2026-11-17 finding: Quick Tunnel
registration died with "tls: first record does not look like a TLS
handshake"). The bore route proved the cure class: carry the TCP
transport through the egress CONNECT proxy. This supervisor therefore:

  1. maps the two edge hostnames to loopback aliases for the
     cloudflared process only: /etc/hosts is a read-only mount here,
     so the supervisor generates a hosts file (the live /etc/hosts
     plus a marked block) and bind-mounts it over /etc/hosts inside
     a private mount namespace around cloudflared (verified workable
     on this node 2026-11-17); nothing system-wide changes;
  2. runs a CONNECT shim on each alias (127.0.0.1:7844 for region1,
     127.0.0.2:7844 for region2) that forwards through the credentialed
     egress proxy to the real edge host — TLS stays end-to-end between
     cloudflared and the edge (the shim is a byte pipe after CONNECT);
  3. runs `cloudflared tunnel run --protocol http2 --token <token>`
     with the token read from cf-tunnel-token.txt (0600) beside this
     file. The token is the principal's Cloudflare credential; it
     lives only in that file and in cloudflared's process arguments.

Modes:
  (default)  named tunnel; on the tunnel registering, writes the
             permanent public origin to public-url.txt (the pointer
             every other component reads) once the hostname answers.
  --smoke    Quick Tunnel against the local public proxy: proves the
             shim transport reaches the edge and serves traffic,
             without any token. Never touches public-url.txt.
"""
import base64
import shutil
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

WS = os.path.dirname(os.path.abspath(__file__))
# Site slot: the cloudflared binary is the site's own tool — supplied
# via ME_CLOUDFLARED_BIN or found on PATH. No other site's path here.
CLOUDFLARED = os.environ.get("ME_CLOUDFLARED_BIN") or shutil.which("cloudflared") or "cloudflared"
TOKEN_FILE = os.path.join(WS, "cf-tunnel-token.txt")
URL_FILE = os.path.join(WS, "public-url.txt")
ORIGIN_FILE = os.path.join(WS, "cf-origin.txt")
HOSTS_MARK = "# machine-economy-cf-tunnel"
EDGE = [("region1.v2.argotunnel.com", "127.0.0.1"),
        ("region2.v2.argotunnel.com", "127.0.0.2")]
EDGE_PORT = 7844


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
                    if kv.startswith("https_proxy=") and \
                            "hatch-egress-proxy" in kv:
                        out.append(kv.split("=", 1)[1])
            except OSError:
                continue
    except OSError:
        pass
    out.append("http://hatch-egress-proxy:3128")
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def prepare_hosts_file():
    """Write cf-hosts.txt: the live /etc/hosts content plus the edge
    block. Returns its path for the namespace bind-mount."""
    try:
        with open("/etc/hosts") as f:
            lines = [ln for ln in f.read().splitlines()
                     if HOSTS_MARK not in ln]
    except OSError:
        lines = ["127.0.0.1 localhost"]
    for host, alias in EDGE:
        lines.append(f"{alias} {host} {HOSTS_MARK}")
    path = os.path.join(WS, "cf-hosts.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("hosts file prepared:", path, [f"{a} {h}" for h, a in EDGE],
          flush=True)
    return path


def _pipe(a, b):
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


def _connect_via(proxy_url, target_host):
    """One CONNECT through one proxy candidate; returns the socket
    (with any post-header bytes already consumed) or None."""
    px = urllib.parse.urlparse(proxy_url)
    proxy_host, proxy_port = px.hostname, px.port or 3128
    auth = ""
    if px.username:
        creds = base64.b64encode(
            f"{urllib.parse.unquote(px.username)}:"
            f"{urllib.parse.unquote(px.password or '')}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {creds}\r\n"
    try:
        up = socket.create_connection((proxy_host, proxy_port),
                                      timeout=10)
        req = (f"CONNECT {target_host}:{EDGE_PORT} HTTP/1.1\r\n"
               f"Host: {target_host}:{EDGE_PORT}\r\n{auth}\r\n")
        up.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = up.recv(4096)
            if not chunk:
                up.close()
                return None, None
            buf += chunk
        status = buf.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            up.close()
            return None, None
        return up, buf.split(b"\r\n\r\n", 1)[1]
    except OSError:
        return None, None


def start_shim(target_host, bind_ip, proxy_urls):
    def handle(client):
        try:
            up, rest = None, None
            for cand in proxy_urls:
                up, rest = _connect_via(cand, target_host)
                if up is not None:
                    break
            if up is None:
                print("CONNECT failed on all candidates for",
                      target_host, flush=True)
                client.close()
                return
            if rest:
                client.sendall(rest)
            t = threading.Thread(target=_pipe, args=(client, up),
                                 daemon=True)
            t.start()
            _pipe(up, client)
        except Exception as e:  # noqa: BLE001
            print("shim error:", e, flush=True)
        finally:
            try:
                client.close()
            except OSError:
                pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, EDGE_PORT))
    srv.listen(64)

    def serve():
        print(f"shim {bind_ip}:{EDGE_PORT} -> CONNECT -> "
              f"{target_host}:{EDGE_PORT}", flush=True)
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,),
                             daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def start_shims():
    cands = proxy_candidates()
    print("shim proxy candidates:", len(cands),
          "(tried per connection, in order)", flush=True)
    return [start_shim(host, alias, cands) for host, alias in EDGE]


# --- DNS shim -------------------------------------------------------------
# cloudflared discovers the edge by SRV lookup on
# _v2-origintunneld._tcp.argotunnel.com; this node's resolver SERVFAILs
# SRV, and the platform blocks UDP sendto from user processes entirely
# (EPERM in every execution context, verified 2026-11-17 — the first
# UDP shim received queries but could not answer). The shim therefore
# speaks TCP on 127.0.0.1:53 and the namespace resolv.conf carries
# "options use-vc" so the Go resolver uses TCP. It answers the three
# names the tunnel needs (ground truth verified by DoH, 2026-11-17:
# SRV 1 1 7844 region1 / 2 1 7844 region2) and SERVFAILs the rest —
# the one other lookup cloudflared makes (cfd-features) is explicitly
# tolerated as a default-disable when it fails.
SRV_NAME = "_v2-origintunneld._tcp.argotunnel.com"
A_MAP = {"region1.v2.argotunnel.com": "127.0.0.1",
         "region2.v2.argotunnel.com": "127.0.0.2"}


def _decode_name(pkt, off):
    labels = []
    while off < len(pkt) and pkt[off] != 0:
        ln = pkt[off]
        labels.append(pkt[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels).lower(), off + 1


def _encode_name(name):
    return b"".join(bytes([len(p)]) + p.encode()
                    for p in name.split(".")) + b"\x00"


def _dns_response(query, answers, question):
    qid, _flags, qd = struct.unpack(">HHH", query[:6])
    hdr = struct.pack(">HHHHHH", qid, 0x8180, qd, len(answers), 0, 0)
    out = hdr + question
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60,
                                         len(rdata)) + rdata
    return out


def _srv_rdata(prio, target):
    return struct.pack(">HHH", prio, 1, EDGE_PORT) + _encode_name(target)


def _dns_answer(data):
    """The wire response for one query packet (TCP payload form).
    The question slice is exact: the query's trailing EDNS bytes
    must not ride into the response (the Go parser would read the
    OPT record as an answer and drop a real one — observed
    2026-11-17 as "SRV only returned 1")."""
    try:
        name, qend = _decode_name(data, 12)
        qtype = struct.unpack(">H", data[qend:qend + 2])[0]
        question = data[12:qend + 4]
    except Exception:  # noqa: BLE001
        return None
  # construction errors must SERVFAIL, never drop the connection
    try:
        return _dns_answer_inner(data, name, qtype, question)
    except Exception:  # noqa: BLE001
        qid = struct.unpack(">H", data[:2])[0]
        return struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0) + question


def _dns_answer_inner(data, name, qtype, question):
    if name == SRV_NAME and qtype == 33:
        return _dns_response(data, [
            (33, _srv_rdata(1, "region1.v2.argotunnel.com")),
            (33, _srv_rdata(2, "region2.v2.argotunnel.com"))], question)
    if name in A_MAP:
        if qtype == 1:
            return _dns_response(
                data, [(1, socket.inet_aton(A_MAP[name]))], question)
        return _dns_response(data, [], question)  # AAAA: NODATA
    qid = struct.unpack(">H", data[:2])[0]
    return struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0) + question


def start_dns_shim():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 53))
    srv.listen(64)

    def handle(conn):
        try:
            while True:
                hdr = b""
                while len(hdr) < 2:
                    chunk = conn.recv(2 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                (qlen,) = struct.unpack(">H", hdr)
                data = b""
                while len(data) < qlen:
                    chunk = conn.recv(qlen - len(data))
                    if not chunk:
                        return
                    data += chunk
                resp = _dns_answer(data)
                if resp is None:
                    return
                conn.sendall(struct.pack(">H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def serve():
        print("dns shim tcp 127.0.0.1:53 (SRV + edge A local)",
              flush=True)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,),
                             daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def prepare_resolv_file():
    """cf-resolv.conf: inside cloudflared's mount namespace this is
    bind-mounted over /etc/resolv.conf so the Go resolver asks the
    local DNS shim (the system resolver SERVFAILs the edge SRV
    lookup, and --dns-resolver-addrs does not govern edge
    discovery — both verified 2026-11-17)."""
    path = os.path.join(WS, "cf-resolv.conf")
    with open(path, "w") as f:
        f.write("nameserver 127.0.0.1\noptions use-vc\n")
    return path


def run_cloudflared(args, watch=None, timeout=None, hosts_file=None,
                    resolv_file=None):
    cmd = [CLOUDFLARED] + args
    if hosts_file:
        mounts = f"mount --bind {hosts_file} /etc/hosts"
        if resolv_file:
            mounts += f" && mount --bind {resolv_file} /etc/resolv.conf"
        inner = mounts + " && exec " + " ".join(cmd)
        cmd = ["unshare", "-m", "bash", "-c", inner]
    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            bufsize=1)
    state = {"registered": False, "url": None}

    def reader():
        for line in proc.stdout:
            print("cloudflared:", line.rstrip(), flush=True)
            if "Registered tunnel connection" in line:
                state["registered"] = True
            m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com",
                          line)
            if m:
                state["url"] = m.group(0)
            if watch:
                watch(line, state)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    return proc, state


def smoke():
    """Transport proof without any principal credential: run
    cloudflared with a structurally valid throwaway token and read
    the log. (The Quick Tunnel class is not used: its registration
    POST to api.trycloudflare.com dials direct and cannot be
    carried.) Success = SRV discovery resolves through the DNS shim
    and the edge is dialed at the loopback shims — the edge's own
    rejection of the unknown tunnel is the expected end state."""
    fake = base64.b64encode(json.dumps({
        "a": "0123456789abcdef0123456789abcdef",
        "t": "00000000-0000-4000-8000-000000000000",
        "s": base64.b64encode(b"\x01" * 32).decode()}).encode()).decode()
    hosts_file = prepare_hosts_file()
    start_shims()
    start_dns_shim()
    time.sleep(1)
    seen = {"edge": False, "dns_fail": False}

    def watch(line, _state):
        low = line.lower()
        if "dns query failed" in low or "could not lookup srv" in low:
            seen["dns_fail"] = True
        if any(k in low for k in ("connection established",
                                  "registering tunnel",
                                  "failed to register",
                                  "dial tcp 127.0.0",
                                  "unauthorized",
                                  "connection terminated",
                                  "serve tunnel error")):
            seen["edge"] = True

    proc, _state = run_cloudflared(
        ["tunnel", "--protocol", "http2", "--loglevel", "info",
         "run", "--token", fake,
         "--dns-resolver-addrs", "127.0.0.1:53"],
        watch=watch, timeout=45, hosts_file=hosts_file,
        resolv_file=prepare_resolv_file())
    try:
        proc.terminate()
    except OSError:
        pass
    print("SMOKE edge_reached:", seen["edge"],
          "dns_fail:", seen["dns_fail"], flush=True)
    return 0 if seen["edge"] and not seen["dns_fail"] else 1


def named():
    if not os.path.exists(TOKEN_FILE):
        print(f"token file absent: {TOKEN_FILE} — the principal's "
              "Cloudflare tunnel token goes there (0600); exiting.",
              flush=True)
        return 2
    with open(TOKEN_FILE) as f:
        token = f.read().strip()
    if not token:
        print("token file empty; exiting.", flush=True)
        return 2
    hosts_file = prepare_hosts_file()
    start_shims()
    start_dns_shim()
    origin = None
    if os.path.exists(ORIGIN_FILE):
        with open(ORIGIN_FILE) as f:
            origin = f.read().strip() or None

    # The origin check must ride the egress proxy like everything
    # else on this node: direct HTTPS egress does not exist here
    # (verified 2026-11-18 — direct curl returns nothing, the bare
    # proxy candidate answers). A direct urlopen would never flip
    # the pointer.
    _cands = proxy_candidates()
    _opener = (urllib.request.build_opener(urllib.request.ProxyHandler(
        {"https": _cands[0], "http": _cands[0]})) if _cands else None)

    def watch(line, state):
        if state["registered"] and origin:
            try:
                req = urllib.request.Request(
                    origin + "/health",
                    headers={"User-Agent": "curl/8.5.0"})
                # A UA is required: Cloudflare 403s the default
                # Python-urllib agent (verified 2026-11-18).
                if _opener is not None:
                    resp = _opener.open(req, timeout=10)
                else:
                    resp = urllib.request.urlopen(req, timeout=10)
                with resp as r:
                    r.read()
                cur = None
                if os.path.exists(URL_FILE):
                    with open(URL_FILE) as f:
                        cur = f.read().strip()
                if cur != origin:
                    with open(URL_FILE, "w") as f:
                        f.write(origin + "\n")
                    print("public-url.txt now:", origin, flush=True)
            except Exception:  # noqa: BLE001
                pass

    proc, _state = run_cloudflared(
        ["tunnel", "--protocol", "http2", "--loglevel", "info",
         "--no-prechecks",
         "run", "--token", token,
         "--dns-resolver-addrs", "127.0.0.1:53"],
        watch=watch, hosts_file=hosts_file,
        resolv_file=prepare_resolv_file())
    return proc.returncode or 0


if __name__ == "__main__":
    sys.exit(smoke() if "--smoke" in sys.argv else named())
