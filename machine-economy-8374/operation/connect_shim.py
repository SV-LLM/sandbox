import os, socket, sys, threading, base64, urllib.parse
target_host, target_port, listen_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
px = urllib.parse.urlparse(os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY'))
proxy_host, proxy_port = px.hostname, px.port or 3128
auth = ""
if px.username:
    creds = base64.b64encode(f"{urllib.parse.unquote(px.username)}:{urllib.parse.unquote(px.password or '')}".encode()).decode()
    auth = f"Proxy-Authorization: Basic {creds}\r\n"
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except OSError: pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except OSError: pass
def handle(client):
    try:
        up = socket.create_connection((proxy_host, proxy_port), timeout=15)
        req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth}\r\n"
        up.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = up.recv(4096)
            if not chunk: raise OSError("proxy closed during CONNECT")
            buf += chunk
        status = buf.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            print("CONNECT refused:", status.decode(errors="replace"), flush=True); client.close(); up.close(); return
        rest = buf.split(b"\r\n\r\n", 1)[1]
        if rest: client.sendall(rest)
        t = threading.Thread(target=pipe, args=(client, up), daemon=True); t.start()
        pipe(up, client)
    except Exception as e:
        print("shim error:", e, flush=True)
    finally:
        try: client.close()
        except OSError: pass
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen_port)); srv.listen(64)
print(f"shim listening 127.0.0.1:{listen_port} -> CONNECT -> {target_host}:{target_port}", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
