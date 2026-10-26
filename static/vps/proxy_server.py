#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64, json, struct, random
from typing import Any

# [安全] 凭证不再由 C2 下发时硬编码，改为读取本机 600 权限的 c2.json（由 /agent 安装脚本写入）
def _load_c2_conf():
    try:
        with open("/opt/proxy_lite/c2.json", "r") as _f:
            return json.load(_f)
    except Exception:
        return {}
_C2CONF = _load_c2_conf()
PROXY_USER = str(_C2CONF.get("proxy_user", "")).encode()
PROXY_PASS = str(_C2CONF.get("proxy_pass", "")).encode()

# [安全] 连接数上限与空闲超时，防线程耗尽 DoS
_MAX_CONN = 200
_conn_sem = threading.BoundedSemaphore(_MAX_CONN)
_IDLE_TIMEOUT = 300

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def _dns_query(host: str, bind_interface: str, dns_server: str = "8.8.8.8", timeout: float = 8) -> str:
    # [安全] 极简 DNS/UDP 客户端：查询走隧道内，防止把代理目标域名暴露给 VPS 服务商
    qid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join([bytes([len(label)]) + label.encode("idna") for label in host.rstrip(".").split(".")]) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        if bind_interface:
            s.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode("utf-8"))
        s.sendto(packet, (dns_server, 53))
        data, _ = s.recvfrom(512)
    finally:
        s.close()
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
        raise OSError("bad dns reply")
    ancount = struct.unpack(">H", data[6:8])[0]
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    for _ in range(ancount):
        if off + 10 > len(data):
            break
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            return socket.inet_ntoa(rdata)
    raise OSError("no A record")

def resolve_host(host: str, bind_interface: str) -> str:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return host
        except OSError:
            pass
    try:
        if bind_interface:
            return _dns_query(host, bind_interface)
    except Exception:
        pass
    return socket.gethostbyname(host)

def create_connection(address: tuple[str, int], bind_interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    err = None
    try:
        resolved = resolve_host(host, bind_interface)
    except Exception as e:
        raise OSError("dns failed: {}".format(e))
    for res in socket.getaddrinfo(resolved, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    last_active = time.time()
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 60)
        if errored:
            return
        if time.time() - last_active > _IDLE_TIMEOUT:
            return  # [安全] 空闲连接超时断开，防连接堆积
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)
            last_active = time.time()

def socks5_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\x02" not in methods:
            client.sendall(b"\x05\xFF") 
            return
        client.sendall(b"\x05\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\x01\x01") 
            return
        client.sendall(b"\x01\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), bind_interface, timeout=20)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), bind_interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((parsed.hostname, port), bind_interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], bind_interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05": socks5_client(client, first, bind_interface)
        else: http_client(client, first, bind_interface)
    except:
        try: client.close()
        except: pass
    finally:
        try: _conn_sem.release()
        except: pass

def start_proxy_server(host: str, port: int, bind_interface: str = "tun0") -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            if not _conn_sem.acquire(blocking=False):
                # [安全] 连接数达上限直接拒绝，防线程耗尽 DoS
                try: client.close()
                except: pass
                continue
            threading.Thread(target=proxy_client, args=(client, address, bind_interface), daemon=True).start()
        except: time.sleep(0.5)
