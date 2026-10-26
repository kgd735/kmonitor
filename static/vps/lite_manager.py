# [KUI 融合版] 引擎源码来自 Free-Residential-IP-Proxy-Controller-Sec，已整合进 kui-worker：
# C2 地址即 KUI 本身，接口路径为 /api/proxy/*；凭证仍只读本机 600 权限 c2.json。
#!/usr/bin/env python3
import base64, csv, os, random, subprocess, threading, time, urllib.request, urllib.parse, json, sys
from pathlib import Path

MAX_CONCURRENT_NODES = 1
BAKED_PROXY_PORT = __BAKED_PROXY_PORT__
PORT_FILE = WORKSPACE / "proxy_port"
def load_base_port():
    # 面板修改监听端口后持久化到本机文件；重启时优先读取，避免回退到 baked 值导致无限重启
    try:
        p = int(PORT_FILE.read_text(encoding="utf-8").strip())
        if 1 <= p <= 65535:
            return p
    except:
        pass
    return BAKED_PROXY_PORT
BASE_PROXY_PORT = load_base_port()
API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = ""  # [安全] 由 load_c2_conf() 从本机 c2.json 填充，不再由 C2 下发时硬编码

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
LOG_MAX_BYTES = 256 * 1024
REPORT_LOG_BYTES = 12 * 1024
MANAGER_LOG_FILE = WORKSPACE / "manager.log"

GOLDEN_NODES_FILE = WORKSPACE / "golden_nodes.json"
golden_nodes = {}
golden_lock = threading.Lock()

# [安全] 所有凭证从本机 600 权限的 c2.json 读取（由 /agent 安装脚本写入），C2 下发代码中不再包含任何口令
WEB_USER = ""
WEB_PASS = ""

def load_c2_conf():
    global WEB_USER, WEB_PASS, C2_URL
    try:
        with open(str(WORKSPACE / "c2.json"), "r") as f:
            conf = json.load(f)
        WEB_USER = str(conf.get("web_user", ""))
        WEB_PASS = str(conf.get("web_pass", ""))
        C2_URL = str(conf.get("c2_url", ""))
    except Exception as e:
        print("[-] 无法读取 c2.json，请重新运行纳管命令: {}".format(e), flush=True)

dynamic_slot_map = {0: "JP"}
control_mode = "auto"
manual_node_ip = ""
youtube_check_enabled = False
config_fetch_interval = 15
heartbeat_interval = 30
pool = {0: {"process": None, "ip": "", "country": "", "connected_at": 0, "connecting": False}}
pool_lock = threading.Lock()
public_ip = ""
BOOT_ID = ""  # [防误卸载] 本机持久化启动标识：写入 WORKSPACE/boot_id，重装变化、重启不变

def append_bounded_log(log_file, stream):
    try:
        with open(log_file, "a", buffering=1) as output:
            for line in iter(stream.readline, b""):
                output.write(line.decode("utf-8", errors="replace"))
                output.flush()
                if log_file.stat().st_size > LOG_MAX_BYTES:
                    content = log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                    log_file.write_bytes(b"[log truncated]\n" + content)
    except: pass

def read_recent_log(log_file):
    try:
        return log_file.read_text(errors="replace")[-REPORT_LOG_BYTES:]
    except: return ""

def read_recent_logs():
    try:
        result = subprocess.run(
            ["journalctl", "-u", "proxy-lite.service", "-n", "120", "--no-pager", "-o", "short-iso"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        journal = result.stdout.decode("utf-8", errors="replace").strip()
        if journal:
            return journal[-REPORT_LOG_BYTES:]
    except: pass
    manager = read_recent_log(MANAGER_LOG_FILE)
    openvpn = read_recent_log(WORKSPACE / "ovpn_err_0.log")
    return (manager + "\n" + openvpn)[-REPORT_LOG_BYTES:]

class BoundedTee:
    def __init__(self, console, log_file):
        self.console = console
        self.log_file = log_file

    def write(self, value):
        try:
            self.console.write(value)
        except UnicodeEncodeError:
            try:
                if hasattr(self.console, "buffer"):
                    self.console.buffer.write(value.encode("utf-8", errors="replace"))
                else:
                    self.console.write(value.encode("ascii", errors="replace").decode("ascii"))
            except: pass
        try:
            self.console.flush()
        except: pass
        try:
            with open(self.log_file, "a", buffering=1) as output:
                output.write(value)
            if self.log_file.stat().st_size > LOG_MAX_BYTES:
                content = self.log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                self.log_file.write_bytes(b"[log truncated]\n" + content)
        except: pass

    def flush(self):
        self.console.flush()

dead_ips = {} 

last_switch_timestamps = {0: 0}
global_node_reservoir = {} 
reservoir_lock = threading.Lock()

_cached_snapshot = []
_last_harvest_time = 0

def get_boot_id():
    """读取或生成本机启动标识，持久化到 WORKSPACE/boot_id。
    守护进程重启时保持不变；rm -rf 重装后重新生成，C2 据此识别全新安装。"""
    p = WORKSPACE / "boot_id"
    try:
        bid = p.read_text(encoding="utf-8").strip()
        if bid:
            return bid[:64]
    except:
        pass
    bid = "%d-%06d" % (int(time.time()), random.randint(0, 999999))
    try:
        p.write_text(bid, encoding="utf-8")
    except:
        pass
    return bid

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": f"Basic {auth_ptr}"
    }

def is_ip_blacklisted(ip):
    if ip in dead_ips:
        if time.time() < dead_ips[ip]["expire_at"]:
            return True
        else:
            del dead_ips[ip]
    return False

def add_to_blacklist(ip, country, reason="fault", duration=60):
    dead_ips[ip] = {
        "country": country,
        "expire_at": time.time() + duration,
        "reason": reason
    }

def load_golden_nodes():
    global golden_nodes
    try:
        if GOLDEN_NODES_FILE.exists():
            with open(GOLDEN_NODES_FILE, 'r') as f: golden_nodes = json.load(f)
            print(f"[*] 📥 成功加载【黄金备用池】，当前储备历史高质节点数: {len(golden_nodes)}", flush=True)
    except: pass

def save_golden_nodes():
    try:
        with open(GOLDEN_NODES_FILE, 'w') as f: json.dump(golden_nodes, f)
    except: pass

def add_golden_node(node):
    with golden_lock:
        golden_nodes[node["ip"]] = {
            "ip": node["ip"], "country": node["country"], "config": node["config"],
            "ping": node.get("ping", 9999), "added_at": time.time()
        }
    save_golden_nodes()

def remove_golden_node(ip):
    with golden_lock:
        if ip in golden_nodes: del golden_nodes[ip]
    save_golden_nodes()

def fetch_config():
    # [多机] 上报本机公网 IP + 启动标识，C2 据此下发该 VPS 的专属策略
    # （国家/手动节点/远程卸载指令）；boot_id 变化时 C2 会清除残留卸载标记
    query = ""
    try:
        if public_ip and public_ip != "Unknown_IP":
            query = "?ip=" + urllib.parse.quote(str(public_ip), safe="")
            if BOOT_ID:
                query += "&boot=" + urllib.parse.quote(str(BOOT_ID), safe="")
    except:
        pass
    req = urllib.request.Request(f"{C2_URL}/api/proxy/agent-config{query}", headers=get_c2_headers())
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))

def do_uninstall():
    """[远程卸载] 响应面板删除指令：通知 C2 注销 -> 掐断隧道 -> 清理策略路由
    -> 移除 systemd 守护 -> 删除工作目录(含本脚本与凭证) -> 退出进程。"""
    try:
        payload = json.dumps({"ip": public_ip, "boot_id": BOOT_ID}).encode("utf-8")
        req = urllib.request.Request(f"{C2_URL}/api/proxy/server/uninstalled", data=payload, headers=get_c2_headers(), method="POST")
        urllib.request.urlopen(req, timeout=10)
        print("[*] 已通知调度中心注销本机纳管信息。", flush=True)
    except Exception as e:
        print("[-] 注销通知发送失败，继续本地清理: {}".format(e), flush=True)
    with pool_lock:
        for slot, info in pool.items():
            proc = info.get("process")
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                except:
                    pass
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    time.sleep(1)
    subprocess.run(["pkill", "-9", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    for slot in range(MAX_CONCURRENT_NODES):
        table = str(100 + slot)
        subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
        subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["systemctl", "disable", "proxy-lite.service"], capture_output=True)
    for f in ["/lib/systemd/system/proxy-lite.service", "/etc/systemd/journald.conf.d/proxy-lite.conf"]:
        try:
            os.remove(f)
        except:
            pass
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    # 先移除 unit 文件并 daemon-reload，systemd 不再跟踪本服务，退出后不会被拉起
    subprocess.run(["rm", "-rf", str(WORKSPACE)], capture_output=True)
    print("[+] 远程卸载完成：隧道、路由、守护进程与全部文件已清除。", flush=True)
    os._exit(0)

def apply_config(data):
    global dynamic_slot_map, last_switch_timestamps, BASE_PROXY_PORT, control_mode, manual_node_ip, youtube_check_enabled, config_fetch_interval, heartbeat_interval
    # [远程卸载] 面板下发删除指令时，彻底清理本机并退出
    if isinstance(data, dict) and data.get("uninstall") is True:
        print("[!] 收到调度中心远程卸载指令，开始清理本机...", flush=True)
        do_uninstall()
    if "proxy_port" in data:
        try:
            new_port = int(data["proxy_port"])
        except:
            new_port = 0
        if 1 <= new_port <= 65535 and new_port != BASE_PROXY_PORT:
            print(f"[*] 检测到监听端口变更: {BASE_PROXY_PORT} -> {new_port}，准备重启服务...", flush=True)
            try:
                PORT_FILE.write_text(str(new_port), encoding="utf-8")
            except:
                pass
            BASE_PROXY_PORT = new_port
            os._exit(0)
    new_mode = "manual" if data.get("mode") == "manual" else "auto"
    new_manual_node_ip = str(data.get("manual_node_ip", "")).strip()
    mode_changed = new_mode != control_mode or (new_mode == "manual" and new_manual_node_ip != manual_node_ip)
    control_mode = new_mode
    manual_node_ip = new_manual_node_ip
    youtube_check_enabled = data.get("youtube_check", False) is True
    config_fetch_interval = max(5, min(3600, int(data.get("config_fetch_interval", 15))))
    heartbeat_interval = max(10, min(3600, int(data.get("heartbeat_interval", 30))))
    if "slot_map" in data:
        new_map = {int(k): str(v).upper() for k, v in data.get("slot_map", {}).items()}
        force_switch = {int(k): int(v) for k, v in data.get("force_switch", {}).items()}
    else:
        # [兼容] 老格式：整个 dict 即 slot_map；只取数字型键，避免被 uninstall 等新增键误伤
        new_map = {int(k): str(v).upper() for k, v in data.items() if str(k).lstrip("-").isdigit()}
        force_switch = {}
    with pool_lock:
        for slot, desired_country in new_map.items():
            if slot >= MAX_CONCURRENT_NODES: continue
            dynamic_slot_map[slot] = desired_country
            info = pool[slot]
            cmd_ts = force_switch.get(slot, 0)
            should_switch = False
            if cmd_ts > last_switch_timestamps[slot]:
                last_switch_timestamps[slot] = cmd_ts
                should_switch = True
                print(f"[*] ⚡ 接收到母机手动干预指令: 强制刷新单端口网络层IP！", flush=True)
            if info["process"] and info["process"].poll() is None:
                current_country = info.get("country", "")
                if (current_country and current_country != desired_country) or should_switch or mode_changed:
                    if not should_switch:
                        print(f"[*] 策略变更触发: 需要从 {current_country} 切换到 {desired_country}，正在掐断旧连接...", flush=True)
                    if info["ip"]:
                        add_to_blacklist(info["ip"], info["country"], reason="manual", duration=60)
                    try: info["process"].terminate(); info["process"].wait(timeout=2)
                    except: info["process"].kill()

def update_config_loop():
    while True:
        try:
            apply_config(fetch_config())
        except: pass
        time.sleep(config_fetch_interval)

def c2_heartbeat_loop():
    if not public_ip or public_ip == "Unknown_IP": get_public_ip()
    try:
        payload = json.dumps({"ip": public_ip, "boot_id": BOOT_ID, "details": [], "log": read_recent_logs()}).encode('utf-8')
        req = urllib.request.Request(f"{C2_URL}/api/proxy/report", data=payload, headers=get_c2_headers(), method='POST')
        urllib.request.urlopen(req, timeout=10)
    except: pass
    while True:
        time.sleep(heartbeat_interval)
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None:
                    uptime = time.time() - info["connected_at"]
                    if uptime > 10: 
                        actual_country = info.get("country", dynamic_slot_map.get(slot, "UN"))
                        details.append({"slot": slot, "country": actual_country, "port": BASE_PROXY_PORT, "connected_time": int(uptime), "node_ip": info["ip"]})
        log_file = WORKSPACE / "ovpn_err_0.log"
        with reservoir_lock:
            candidates = [{"ip": n["ip"], "country": n["country"], "ping": n.get("ping", 9999)} for n in global_node_reservoir.values() if n.get("ip") and not is_ip_blacklisted(n["ip"])]
        candidates.sort(key=lambda n: n["ping"])
        payload = json.dumps({"ip": public_ip, "boot_id": BOOT_ID, "details": details, "log": read_recent_logs(), "candidates": candidates[:500]}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/proxy/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] 成功向心跳控制塔汇报。连通率: {len(details)} / 1", flush=True)
        except: pass

def setup_env():
    load_c2_conf()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    global BOOT_ID
    BOOT_ID = get_boot_id()
    sys.stdout = BoundedTee(sys.__stdout__, MANAGER_LOG_FILE)
    sys.stderr = BoundedTee(sys.__stderr__, MANAGER_LOG_FILE)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\nvpn\n")
        AUTH_FILE.chmod(0o600)
    load_golden_nodes()

def harvest_snapshot_nodes() -> list:
    global _cached_snapshot, _last_harvest_time
    if time.time() - _last_harvest_time < 300 and _cached_snapshot:
        return _cached_snapshot
        
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        if nodes:
            _cached_snapshot = nodes
            _last_harvest_time = time.time()
        return _cached_snapshot
    except: return _cached_snapshot

def setup_routing(slot: int):
    dev, table = f"tun{slot}", str(100 + slot)
    subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", table], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", dev, "table", table], capture_output=True)

# [安全] OpenVPN 配置指令黑名单：第三方志愿者节点下发的 .ovpn 以 root 身份执行，
# 配置文件内手写的 redirect-gateway / route / dhcp-option / up / down 等指令不受
# 命令行 --route-nopull 限制，必须在写入前过滤，含危险指令的节点直接拒收并拉黑。
_OVPN_BLOCKED_DIRECTIVES = (
    "redirect-gateway", "redirect-private",
    "route", "route-ipv6", "route-delay", "route-metric", "route-up", "route-pre-down",
    "dhcp-option", "dhcp-renew", "dhcp-release",
    "up", "down", "ipchange", "tls-verify",
    "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
    "plugin", "management", "management-hold", "management-query-passwords",
    "http-proxy", "http-proxy-option", "http-proxy-retry", "http-proxy-timeout", "socks-proxy",
    "setenv", "setenv-safe", "setenv-opt", "script-security", "pull-filter",
    "pkcs12", "askpass", "auth-retry",
)

def sanitize_ovpn_config(text):
    """清洗第三方下发的 OpenVPN 配置。返回 (cleaned_text, ok)，
    ok 为 False 表示配置含有危险指令，调用方应拒收该节点。内联证书块(<ca>/<cert>/...)原样保留。"""
    out_lines = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("<"):
            in_block = not line.startswith("</")
            out_lines.append(raw)
            continue
        if in_block:
            out_lines.append(raw)
            continue
        key = line.split()[0].lower()
        if key in _OVPN_BLOCKED_DIRECTIVES:
            return "", False
        out_lines.append(raw)
    return "\n".join(out_lines) + "\n", True

def connect_slot(slot: int, node: dict):
    try:
        dev, cfg_path, log_file = f"tun{slot}", CONFIG_DIR / f"tun{slot}.ovpn", WORKSPACE / f"ovpn_err_{slot}.log"
        clean_cfg, cfg_ok = sanitize_ovpn_config(node["config"])
        if not cfg_ok:
            print("[-] 单端口 ({}) 节点配置含危险指令，已拒收并拉黑24h: {}".format(node["country"], node["ip"]), flush=True)
            add_to_blacklist(node["ip"], node["country"], reason="evil-config", duration=86400)
            with pool_lock: pool[slot]["connecting"] = False
            return
        cfg_path.write_text(clean_cfg)
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--route-nopull", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "10", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
        log_file.write_text("")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=append_bounded_log, args=(log_file, process.stdout), daemon=True).start()
        
        success = False
        for _ in range(25):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            is_residential = True
            try:
                print(f"[*] 单端口 ({node['country']}) 隧道初步打通，鉴定是否为纯正住宅IP...", flush=True)
                # [修复] 先经隧道获取真实出口 IP，再查该 IP 的类型；原来误查了 VPN 服务器 IP
                egress_ip = ""
                try:
                    egr = subprocess.run(
                        ["curl", "-s", "-m", "10", "--interface", f"tun{slot}", "https://api.ipify.org"],
                        capture_output=True, text=True, timeout=15)
                    egress_ip = (egr.stdout or "").strip()
                except Exception:
                    egress_ip = ""
                check_ip = egress_ip or node["ip"]
                print(f"[*] 隧道出口 IP 为 {check_ip}，正在鉴定...", flush=True)
                req_url = f"https://ip.net.coffee/ip/{check_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    api_resp = check_res.read().decode("utf-8").lower()
                    if "residential" in api_resp or "isp" in api_resp or "住宅" in api_resp: is_residential = True
                    else:
                        clean_resp = api_resp.replace(" ", "").replace("\n", "").replace("\r", "")
                        if "hosting" in api_resp or "datacenter" in api_resp or "机房" in api_resp or "data center" in api_resp:
                            if '"hosting":false' not in clean_resp and '"datacenter":false' not in clean_resp: is_residential = False
            except: pass
            
            if not is_residential:
                is_history_golden = False
                with golden_lock:
                    if node["ip"] in golden_nodes: is_history_golden = True
                
                if is_history_golden:
                    print(f"[*] 单端口 ({node['country']}) 虽为机房IP，但具备【历史黄金池】免死特权，强制放行: {node['ip']}", flush=True)
                else:
                    print(f"[-] 单端口 ({node['country']}) 检测为机房IP，暂时隔离冷却(2小时): {node['ip']}", flush=True)
                    try: process.terminate(); process.wait(timeout=2)
                    except: process.kill()
                    add_to_blacklist(node["ip"], node["country"], reason="datacenter", duration=7200) 
                    with pool_lock: pool[slot]["connecting"] = False
                    return

            setup_routing(slot)
            
            services_passed = True
            if youtube_check_enabled:
                print(f"[*] 单端口 ({node['country']}) 核验通过，执行 YouTube 业务连通性测试...", flush=True)
                test_urls = ["https://www.youtube.com"]
                for test_url in test_urls:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "15", "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "--interface", f"tun{slot}", test_url], capture_output=True)
                    if res.returncode != 0:
                        print(f"[-] 单端口 ({node['country']}) 访问 {test_url} 阻断/超时，临时冷却: {node['ip']}", flush=True)
                        services_passed = False
                        break
            
            if not services_passed:
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()
                add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
                with pool_lock: pool[slot]["connecting"] = False
                return

            add_golden_node(node)
            with pool_lock:
                pool[slot]["process"] = process
                pool[slot]["ip"] = node["ip"]
                pool[slot]["country"] = node["country"]
                pool[slot]["connected_at"] = time.time()
            print(f"[+] 单端口 ({node['country']}) 优质IP完全就绪入池: {node['ip']}", flush=True)
        else:
            try: process.terminate(); process.wait(timeout=2)
            except: process.kill()
            add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
    finally:
        with pool_lock: pool[slot]["connecting"] = False

def health_check_loop():
    test_targets = [
        "http://www.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    while True:
        time.sleep(60) 
        slots_to_check = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None and (time.time() - info["connected_at"] > 60):
                    slots_to_check.append((slot, info["process"], info["ip"], dynamic_slot_map.get(slot, "UN")))
        
        for slot, process, ip, country in slots_to_check:
            failed = True
            
            for attempt in range(2):
                alive = False
                for target in test_targets:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "10", "--interface", f"tun{slot}", target], capture_output=True)
                    if res.returncode == 0:
                        alive = True
                        break 
                
                if alive:
                    failed = False
                    break 
                    
                time.sleep(3)

            if failed:
                print(f"[!] 单端口网络 连续多次【多渠道联合盲探】均失败！判定掉线重拨: {ip}", flush=True)
                add_to_blacklist(ip, country, reason="fault", duration=60)
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()

def maintain_pool():
    global dead_ips, global_node_reservoir, golden_nodes
    while True:
        snapshot = harvest_snapshot_nodes()
        with reservoir_lock:
            for n in snapshot:
                global_node_reservoir[n["ip"]] = n
                
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)
            print(f"[*] ⚡ 蓄水池循环，当前大池常驻: {len(global_node_reservoir)} 个 (极品保留库: {len(golden_nodes)} 个)", flush=True)

        empty_slots = []
        with pool_lock:
            for slot, info in pool.items():
                if not info["connecting"] and (info["process"] is None or info["process"].poll() is not None):
                    empty_slots.append(slot)
                    info["process"] = None; info["ip"] = ""; info["country"] = ""
        
        if empty_slots:
            with reservoir_lock:
                all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x.get("ping", 9999))
            with golden_lock:
                all_golden_nodes = sorted(list(golden_nodes.values()), key=lambda x: x.get("ping", 9999))

            used_ips = [info["ip"] for info in pool.values() if info["ip"]]
            
            for slot in empty_slots:
                if control_mode == "manual":
                    node = next((n for n in all_pool_nodes if n["ip"] == manual_node_ip), None)
                    if not node:
                        node = next((n for n in all_golden_nodes if n["ip"] == manual_node_ip), None)
                    if node and node["ip"] not in used_ips and not is_ip_blacklisted(node["ip"]):
                        used_ips.append(node["ip"])
                        with pool_lock: pool[slot]["connecting"] = True
                        threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    else:
                        print(f"[-] 手动模式: 等待所选节点 {manual_node_ip or '(未选择)'} 可用...", flush=True)
                    continue

                target_country = dynamic_slot_map.get(slot, "JP")
                
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                
                if not candidates:
                    golden_candidates = [n for n in all_golden_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                    if golden_candidates:
                        print(f"[*] 🏆 主池枯竭，触发【黄金备用池】！正在提取历史高质 [{target_country}] 节点...", flush=True)
                        candidates = golden_candidates

                if not candidates:
                    now_ts = time.time()
                    country_blacklisted = [ip for ip, meta in list(dead_ips.items()) if meta["country"] == target_country and now_ts < meta["expire_at"] and meta["reason"] != "datacenter"]
                    
                    if country_blacklisted:
                        for bip in country_blacklisted:
                            dead_ips.pop(bip, None)
                        print(f"[!] ⚡ 区域紧急熔断：[{target_country}] 储备资源彻底归零！已精准释放该区域共 {len(country_blacklisted)} 个冷却中节点提前救场！", flush=True)
                        candidates = [n for n in (all_pool_nodes + all_golden_nodes) if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]

                if candidates:
                    node = candidates.pop(0)
                    used_ips.append(node["ip"])
                    with pool_lock: pool[slot]["connecting"] = True
                    threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    time.sleep(0.5)
                else:
                    print(f"[-] 单端口: 本地【大池+黄金储备】中该国家可用配额彻底打空，挂起抓取...", flush=True)
        time.sleep(5)

def main():
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    
    print("========================================", flush=True)
    print("  免费住宅IP智能调度系统 [防误杀极品节点单端口版] 启动！", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=update_config_loop, daemon=True).start()

    try:
        apply_config(fetch_config())
    except: pass

    import proxy_server
    for i in range(MAX_CONCURRENT_NODES):
        threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", BASE_PROXY_PORT, f"tun{i}"), daemon=True).start()
    
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
