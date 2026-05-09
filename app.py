#!/usr/bin/env python3
"""
NetAnalyzer v2 — Пассивный захват трафика + обнаружение устройств в сети
Требования: pip install flask flask-cors psutil scapy
Запуск:     sudo python3 app.py   (нужен root для scapy/promiscuous mode)
"""

import subprocess, threading, time, json, re, os, socket, statistics, ipaddress, uuid
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template, Response, request, send_file
from flask_cors import CORS

# ── Зависимости ───────────────────────────────────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[WARN] pip install psutil")

try:
    from scapy.all import (
        sniff, ARP, IP, TCP, UDP, ICMP, Ether,
        get_if_list, conf as scapy_conf
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] pip install scapy  — пассивный захват недоступен")

app = Flask(__name__)
CORS(app)

# ── Конфиг ────────────────────────────────────────────────────────────────────
IFACE        = os.environ.get("IFACE", "")          # "" = авто (первый не-lo)
PING_HOST    = os.environ.get("PING_HOST", "8.8.8.8")
HISTORY_SIZE = 300   # 5 минут при 1 сек/тик
SCAN_INTERVAL = 30   # секунд между ARP-сканами
EVENTS_IN_MEMORY = int(os.environ.get("EVENTS_IN_MEMORY", "2000"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "./logs")).resolve()
CAPTURE_DIR = Path(os.environ.get("CAPTURE_DIR", "./captures")).resolve()
CAPTURE_MAX_SECONDS = int(os.environ.get("CAPTURE_MAX_SECONDS", "300"))

LOG_DIR.mkdir(parents=True, exist_ok=True)
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

# ── Глобальное состояние ──────────────────────────────────────────────────────
# Используем reentrant lock: add_event() может вызываться внутри участков,
# где уже удерживается lock (например, в discovery_loop).
lock = threading.RLock()

# История метрик сервера (сам интерфейс)
server_metrics = {
    k: deque(maxlen=HISTORY_SIZE)
    for k in ["latency","jitter","packet_loss","bandwidth_rx","bandwidth_tx",
              "response_time","errors","timestamps"]
}

# Устройства в сети: { ip -> {...} }
devices: dict[str, dict] = {}

# Захваченный трафик: { ip -> {proto: bytes, total_rx, total_tx, pps, ...} }
traffic: dict[str, dict] = defaultdict(lambda: {
    "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0,
    "rx_bytes": 0, "tx_bytes": 0,
    "rx_bytes_prev": 0, "tx_bytes_prev": 0,
    "rx_mbps": 0.0, "tx_mbps": 0.0,
    "packets": 0, "pps": 0,
    "packets_prev": 0,
    "last_seen": 0,
})

# Метрики на устройство: { ip -> {latency, jitter, packet_loss, history:[]} }
host_metrics: dict[str, dict] = defaultdict(lambda: {
    "latency": 0.0, "jitter": 0.0, "packet_loss": 0.0,
    "history_lat": deque(maxlen=60),
    "history_jit": deque(maxlen=60),
    "last_ping": 0,
})

# Журнал событий
events = deque(maxlen=EVENTS_IN_MEMORY)
capture_jobs: dict[str, dict] = {}

# Подсчёт скорости
_speed_ts = time.time()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def _event_log_file(date_str: str | None = None) -> Path:
    if not date_str:
        date_str = datetime.now().strftime("%Y-%m-%d")
    return LOG_DIR / f"{date_str}.log"

def _write_event_to_disk(rec: dict):
    try:
        line = json.dumps(rec, ensure_ascii=False)
        with _event_log_file().open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def add_event(msg, level="info"):
    rec = {"time": ts(), "msg": msg, "level": level}
    with lock:
        events.appendleft(rec)
    _write_event_to_disk(rec)


# ── Определение интерфейса ────────────────────────────────────────────────────

def detect_iface():
    global IFACE
    if IFACE:
        return IFACE
    # На Linux самый надёжный способ — интерфейс default route.
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=3
        )
        # Пример строки: "default via 192.168.1.1 dev ens18 proto dhcp ..."
        m = re.search(r"\bdev\s+(\S+)", r.stdout or "")
        if m:
            IFACE = m.group(1)
            return IFACE
    except Exception:
        pass
    if HAS_PSUTIL:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, st in stats.items():
            if name == "lo" or not st.isup:
                continue
            for a in addrs.get(name, []):
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    IFACE = name
                    return IFACE
    return "eth0"

def get_my_ip(iface):
    if HAS_PSUTIL:
        for a in psutil.net_if_addrs().get(iface, []):
            if a.family == socket.AF_INET:
                return a.address
    return "127.0.0.1"

def get_network_prefix(iface):
    """Возвращает сеть вида 192.168.1.0/24"""
    if HAS_PSUTIL:
        for a in psutil.net_if_addrs().get(iface, []):
            if a.family == socket.AF_INET:
                try:
                    net = ipaddress.IPv4Network(
                        f"{a.address}/{a.netmask}", strict=False
                    )
                    return str(net)
                except Exception:
                    pass
    return "192.168.1.0/24"


# ── ARP-сканирование (обнаружение устройств) ──────────────────────────────────

def arp_scan(network: str, iface: str):
    """Запускает arp-scan или nmap для нахождения устройств."""
    found = {}

    # Способ 1: arp-scan по целевой сети и интерфейсу (быстрее и точнее)
    try:
        r = subprocess.run(
            ["arp-scan", network, f"--interface={iface}"],
            capture_output=True, text=True, timeout=20
        )
        if (not r.stdout.strip()) and (r.returncode != 0):
            # Fallback для окружений, где network-формат отклоняется,
            # но --localnet работает стабильно.
            r = subprocess.run(
                ["arp-scan", "--localnet", f"--interface={iface}"],
                capture_output=True, text=True, timeout=20
            )
        for line in r.stdout.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)\s*(.*)", line)
            if m:
                ip, mac, vendor = m.groups()
                found[ip] = {"ip": ip, "mac": mac.upper(), "vendor": vendor.strip(),
                              "hostname": "", "method": "arp-scan"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Способ 2: nmap ARP ping (если arp-scan недоступен)
    if not found:
        try:
            r = subprocess.run(
                # Не используем --open: иначе "живые" хосты без открытых портов
                # могут отфильтровываться и выглядеть как "не найденные".
                ["nmap", "-sn", "-PR", "-n", "-e", iface, network],
                capture_output=True, text=True, timeout=60
            )
            ip, mac, hostname = None, "", ""
            for line in r.stdout.splitlines():
                mip = re.search(r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)", line)
                mip2 = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
                mmac = re.search(r"MAC Address: ([\w:]+)(?: \((.+?)\))?", line)
                if mip:
                    hostname, ip = mip.groups()
                elif mip2:
                    ip = mip2.group(1); hostname = ""
                if mmac and ip:
                    mac, vendor = mmac.group(1), mmac.group(2) or ""
                    found[ip] = {"ip": ip, "mac": mac.upper(), "vendor": vendor,
                                 "hostname": hostname, "method": "nmap"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Способ 3: ARP-таблица как fallback, если активный скан ничего не дал.
    if not found:
        try:
            net_obj = ipaddress.ip_network(network, strict=False)
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip, flags, mac, dev = parts[0], parts[2], parts[3], parts[5]
                        if (
                            mac != "00:00:00:00:00:00"
                            and flags == "0x2"
                            and dev == iface
                            and ip not in found
                            and ipaddress.ip_address(ip) in net_obj
                        ):
                            found[ip] = {"ip": ip, "mac": mac.upper(), "vendor": "",
                                        "hostname": "", "method": "arp-table"}
        except Exception:
            pass

    def resolve_hostname(ip: str, current: str = "") -> str:
        if current and current != ip and current.lower() != "unknown":
            return current
        try:
            host = socket.gethostbyaddr(ip)[0]
            if host and host != ip:
                return host
        except Exception:
            pass
        # Часто телефоны отвечают в mDNS; пробуем avahi, если установлен.
        try:
            r = subprocess.run(
                ["avahi-resolve-address", ip],
                capture_output=True, text=True, timeout=2
            )
            if r.returncode == 0 and "\t" in r.stdout:
                host = r.stdout.split("\t", 1)[1].strip()
                if host and host != ip:
                    return host
        except Exception:
            pass
        return current or ip

    # Разрешение имён
    for ip, info in found.items():
        info["hostname"] = resolve_hostname(ip, info.get("hostname", ""))

    return found


def discovery_loop():
    """Периодически сканирует сеть."""
    iface   = detect_iface()
    my_ip   = get_my_ip(iface)
    network = get_network_prefix(iface)

    add_event(f"Интерфейс: {iface} ({my_ip})", "info")
    add_event(f"Сканирую сеть {network}...", "info")

    while True:
        now = time.time()
        found = arp_scan(network, iface)
        if not found:
            add_event(
                f"Сканирование не вернуло хосты (iface={iface}, network={network})",
                "warn"
            )

        with lock:
            for ip, info in found.items():
                if ip not in devices:
                    add_event(f"Новое устройство: {ip} [{info.get('vendor','')}]", "info")
                devices[ip] = {
                    **info,
                    "is_self": ip == my_ip,
                    "online": True,
                    "last_seen": ts(),
                    "last_seen_ts": now,
                    "rx_mbps":  traffic[ip]["rx_mbps"],
                    "tx_mbps":  traffic[ip]["tx_mbps"],
                    "pps":      traffic[ip]["pps"],
                }

            # Считаем offline по TTL, чтобы не держать "вечный online".
            online_ttl = SCAN_INTERVAL * 2.5
            for ip in list(devices.keys()):
                age = now - float(devices[ip].get("last_seen_ts", 0))
                devices[ip]["online"] = age <= online_ttl

        time.sleep(SCAN_INTERVAL)


# ── Scapy: пассивный захват пакетов ──────────────────────────────────────────

def process_packet(pkt):
    """Вызывается для каждого захваченного пакета."""
    try:
        src_ip = dst_ip = None
        proto  = "Other"
        size   = len(pkt)

        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            proto  = "ARP"
        elif IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP  in pkt: proto = "TCP"
            elif UDP  in pkt: proto = "UDP"
            elif ICMP in pkt: proto = "ICMP"

        if src_ip:
            with lock:
                t = traffic[src_ip]
                t[proto] += size
                t["tx_bytes"] += size
                t["packets"]  += 1
                t["last_seen"]  = time.time()
        if dst_ip and dst_ip != src_ip:
            with lock:
                t = traffic[dst_ip]
                t["rx_bytes"] += size

    except Exception:
        pass


def capture_loop():
    """Запускает Scapy sniffer в отдельном потоке."""
    if not HAS_SCAPY:
        add_event("Scapy недоступен — только активные замеры", "warn")
        return

    iface = detect_iface()
    add_event(f"Захват пакетов: {iface} (promiscuous)", "info")

    try:
        # Включаем promiscuous mode
        subprocess.run(["ip", "link", "set", iface, "promisc", "on"],
                       capture_output=True)
        sniff(iface=iface, prn=process_packet, store=False)
    except Exception as e:
        add_event(f"Захват остановлен: {e}", "error")


def speed_calc_loop():
    """Раз в секунду пересчитывает скорости в Мбит/с."""
    global _speed_ts
    while True:
        time.sleep(1)
        now = time.time()
        dt  = now - _speed_ts
        _speed_ts = now

        with lock:
            for ip, t in traffic.items():
                rx_d = t["rx_bytes"] - t["rx_bytes_prev"]
                tx_d = t["tx_bytes"] - t["tx_bytes_prev"]
                pps_d = t["packets"] - t["packets_prev"]

                t["rx_mbps"] = round(rx_d * 8 / (dt * 1_000_000), 3)
                t["tx_mbps"] = round(tx_d * 8 / (dt * 1_000_000), 3)
                t["pps"]     = pps_d

                t["rx_bytes_prev"] = t["rx_bytes"]
                t["tx_bytes_prev"] = t["tx_bytes"]
                t["packets_prev"]  = t["packets"]

                if ip in devices:
                    devices[ip]["rx_mbps"] = t["rx_mbps"]
                    devices[ip]["tx_mbps"] = t["tx_mbps"]
                    devices[ip]["pps"]     = t["pps"]


# ── Ping-замеры к хостам ──────────────────────────────────────────────────────

def ping_host(ip: str, count=4):
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", "1", "-i", "0.2", ip],
            capture_output=True, text=True, timeout=10
        )
        out = r.stdout
        loss_m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
        rtt_m  = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
        loss   = float(loss_m.group(1)) if loss_m else 100.0
        if rtt_m:
            return float(rtt_m.group(2)), float(rtt_m.group(4)), loss
        return 999.0, 0.0, loss
    except Exception:
        return 999.0, 0.0, 100.0


def ping_all_loop():
    """Периодически пингует все известные устройства."""
    while True:
        with lock:
            ips = [ip for ip, d in devices.items() if d.get("online")]

        for ip in ips:
            lat, jit, loss = ping_host(ip)
            with lock:
                h = host_metrics[ip]
                h["latency"]     = lat
                h["jitter"]      = jit
                h["packet_loss"] = loss
                h["history_lat"].append(lat)
                h["history_jit"].append(jit)
                h["last_ping"]   = time.time()

                if ip in devices:
                    devices[ip]["latency"]     = lat
                    devices[ip]["jitter"]      = jit
                    devices[ip]["packet_loss"] = loss

            if loss >= 100:
                add_event(f"{ip} не отвечает (100% loss)", "error")
            elif loss > 5:
                add_event(f"{ip} потеря пакетов {loss:.0f}%", "warn")
            elif lat > 150:
                add_event(f"{ip} высокая задержка {lat:.0f} мс", "warn")

            time.sleep(0.5)   # не флудить

        time.sleep(10)


# ── Метрики самого сервера ────────────────────────────────────────────────────
_prev_net_io = None
_prev_net_ts  = None
_prev_errs   = None

def server_metrics_loop():
    global _prev_net_io, _prev_net_ts, _prev_errs
    last_lat = last_jit = last_loss = 0.0
    last_ping_ts = 0

    while True:
        time.sleep(1)
        now = time.time()

        # Пропускная способность
        rx_mbps = tx_mbps = 0.0
        if HAS_PSUTIL:
            try:
                iface = detect_iface()
                io = psutil.net_io_counters(pernic=True).get(iface)
                if io and _prev_net_io and _prev_net_ts:
                    dt = now - _prev_net_ts
                    rx_mbps = (io.bytes_recv - _prev_net_io.bytes_recv) * 8 / (dt * 1e6)
                    tx_mbps = (io.bytes_sent - _prev_net_io.bytes_sent) * 8 / (dt * 1e6)
                _prev_net_io, _prev_net_ts = io, now
            except Exception:
                pass

        # Ошибки
        errs = 0
        if HAS_PSUTIL:
            try:
                io2 = psutil.net_io_counters()
                total = io2.errin + io2.errout + io2.dropin + io2.dropout
                if _prev_errs is not None:
                    errs = max(0, total - _prev_errs)
                _prev_errs = total
            except Exception:
                pass

        # Ping (каждые 10 сек)
        if now - last_ping_ts >= 10:
            last_lat, last_jit, last_loss = ping_host(PING_HOST)
            last_ping_ts = now

        with lock:
            server_metrics["latency"].append(round(last_lat, 1))
            server_metrics["jitter"].append(round(last_jit, 1))
            server_metrics["packet_loss"].append(round(last_loss, 2))
            server_metrics["bandwidth_rx"].append(round(max(0, rx_mbps), 3))
            server_metrics["bandwidth_tx"].append(round(max(0, tx_mbps), 3))
            server_metrics["errors"].append(errs)
            server_metrics["timestamps"].append(ts())


# ── Flask API ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    """Список всех устройств в сети."""
    with lock:
        result = []
        for ip, d in devices.items():
            t = traffic.get(ip, {})
            result.append({
                **d,
                "proto_breakdown": {
                    k: t.get(k, 0)
                    for k in ["TCP","UDP","ICMP","ARP","Other"]
                },
                "total_packets": t.get("packets", 0),
            })
        result.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return jsonify(result)


@app.route("/api/device/<ip>")
def api_device(ip: str):
    """Детальные метрики конкретного устройства."""
    with lock:
        dev = devices.get(ip, {"ip": ip, "online": False})
        t   = traffic.get(ip, {})
        h   = host_metrics.get(ip, {})
        return jsonify({
            "info": dev,
            "metrics": {
                "latency":      h.get("latency", 0),
                "jitter":       h.get("jitter", 0),
                "packet_loss":  h.get("packet_loss", 0),
                "rx_mbps":      t.get("rx_mbps", 0),
                "tx_mbps":      t.get("tx_mbps", 0),
                "pps":          t.get("pps", 0),
            },
            "history": {
                "latency": list(h.get("history_lat", [])),
                "jitter":  list(h.get("history_jit", [])),
            },
            "traffic": {
                k: t.get(k, 0) for k in ["TCP","UDP","ICMP","ARP","Other",
                                          "rx_bytes","tx_bytes","packets"]
            }
        })


@app.route("/api/server")
def api_server():
    """Метрики самого сервера."""
    with lock:
        def last(k): d=server_metrics[k]; return d[-1] if d else 0
        def hist(k,n=60): return list(server_metrics[k])[-n:]
        return jsonify({
            "current": {k: last(k) for k in
                        ["latency","jitter","packet_loss",
                         "bandwidth_rx","bandwidth_tx","errors","timestamps"]},
            "history": {k: hist(k) for k in
                        ["latency","jitter","packet_loss",
                         "bandwidth_rx","bandwidth_tx","errors","timestamps"]},
        })


@app.route("/api/traffic/global")
def api_traffic_global():
    """Суммарный трафик по всем устройствам."""
    with lock:
        totals = defaultdict(int)
        for t in traffic.values():
            for k in ["TCP","UDP","ICMP","ARP","Other","rx_bytes","tx_bytes","packets"]:
                totals[k] += t.get(k, 0)
        rx_total = sum(t.get("rx_mbps",0) for t in traffic.values())
        tx_total = sum(t.get("tx_mbps",0) for t in traffic.values())
    return jsonify({**dict(totals), "rx_mbps": round(rx_total,3), "tx_mbps": round(tx_total,3)})


@app.route("/api/stream")
def api_stream():
    """SSE: обновления в реальном времени."""
    def gen():
        while True:
            with lock:
                def last(k): d=server_metrics[k]; return d[-1] if d else 0
                devs_brief = [
                    {"ip": ip, "online": d.get("online"),
                     "rx_mbps": d.get("rx_mbps",0), "tx_mbps": d.get("tx_mbps",0),
                     "latency": d.get("latency",0), "pps": d.get("pps",0)}
                    for ip, d in devices.items()
                ]
                payload = {
                    "server": {k: last(k) for k in
                               ["latency","jitter","packet_loss",
                                "bandwidth_rx","bandwidth_tx","errors"]},
                    "devices": devs_brief,
                    "event_count": len(events),
                    "ts": ts(),
                }
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(1)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.route("/api/events")
def api_events():
    limit = max(1, min(500, int(request.args.get("limit", "50"))))
    offset = max(0, int(request.args.get("offset", "0")))
    with lock:
        ev = list(events)
    return jsonify({
        "items": ev[offset:offset + limit],
        "total": len(ev),
        "offset": offset,
        "limit": limit
    })


@app.route("/api/events/files")
def api_events_files():
    files = sorted([p.name for p in LOG_DIR.glob("*.log")], reverse=True)
    return jsonify({"files": files})


@app.route("/api/events/download")
def api_events_download():
    date_str = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        return jsonify({"error": "invalid date format, expected YYYY-MM-DD"}), 400
    p = _event_log_file(date_str)
    if not p.exists():
        return jsonify({"error": f"log not found for {date_str}"}), 404
    return send_file(p, as_attachment=True, download_name=f"netanalyzer-events-{date_str}.log")


@app.route("/api/ping/<ip>")
def api_ping(ip: str):
    """Ручной ping до любого IP."""
    lat, jit, loss = ping_host(ip, count=5)
    return jsonify({"ip": ip, "latency": lat, "jitter": jit, "packet_loss": loss})


@app.route("/api/info")
def api_info():
    iface = detect_iface()
    return jsonify({
        "iface": iface, "my_ip": get_my_ip(iface),
        "network": get_network_prefix(iface),
        "has_scapy": HAS_SCAPY, "has_psutil": HAS_PSUTIL,
        "devices_count": len(devices),
        "log_dir": str(LOG_DIR),
        "capture_dir": str(CAPTURE_DIR),
    })


def _capture_worker(job_id: str, ip: str, iface: str, seconds: int, out_file: Path):
    target = [] if ip == "all" else ["host", ip]
    cmd = [
        "tcpdump", "-i", iface, *target,
        "-w", str(out_file), "-G", str(seconds), "-W", "1"
    ]
    try:
        add_event(f"TCPDUMP старт: {ip}, {seconds}s", "info")
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=seconds + 20
        )
        with lock:
            job = capture_jobs.get(job_id, {})
            job["finished_at"] = time.time()
            if r.returncode == 0 and out_file.exists() and out_file.stat().st_size > 24:
                job["status"] = "done"
                job["size"] = out_file.stat().st_size
                add_event(f"TCPDUMP готов: {out_file.name}", "info")
            else:
                job["status"] = "error"
                job["error"] = (r.stderr or r.stdout or "tcpdump failed").strip()[:300]
                add_event(f"TCPDUMP ошибка: {job['error']}", "error")
            capture_jobs[job_id] = job
    except Exception as e:
        with lock:
            job = capture_jobs.get(job_id, {})
            job["status"] = "error"
            job["error"] = str(e)
            job["finished_at"] = time.time()
            capture_jobs[job_id] = job
        add_event(f"TCPDUMP exception: {e}", "error")


@app.route("/api/capture/start/<ip>", methods=["POST"])
def api_capture_start(ip: str):
    iface = detect_iface()
    if ip != "all":
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "invalid ip"}), 400

    seconds = max(5, min(CAPTURE_MAX_SECONDS, int(request.args.get("seconds", "30"))))
    job_id = uuid.uuid4().hex[:12]
    ts_name = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_ip = ip.replace(":", "_")
    out_file = CAPTURE_DIR / f"capture-{safe_ip}-{ts_name}.pcap"
    target = [] if ip == "all" else ["host", ip]

    cmd = [
        "tcpdump", "-i", iface, *target,
        "-w", str(out_file), "-G", str(seconds), "-W", "1"
    ]
    with lock:
        capture_jobs[job_id] = {
            "id": job_id,
            "status": "running",
            "ip": ip,
            "iface": iface,
            "seconds": seconds,
            "file": str(out_file),
            "started_at": time.time(),
            "cmd": " ".join(cmd),
        }

    threading.Thread(
        target=_capture_worker, args=(job_id, ip, iface, seconds, out_file), daemon=True
    ).start()
    return jsonify({"job_id": job_id, "status": "running", "seconds": seconds})


@app.route("/api/capture/status/<job_id>")
def api_capture_status(job_id: str):
    with lock:
        job = capture_jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    resp = dict(job)
    if job.get("status") == "done":
        resp["download_url"] = f"/api/capture/download/{job_id}"
    return jsonify(resp)


@app.route("/api/capture/download/<job_id>")
def api_capture_download(job_id: str):
    with lock:
        job = capture_jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    if job.get("status") != "done":
        return jsonify({"error": "capture not ready"}), 409
    p = Path(job["file"])
    if not p.exists():
        return jsonify({"error": "pcap file not found"}), 404
    return send_file(p, as_attachment=True, download_name=p.name)


# ── Запуск ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    add_event("NetAnalyzer v2 запущен", "info")

    threads = [
        threading.Thread(target=discovery_loop,    daemon=True),
        threading.Thread(target=server_metrics_loop,daemon=True),
        threading.Thread(target=speed_calc_loop,   daemon=True),
        threading.Thread(target=ping_all_loop,     daemon=True),
    ]
    if HAS_SCAPY:
        threads.append(threading.Thread(target=capture_loop, daemon=True))

    for t in threads:
        t.start()

    time.sleep(1)
    print("=" * 55)
    print("  NetAnalyzer v2")
    print(f"  Интерфейс : {detect_iface()}")
    print(f"  Моя IP    : {get_my_ip(detect_iface())}")
    print(f"  Сеть      : {get_network_prefix(detect_iface())}")
    print(f"  Scapy     : {'✓' if HAS_SCAPY else '✗ (только активные замеры)'}")
    print("  URL       : http://0.0.0.0:5000")
    print("=" * 55)

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
