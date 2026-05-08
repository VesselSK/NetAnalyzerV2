#!/usr/bin/env python3
"""
NetAnalyzer v2 — Пассивный захват трафика + обнаружение устройств в сети
Требования: pip install flask flask-cors psutil scapy
Запуск:     sudo python3 app.py   (нужен root для scapy/promiscuous mode)
"""

import subprocess, threading, time, json, re, os, socket, statistics, ipaddress
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template, Response
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

# ── Глобальное состояние ──────────────────────────────────────────────────────
lock = threading.Lock()

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
events = deque(maxlen=100)

# Подсчёт скорости
_speed_ts = time.time()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def add_event(msg, level="info"):
    with lock:
        events.appendleft({"time": ts(), "msg": msg, "level": level})


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

    # Способ 3: ARP из таблицы ядра (всегда доступен)
    try:
        net_obj = ipaddress.ip_network(network, strict=False)
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3]
                    if (
                        mac != "00:00:00:00:00:00"
                        and ip not in found
                        and ipaddress.ip_address(ip) in net_obj
                    ):
                        found[ip] = {"ip": ip, "mac": mac.upper(), "vendor": "",
                                     "hostname": "", "method": "arp-table"}
    except Exception:
        pass

    # Разрешение имён (быстрый DNS)
    for ip, info in found.items():
        if not info.get("hostname"):
            try:
                info["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                info["hostname"] = ip

    return found


def discovery_loop():
    """Периодически сканирует сеть."""
    iface   = detect_iface()
    my_ip   = get_my_ip(iface)
    network = get_network_prefix(iface)

    add_event(f"Интерфейс: {iface} ({my_ip})", "info")
    add_event(f"Сканирую сеть {network}...", "info")

    while True:
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
                    "rx_mbps":  traffic[ip]["rx_mbps"],
                    "tx_mbps":  traffic[ip]["tx_mbps"],
                    "pps":      traffic[ip]["pps"],
                }
            # Помечаем пропавшие
            for ip in list(devices.keys()):
                if ip not in found:
                    devices[ip]["online"] = False

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
    with lock:
        return jsonify(list(events)[:30])


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
    })


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
