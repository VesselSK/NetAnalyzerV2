# NetAnalyzer v2 — Развёртывание

## Что нового в v2
- Сканирование ВСЕХ устройств в сети (ARP-scan / nmap / /proc/net/arp)
- Пассивный захват трафика через Scapy (promiscuous mode)
- Метрики на каждое устройство: RTT, Jitter, Loss, RX/TX Мбит/с, PPS
- Выбор устройства в сайдбаре — детальный дашборд
- Трафик по протоколам (TCP/UDP/ICMP/ARP/Other) на каждый хост

---

## Требования

```
Debian 11/12
Python 3.10+
Сеть ВМ: Bridged (обязательно!)
```

---

## 1. Системные пакеты

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    iputils-ping nmap arp-scan tcpdump iperf3 avahi-utils libpcap-dev
```

`arp-scan` и `nmap` используются для обнаружения устройств.  
`libpcap-dev` нужен для Scapy (захват пакетов).

---

## 2. Установка проекта

```bash
sudo mkdir -p /opt/netanalyzer
sudo chown $USER:$USER /opt/netanalyzer
cp app.py /opt/netanalyzer/
cp requirements.txt /opt/netanalyzer/
mkdir -p /opt/netanalyzer/templates
cp index.html /opt/netanalyzer/templates/index.html

cd /opt/netanalyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 3. Включение promiscuous mode

```bash
# Узнать имя интерфейса
ip link show

# Включить promiscuous (замените eth0 на ваш интерфейс)
sudo ip link set eth0 promisc on

# Проверить (должно быть PROMISC в флагах)
ip link show eth0
```

Чтобы promiscuous включался автоматически при старте:
```bash
# /etc/network/interfaces или через systemd-networkd
# Добавить в /etc/rc.local:
ip link set eth0 promisc on
```

---

## 4. Запуск (нужен root для Scapy)

```bash
cd /opt/netanalyzer
source venv/bin/activate
sudo venv/bin/python3 app.py
```

Откройте в браузере: `http://<IP_вашей_ВМ>:5000`

---

## 5. Переменные окружения

```bash
IFACE=eth0          # интерфейс (авто если пусто)
PING_HOST=8.8.8.8   # хост для baseline-пинга
LOG_DIR=/opt/netanalyzer/logs        # где хранить логи событий по дням
CAPTURE_DIR=/opt/netanalyzer/captures # где хранить pcap-файлы
DEVICE_NAMES_FILE=/opt/netanalyzer/device-names.json # пользовательские имена
IPERF_MAX_SECONDS=60   # максимум длительности iperf3-теста
```

Пример:
```bash
sudo IFACE=eth0 venv/bin/python3 app.py
```

---

## 6. Systemd (автозапуск от root)

```ini
# /etc/systemd/system/netanalyzer.service
[Unit]
Description=NetAnalyzer v2
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netanalyzer
ExecStart=/opt/netanalyzer/venv/bin/python3 app.py
Restart=always
RestartSec=2
Environment=IFACE=eth0
Environment=LOG_DIR=/opt/netanalyzer/logs
Environment=CAPTURE_DIR=/opt/netanalyzer/captures
Environment=DEVICE_NAMES_FILE=/opt/netanalyzer/device-names.json
Environment=IPERF_MAX_SECONDS=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netanalyzer
sudo systemctl status netanalyzer --no-pager
sudo journalctl -u netanalyzer -n 100 --no-pager
```

---

## 7. Nginx (обратный прокси)

```nginx
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 8. API эндпоинты

| URL                      | Описание                                   |
|--------------------------|--------------------------------------------|
| `GET /`                  | Веб-интерфейс                              |
| `GET /api/devices`       | Все устройства в сети (JSON)               |
| `GET /api/device/<ip>`   | Детальные метрики устройства               |
| `GET /api/ping/<ip>`     | Ручной ping до любого IP                   |
| `GET /api/server`        | Метрики самого сервера                     |
| `GET /api/traffic/global`| Суммарный трафик по сети                   |
| `GET /api/stream`        | SSE поток обновлений                       |
| `GET /api/events`        | Журнал событий (пагинация: limit, offset) |
| `GET /api/events/files`  | Список дневных лог-файлов                  |
| `GET /api/events/download?date=YYYY-MM-DD` | Скачать лог за день         |
| `GET /api/info`          | Информация об интерфейсе и сети            |
| `POST /api/capture/start/<ip>?seconds=30` | Старт tcpdump по IP         |
| `GET /api/capture/status/<job_id>` | Статус захвата                       |
| `GET /api/capture/download/<job_id>` | Скачать pcap                   |
| `POST /api/iperf/start/<ip>?seconds=10` | Старт iperf3-теста до устройства |
| `GET /api/iperf/status/<job_id>` | Статус/результат iperf3              |
| `GET/POST /api/device-name/<ip>` | Получить/сохранить пользовательское имя |

---

## 9. Обновление без "ручного шаманства"

```bash
# 1) Остановить сервис
sudo systemctl stop netanalyzer

# 2) Обновить файлы приложения
cd /opt/netanalyzer
cp /path/to/new/app.py .
cp /path/to/new/index.html ./templates/index.html
cp /path/to/new/requirements.txt .

# 3) (опционально) обновить зависимости
source venv/bin/activate
pip install -r requirements.txt
deactivate

# 4) Запустить обратно
sudo systemctl start netanalyzer
sudo systemctl status netanalyzer --no-pager
```

Если используете nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 10. Возможные проблемы

**Scapy: Operation not permitted**
```bash
# Запускать только от root или через setcap:
sudo setcap cap_net_raw,cap_net_admin=eip venv/bin/python3
```

**arp-scan не находит устройства**
```bash
# Убедитесь что интерфейс bridged и в той же подсети что хост
sudo arp-scan --localnet --interface=eth0
```

**Хостовая машина не видна**
```bash
# На хосте (Windows): отключить фаервол для приватных сетей ИЛИ
# разрешить ICMP (ping) в Windows Defender Firewall
```

**Scapy не захватывает трафик**
```bash
# Убедитесь что promiscuous mode включён:
ip link show eth0 | grep PROMISC

# Проверьте tcpdump:
sudo tcpdump -i eth0 -c 10
```