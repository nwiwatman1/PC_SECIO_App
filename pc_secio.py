"""
PC_SECIO_App - Windows Network Security I/O Monitor
Taps Windows kernel network tables via psutil/iphlpapi.dll
Shows all inbound/outbound IP connections with GeoIP, port info, and trust scoring
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import sqlite3
import socket
import json
import os
import sys
import csv
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
import urllib.request
import urllib.parse

try:
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

# ─────────────────────────────────────────────
#  DATABASE SETUP
# ─────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pc_secio.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            direction TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            protocol TEXT,
            status TEXT,
            pid INTEGER,
            process_name TEXT,
            country TEXT,
            country_code TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            trust_level TEXT,
            trust_score INTEGER,
            port_label TEXT,
            flag TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY,
            data TEXT,
            cached_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  KNOWN PORTS & TRUST DATA
# ─────────────────────────────────────────────
KNOWN_PORTS = {
    20: ("FTP Data", "Medium"),
    21: ("FTP Control", "Medium"),
    22: ("SSH", "Medium"),
    23: ("Telnet", "Low"),
    25: ("SMTP", "Medium"),
    53: ("DNS", "High"),
    67: ("DHCP Server", "High"),
    68: ("DHCP Client", "High"),
    80: ("HTTP", "Medium"),
    110: ("POP3", "Medium"),
    119: ("NNTP", "Low"),
    123: ("NTP", "High"),
    135: ("RPC", "Low"),
    137: ("NetBIOS NS", "Low"),
    138: ("NetBIOS DGM", "Low"),
    139: ("NetBIOS SSN", "Low"),
    143: ("IMAP", "Medium"),
    161: ("SNMP", "Low"),
    194: ("IRC", "Low"),
    389: ("LDAP", "Medium"),
    443: ("HTTPS", "High"),
    445: ("SMB", "Low"),
    465: ("SMTPS", "Medium"),
    500: ("IKE/VPN", "Medium"),
    514: ("Syslog", "Medium"),
    587: ("SMTP TLS", "Medium"),
    631: ("IPP Print", "Medium"),
    636: ("LDAPS", "Medium"),
    993: ("IMAPS", "High"),
    995: ("POP3S", "High"),
    1080: ("SOCKS Proxy", "Low"),
    1194: ("OpenVPN", "Medium"),
    1433: ("MS SQL", "Low"),
    1434: ("MS SQL Browser", "Low"),
    1723: ("PPTP VPN", "Low"),
    3306: ("MySQL", "Low"),
    3389: ("RDP", "Low"),
    4444: ("Metasploit", "Low"),
    5900: ("VNC", "Low"),
    5938: ("TeamViewer", "Medium"),
    6881: ("BitTorrent", "Low"),
    8080: ("HTTP Alt", "Medium"),
    8443: ("HTTPS Alt", "Medium"),
    9050: ("Tor", "Low"),
    27017: ("MongoDB", "Low"),
}

HIGH_TRUST_COUNTRIES = {
    "US", "CA", "GB", "DE", "FR", "NL", "SE", "NO", "DK", "FI",
    "CH", "AU", "NZ", "JP", "SG", "IE", "AT", "BE", "LU", "IS"
}
LOW_TRUST_COUNTRIES = {
    "CN", "RU", "KP", "IR", "SY", "CU", "BY", "MM", "VE", "LY"
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 9050, 1080, 23, 135, 137, 138, 139, 445}

# ─────────────────────────────────────────────
#  TRUST SCORING ENGINE
# ─────────────────────────────────────────────
def calculate_trust(remote_ip, remote_port, country_code, isp):
    score = 50  # neutral start
    reasons = []

    # Private / loopback = high trust
    if remote_ip.startswith(("127.", "10.", "192.168.", "172.16.", "::1", "fe80")):
        return "High", 95, "Local/private network"

    # Port analysis
    port_info = KNOWN_PORTS.get(remote_port)
    if port_info:
        label, port_trust = port_info
        if port_trust == "High":
            score += 20
        elif port_trust == "Low":
            score -= 25
    else:
        label = f"Port {remote_port}"

    if remote_port in SUSPICIOUS_PORTS:
        score -= 30
        reasons.append("suspicious port")

    # Ephemeral ports (random outbound) - neutral
    if remote_port > 49151:
        label = "Ephemeral"

    # Country analysis
    if country_code in HIGH_TRUST_COUNTRIES:
        score += 15
    elif country_code in LOW_TRUST_COUNTRIES:
        score -= 30
        reasons.append("flagged country")
    elif not country_code:
        score -= 10

    # ISP heuristics
    if isp:
        isp_lower = isp.lower()
        if any(x in isp_lower for x in ["amazon", "google", "microsoft", "cloudflare", "akamai", "fastly"]):
            score += 15
            reasons.append("major cloud provider")
        if any(x in isp_lower for x in ["vpn", "proxy", "tor", "anonymous"]):
            score -= 20
            reasons.append("VPN/proxy/Tor")

    score = max(0, min(100, score))

    if score >= 70:
        level = "High"
    elif score >= 45:
        level = "Medium"
    elif score >= 20:
        level = "Low"
    else:
        level = "Low"

    port_label = KNOWN_PORTS.get(remote_port, (f"Port {remote_port}", "Unknown"))[0]
    return level, score, port_label

# ─────────────────────────────────────────────
#  GEO IP LOOKUP  (ip-api.com — free, no key)
# ─────────────────────────────────────────────
_geo_cache = {}

def geo_lookup(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Check DB cache first
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT data FROM geo_cache WHERE ip=?", (ip,))
    row = c.fetchone()
    conn.close()

    if row:
        data = json.loads(row[0])
        _geo_cache[ip] = data
        return data

    # Private IPs
    if ip.startswith(("127.", "10.", "192.168.", "172.16.", "::1", "fe80")):
        data = {"country": "Local", "countryCode": "LO", "regionName": "", "city": "", "isp": "Local Network", "flag": "🏠"}
        _geo_cache[ip] = data
        return data

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org"
        req = urllib.request.Request(url, headers={"User-Agent": "PC_SECIO/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                data["flag"] = country_flag(data.get("countryCode", ""))
                _geo_cache[ip] = data
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO geo_cache (ip,data,cached_at) VALUES (?,?,?)",
                          (ip, json.dumps(data), datetime.now().isoformat()))
                conn.commit()
                conn.close()
                return data
    except Exception:
        pass

    data = {"country": "Unknown", "countryCode": "", "regionName": "", "city": "", "isp": "", "flag": "🌐"}
    _geo_cache[ip] = data
    return data

def country_flag(code):
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)
    except Exception:
        return "🌐"

# ─────────────────────────────────────────────
#  NETWORK SCANNER  (calls Windows kernel tables)
# ─────────────────────────────────────────────
def get_local_ips():
    local = set()
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            local.add(addr.address)
    return local

def scan_connections():
    local_ips = get_local_ips()
    results = []
    seen = set()

    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return results

    proc_map = {}
    try:
        for p in psutil.process_iter(["pid", "name"]):
            proc_map[p.info["pid"]] = p.info["name"]
    except Exception:
        pass

    for c in conns:
        if not c.raddr:
            continue

        local_ip = c.laddr.ip if c.laddr else ""
        local_port = c.laddr.port if c.laddr else 0
        remote_ip = c.raddr.ip
        remote_port = c.raddr.port

        key = (local_ip, local_port, remote_ip, remote_port)
        if key in seen:
            continue
        seen.add(key)

        direction = "IN" if local_ip in local_ips and remote_ip not in local_ips else "OUT"
        protocol = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        status = c.status or ""
        pid = c.pid or 0
        process_name = proc_map.get(pid, "Unknown")

        results.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "direction": direction,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": protocol,
            "status": status,
            "pid": pid,
            "process_name": process_name,
        })

    return results

def enrich_and_store(raw):
    enriched = []
    for r in raw:
        geo = geo_lookup(r["remote_ip"])
        country = geo.get("country", "Unknown")
        country_code = geo.get("countryCode", "")
        region = geo.get("regionName", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")
        flag = geo.get("flag", "🌐")

        trust_level, trust_score, port_label = calculate_trust(
            r["remote_ip"], r["remote_port"], country_code, isp
        )

        row = {**r, "country": country, "country_code": country_code,
               "region": region, "city": city, "isp": isp,
               "trust_level": trust_level, "trust_score": trust_score,
               "port_label": port_label, "flag": flag}
        enriched.append(row)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO connections
            (timestamp,direction,local_ip,local_port,remote_ip,remote_port,
             protocol,status,pid,process_name,country,country_code,region,
             city,isp,trust_level,trust_score,port_label,flag)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (row["timestamp"], row["direction"], row["local_ip"], row["local_port"],
              row["remote_ip"], row["remote_port"], row["protocol"], row["status"],
              row["pid"], row["process_name"], row["country"], row["country_code"],
              row["region"], row["city"], row["isp"], row["trust_level"],
              row["trust_score"], row["port_label"], row["flag"]))
        conn.commit()
        conn.close()

    return enriched

# ─────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────
TRUST_COLORS = {
    "High":    {"bg": "#0d3b2e", "fg": "#00e5a0", "badge": "#00c87a"},
    "Medium":  {"bg": "#2e2800", "fg": "#ffd166", "badge": "#f0b429"},
    "Low":     {"bg": "#3b0d0d", "fg": "#ff6b6b", "badge": "#e53e3e"},
    "Unknown": {"bg": "#1a1a2e", "fg": "#a0aec0", "badge": "#718096"},
}

DARK = {
    "bg":        "#0a0e1a",
    "panel":     "#0f1623",
    "card":      "#151d2e",
    "border":    "#1e2d45",
    "text":      "#e2e8f0",
    "muted":     "#64748b",
    "accent":    "#3b82f6",
    "accent2":   "#06b6d4",
    "header_bg": "#0d1526",
}

class PC_SECIO_App:
    def __init__(self, root):
        self.root = root
        self.root.title("PC_SECIO  •  Network Security Monitor")
        self.root.geometry("1400x860")
        self.root.configure(bg=DARK["bg"])
        self.root.minsize(1100, 650)

        self.scanning = False
        self.scan_interval = tk.IntVar(value=10)
        self.filter_trust = tk.StringVar(value="All")
        self.filter_dir = tk.StringVar(value="All")
        self.filter_proto = tk.StringVar(value="All")
        self.search_var = tk.StringVar()
        self.date_from = tk.StringVar(value=(datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"))
        self.date_to   = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        self.all_rows = []
        self._store_full = {}   # must exist before any row-select event fires
        self.sort_col = "timestamp"
        self.sort_rev = True

        self._setup_styles()
        self._build_ui()
        self.refresh_from_db()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure(".", background=DARK["bg"], foreground=DARK["text"], font=("Consolas", 10))

        style.configure("Treeview",
            background=DARK["card"], foreground=DARK["text"],
            fieldbackground=DARK["card"], rowheight=32,
            font=("Consolas", 10), borderwidth=0)
        style.configure("Treeview.Heading",
            background=DARK["header_bg"], foreground=DARK["accent2"],
            font=("Consolas", 10, "bold"), relief="flat", borderwidth=0)
        style.map("Treeview",
            background=[("selected", DARK["border"])],
            foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", DARK["border"])])

        style.configure("TCombobox",
            background=DARK["card"], foreground=DARK["text"],
            fieldbackground=DARK["card"], selectbackground=DARK["border"],
            arrowcolor=DARK["accent"])
        style.configure("TScrollbar",
            background=DARK["card"], troughcolor=DARK["panel"],
            arrowcolor=DARK["accent"])

    def _build_ui(self):
        # ── TOP BAR ──
        top = tk.Frame(self.root, bg=DARK["panel"], height=64)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        tk.Label(top, text="🛡", font=("Segoe UI Emoji", 22),
                 bg=DARK["panel"], fg=DARK["accent2"]).pack(side="left", padx=(18, 6), pady=10)
        tk.Label(top, text="PC_SECIO", font=("Consolas", 18, "bold"),
                 bg=DARK["panel"], fg=DARK["text"]).pack(side="left")
        tk.Label(top, text="  Network Security I/O Monitor",
                 font=("Consolas", 11), bg=DARK["panel"], fg=DARK["muted"]).pack(side="left", pady=2)

        # Status pill
        self.status_lbl = tk.Label(top, text="● IDLE", font=("Consolas", 10, "bold"),
                                   bg=DARK["panel"], fg=DARK["muted"])
        self.status_lbl.pack(side="right", padx=18)

        self.last_scan_lbl = tk.Label(top, text="Last scan: —",
                                      font=("Consolas", 9), bg=DARK["panel"], fg=DARK["muted"])
        self.last_scan_lbl.pack(side="right", padx=10)

        # ── STATS BAR ──
        stats = tk.Frame(self.root, bg=DARK["bg"], pady=6)
        stats.pack(fill="x")
        self.stat_labels = {}
        for key, color in [("Total", DARK["accent2"]), ("High ✓", "#00e5a0"),
                           ("Medium ◈", "#ffd166"), ("Low ✗", "#ff6b6b"), ("Unknown ?", DARK["muted"])]:
            f = tk.Frame(stats, bg=DARK["card"], padx=18, pady=6)
            f.pack(side="left", padx=(8, 0))
            tk.Label(f, text=key, font=("Consolas", 9), bg=DARK["card"], fg=DARK["muted"]).pack()
            lbl = tk.Label(f, text="0", font=("Consolas", 16, "bold"), bg=DARK["card"], fg=color)
            lbl.pack()
            self.stat_labels[key] = lbl

        # ── FILTER BAR ──
        fbar = tk.Frame(self.root, bg=DARK["panel"], pady=8)
        fbar.pack(fill="x")

        def combo(parent, label, var, values, w=120):
            tk.Label(parent, text=label, font=("Consolas", 9),
                     bg=DARK["panel"], fg=DARK["muted"]).pack(side="left", padx=(10, 2))
            cb = ttk.Combobox(parent, textvariable=var, values=values, width=w//10, state="readonly")
            cb.pack(side="left", padx=(0, 6))
            cb.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
            return cb

        combo(fbar, "Trust:", self.filter_trust,
              ["All", "High", "Medium", "Low", "Unknown"])
        combo(fbar, "Direction:", self.filter_dir, ["All", "IN", "OUT"])
        combo(fbar, "Protocol:", self.filter_proto, ["All", "TCP", "UDP"])

        tk.Label(fbar, text="From:", font=("Consolas", 9),
                 bg=DARK["panel"], fg=DARK["muted"]).pack(side="left", padx=(14, 2))
        tk.Entry(fbar, textvariable=self.date_from, width=11,
                 bg=DARK["card"], fg=DARK["text"], insertbackground=DARK["text"],
                 relief="flat", font=("Consolas", 10)).pack(side="left")
        tk.Label(fbar, text="To:", font=("Consolas", 9),
                 bg=DARK["panel"], fg=DARK["muted"]).pack(side="left", padx=(8, 2))
        tk.Entry(fbar, textvariable=self.date_to, width=11,
                 bg=DARK["card"], fg=DARK["text"], insertbackground=DARK["text"],
                 relief="flat", font=("Consolas", 10)).pack(side="left")
        tk.Button(fbar, text="Apply Dates", command=self.refresh_from_db,
                  bg=DARK["border"], fg=DARK["accent2"], relief="flat",
                  font=("Consolas", 9), cursor="hand2", padx=8).pack(side="left", padx=(6, 0))

        tk.Label(fbar, text="Search:", font=("Consolas", 9),
                 bg=DARK["panel"], fg=DARK["muted"]).pack(side="left", padx=(14, 2))
        search_entry = tk.Entry(fbar, textvariable=self.search_var, width=20,
                                bg=DARK["card"], fg=DARK["text"], insertbackground=DARK["text"],
                                relief="flat", font=("Consolas", 10))
        search_entry.pack(side="left")
        search_entry.bind("<KeyRelease>", lambda e: self.apply_filters())

        # ── CONTROL BAR ──
        cbar = tk.Frame(self.root, bg=DARK["bg"], pady=6)
        cbar.pack(fill="x")

        self.scan_btn = tk.Button(cbar, text="▶  START SCAN",
                                  command=self.toggle_scan,
                                  bg=DARK["accent"], fg="white",
                                  font=("Consolas", 10, "bold"), relief="flat",
                                  cursor="hand2", padx=14, pady=6)
        self.scan_btn.pack(side="left", padx=8)

        tk.Button(cbar, text="⟳  Refresh DB", command=self.refresh_from_db,
                  bg=DARK["card"], fg=DARK["accent2"], relief="flat",
                  font=("Consolas", 10), cursor="hand2", padx=10, pady=6).pack(side="left", padx=4)

        tk.Button(cbar, text="⬇  Export CSV", command=self.export_csv,
                  bg=DARK["card"], fg=DARK["accent2"], relief="flat",
                  font=("Consolas", 10), cursor="hand2", padx=10, pady=6).pack(side="left", padx=4)

        tk.Button(cbar, text="🗑  Clear DB", command=self.clear_db,
                  bg=DARK["card"], fg="#ff6b6b", relief="flat",
                  font=("Consolas", 10), cursor="hand2", padx=10, pady=6).pack(side="left", padx=4)

        tk.Label(cbar, text="Interval (s):", font=("Consolas", 9),
                 bg=DARK["bg"], fg=DARK["muted"]).pack(side="left", padx=(20, 4))
        tk.Spinbox(cbar, from_=5, to=300, textvariable=self.scan_interval, width=5,
                   bg=DARK["card"], fg=DARK["text"], insertbackground=DARK["text"],
                   buttonbackground=DARK["border"], relief="flat",
                   font=("Consolas", 10)).pack(side="left")

        # ── TABLE ──
        table_frame = tk.Frame(self.root, bg=DARK["bg"])
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        cols = ("timestamp", "direction", "flag", "remote_ip", "remote_port",
                "port_label", "country", "isp", "protocol", "process_name",
                "status", "trust_level", "trust_score")
        col_labels = {
            "timestamp": "Timestamp", "direction": "Dir", "flag": "🌍",
            "remote_ip": "Remote IP", "remote_port": "Port",
            "port_label": "Service", "country": "Country",
            "isp": "ISP / Org", "protocol": "Proto",
            "process_name": "Process", "status": "Status",
            "trust_level": "Trust", "trust_score": "Score"
        }
        col_widths = {
            "timestamp": 150, "direction": 45, "flag": 35,
            "remote_ip": 130, "remote_port": 55, "port_label": 110,
            "country": 110, "isp": 160, "protocol": 50,
            "process_name": 120, "status": 90, "trust_level": 70, "trust_score": 55
        }

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 selectmode="extended")
        for col in cols:
            self.tree.heading(col, text=col_labels[col],
                              command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=col_widths[col], minwidth=30, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        # Tag colours
        for trust, c in TRUST_COLORS.items():
            self.tree.tag_configure(trust, foreground=c["fg"])
        self.tree.tag_configure("stripe", background="#111827")

        # ── DETAIL PANEL ──
        detail = tk.Frame(self.root, bg=DARK["panel"], height=110)
        detail.pack(fill="x", side="bottom")
        detail.pack_propagate(False)

        tk.Label(detail, text="Connection Detail",
                 font=("Consolas", 9, "bold"), bg=DARK["panel"],
                 fg=DARK["muted"]).pack(anchor="w", padx=12, pady=(6, 0))
        self.detail_lbl = tk.Label(detail, text="Select a row to see full details.",
                                   font=("Consolas", 10), bg=DARK["panel"],
                                   fg=DARK["text"], justify="left", wraplength=1380)
        self.detail_lbl.pack(anchor="w", padx=12)

    # ─────── SCAN CONTROL ───────
    def toggle_scan(self):
        if self.scanning:
            self.scanning = False
            self.scan_btn.config(text="▶  START SCAN", bg=DARK["accent"])
            self.status_lbl.config(text="● IDLE", fg=DARK["muted"])
        else:
            self.scanning = True
            self.scan_btn.config(text="⏹  STOP SCAN", bg="#dc2626")
            self.status_lbl.config(text="● SCANNING", fg="#00e5a0")
            t = threading.Thread(target=self.scan_loop, daemon=True)
            t.start()

    def scan_loop(self):
        while self.scanning:
            # NEVER touch tkinter widgets directly from a background thread
            # Always hand off to main thread via root.after(0, ...)
            self.root.after(0, lambda: self.status_lbl.config(
                text="● SCANNING…", fg="#ffd166"))
            try:
                raw = scan_connections()
                enriched = enrich_and_store(raw)
                count = len(enriched)
                ts_str = datetime.now().strftime('%H:%M:%S')
                today = datetime.now().strftime("%Y-%m-%d")

                def _ui_update(c=count, ts=ts_str, td=today):
                    # Auto-advance date_to so today's rows are never excluded
                    self.date_to.set(td)
                    self.refresh_from_db()
                    self.last_scan_lbl.config(
                        text=f"Last scan: {ts}  ({c} connections)")
                    self.status_lbl.config(text="● SCANNING", fg="#00e5a0")

                self.root.after(0, _ui_update)

            except Exception as e:
                err_str = str(e)
                self.root.after(0, lambda s=err_str: self.status_lbl.config(
                    text=f"● ERR: {s[:60]}", fg="#ff6b6b"))

            interval = self.scan_interval.get()
            for _ in range(interval * 2):
                if not self.scanning:
                    break
                time.sleep(0.5)

    # ─────── DATA LOADING ───────
    def refresh_from_db(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            df = (self.date_from.get().strip() or "2000-01-01") + "T00:00:00"
            dt = (self.date_to.get().strip()   or "2099-12-31") + "T23:59:59"
            c.execute("""
                SELECT timestamp,direction,flag,remote_ip,remote_port,port_label,
                       country,isp,protocol,process_name,status,trust_level,trust_score,
                       local_ip,local_port,region,city,country_code,pid
                FROM connections
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp DESC
                LIMIT 5000
            """, (df, dt))
            rows = c.fetchall()
            conn.close()
            self.all_rows = rows
            self.apply_filters()
        except Exception as e:
            messagebox.showerror("DB Error", str(e))

    def apply_filters(self):
        trust_f = self.filter_trust.get()
        dir_f = self.filter_dir.get()
        proto_f = self.filter_proto.get()
        search = self.search_var.get().lower()

        filtered = []
        for row in self.all_rows:
            ts, direction, flag, rip, rport, plabel, country, isp, proto, proc, status, trust, score, lip, lport, region, city, cc, pid = row

            if trust_f != "All" and trust != trust_f:
                continue
            if dir_f != "All" and direction != dir_f:
                continue
            if proto_f != "All" and proto != proto_f:
                continue
            if search:
                haystack = f"{rip} {country} {isp} {proc} {plabel} {proto} {trust}".lower()
                if search not in haystack:
                    continue
            filtered.append(row)

        self.populate_table(filtered)
        self.update_stats(filtered)

    def populate_table(self, rows):
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(rows):
            ts, direction, flag, rip, rport, plabel, country, isp, proto, proc, status, trust, score, *_ = row
            flag = flag or "🌐"
            values = (ts, direction, flag, rip, rport, plabel, country, isp, proto, proc, status, trust, score)
            tags = [trust]
            if i % 2 == 1:
                tags.append("stripe")
            self.tree.insert("", "end", values=values, tags=tags, iid=str(i))
            # Store full row
            self.tree.set(str(i), "timestamp", ts)

        self._store_full = {str(i): row for i, row in enumerate(rows)}

    def update_stats(self, rows):
        total = len(rows)
        counts = defaultdict(int)
        for row in rows:
            trust = row[11]
            counts[trust] += 1

        self.stat_labels["Total"].config(text=str(total))
        self.stat_labels["High ✓"].config(text=str(counts.get("High", 0)))
        self.stat_labels["Medium ◈"].config(text=str(counts.get("Medium", 0)))
        self.stat_labels["Low ✗"].config(text=str(counts.get("Low", 0)))
        self.stat_labels["Unknown ?"].config(text=str(counts.get("Unknown", 0)))

    def on_row_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        row = self._store_full.get(iid)
        if not row:
            return
        ts, direction, flag, rip, rport, plabel, country, isp, proto, proc, status, trust, score, lip, lport, region, city, cc, pid = row
        txt = (f"  {flag}  {direction}  {ts}  |  Remote: {rip}:{rport} ({plabel})  |  "
               f"Local: {lip}:{lport}  |  Process: {proc} (PID {pid})  |  "
               f"Country: {country} ({cc}) › {region} › {city}  |  "
               f"ISP: {isp}  |  Protocol: {proto}  |  Status: {status}  |  "
               f"Trust: {trust}  (score {score}/100)")
        self.detail_lbl.config(text=txt)

    def sort_by(self, col):
        col_idx = {"timestamp": 0, "direction": 1, "flag": 2, "remote_ip": 3,
                   "remote_port": 4, "port_label": 5, "country": 6, "isp": 7,
                   "protocol": 8, "process_name": 9, "status": 10,
                   "trust_level": 11, "trust_score": 12}.get(col, 0)
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col = col
            self.sort_rev = True
        self.all_rows.sort(key=lambda r: (r[col_idx] or ""), reverse=self.sort_rev)
        self.apply_filters()

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"pc_secio_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if not path:
            return
        headers = ["timestamp","direction","flag","remote_ip","remote_port","port_label",
                   "country","isp","protocol","process_name","status","trust_level","trust_score",
                   "local_ip","local_port","region","city","country_code","pid"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for row in self.all_rows:
                w.writerow(row)
        messagebox.showinfo("Export", f"Exported {len(self.all_rows)} rows to:\n{path}")

    def clear_db(self):
        if messagebox.askyesno("Clear Database",
                               "Delete ALL stored connection records?\nThis cannot be undone."):
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM connections")
            conn.commit()
            conn.close()
            self.all_rows = []
            self.apply_filters()

# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
def main():
    init_db()
    root = tk.Tk()

    # Try to set app icon
    try:
        root.iconbitmap(default="")
    except Exception:
        pass

    try:
        root.tk.call("tk", "scaling", 1.25)
    except Exception:
        pass

    app = PC_SECIO_App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
