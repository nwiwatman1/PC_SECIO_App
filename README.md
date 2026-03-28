# 🛡 PC_SECIO — Network Security I/O Monitor

> **See every IP talking to your Windows PC. Ranked by trust. Filtered by date. Open to improve.**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)
![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-yellow.svg)
![Status: Prototype](https://img.shields.io/badge/Status-Prototype-orange.svg)

---

## The Idea

Most people have no idea what their PC is doing on the network right now.
Which IPs are connecting *in*? Which processes are talking *out*? Where in the
world are those servers? Can they be trusted?

PC_SECIO answers those questions with a live, filterable, scored table —
pulled directly from the Windows kernel's network connection tables.

This is a **working prototype** released as an open idea. The goal is not a
finished product — it is a starting point that anyone can download, run,
improve, and share.

---

## What It Does Right Now

- **Taps Windows kernel network tables** via `iphlpapi.dll` (through psutil)
  to list every active TCP/UDP connection on your machine
- **GeoIP enrichment** — country, region, city, ISP for every remote IP
  (powered by ip-api.com, free, no API key required)
- **Trust scoring** — ranks each connection High / Medium / Low / Unknown
  based on port reputation, country, and ISP signals
- **Filters** — by trust level, direction (IN/OUT), protocol, free-text search,
  and date range
- **History** — all connections stored in a local SQLite database
- **Export** — one-click CSV export of any filtered view
- **Packagable** — ships as a single standalone `.exe` via PyInstaller,
  no Python install needed on the recipient's machine

---

## Quick Start

### Option A — Run from source (developers)

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/PC_SECIO_App.git
cd PC_SECIO_App

# 2. Install dependency
pip install psutil

# 3. Run (as Administrator for full visibility)
python pc_secio.py
```

### Option B — Double-click (Windows users)

1. Download the ZIP from [Releases](../../releases/latest)
2. Extract to any folder (e.g. `C:\PC_SECIO\`)
3. Right-click `setup_and_run.bat` → **Run as administrator**

### Option C — Standalone EXE

```bash
# Build a single .exe to share (no Python needed on recipient's PC)
build_exe.bat
# Output: dist\PC_SECIO_App.exe
```

> **Why Run as Administrator?**
> Windows restricts access to network connection details for system processes.
> Without admin rights the app still works but shows fewer connections.

---

## How Trust Scoring Works

Each connection is scored 0–100 based on three signals:

**Port reputation**
| Raises trust | Lowers trust |
|---|---|
| HTTPS (443), DNS (53), NTP (123), IMAPS (993) | Telnet (23), SMB (445), RDP (3389), Tor (9050) |

**Country**
| Raises trust | Lowers trust |
|---|---|
| US, CA, GB, DE, FR, NL, SE, AU, JP, SG... | CN, RU, KP, IR, SY, BY... |

**ISP / Organisation**
| Raises trust | Lowers trust |
|---|---|
| AWS, Google, Microsoft, Cloudflare, Akamai | VPN, Proxy, Tor exit nodes |

Scores map to: **High** (70–100) · **Medium** (45–69) · **Low** (0–44)

The trust list is intentionally opinionated and imperfect — contributions to improve it are very welcome.

---

## Architecture & The Road Ahead

The current implementation uses Python for everything. The original vision —
and the right long-term architecture — is a hybrid:

```
┌─────────────────────────────────────┐
│  Python GUI  (tkinter / future Qt)  │  ← open, easy to improve
└──────────────┬──────────────────────┘
               │ ctypes
┌──────────────▼──────────────────────┐
│  pc_secio_core.dll  (MASM / C)      │  ← compiled, harder to tamper with
└──────────────┬──────────────────────┘
               │ direct syscalls
┌──────────────▼──────────────────────┐
│  Windows NT Kernel                  │  NtQuerySystemInformation
│  iphlpapi.dll / ntdll.dll           │  GetExtendedTcpTable / GetExtendedUdpTable
└─────────────────────────────────────┘
```

Moving the kernel-access layer to compiled MASM or C makes the core
significantly harder to reverse-engineer or hook, while keeping the UI layer
open for community improvement.

---

## Ideas for Contributors

This project is deliberately left open-ended. Here are directions worth exploring:

**Core engine**
- [ ] Rewrite the network scanner as a MASM or C DLL called via ctypes
- [ ] Add UDP connection tracking (currently partial)
- [ ] Historical connection graphing over time
- [ ] Background Windows service mode (no GUI required)

**Trust engine**
- [ ] Integrate threat intelligence feeds (AbuseIPDB, Shodan, VirusTotal)
- [ ] Machine-learning anomaly detection on connection patterns
- [ ] User-configurable allow/block lists
- [ ] Alert on first-seen IPs or unexpected ports

**UI**
- [ ] Replace tkinter with a proper Qt or web-based interface
- [ ] Real-time traffic graph (bytes/s per connection)
- [ ] World map view of active connections
- [ ] System tray mode with trust-level alerts

**Distribution**
- [ ] Windows installer (NSIS or Inno Setup)
- [ ] Auto-update mechanism
- [ ] Signed executable

---

## Project Structure

```
PC_SECIO_App/
├── pc_secio.py          ← Main application (Python source)
├── PC_SECIO_App.spec    ← PyInstaller build configuration
├── setup_and_run.bat    ← Run from source (Windows)
├── build_exe.bat        ← Build standalone EXE
├── LICENSE              ← MIT License
├── README.md            ← This file
└── pc_secio.db          ← Created on first run (your local data, not tracked)
```

---

## Privacy & Data

- All data stays **local** on your machine in `pc_secio.db`
- GeoIP lookups contact `ip-api.com` — only remote IP addresses are sent, no personal data
- Lookup results are cached locally so repeated scans don't re-hit the network
- The app makes no other outbound connections

---

## Credits & Acknowledgements

- **Concept, requirements & testing** — the human behind this project, who
  had the idea, drove every requirement, tested every iteration, and is
  responsible for what it becomes next
- **Initial code generation & debugging** — [Claude](https://claude.ai)
  (Anthropic's AI assistant), which generated the Python prototype, debugged
  threading and date-filter issues, and helped design the trust scoring
  architecture. Claude was a tool in the process — like a compiler or a library.
- **psutil** — the excellent cross-platform process/network library by
  Giampaolo Rodolà (MIT License)
- **ip-api.com** — free GeoIP API used for country/ISP lookups

---

## Disclaimer

This software is provided for **educational and personal security awareness purposes only**.

- It is not a commercial security product
- The trust scores are heuristic estimates, not definitive security verdicts
- No connection should be blocked or allowed based solely on this tool's output
- The author(s) accept no liability for any decisions made based on this software's output

See [LICENSE](LICENSE) for full terms.

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first
to discuss what you would like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes (`git commit -m 'Add: my improvement'`)
4. Push (`git push origin feature/my-improvement`)
5. Open a Pull Request

---

## License

MIT — see [LICENSE](LICENSE) for full text.

In short: use it, modify it, distribute it, build on it.
Keep the copyright notice. Don't hold the author liable. That's it.
