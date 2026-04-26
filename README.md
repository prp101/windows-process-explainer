# Windows Process Killer

> A fast terminal UI for scanning, understanding, and killing Windows processes — without the noise of Task Manager.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=flat-square&logo=windows&logoColor=white)

---

## What it does

Windows ships with ~300 background processes at any given time. Most are mystery `.exe` files with cryptic names. This tool:

- **Scans & categorizes** every running process — System, Browser, Developer, Gaming, Security, Communication, Media, and more
- **Describes** each process in plain English — built-in database of 200+ known processes, falls back to reading the executable's Windows PE version info
- **Rates kill safety** for every process — tells you whether killing is safe, risky, or actively recommended
- **Kills** any process with a single keystroke, with a confirmation dialog that warns before touching anything critical
- **Blocks** a process from ever restarting — detects and disables the Windows service, registry autostart entry, or scheduled task behind it
- **Expands** any process to show full details and a live-fetched online description, all inline — no browser

---

## Screenshot

```
 Windows Process Killer ──────────────────────────────────── 14:32 ──
 Filter by name, category, description…           100 / 307 processes
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ PID   ┃ Process Name             ┃ Category        ┃ Safety     ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│  4424 │ MemCompression           │ ⚙  System       │ ⛔ Risky   │
│  2968 │ bdservicehost.exe        │ 🛡  Security     │ ⛔ Risky   │
│   404 │ brave.exe                │ 🌐 Browser      │ ✓ Safe     │
│  7404 │ Cursor.exe               │ 💻 Developer    │ ✓ Safe     │
│  1882 │ epicgameslauncher.exe    │ 🎮 Gaming       │ ★ Kill it  │
│   ... │ ...                      │ ...             │ ...        │
└───────┴──────────────────────────┴─────────────────┴────────────┘
 K kill   B block   E expand   R refresh   / search   Q quit
```

---

## Getting started

**Prerequisites:** Python 3.10+ on Windows 11

```bat
git clone https://github.com/your-username/windows-killer
cd windows-killer
run.bat
```

`run.bat` creates a virtual environment, installs dependencies, and launches the app — both from the terminal and by double-clicking in File Explorer.

> **Tip:** Right-click `run.bat` → *Run as administrator* to kill or block protected system processes.

---

## Keybindings

| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate the process list |
| `K` or `Delete` | Kill selected process (confirmation required) |
| `B` | Block — kill the process and disable everything that restarts it |
| `E` | Expand — full details + live online description fetched inline |
| `R` | Full refresh — re-scan and rebuild the list |
| `/` | Search — filter by name, category, description, or safety rating |
| `Esc` | Clear search / close any open panel |
| Click column header | Sort by that column (click again to reverse) |
| `Q` | Quit |

---

## Kill safety ratings

Every process in the list gets a safety rating so you know what you're dealing with before you hit `K`.

| Rating | Color | Meaning |
|--------|-------|---------|
| `⛔ Risky` | Red | Windows system or security process — killing may destabilize or crash |
| `⚠ Caution` | Yellow | May lose data (open Office files, running databases, Docker containers) |
| `✓ Safe` | Green | User application — safe to close at any time |
| `★ Kill it` | Bright green | Known bloat — unnecessary background process actively recommended for removal |

Click the **Safety** column header to sort: all `★ Kill it` processes float to the top.

**Known bloat includes:** Epic Games Launcher, Steam Web Helper, NVIDIA Telemetry, Windows Compatibility Telemetry, Cortana, Office Click-to-Run updater, Xbox Game Bar, Edge WebView2 background instances, and more.

---

## Block (`B`) — kill and prevent restart

Pressing `B` opens a panel that scans for every mechanism that could bring the process back:

```
epicgameslauncher.exe  🎮 Gaming  PID 5832

Found 2 startup mechanisms:

  ⚙  Windows Service — Epic Games Launcher Service
  🔑  Registry autostart (HKCU Run): EpicGamesLauncher

Kill & Block will terminate the process and disable all
of the above so it cannot start again automatically.

  Enter confirm    Esc cancel
```

What gets disabled:

| Type | How | Icon |
|------|-----|------|
| Windows Service | `sc config ... start= disabled` | ⚙ |
| Registry Run key | Deletes the value from `HKCU/HKLM\...\Run` | 🔑 |
| Scheduled Task | `schtasks /Change /TN ... /DISABLE` | ⏰ |

> Service and HKLM changes require Administrator. Run as admin for full blocking power.

---

## Expand (`E`) — live process details

```
NahimicService.exe   ❓ Other   PID 6132

── Identity ─────────────────────────────────────────────
  Description   NahimicService
  Company       Nahimic
  Product       NahimicService
  Version       2.8.2.0

── Location ─────────────────────────────────────────────
  C:\Windows\System32\NahimicService.exe

── Runtime ──────────────────────────────────────────────
  User      SYSTEM
  Started   2026-04-25 23:25:39
  Parent    services.exe (PID 1744)
  CPU  0.0%   RAM  12.4 MB

── Online Description ───────────────────────────────────
  nahimicservice.exe is an executable file that is part
  of the Nahimic software, developed by A-Volute. Nahimic
  is a technology company that specializes in 3D sound
  software for gaming…
```

The **Online Description** fetches from DuckDuckGo's Instant Answer API and file.net simultaneously — whichever returns first wins. Local info appears instantly; the description fills in within a couple of seconds.

---

## How process descriptions work

1. **Built-in database** — 200+ curated entries for browsers, dev tools, games, security software, Microsoft apps, communication tools, and more
2. **Windows PE version info** — for unlisted processes, reads `FileDescription`, `CompanyName`, `ProductName`, and `FileVersion` directly from the `.exe` using the Windows version API (no external tools)
3. **Online lookup** (Expand panel only) — DuckDuckGo Instant Answer API + file.net queried in parallel

---

## Process categories

| Icon | Category | Examples |
|------|----------|---------|
| ⚙ | **System** | `svchost.exe`, `explorer.exe`, `dwm.exe`, `lsass.exe` |
| 🌐 | **Browser** | Chrome, Edge, Firefox, Brave, Opera |
| 💻 | **Developer** | VS Code, Node.js, Python, Docker, Git, PowerShell |
| 🪟 | **Microsoft** | Word, Excel, Teams, OneDrive, Outlook |
| 🎮 | **Gaming** | Steam, Epic, Valorant, GeForce Experience |
| 🛡 | **Security** | Defender, Bitdefender, Kaspersky, VPNs, password managers |
| 💬 | **Communication** | Discord, Slack, Zoom, Telegram, WhatsApp |
| 🎵 | **Media** | Spotify, VLC, OBS, Photoshop, Premiere |
| ⚡ | **Runtime** | Java (JVM), .NET host processes |
| ❓ | **Other** | Everything else |

---

## Performance

The app is built to stay responsive at all times:

- **Non-blocking scan** — process enumeration runs in a background thread; the UI is never frozen
- **Smart skip** — known system/security processes skip expensive `OpenProcess` calls that trigger Windows security audits (the main source of scan slowness on Windows)
- **Result caching** — process categorization and PE version info are cached so repeat scans are instant
- **Zero UI work on background refresh** — the 30-second background scan updates internal data only; no table repaints, no scroll stutter
- **100-row cap** — the table shows the top 100 processes by RAM (the ones you actually care about); use `/` to search across all 300+
- **Fixed column widths** — prevents Textual's layout engine from scanning all rows on every scroll event

Press `R` to force a full rebuild with fresh CPU/RAM values.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `psutil` | Process enumeration, memory/CPU stats, kill, service detection |
| `textual` | Terminal UI framework |

Both install automatically on first run via `run.bat`.

---

## Files

```
windows-killer/
├── main.py          # entire application (~700 lines)
├── requirements.txt
├── run.bat          # launcher — works from terminal and File Explorer
└── README.md
```
