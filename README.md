# Windows Process Killer

> A terminal UI for scanning, understanding, and killing Windows processes — without the noise of Task Manager.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What it does

Windows ships with ~300 background processes at any given time. Most of them are mystery `.exe` files with cryptic names. This tool:

- **Scans** every running process and **categorizes** it — System, Browser, Developer, Gaming, Security, Communication, Media, and more
- **Labels** each process with a plain-English description (built-in database of 200+ known processes, falls back to reading the executable's Windows version info)
- Lets you **kill** any process with a single keystroke — with a confirmation dialog that warns you before you kill something critical
- Lets you **expand** any process with `E` to see its full details *and* a fetched online description, all inline

---

## Screenshot

```
┌─ Windows Process Killer ─────────────────────────────── 14:32:01 ─┐
│ Filter by name, category, description…                 312/312      │
├────┬──────────────────────┬──────────────┬───────────────────┬─────┤
│PID │ Process Name         │ Category     │ Description       │ RAM │
├────┼──────────────────────┼──────────────┼───────────────────┼─────┤
│4424│ MemCompression       │ ⚙  System    │ Memory Compress…  │1971 │
│2968│ bdservicehost.exe    │ 🛡  Security  │ Bitdefender Ser…  │ 467 │
│404 │ brave.exe            │ 🌐 Browser   │ Brave Browser     │ 429 │
│7404│ Cursor.exe           │ 💻 Developer │ Cursor — AI code… │ 391 │
│... │ ...                  │ ...          │ ...               │ ... │
└────┴──────────────────────┴──────────────┴───────────────────┴─────┘
 K kill   E expand   R refresh   / search   Q quit
```

---

## Getting started

**Prerequisites:** Python 3.10+ on Windows 11

```bat
git clone https://github.com/your-username/windows-killer
cd windows-killer
run.bat
```

That's it. `run.bat` creates a virtual environment, installs dependencies, and launches the app on first run. Subsequent runs skip straight to launch.

> **Tip:** Right-click `run.bat` → *Run as administrator* to be able to kill protected system processes.

---

## Keybindings

| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate processes |
| `K` or `Delete` | Kill selected process (shows confirmation) |
| `E` | Expand — shows full details + fetches live online description |
| `R` | Full refresh (rebuild list, re-sort) |
| `/` | Focus search bar — filter by name, category, or description |
| `Esc` | Clear search / close panel |
| Click column header | Sort by that column (click again to reverse) |
| `Q` | Quit |

---

## Process categories

| Icon | Category | Color | Examples |
|------|----------|-------|---------|
| ⚙ | **System** | Blue | `svchost.exe`, `explorer.exe`, `dwm.exe` |
| 🌐 | **Browser** | Green | Chrome, Edge, Firefox, Brave |
| 💻 | **Developer** | Cyan | VS Code, Node, Python, Docker, Git |
| 🪟 | **Microsoft** | Blue | Word, Excel, Teams, OneDrive |
| 🎮 | **Gaming** | Red | Steam, Epic, Discord, GeForce Experience |
| 🛡 | **Security** | Yellow | Defender, Bitdefender, VPNs |
| 💬 | **Communication** | Cyan | Discord, Slack, Zoom, Telegram |
| 🎵 | **Media** | Magenta | Spotify, VLC, OBS, Adobe suite |
| ⚡ | **Runtime** | Magenta | Java, .NET hosts |
| ❓ | **Other** | White | Everything else |

System and Security processes show dimmed names as a visual reminder that killing them may destabilize Windows.

---

## Expand panel (`E`)

Pressing `E` on any process opens a detail panel that shows:

```
chrome.exe   🌐 Browser   PID 21888

── Identity ──────────────────────────────────────────
  Description   Google Chrome
  Company       Google LLC
  Product       Google Chrome
  Version       147.0.7000.123

── Location ───────────────────────────────────────────
  C:\Program Files\Google\Chrome\Application\chrome.exe

── Runtime ────────────────────────────────────────────
  User      DESKTOP-ABC\You
  Started   2026-04-26 09:12:34
  Parent    explorer.exe (PID 4892)
  CPU  0.3%   RAM  429.1 MB   Status  running

── Online Description ─────────────────────────────────
  Google Chrome is a cross-platform web browser developed
  by Google. It was first released in 2008 for Windows …
  — Wikipedia
```

The **Online Description** section fetches from DuckDuckGo's Instant Answer API and file.net in parallel. Local info appears instantly; the online description fills in within a few seconds.

---

## How descriptions work

1. **Built-in database** — 200+ hand-curated entries for common Windows processes, browsers, dev tools, games, security software, etc.
2. **Windows version info** — for unlisted processes, reads the `FileDescription`, `CompanyName`, and `ProductName` fields directly from the `.exe` using the Windows PE version info API (no external tools needed).
3. **Online lookup** (Expand panel only) — queries DuckDuckGo Instant Answer API and file.net in parallel; shows whichever returns first.

---

## Auto-refresh

The process list auto-refreshes every **5 seconds**. Only CPU% and RAM values update silently in-place — the table never jumps or rebuilds, and scrolling is never blocked. Press `R` to force a full rebuild (picks up new/exited processes and re-sorts).

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `psutil` | ≥ 5.9 | Process enumeration, memory/CPU stats, kill |
| `textual` | ≥ 0.47 | Terminal UI framework |

Both install automatically via `run.bat`.

---

## License

MIT
