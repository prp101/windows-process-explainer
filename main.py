#!/usr/bin/env python3
"""Windows Process Killer - Interactive TUI for scanning, categorizing, and killing processes."""

from __future__ import annotations

import ctypes
import struct
import os
import asyncio
import datetime
import json
import re
import html as _html
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import psutil
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Container, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, Button, Static
from textual.reactive import reactive

# ── Category definitions ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class Category:
    name: str
    color: str
    icon: str
    safe_to_kill: bool

CATEGORIES: dict[str, Category] = {
    "system":        Category("System",        "bright_blue",    "⚙",  False),
    "browser":       Category("Browser",       "bright_green",   "🌐", True),
    "developer":     Category("Developer",     "cyan",           "💻", True),
    "microsoft":     Category("Microsoft",     "blue",           "🪟", True),
    "gaming":        Category("Gaming",        "bright_red",     "🎮", True),
    "security":      Category("Security",      "bright_yellow",  "🛡", False),
    "runtime":       Category("Runtime",       "magenta",        "⚡", False),
    "communication": Category("Communication", "bright_cyan",    "💬", True),
    "media":         Category("Media",         "bright_magenta", "🎵", True),
    "other":         Category("Other",         "white",          "❓", True),
}

# ── Known process database ───────────────────────────────────────────────────
# Maps lowercase exe name → (category, human description)

KNOWN_PROCESSES: dict[str, tuple[str, str]] = {
    # Windows Core
    "system":                         ("system",  "Windows kernel process"),
    "system idle process":            ("system",  "CPU idle time counter"),
    "smss.exe":                       ("system",  "Session Manager — starts user sessions"),
    "csrss.exe":                      ("system",  "Client/Server Runtime — core Win32 subsystem"),
    "wininit.exe":                    ("system",  "Windows Init — starts core services at boot"),
    "winlogon.exe":                   ("system",  "Logon Process — handles sign-in/out & screen lock"),
    "services.exe":                   ("system",  "Service Control Manager — manages all Windows services"),
    "lsass.exe":                      ("system",  "Local Security Authority — authentication & policy"),
    "lsaiso.exe":                     ("system",  "LSA Isolated — credential guard (virtualization-based)"),
    "svchost.exe":                    ("system",  "Service Host — container that runs Windows services"),
    "explorer.exe":                   ("system",  "Windows Explorer — desktop, taskbar & file manager"),
    "dwm.exe":                        ("system",  "Desktop Window Manager — renders the Windows desktop"),
    "taskhostw.exe":                  ("system",  "Task Host — runs scheduled tasks"),
    "conhost.exe":                    ("system",  "Console Host — renders terminal/CMD windows"),
    "ctfmon.exe":                     ("system",  "Text Input Manager — language bar & IME support"),
    "dllhost.exe":                    ("system",  "COM Surrogate — hosts COM objects out-of-process"),
    "fontdrvhost.exe":                ("system",  "Font Driver Host — user-mode font rendering"),
    "registry":                       ("system",  "Windows Registry process"),
    "memory compression":             ("system",  "Memory Compression — compresses RAM pages"),
    "memcompression":                 ("system",  "Memory Compression — compresses RAM pages to free physical memory"),
    "runtimebroker.exe":              ("system",  "Runtime Broker — manages UWP app permissions"),
    "startmenuexperiencehost.exe":    ("system",  "Start Menu host process"),
    "searchhost.exe":                 ("system",  "Windows Search UI"),
    "searchindexer.exe":              ("system",  "Search Indexer — indexes files for fast search"),
    "sihost.exe":                     ("system",  "Shell Infrastructure Host"),
    "spoolsv.exe":                    ("system",  "Print Spooler — manages print queues"),
    "audiodg.exe":                    ("system",  "Audio Device Graph — processes audio streams"),
    "secure system":                  ("system",  "Secure Kernel — virtualization-based security"),
    "vmmem":                          ("system",  "Hyper-V/WSL2 VM — virtual machine memory"),
    "vmwp.exe":                       ("system",  "Virtual Machine Worker (Hyper-V)"),
    "wsl.exe":                        ("developer", "Windows Subsystem for Linux"),
    "wslhost.exe":                    ("developer", "WSL host process"),
    "wslservice.exe":                 ("developer", "WSL background service"),
    "taskmgr.exe":                    ("system",  "Task Manager"),
    "msiexec.exe":                    ("system",  "Windows Installer — installs/updates software"),
    "wuauclt.exe":                    ("system",  "Windows Update agent"),
    "tiworker.exe":                   ("system",  "Windows Update TiWorker — applies updates"),
    "backgroundtaskhost.exe":         ("system",  "Background Task Host — runs background UWP tasks"),
    "applicationframehost.exe":       ("system",  "App Frame Host — hosts UWP app windows"),
    "textinputhost.exe":              ("system",  "Touch Keyboard / handwriting panel"),
    # Security
    "msmpeng.exe":                    ("security", "Microsoft Defender Antivirus engine"),
    "nissrv.exe":                     ("security", "Microsoft Defender Network Inspection"),
    "securityhealthservice.exe":      ("security", "Windows Security Health Service"),
    "securityhealthsystray.exe":      ("security", "Windows Security tray icon"),
    "mbam.exe":                       ("security", "Malwarebytes Anti-Malware"),
    "mbamservice.exe":                ("security", "Malwarebytes service"),
    "avgui.exe":                      ("security", "AVG Antivirus UI"),
    "avguard.exe":                    ("security", "Avira Antivirus Guard"),
    "avp.exe":                        ("security", "Kaspersky Antivirus process"),
    "bdagent.exe":                    ("security", "Bitdefender Agent"),
    "bdservicehost.exe":              ("security", "Bitdefender Service Host"),
    "bdntwrk.exe":                    ("security", "Bitdefender Network Module"),
    "bdredline.exe":                  ("security", "Bitdefender threat intelligence"),
    "updatesrv.exe":                  ("security", "Bitdefender Update Service"),
    "egui.exe":                       ("security", "ESET Security UI"),
    "ekrn.exe":                       ("security", "ESET Kernel Service"),
    "nortonsecurity.exe":             ("security", "Norton Security"),
    "mcshield.exe":                   ("security", "McAfee Shield"),
    "1password.exe":                  ("security", "1Password password manager"),
    "bitwarden.exe":                  ("security", "Bitwarden password manager"),
    "keepass.exe":                    ("security", "KeePass password manager"),
    "nordvpn.exe":                    ("security", "NordVPN client"),
    "expressvpn.exe":                 ("security", "ExpressVPN client"),
    "protonvpn.exe":                  ("security", "ProtonVPN client"),
    "mullvad.exe":                    ("security", "Mullvad VPN client"),
    # Browsers
    "chrome.exe":                     ("browser", "Google Chrome"),
    "msedge.exe":                     ("browser", "Microsoft Edge"),
    "firefox.exe":                    ("browser", "Mozilla Firefox"),
    "opera.exe":                      ("browser", "Opera Browser"),
    "brave.exe":                      ("browser", "Brave Browser (privacy-focused)"),
    "vivaldi.exe":                    ("browser", "Vivaldi Browser"),
    "iexplore.exe":                   ("browser", "Internet Explorer (legacy, deprecated)"),
    "waterfox.exe":                   ("browser", "Waterfox Browser"),
    "librewolf.exe":                  ("browser", "LibreWolf — privacy-hardened Firefox"),
    "arc.exe":                        ("browser", "Arc Browser"),
    "zen.exe":                        ("browser", "Zen Browser"),
    "thorium.exe":                    ("browser", "Thorium Browser"),
    # Communication
    "teams.exe":                      ("communication", "Microsoft Teams (classic)"),
    "ms-teams.exe":                   ("communication", "Microsoft Teams (new version)"),
    "slack.exe":                      ("communication", "Slack — workplace messaging"),
    "discord.exe":                    ("communication", "Discord — voice, video & text chat"),
    "discordptb.exe":                 ("communication", "Discord Public Test Build"),
    "discordcanary.exe":              ("communication", "Discord Canary (dev build)"),
    "zoom.exe":                       ("communication", "Zoom — video conferencing"),
    "skype.exe":                      ("communication", "Skype"),
    "telegram.exe":                   ("communication", "Telegram"),
    "signal.exe":                     ("communication", "Signal — encrypted messaging"),
    "whatsapp.exe":                   ("communication", "WhatsApp Desktop"),
    "thunderbird.exe":                ("communication", "Mozilla Thunderbird — email client"),
    "element.exe":                    ("communication", "Element — Matrix protocol client"),
    "mattermost.exe":                 ("communication", "Mattermost — team messaging"),
    "outlook.exe":                    ("microsoft",     "Microsoft Outlook — email & calendar"),
    "loom.exe":                       ("communication", "Loom — async video messaging"),
    # Microsoft Office / Apps
    "winword.exe":                    ("microsoft", "Microsoft Word"),
    "excel.exe":                      ("microsoft", "Microsoft Excel"),
    "powerpnt.exe":                   ("microsoft", "Microsoft PowerPoint"),
    "onenote.exe":                    ("microsoft", "Microsoft OneNote"),
    "msaccess.exe":                   ("microsoft", "Microsoft Access"),
    "mspub.exe":                      ("microsoft", "Microsoft Publisher"),
    "visio.exe":                      ("microsoft", "Microsoft Visio"),
    "onedrive.exe":                   ("microsoft", "OneDrive — Microsoft cloud sync"),
    "officeclicktorun.exe":           ("microsoft", "Office Click-to-Run update service"),
    "msedgewebview2.exe":             ("microsoft", "Edge WebView2 — embedded browser component"),
    "copilot.exe":                    ("microsoft", "Microsoft Copilot AI assistant"),
    "cortana.exe":                    ("microsoft", "Cortana — Windows voice assistant"),
    "notepad.exe":                    ("microsoft", "Notepad"),
    "mspaint.exe":                    ("microsoft", "Microsoft Paint"),
    "snippingtool.exe":               ("microsoft", "Snipping Tool — screenshot capture"),
    "calculator.exe":                 ("microsoft", "Calculator"),
    "photos.exe":                     ("microsoft", "Windows Photos"),
    "xbox.exe":                       ("gaming",    "Xbox app — PC game pass & achievements"),
    "xboxpcapp.exe":                  ("gaming",    "Xbox PC App"),
    "gamebar.exe":                    ("gaming",    "Xbox Game Bar — overlay & recording"),
    "gamebarft.exe":                  ("gaming",    "Game Bar feature tool"),
    # Developer Tools
    "code.exe":                       ("developer", "Visual Studio Code"),
    "code - insiders.exe":            ("developer", "Visual Studio Code Insiders (preview)"),
    "devenv.exe":                     ("developer", "Visual Studio IDE"),
    "rider64.exe":                    ("developer", "JetBrains Rider — C#/F# IDE"),
    "idea64.exe":                     ("developer", "IntelliJ IDEA — Java/Kotlin IDE"),
    "pycharm64.exe":                  ("developer", "PyCharm — Python IDE"),
    "webstorm64.exe":                 ("developer", "WebStorm — JavaScript/TypeScript IDE"),
    "clion64.exe":                    ("developer", "CLion — C/C++ IDE"),
    "datagrip64.exe":                 ("developer", "DataGrip — database IDE"),
    "goland64.exe":                   ("developer", "GoLand — Go language IDE"),
    "phpstorm64.exe":                 ("developer", "PhpStorm — PHP IDE"),
    "cursor.exe":                     ("developer", "Cursor — AI-first code editor"),
    "windsurf.exe":                   ("developer", "Windsurf — AI code editor"),
    "sublime_text.exe":               ("developer", "Sublime Text editor"),
    "notepad++.exe":                  ("developer", "Notepad++ — advanced text editor"),
    "nvim.exe":                       ("developer", "Neovim — modal text editor"),
    "vim.exe":                        ("developer", "Vim — modal text editor"),
    "python.exe":                     ("developer", "Python interpreter"),
    "pythonw.exe":                    ("developer", "Python (windowless, background script)"),
    "node.exe":                       ("developer", "Node.js — JavaScript runtime"),
    "bun.exe":                        ("developer", "Bun — fast JavaScript/TypeScript runtime"),
    "deno.exe":                       ("developer", "Deno — secure JavaScript runtime"),
    "git.exe":                        ("developer", "Git — version control"),
    "docker.exe":                     ("developer", "Docker CLI"),
    "dockerd.exe":                    ("developer", "Docker daemon (container engine)"),
    "com.docker.backend.exe":         ("developer", "Docker Desktop backend"),
    "docker desktop.exe":             ("developer", "Docker Desktop"),
    "kubectl.exe":                    ("developer", "kubectl — Kubernetes CLI"),
    "powershell.exe":                 ("developer", "Windows PowerShell"),
    "pwsh.exe":                       ("developer", "PowerShell 7+ (cross-platform)"),
    "cmd.exe":                        ("developer", "Command Prompt"),
    "windowsterminal.exe":            ("developer", "Windows Terminal"),
    "wt.exe":                         ("developer", "Windows Terminal (wt shorthand)"),
    "bash.exe":                       ("developer", "Bash shell (Git Bash / WSL)"),
    "postman.exe":                    ("developer", "Postman — API client & testing"),
    "insomnia.exe":                   ("developer", "Insomnia — REST/GraphQL client"),
    "dbeaver.exe":                    ("developer", "DBeaver — universal database client"),
    "tableplus.exe":                  ("developer", "TablePlus — database GUI"),
    "mysqld.exe":                     ("developer", "MySQL database server"),
    "postgres.exe":                   ("developer", "PostgreSQL database server"),
    "redis-server.exe":               ("developer", "Redis in-memory data store"),
    "mongod.exe":                     ("developer", "MongoDB document database server"),
    "nginx.exe":                      ("developer", "Nginx web/reverse-proxy server"),
    "httpd.exe":                      ("developer", "Apache HTTP server"),
    "java.exe":                       ("runtime",   "Java (JVM) — running a Java app"),
    "javaw.exe":                      ("runtime",   "Java (JVM, windowless) — e.g. Minecraft, IDE"),
    "figma.exe":                      ("developer", "Figma — collaborative design tool"),
    "wireshark.exe":                  ("developer", "Wireshark — network packet analyzer"),
    "winscp.exe":                     ("developer", "WinSCP — secure file transfer"),
    "filezilla.exe":                  ("developer", "FileZilla — FTP/SFTP client"),
    "putty.exe":                      ("developer", "PuTTY — SSH/Telnet client"),
    "virtualbox.exe":                 ("developer", "Oracle VirtualBox — virtual machines"),
    "vmplayer.exe":                   ("developer", "VMware Player — virtual machines"),
    # Gaming
    "steam.exe":                      ("gaming", "Steam — PC gaming platform"),
    "steamwebhelper.exe":             ("gaming", "Steam web helper (in-overlay browser)"),
    "epicgameslauncher.exe":          ("gaming", "Epic Games Launcher"),
    "easyanticheat.exe":              ("gaming", "Easy Anti-Cheat — game integrity service"),
    "gog galaxy.exe":                 ("gaming", "GOG Galaxy — DRM-free game platform"),
    "ubisoft connect.exe":            ("gaming", "Ubisoft Connect launcher"),
    "origin.exe":                     ("gaming", "EA Origin game platform (legacy)"),
    "eadesktop.exe":                  ("gaming", "EA Desktop — EA's new game launcher"),
    "battlenet.exe":                  ("gaming", "Battle.net — Blizzard game launcher"),
    "leagueclient.exe":               ("gaming", "League of Legends client"),
    "riotclientservices.exe":         ("gaming", "Riot Games client service"),
    "valorant.exe":                   ("gaming", "Valorant"),
    "cs2.exe":                        ("gaming", "Counter-Strike 2"),
    "csgo.exe":                       ("gaming", "CS:GO (legacy)"),
    "dota2.exe":                      ("gaming", "Dota 2"),
    "geforceexperience.exe":          ("gaming", "NVIDIA GeForce Experience — driver & overlay"),
    "nvcontainer.exe":                ("gaming", "NVIDIA Container — NVIDIA background service"),
    "nvdisplay.container.exe":        ("gaming", "NVIDIA Display Container service"),
    "nvtelemetry.exe":                ("gaming", "NVIDIA Telemetry — usage data collection"),
    "amdrsserv.exe":                  ("gaming", "AMD Radeon Software service"),
    "radeonaddrenalin2020.exe":       ("gaming", "AMD Radeon Adrenalin software"),
    "msiafterburner.exe":             ("other",  "MSI Afterburner — GPU overclocking & monitoring"),
    "rtss.exe":                       ("other",  "RivaTuner Statistics Server — FPS overlay"),
    # Media
    "spotify.exe":                    ("media", "Spotify — music streaming"),
    "vlc.exe":                        ("media", "VLC Media Player"),
    "mpv.exe":                        ("media", "mpv — lightweight media player"),
    "wmplayer.exe":                   ("media", "Windows Media Player"),
    "obs64.exe":                      ("media", "OBS Studio — screen recorder & live streaming"),
    "obs.exe":                        ("media", "OBS Studio — screen recorder & live streaming"),
    "streamlabs obs.exe":             ("media", "Streamlabs OBS"),
    "davinciresolve.exe":             ("media", "DaVinci Resolve — professional video editor"),
    "premiere.exe":                   ("media", "Adobe Premiere Pro — video editor"),
    "afterfx.exe":                    ("media", "Adobe After Effects — motion graphics"),
    "photoshop.exe":                  ("media", "Adobe Photoshop — image editor"),
    "illustrator.exe":                ("media", "Adobe Illustrator — vector graphics"),
    "acrobat.exe":                    ("media", "Adobe Acrobat — PDF editor"),
    "acrobrd.exe":                    ("media", "Adobe Acrobat Reader — PDF viewer"),
    "gimp-2.10.exe":                  ("media", "GIMP — free image editor"),
    "inkscape.exe":                   ("media", "Inkscape — free vector graphics editor"),
    "audacity.exe":                   ("media", "Audacity — audio editor"),
    "reaper.exe":                     ("media", "REAPER — digital audio workstation"),
    "plex.exe":                       ("media", "Plex Media Player"),
    "mpc-hc.exe":                     ("media", "Media Player Classic - Home Cinema"),
    # Utilities
    "everything.exe":                 ("other", "Everything — instant file search"),
    "powertoys.exe":                  ("other", "Microsoft PowerToys — power user utilities"),
    "powertoyslauncher.exe":          ("other", "PowerToys Run — app launcher"),
    "rainmeter.exe":                  ("other", "Rainmeter — desktop widgets/skins"),
    "autohotkey.exe":                 ("other", "AutoHotkey — keyboard/mouse automation"),
    "ahk.exe":                        ("other", "AutoHotkey script"),
    "notion.exe":                     ("other", "Notion — notes & workspace"),
    "obsidian.exe":                   ("other", "Obsidian — local-first note-taking"),
    "dropbox.exe":                    ("other", "Dropbox — cloud file storage sync"),
    "sharex.exe":                     ("other", "ShareX — screenshot & screen recording"),
    "greenshot.exe":                  ("other", "Greenshot — screenshot tool"),
    "snagit.exe":                     ("other", "TechSmith Snagit — screenshot & annotation"),
    "7zfm.exe":                       ("other", "7-Zip File Manager"),
    "winrar.exe":                     ("other", "WinRAR — archive manager"),
    "hwinfo64.exe":                   ("other", "HWiNFO64 — hardware monitoring & sensors"),
    "cpuz_x64.exe":                   ("other", "CPU-Z — CPU & system information"),
    "gpuz.exe":                       ("other", "GPU-Z — GPU information"),
    "procexp64.exe":                  ("other", "Sysinternals Process Explorer"),
    "procmon64.exe":                  ("other", "Sysinternals Process Monitor"),
    "clockify.exe":                   ("other", "Clockify — time tracking"),
    "toggl.exe":                      ("other", "Toggl — time tracking"),
    "anki.exe":                       ("other", "Anki — spaced repetition flashcards"),
}


# ── Windows PE version info reader ───────────────────────────────────────────

def _get_version_info(path: str) -> dict[str, str]:
    """Read string fields from a Windows PE executable's version info block."""
    result: dict[str, str] = {}
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return result
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return result
        lp = ctypes.c_void_p()
        n = ctypes.c_uint()
        if not ver.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(lp), ctypes.byref(n)):
            return result
        if n.value < 4:
            return result
        lang, cp = struct.unpack_from("<HH", ctypes.string_at(lp.value, 4))
        prefixes = [
            f"\\StringFileInfo\\{lang:04X}{cp:04X}\\",
            "\\StringFileInfo\\040904B0\\",
            "\\StringFileInfo\\040904E4\\",
        ]
        fields = ["FileDescription", "CompanyName", "ProductName", "FileVersion", "InternalName"]
        for prefix in prefixes:
            for field in fields:
                if field in result:
                    continue
                if ver.VerQueryValueW(buf, prefix + field, ctypes.byref(lp), ctypes.byref(n)) and lp.value:
                    val = ctypes.wstring_at(lp.value).strip()
                    if val:
                        result[field] = val
    except Exception:
        pass
    return result


# ── Process data ─────────────────────────────────────────────────────────────

@dataclass
class ProcessInfo:
    pid: int
    name: str
    category: str
    description: str
    cpu_percent: float
    memory_mb: float
    exe: Optional[str]
    status: str

    @property
    def safe_to_kill(self) -> bool:
        return CATEGORIES[self.category].safe_to_kill


def _categorize(name: str, exe: Optional[str]) -> tuple[str, str]:
    key = name.lower()
    if key in KNOWN_PROCESSES:
        return KNOWN_PROCESSES[key]
    # Try Windows version info for unknown processes
    if exe and os.path.exists(exe):
        desc = _get_version_info(exe).get("FileDescription")
        if desc:
            d = desc.lower()
            for kw, cat in [
                ("antivirus", "security"), ("antimalware", "security"), ("security", "security"),
                ("browser", "browser"), ("game", "gaming"),
                ("audio", "media"), ("video", "media"), ("media", "media"),
                ("driver", "system"), ("service", "system"),
                ("microsoft", "microsoft"),
            ]:
                if kw in d:
                    return (cat, desc)
            return ("other", desc)
    return ("other", "Unknown process")


def scan_processes() -> list[ProcessInfo]:
    result: list[ProcessInfo] = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                status = proc.status()
                try:
                    exe: Optional[str] = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = None
                try:
                    mem = proc.memory_info().rss / (1024 * 1024)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    mem = 0.0
                try:
                    cpu = proc.cpu_percent(interval=None)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu = 0.0
                category, description = _categorize(name, exe)
                result.append(ProcessInfo(
                    pid=pid, name=name, category=category, description=description,
                    cpu_percent=cpu, memory_mb=mem, exe=exe, status=status,
                ))
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue
    return result


def get_process_details(p: ProcessInfo) -> dict:
    """Collect extended info for a process: cmdline, parent, user, network, version info."""
    d: dict = {
        "cmdline": [],
        "parent": None,
        "username": None,
        "create_time": None,
        "connections": [],
        "file_description": None,
        "company_name": None,
        "product_name": None,
        "file_version": None,
    }
    try:
        proc = psutil.Process(p.pid)
        with proc.oneshot():
            try:
                d["cmdline"] = proc.cmdline()
            except (psutil.AccessDenied, Exception):
                pass
            try:
                parent = proc.parent()
                if parent:
                    d["parent"] = f"{parent.name()} (PID {parent.pid})"
            except (psutil.AccessDenied, Exception):
                pass
            try:
                d["username"] = proc.username()
            except (psutil.AccessDenied, Exception):
                pass
            try:
                ct = proc.create_time()
                d["create_time"] = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
            except (psutil.AccessDenied, Exception):
                pass
            try:
                try:
                    conns = proc.net_connections()
                except AttributeError:
                    conns = proc.connections()
                for c in conns[:8]:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                    d["connections"].append(f"{c.type.name}  {laddr} → {raddr}  [{c.status}]")
            except (psutil.AccessDenied, Exception):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        pass
    if p.exe and os.path.exists(p.exe):
        vi = _get_version_info(p.exe)
        d["file_description"] = vi.get("FileDescription")
        d["company_name"] = vi.get("CompanyName")
        d["product_name"] = vi.get("ProductName")
        d["file_version"] = vi.get("FileVersion")
    return d


# ── Kill confirmation modal ───────────────────────────────────────────────────

class ConfirmKillScreen(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "yes", show=False),
        Binding("enter", "yes", show=False),
        Binding("n", "no", show=False),
        Binding("escape", "no", show=False),
    ]

    def __init__(self, proc: ProcessInfo) -> None:
        super().__init__()
        self.proc = proc

    def compose(self) -> ComposeResult:
        cat = CATEGORIES[self.proc.category]
        warning = (
            "\n[bold red]⚠  System/security process — killing may cause instability![/bold red]"
            if not self.proc.safe_to_kill else ""
        )
        yield Container(
            Static(
                f"[bold white]Kill Process?[/bold white]\n\n"
                f"  PID    [cyan]{self.proc.pid}[/cyan]\n"
                f"  Name   [bold]{self.proc.name}[/bold]\n"
                f"  Type   [{cat.color}]{cat.icon}  {cat.name}[/{cat.color}]\n"
                f"  Info   {self.proc.description}"
                f"{warning}\n\n"
                f"[dim]  [bold]Y / Enter[/bold] confirm    [bold]N / Esc[/bold] cancel[/dim]",
                id="dlg-text",
            ),
            Horizontal(
                Button("Kill  [Y]", variant="error", id="btn-yes"),
                Button("Cancel  [N]", variant="default", id="btn-no"),
                id="dlg-btns",
            ),
            id="dlg",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn-yes")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


# ── Online description fetcher ───────────────────────────────────────────────

async def _http_get(url: str, timeout: int = 7) -> str:
    def _fetch() -> str:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    return await asyncio.to_thread(_fetch)


async def _ddg_lookup(name: str) -> Optional[str]:
    """DuckDuckGo Instant Answer API — works great for well-known software."""
    q = urllib.parse.quote(f"{name.replace('.exe', '')} windows process")
    url = f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1&skip_disambig=1"
    text = await _http_get(url)
    data = json.loads(text)
    abstract = data.get("AbstractText", "").strip()
    if len(abstract) > 60:
        heading = data.get("Heading", "")
        source = data.get("AbstractSource", "")
        parts = []
        if heading:
            parts.append(f"[bold]{heading}[/bold]")
        parts.append(abstract)
        if source:
            parts.append(f"\n[dim italic]— {source}[/dim italic]")
        return "\n  ".join(parts)
    return None


async def _filenet_lookup(name: str) -> Optional[str]:
    """file.net process database — good for obscure Windows processes."""
    url = f"https://www.file.net/process/{urllib.parse.quote(name.lower())}.html"
    try:
        raw = await _http_get(url)
    except (urllib.error.HTTPError, urllib.error.URLError, Exception):
        return None
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.DOTALL | re.IGNORECASE)
    proc_base = name.lower().replace(".exe", "")
    for para in re.findall(r"<p[^>]*>(.*?)</p>", raw, re.DOTALL | re.IGNORECASE):
        text = re.sub(r"<[^>]+>", " ", para)
        text = _html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > 80 and any(
            k in text.lower()
            for k in (proc_base, "this process", "this file", "this program", "executable")
        ):
            return text[:600]
    return None


async def fetch_process_description(name: str) -> str:
    """Fetch description from multiple sources in parallel, return best result."""
    ddg, filenet = await asyncio.gather(
        _ddg_lookup(name),
        _filenet_lookup(name),
        return_exceptions=True,
    )
    if isinstance(ddg, str) and ddg:
        return ddg
    if isinstance(filenet, str) and filenet:
        return filenet
    return "No description found online."


# ── Process detail modal ──────────────────────────────────────────────────────

class ProcessDetailScreen(ModalScreen):
    BINDINGS = [
        Binding("escape", "close", "Close"),
    ]

    def __init__(self, proc: ProcessInfo) -> None:
        super().__init__()
        self.proc = proc

    def compose(self) -> ComposeResult:
        yield Container(
            ScrollableContainer(
                Static(id="detail-local"),
                Static("\n[dim]  Fetching online description…[/dim]", id="detail-online"),
                id="detail-scroll",
            ),
            Horizontal(
                Button("Close  [Esc]", id="btn-close"),
                id="detail-footer",
            ),
            id="detail-box",
        )

    def on_mount(self) -> None:
        d = get_process_details(self.proc)
        self.query_one("#detail-local", Static).update(self._format_local(d))
        self.run_worker(self._do_fetch_online(), exclusive=False)

    async def _do_fetch_online(self) -> None:
        desc = await fetch_process_description(self.proc.name)
        try:
            self.query_one("#detail-online", Static).update(
                f"\n[bold]── Online Description ────────────────────────────────[/bold]\n"
                f"  {desc}\n"
            )
        except Exception:
            pass  # screen may have been dismissed already

    def _format_local(self, d: dict) -> str:
        cat = CATEGORIES[self.proc.category]
        lines: list[str] = []
        lines.append(
            f"[bold]{self.proc.name}[/bold]   "
            f"[{cat.color}]{cat.icon}  {cat.name}[/{cat.color}]   "
            f"PID [cyan]{self.proc.pid}[/cyan]"
        )
        lines.append("")
        has_identity = any(d.get(k) for k in ("file_description", "company_name", "product_name", "file_version"))
        if has_identity:
            lines.append("[bold]── Identity ─────────────────────────────────────────[/bold]")
            if d.get("file_description"):
                lines.append(f"  Description   [white]{d['file_description']}[/white]")
            if d.get("company_name"):
                lines.append(f"  Company       {d['company_name']}")
            if d.get("product_name"):
                lines.append(f"  Product       {d['product_name']}")
            if d.get("file_version"):
                lines.append(f"  Version       {d['file_version']}")
            lines.append("")
        if self.proc.exe:
            lines.append("[bold]── Location ──────────────────────────────────────────[/bold]")
            lines.append(f"  {self.proc.exe}")
            lines.append("")
        lines.append("[bold]── Runtime ───────────────────────────────────────────[/bold]")
        if d.get("username"):
            lines.append(f"  User      {d['username']}")
        if d.get("create_time"):
            lines.append(f"  Started   {d['create_time']}")
        if d.get("parent"):
            lines.append(f"  Parent    {d['parent']}")
        lines.append(
            f"  CPU       {self.proc.cpu_percent:.1f}%   "
            f"RAM  {self.proc.memory_mb:.1f} MB   "
            f"Status  {self.proc.status}"
        )
        lines.append("")
        if d.get("cmdline"):
            lines.append("[bold]── Command Line ──────────────────────────────────────[/bold]")
            cmd = " ".join(d["cmdline"])
            while len(cmd) > 72:
                lines.append(f"  {cmd[:72]}")
                cmd = cmd[72:]
            if cmd:
                lines.append(f"  {cmd}")
            lines.append("")
        if d.get("connections"):
            lines.append("[bold]── Network Connections ───────────────────────────────[/bold]")
            for conn in d["connections"]:
                lines.append(f"  {conn}")
            lines.append("")
        lines.append("[dim]  [bold]Esc[/bold] close[/dim]")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


# ── Main app ──────────────────────────────────────────────────────────────────

class ProcessKillerApp(App):
    TITLE = "Windows Process Killer"
    SUB_TITLE = "K=kill  R=refresh  /=search  Q=quit  click column header to sort"

    CSS = """
    Screen { background: $background; }

    #search-bar {
        height: 3;
        padding: 0 1;
        background: $panel;
        border-bottom: tall $primary;
    }
    #search-input { width: 1fr; }
    #stats { width: auto; padding: 0 2; content-align: right middle; color: $text-muted; }

    DataTable { height: 1fr; }

    ConfirmKillScreen { align: center middle; }
    #dlg {
        padding: 2 4;
        background: $surface;
        border: thick $error;
        width: 64;
        height: auto;
    }
    #dlg-text { padding: 0 0 1 0; }
    #dlg-btns { height: 3; align: center middle; }
    #dlg-btns Button { margin: 0 1; }

    ProcessDetailScreen { align: center middle; }
    #detail-box {
        width: 84;
        height: 38;
        background: $surface;
        border: thick $primary;
        padding: 1 2 0 2;
    }
    #detail-scroll { height: 1fr; }
    #detail-footer { height: 3; align: center middle; padding-top: 1; }
    #detail-footer Button { margin: 0 1; }
    """

    BINDINGS = [
        Binding("k",       "kill",          "Kill",    show=True),
        Binding("delete",  "kill",          "Kill",    show=False),
        Binding("e",       "expand",        "Expand",  show=True),
        Binding("r",       "refresh",       "Refresh", show=True),
        Binding("ctrl+r",  "refresh",       "Refresh", show=False),
        Binding("/",       "focus_search",  "Search",  show=True),
        Binding("escape",  "clear_search",  "Clear",   show=False),
        Binding("q",       "quit",          "Quit",    show=True),
    ]

    filter_text: reactive[str] = reactive("", init=False)

    _SORT_MAP = {
        "PID": ("pid", True),
        "Process Name": ("name", False),
        "Category": ("category", False),
        "CPU %": ("cpu", True),
        "RAM MB": ("ram", True),
    }

    def __init__(self) -> None:
        super().__init__()
        self._processes: list[ProcessInfo] = []
        self._sort_key = "ram"
        self._sort_rev = True
        self._col_cpu: object = None
        self._col_ram: object = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="search-bar"):
            yield Input(placeholder="Filter by name, category, description…  (press /)", id="search-input")
            yield Label("", id="stats")
        yield DataTable(cursor_type="row", id="table", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        cols = t.add_columns("PID", "Process Name", "Category", "Description", "CPU %", "RAM MB", "Status")
        self._col_cpu = cols[4]
        self._col_ram = cols[5]
        self._load()
        self.set_interval(5, self._background_refresh)

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        self._processes = scan_processes()
        self._render_table()

    async def _background_refresh(self) -> None:
        """Update CPU/RAM values in-place — no table rebuild, no scroll jump."""
        # Run the blocking psutil scan off the event loop so scrolling stays responsive
        new_procs = await asyncio.to_thread(scan_processes)
        self._processes = new_procs
        pid_map = {p.pid: p for p in new_procs}
        t = self.query_one(DataTable)
        for i, rk in enumerate(list(t.rows.keys())):
            try:
                p = pid_map.get(int(rk.value))
                if not p:
                    continue
                cpu_t = Text(
                    f"{p.cpu_percent:5.1f}",
                    style="bold red" if p.cpu_percent > 20 else "yellow" if p.cpu_percent > 5 else "green",
                )
                ram_t = Text(
                    f"{p.memory_mb:8.1f}",
                    style="bold red" if p.memory_mb > 500 else "yellow" if p.memory_mb > 100 else "white",
                )
                t.update_cell(rk, self._col_cpu, cpu_t, update_width=False)
                t.update_cell(rk, self._col_ram, ram_t, update_width=False)
            except Exception:
                pass
            if i % 30 == 29:
                await asyncio.sleep(0)  # yield to event loop every 30 rows

    def _visible(self) -> list[ProcessInfo]:
        q = self.filter_text.lower().strip()
        procs = self._processes
        if q:
            procs = [
                p for p in procs
                if q in p.name.lower() or q in p.description.lower() or q in p.category.lower()
            ]
        key_fn = {
            "pid":  lambda p: p.pid,
            "name": lambda p: p.name.lower(),
            "category": lambda p: p.category,
            "cpu":  lambda p: p.cpu_percent,
            "ram":  lambda p: p.memory_mb,
        }.get(self._sort_key, lambda p: p.memory_mb)
        return sorted(procs, key=key_fn, reverse=self._sort_rev)

    def _render_table(self, keep_cursor: bool = False) -> None:
        t = self.query_one(DataTable)

        # Remember cursor PID
        old_pid: Optional[str] = None
        if keep_cursor and t.row_count:
            try:
                old_pid = list(t.rows.keys())[t.cursor_row].value
            except (IndexError, Exception):
                pass

        t.clear()
        procs = self._visible()

        for p in procs:
            cat = CATEGORIES[p.category]

            name_t = Text(p.name)
            if not p.safe_to_kill:
                name_t.stylize("dim italic")

            cat_t = Text(f"{cat.icon}  {cat.name}", style=cat.color)

            cpu_s = f"{p.cpu_percent:5.1f}"
            cpu_t = Text(cpu_s, style="bold red" if p.cpu_percent > 20 else "yellow" if p.cpu_percent > 5 else "green")

            ram_s = f"{p.memory_mb:8.1f}"
            ram_t = Text(ram_s, style="bold red" if p.memory_mb > 500 else "yellow" if p.memory_mb > 100 else "white")

            desc = p.description
            if len(desc) > 58:
                desc = desc[:57] + "…"

            t.add_row(
                str(p.pid), name_t, cat_t, desc, cpu_t, ram_t, p.status,
                key=str(p.pid),
            )

        label = self.query_one("#stats", Label)
        label.update(f"  {len(procs)} / {len(self._processes)} processes")

        if old_pid:
            try:
                keys = [k.value for k in t.rows.keys()]
                if old_pid in keys:
                    t.move_cursor(row=keys.index(old_pid))
            except Exception:
                pass

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_kill(self) -> None:
        t = self.query_one(DataTable)
        if not t.row_count:
            return
        try:
            pid = int(list(t.rows.keys())[t.cursor_row].value)
        except (IndexError, ValueError, Exception):
            return
        proc = next((p for p in self._processes if p.pid == pid), None)
        if not proc:
            self.notify("Process already exited", severity="warning")
            return

        def _after_confirm(confirmed: bool) -> None:
            if not confirmed:
                return
            try:
                psutil.Process(pid).kill()
                self.notify(f"Killed  {proc.name}  (PID {pid})", severity="information")
            except psutil.NoSuchProcess:
                self.notify("Process already exited", severity="warning")
            except psutil.AccessDenied:
                self.notify(
                    f"Access denied — re-run as Administrator to kill {proc.name}",
                    severity="error",
                )
            except Exception as e:
                self.notify(f"Kill failed: {e}", severity="error")
            self._load()

        self.push_screen(ConfirmKillScreen(proc), _after_confirm)

    def action_expand(self) -> None:
        t = self.query_one(DataTable)
        if not t.row_count:
            return
        try:
            pid = int(list(t.rows.keys())[t.cursor_row].value)
        except (IndexError, ValueError, Exception):
            return
        proc = next((p for p in self._processes if p.pid == pid), None)
        if proc:
            self.push_screen(ProcessDetailScreen(proc))

    def action_refresh(self) -> None:
        self._load()
        self.notify("Refreshed", timeout=1.5)

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_clear_search(self) -> None:
        inp = self.query_one("#search-input", Input)
        inp.value = ""
        self.query_one(DataTable).focus()

    # ── Events ────────────────────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        self.filter_text = event.value
        self._render_table()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        label = str(event.label)
        if label not in self._SORT_MAP:
            return
        key, default_rev = self._SORT_MAP[label]
        if self._sort_key == key:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_key = key
            self._sort_rev = default_rev
        self._render_table()


if __name__ == "__main__":
    ProcessKillerApp().run()
