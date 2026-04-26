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
import subprocess
import winreg
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

# Processes recommended to kill — unnecessary background resource consumers
BLOAT_PROCESSES: frozenset[str] = frozenset({
    # Windows telemetry — phone-home services that spike CPU/disk while idle
    "compattelrunner.exe",    # Compatibility Telemetry Runner
    "wsappx.exe",             # Windows Store diagnostics / AppX deployment worker
    "usoclient.exe",          # Update Session Orchestrator — triggers update scans
    "musnotifyicon.exe",      # Windows Update notification tray icon
    "tiworker.exe",           # Trusted Installer Worker — notorious for HDD thrashing
    "wuauclt.exe",            # Windows Update client
    "diaghost.exe",           # Diagnostic host
    # NVIDIA bloat
    "nvtelemetry.exe",        # NVIDIA Telemetry Container — pure data collection
    # Gaming launchers (huge memory footprint when idle)
    "epicgameslauncher.exe",  # Epic Games Launcher — notorious RAM hog
    "steamwebhelper.exe",     # Steam built-in browser (overlay)
    "gamebar.exe",            # Xbox Game Bar
    "gamebarft.exe",          # Xbox Game Bar feature tool
    # Microsoft background bloat
    "cortana.exe",            # Cortana — rarely used, always running
    "officeclicktorun.exe",   # Office Click-to-Run background updater
    "searchindexer.exe",      # Windows Search Indexer — heavy on HDDs
    "msedgewebview2.exe",     # Edge WebView2 — embedded browser running for no reason
})

# Processes where killing may cause data loss or break functionality
CAUTION_PROCESSES: frozenset[str] = frozenset({
    # Office apps — unsaved work will be lost
    "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "msaccess.exe",
    # Databases — abrupt kill may corrupt data
    "mysqld.exe", "postgres.exe", "mongod.exe", "redis-server.exe",
    # Container / VM engines
    "dockerd.exe", "com.docker.backend.exe", "vmplayer.exe",
    # Java — unknown app, could be anything critical
    "java.exe", "javaw.exe",
})


# Pre-built set of known system/security process names.
# For these we skip expensive psutil calls (memory_info, cpu_percent, exe)
# because they always fail with AccessDenied — and each failure triggers a
# Windows security audit IPC that can cost 30-100 ms per call.
_PROTECTED_NAMES: frozenset[str] = frozenset(
    name for name, (cat, _) in KNOWN_PROCESSES.items()
    if cat in ("system", "security")
)

# Caches so repeat scans don't redo work
_CATEGORIZE_CACHE: dict[str, tuple[str, str]] = {}
_VERSION_INFO_CACHE: dict[str, dict[str, str]] = {}


def get_kill_rating(proc: ProcessInfo) -> tuple[str, str, str]:
    """Return (level, label, color) describing how safe/recommended killing this process is."""
    name = proc.name.lower()
    # System and security are always dangerous to kill
    if proc.category in ("system", "security"):
        return ("risky",   "⛔ Risky",   "red")
    # Processes with known data-loss risk
    if name in CAUTION_PROCESSES:
        return ("caution", "⚠ Caution",  "yellow")
    # Known bloat — actively recommend killing
    if name in BLOAT_PROCESSES:
        return ("bloat",   "★ Kill it",  "bright_green")
    # Java runtime default caution
    if proc.category == "runtime":
        return ("caution", "⚠ Caution",  "yellow")
    return ("safe",    "✓ Safe",    "green")


# ── Windows PE version info reader ───────────────────────────────────────────

def _get_version_info(path: str) -> dict[str, str]:
    """Read string fields from a Windows PE executable's version info block."""
    if path in _VERSION_INFO_CACHE:
        return _VERSION_INFO_CACHE[path]
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
    _VERSION_INFO_CACHE[path] = result
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
    cache_key = exe or name
    if cache_key in _CATEGORIZE_CACHE:
        return _CATEGORIZE_CACHE[cache_key]
    result: tuple[str, str]
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
                    result = (cat, desc)
                    break
            else:
                result = ("other", desc)
        else:
            result = ("other", "Unknown process")
    else:
        result = ("other", "Unknown process")
    _CATEGORIZE_CACHE[cache_key] = result
    return result


def scan_processes() -> list[ProcessInfo]:
    result: list[ProcessInfo] = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                if not name:
                    continue
                # Skip expensive OpenProcess calls for known system/security processes.
                # Each failed call triggers a Windows security audit IPC (~30-100 ms each).
                if name.lower() in _PROTECTED_NAMES:
                    exe, mem, cpu = None, 0.0, 0.0
                else:
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
                    cpu_percent=cpu, memory_mb=mem, exe=exe, status="",
                ))
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue
    return result


# ── Startup-mechanism detection & blocking ────────────────────────────────────

@dataclass
class StartupEntry:
    kind: str        # "service" | "registry" | "task"
    label: str       # human-readable description shown in UI
    detail: str      # technical id: service name, reg value name, task path
    extra: dict      # kind-specific data needed for disable


_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKCU Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKLM Run"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
]


def _check_services(pid: int, exe_name: str) -> list[StartupEntry]:
    entries: list[StartupEntry] = []
    # Check running services by PID (fastest path)
    try:
        for svc in psutil.win_service_iter():
            try:
                if svc.pid() == pid:
                    info = svc.as_dict()
                    if info.get("start_type") != "disabled":
                        entries.append(StartupEntry(
                            kind="service",
                            label=f"Windows Service — {info.get('display_name', svc.name())}",
                            detail=svc.name(),
                            extra={},
                        ))
            except Exception:
                continue
    except Exception:
        pass
    if entries:
        return entries
    # Fallback: scan registry for any service whose ImagePath mentions this exe
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services") as root:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(root, i); i += 1
                    with winreg.OpenKey(root, svc_name) as sk:
                        try:
                            img, _ = winreg.QueryValueEx(sk, "ImagePath")
                            if exe_name in img.lower():
                                start, _ = winreg.QueryValueEx(sk, "Start")
                                if start != 4:  # 4 = disabled
                                    try:
                                        display, _ = winreg.QueryValueEx(sk, "DisplayName")
                                        if display.startswith("@"):
                                            display = svc_name
                                    except OSError:
                                        display = svc_name
                                    entries.append(StartupEntry(
                                        kind="service",
                                        label=f"Windows Service — {display}",
                                        detail=svc_name,
                                        extra={},
                                    ))
                        except OSError:
                            pass
                except OSError:
                    break
    except Exception:
        pass
    return entries


def _check_registry(exe_name: str, exe_path: str) -> list[StartupEntry]:
    entries: list[StartupEntry] = []
    for hive, key_path, label in _RUN_KEYS:
        try:
            with winreg.OpenKey(hive, key_path, access=winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i); i += 1
                        v = value.lower()
                        if exe_name in v or (exe_path and exe_path in v):
                            entries.append(StartupEntry(
                                kind="registry",
                                label=f"Registry autostart ({label}): {name}",
                                detail=name,
                                extra={"hive": hive, "key_path": key_path},
                            ))
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError, OSError):
            pass
    return entries


def _check_tasks(exe_name: str) -> list[StartupEntry]:
    entries: list[StartupEntry] = []
    try:
        ps = (
            f'$n="{exe_name}";'
            '$t=Get-ScheduledTask|Where-Object{$_.Actions|Where-Object{$_.Execute -like "*$n*"}};'
            'if($t){$t|Select-Object TaskName,TaskPath|ConvertTo-Json -Compress}'
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=8,
        )
        if r.stdout.strip():
            data = json.loads(r.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for task in data:
                path = (task.get("TaskPath") or "\\") + (task.get("TaskName") or "")
                entries.append(StartupEntry(
                    kind="task",
                    label=f"Scheduled Task: {task.get('TaskName', path)}",
                    detail=path,
                    extra={},
                ))
    except Exception:
        pass
    return entries


def find_startup_entries(proc: ProcessInfo) -> list[StartupEntry]:
    """Find all mechanisms that could start/restart this process."""
    exe = proc.exe or proc.name
    exe_name = os.path.basename(exe).lower()
    exe_path = exe.lower()
    entries: list[StartupEntry] = []
    entries += _check_services(proc.pid, exe_name)
    entries += _check_registry(exe_name, exe_path)
    entries += _check_tasks(exe_name)
    # Deduplicate by (kind, detail)
    seen: set[tuple[str, str]] = set()
    unique = []
    for e in entries:
        key = (e.kind, e.detail)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


def disable_startup_entry(entry: StartupEntry) -> tuple[bool, str]:
    """Disable a startup entry. Returns (success, message)."""
    try:
        if entry.kind == "service":
            subprocess.run(["sc", "stop", entry.detail], capture_output=True, timeout=5)
            r = subprocess.run(
                ["sc", "config", entry.detail, "start=", "disabled"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return True, f"Service '{entry.detail}' disabled"
            return False, "sc config failed — run as Administrator"

        elif entry.kind == "registry":
            hive = entry.extra["hive"]
            key_path = entry.extra["key_path"]
            with winreg.OpenKey(hive, key_path, access=winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, entry.detail)
            return True, f"Removed autostart key '{entry.detail}'"

        elif entry.kind == "task":
            task_name = entry.detail.lstrip("\\")
            r = subprocess.run(
                ["schtasks", "/Change", "/TN", task_name, "/DISABLE"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return True, f"Task '{task_name}' disabled"
            return False, "schtasks failed — run as Administrator"

    except PermissionError:
        return False, "Access denied — run as Administrator"
    except Exception as e:
        return False, str(e)
    return False, "Unknown error"


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


# ── Block (kill + prevent restart) modal ─────────────────────────────────────

class BlockScreen(ModalScreen):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter",  "confirm", "Block"),
    ]

    def __init__(self, proc: ProcessInfo) -> None:
        super().__init__()
        self.proc = proc
        self._entries: list[StartupEntry] = []

    def compose(self) -> ComposeResult:
        yield Container(
            Static(id="block-body"),
            Horizontal(
                Button("Kill & Block  [Enter]", id="btn-block", variant="error"),
                Button("Cancel  [Esc]", id="btn-cancel"),
                id="block-footer",
            ),
            id="block-box",
        )

    def on_mount(self) -> None:
        cat = CATEGORIES[self.proc.category]
        self.query_one("#block-body", Static).update(
            f"[bold]{self.proc.name}[/bold]  [{cat.color}]{cat.icon} {cat.name}[/{cat.color}]"
            f"  PID [cyan]{self.proc.pid}[/cyan]\n\n"
            f"[dim]  Scanning for startup mechanisms…[/dim]"
        )
        self.run_worker(self._scan(), exclusive=False)

    async def _scan(self) -> None:
        entries = await asyncio.to_thread(find_startup_entries, self.proc)
        self._entries = entries
        cat = CATEGORIES[self.proc.category]
        lines: list[str] = [
            f"[bold]{self.proc.name}[/bold]  [{cat.color}]{cat.icon} {cat.name}[/{cat.color}]"
            f"  PID [cyan]{self.proc.pid}[/cyan]",
            "",
        ]
        if entries:
            lines.append(f"[bold]Found {len(entries)} startup mechanism{'s' if len(entries) != 1 else ''}:[/bold]")
            lines.append("")
            for e in entries:
                icon = {"service": "⚙", "registry": "🔑", "task": "⏰"}.get(e.kind, "◆")
                lines.append(f"  [yellow]{icon}[/yellow]  {e.label}")
            lines.append("")
            lines.append("[dim]  Kill & Block will terminate the process and disable all[/dim]")
            lines.append("[dim]  of the above so it cannot start again automatically.[/dim]")
        else:
            lines += [
                "[yellow]No startup mechanisms found.[/yellow]",
                "",
                "This process is not registered as a Windows service,",
                "has no registry autostart entry, and no scheduled task.",
                "",
                "[dim]  It may be launched by another process or application.[/dim]",
                "[dim]  Kill & Block will only terminate the current instance.[/dim]",
            ]
        lines += ["", "[dim]  [bold]Enter[/bold] confirm    [bold]Esc[/bold] cancel[/dim]"]
        try:
            self.query_one("#block-body", Static).update("\n".join(lines))
            btn = self.query_one("#btn-block", Button)
            btn.label = ("Kill & Block  [Enter]" if entries else "Kill  [Enter]")
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self._entries if event.button.id == "btn-block" else None)

    def action_confirm(self) -> None:
        self.dismiss(self._entries)

    def action_cancel(self) -> None:
        self.dismiss(None)


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
    #stats { width: 38; padding: 0 2; content-align: right middle; color: $text-muted; }

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

    BlockScreen { align: center middle; }
    #block-box {
        width: 72;
        height: auto;
        max-height: 36;
        background: $surface;
        border: thick $warning;
        padding: 1 2 0 2;
    }
    #block-body { height: auto; }
    #block-footer { height: 3; align: center middle; padding-top: 1; }
    #block-footer Button { margin: 0 1; }
    """

    BINDINGS = [
        Binding("k",       "kill",          "Kill",    show=True),
        Binding("delete",  "kill",          "Kill",    show=False),
        Binding("b",       "block",         "Block",   show=True),
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
        "Safety": ("safety", True),
        "CPU %": ("cpu", True),
        "RAM MB": ("ram", True),
    }
    _SAFETY_ORDER = {"bloat": 3, "safe": 2, "caution": 1, "risky": 0}

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
        yield DataTable(cursor_type="row", id="table", zebra_stripes=True, show_row_labels=False)
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        # Explicit widths stop Textual scanning all rows to auto-measure columns on scroll.
        ck = [
            t.add_column("PID",          width=7),
            t.add_column("Process Name", width=26),
            t.add_column("Category",     width=16),
            t.add_column("Safety",       width=12),
            t.add_column("Description",  width=44),
            t.add_column("CPU %",        width=7),
            t.add_column("RAM MB",       width=9),
        ]
        self._col_cpu = ck[5]
        self._col_ram = ck[6]
        self.set_interval(30, self._background_refresh)
        self.run_worker(self._load(), exclusive=True, name="load")

    # ── Data loading ──────────────────────────────────────────────────────────

    async def _load(self) -> None:
        self.query_one("#stats", Label).update("  [dim]Scanning…[/dim]")
        self._processes = await asyncio.to_thread(scan_processes)
        self._render_table()

    async def _background_refresh(self) -> None:
        """Silently refresh process data — zero UI work, zero scroll stutter."""
        self._processes = await asyncio.to_thread(scan_processes)

    def _visible(self) -> list[ProcessInfo]:
        q = self.filter_text.lower().strip()
        procs = self._processes
        if q:
            procs = [
                p for p in procs
                if q in p.name.lower()
                or q in p.description.lower()
                or q in p.category.lower()
                or q in get_kill_rating(p)[1].lower()
            ]
        key_fn = {
            "pid":    lambda p: p.pid,
            "name":   lambda p: p.name.lower(),
            "category": lambda p: p.category,
            "safety": lambda p: self._SAFETY_ORDER[get_kill_rating(p)[0]],
            "cpu":    lambda p: p.cpu_percent,
            "ram":    lambda p: p.memory_mb,
        }.get(self._sort_key, lambda p: p.memory_mb)
        result = sorted(procs, key=key_fn, reverse=self._sort_rev)
        # Cap unfiltered view — DataTable O(n) scroll work becomes noticeable above ~250 rows.
        # Search always shows all matches regardless of cap.
        if not self.filter_text.strip():
            result = result[:100]
        return result

    def _render_table(self, keep_cursor: bool = False) -> None:
        t = self.query_one(DataTable)

        # Remember cursor PID
        old_pid: Optional[str] = None
        if keep_cursor and t.row_count:
            try:
                old_pid = list(t.rows.keys())[t.cursor_row].value
            except (IndexError, Exception):
                pass

        procs = self._visible()

        with self.batch_update():
            t.clear()
            for p in procs:
                cat = CATEGORIES[p.category]

                name_t = Text(p.name)
                if not p.safe_to_kill:
                    name_t.stylize("dim italic")

                cat_t = Text(f"{cat.icon}  {cat.name}", style=cat.color)

                _level, _label, _color = get_kill_rating(p)
                safety_t = Text(_label, style=f"bold {_color}" if _level in ("bloat", "risky") else _color)

                cpu_s = f"{p.cpu_percent:5.1f}"
                cpu_t = Text(cpu_s, style="bold red" if p.cpu_percent > 20 else "yellow" if p.cpu_percent > 5 else "green")

                ram_s = f"{p.memory_mb:8.1f}"
                ram_t = Text(ram_s, style="bold red" if p.memory_mb > 500 else "yellow" if p.memory_mb > 100 else "white")

                desc = p.description
                if len(desc) > 58:
                    desc = desc[:57] + "…"

                t.add_row(
                    str(p.pid), name_t, cat_t, safety_t, desc, cpu_t, ram_t,
                    key=str(p.pid),
                )

        label = self.query_one("#stats", Label)
        total = len(self._processes)
        shown = len(procs)
        cap_note = "  [dim](/ to search all)[/dim]" if shown == 100 and not self.filter_text.strip() else ""
        label.update(f"  {shown} / {total} processes{cap_note}")

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
            self.run_worker(self._load(), exclusive=True, name="load")

        self.push_screen(ConfirmKillScreen(proc), _after_confirm)

    def action_block(self) -> None:
        t = self.query_one(DataTable)
        if not t.row_count:
            return
        try:
            pid = int(list(t.rows.keys())[t.cursor_row].value)
        except (IndexError, ValueError, Exception):
            return
        proc = next((p for p in self._processes if p.pid == pid), None)
        if not proc:
            self.notify("Process not found", severity="warning")
            return

        def _after_block(entries: Optional[list[StartupEntry]]) -> None:
            if entries is None:
                return  # cancelled
            msgs: list[str] = []
            try:
                psutil.Process(proc.pid).kill()
                msgs.append(f"Killed {proc.name}")
            except psutil.NoSuchProcess:
                msgs.append(f"{proc.name} already exited")
            except psutil.AccessDenied:
                msgs.append("Kill denied — run as Administrator")
            for entry in entries:
                ok, msg = disable_startup_entry(entry)
                msgs.append(("✓ " if ok else "✗ ") + msg)
            self.notify("  ·  ".join(msgs), timeout=7)
            self.run_worker(self._load(), exclusive=True, name="load")

        self.push_screen(BlockScreen(proc), _after_block)

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
        self.run_worker(self._load(), exclusive=True, name="load")
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
