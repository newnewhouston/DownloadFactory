"""
DownloadFactory v1.0
One Factory-line console that unifies four downloaders behind a single local
page, with a HARD, FAIL-CLOSED VPN GATE on torrents.

  Video      - YT-DLP GUI v1.4, managed worker on 127.0.0.1:7331 (iframe)
  Torrents   - Transmission 4.1.3 daemon, spawned + driven over RPC   <-- GATED
  Galleries  - Hitomi Downloader (owner-supplied exe), HTTP API       (iframe)
  VPN & Leak - PIA via piactl + ipleak.net egress/DNS/torrent-address checks

The gate is the product: torrents cannot start unless PIA reports the literal
state "Connected" AND hands us a tunnel IP. Transmission's peer traffic is
bound to that tunnel IP; if the VPN drops, every torrent is stopped within one
monitor tick. Every failure mode - piactl missing, timing out, monitor dead -
is treated as NOT CONNECTED. The gate never fails open.

Run (dev):   py -3 "DownloadFactory 1.0.py"
Flags:       --port N       serve the shell on a specific port (default 8133)
             --no-browser   don't auto-open the browser
             --selftest     run the headless gate/RPC self-tests and exit

Localhost only. No LAN exposure, no cloud. Secrets never touch this folder.
"""

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import webbrowser
from urllib.parse import urlparse

DF_VERSION = "1.0"

# --------------------------------------------------------------------------
# Console hygiene (mirrors the sibling Factory apps)
# --------------------------------------------------------------------------
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_PNG = os.path.join(HERE, "DownloadFactory Logo 0.1.png")

# Everything secret or machine-local lives OUTSIDE the vault.
APPDATA = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "DownloadFactory"
)
TR_CONFIG_DIR = os.path.join(APPDATA, "transmission")
RPC_AUTH_FILE = os.path.join(APPDATA, "rpc-auth.json")
RUNTIME_FILE = os.path.join(APPDATA, "runtime.json")


def log(msg):
    print(f"[df] {msg}", flush=True)


def _expand(p):
    return os.path.abspath(os.path.expanduser(os.path.expandvars(p))) if p else p


# --------------------------------------------------------------------------
# config.json - NON-SECRET ONLY (this folder syncs to other machines)
# --------------------------------------------------------------------------
CONFIG_PATH = os.path.join(HERE, "config.json")

DEFAULT_CONFIG = {
    "_comment": "DownloadFactory v1.0 - NON-SECRET settings only. Passwords/tokens "
                "live in %LOCALAPPDATA%\\DownloadFactory\\, never in this file.",
    "shell_port": 8133,
    "downloads_root": "~/Downloads/DownloadFactory",
    "transmission": {
        "daemon": "C:/Program Files/Transmission/transmission-daemon.exe",
        "rpc_port": 9091,
        "peer_port": 51413,
        "download_dir": "~/Downloads/DownloadFactory/torrents",
    },
    "pia": {
        "piactl": "C:/Program Files/Private Internet Access/piactl.exe",
        "request_port_forward": False,
        "auto_resume_after_reconnect": False,
    },
    "ytdlp": {
        "enabled": True,
        "port": 7331,
        "script": "../YT-DLP GUI/yt-dlp-gui.py",
        "exe": "../YT-DLP GUI/YT-DLP GUI.exe",
        "launch_on_start": True,
    },
    "hitomi": {
        "enabled": True,
        "exe": "",
        "api_ports": [6975, 6976, 6977, 6978],
        "launch_on_start": False,
    },
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = _deep_merge(cfg, json.load(f))
        except (OSError, ValueError) as e:
            log(f"config.json unreadable ({e}); using defaults")
    else:
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            log("wrote a default config.json")
        except OSError:
            pass
    return cfg


CFG = load_config()

PIACTL = _expand(CFG["pia"]["piactl"])
TR_DAEMON = _expand(CFG["transmission"]["daemon"])
TR_RPC_PORT = int(CFG["transmission"]["rpc_port"])
TR_RPC_URL = f"http://127.0.0.1:{TR_RPC_PORT}/transmission/rpc"
TR_DOWNLOAD_DIR = _expand(CFG["transmission"]["download_dir"])

# requests is the only third-party dep besides flask; both ship with the
# YT-DLP GUI stack already present on this machine.
try:
    import requests
except ImportError:  # pragma: no cover
    log("FATAL: the 'requests' package is required.  py -3 -m pip install requests")
    raise

try:
    from flask import Flask, Response, jsonify, request, send_file
except ImportError:  # pragma: no cover
    log("FATAL: the 'flask' package is required.  py -3 -m pip install flask")
    raise


# ==========================================================================
# PHASE 1 - THE VPN SPINE
# Every function here fails closed. None of them may raise.
# ==========================================================================

def _piactl(*args, timeout=6):
    """Run a one-shot piactl command. Returns (rc, stdout). Never raises."""
    try:
        r = subprocess.run(
            [PIACTL, *args],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode, (r.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return 2, ""  # fail-closed: a missing/hung piactl reads as "not connected"


def vpn_state():
    """The exact piactl connectionstate string, or 'Unknown' on any error."""
    rc, out = _piactl("get", "connectionstate")
    return out if rc == 0 and out else "Unknown"


def vpn_ip():
    """Tunnel-local IP for bind-address-ipv4, or None."""
    rc, out = _piactl("get", "vpnip")
    return out if rc == 0 and out and out != "Unknown" else None


def pub_ip():
    """Public egress IP as PIA sees it, or None."""
    rc, out = _piactl("get", "pubip")
    return out if rc == 0 and out and out != "Unknown" else None


def pia_region():
    rc, out = _piactl("get", "region")
    return out if rc == 0 and out else "unknown"


def pia_portforward():
    """A port number (int), or a status word: Inactive/Attempting/Failed/Unavailable."""
    rc, out = _piactl("get", "portforward")
    if rc != 0 or not out:
        return "Unavailable"
    return int(out) if out.isdigit() else out


# --------------------------------------------------------------------------
# Finding the address Transmission must actually bind to.
#
# `piactl get vpnip` is NOT it. On OpenVPN it returns the SERVER-side endpoint
# (e.g. 212.32.69.17) which is not assigned to any local interface, so binding
# to it makes Transmission fail every connection with
#   "Couldn't obtain source address in any IP protocol, no network connections
#    possible"
# - torrents are added, sit at 0 peers forever, and never move. That is the
# safe direction (a stall, not a leak) but it is still broken.
#
# What we need is the local IPv4 assigned to PIA's own tunnel adapter
# ("Private Internet Access Network Adapter" on OpenVPN, "wgpia0" on
# WireGuard). We only ever return an address that sits on a PIA adapter, so
# this can never accidentally hand back the LAN address and leak.
# --------------------------------------------------------------------------
PIA_ADAPTER_HINTS = ("private internet access", "wgpia", "wintun", "tap-windows",
                     "pia openvpn")
_adapter_cache = {"t": 0.0, "val": None}


def _pia_adapter_ips():
    """{ipv4: adapter description} for every PIA tunnel adapter, cached 5 s."""
    now = time.time()
    if _adapter_cache["val"] is not None and now - _adapter_cache["t"] < 5.0:
        return _adapter_cache["val"]
    found = {}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
             "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex "
             "-ErrorAction SilentlyContinue; "
             "[pscustomobject]@{ip=$_.IPAddress; desc=$a.InterfaceDescription} } "
             "| ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=12,
            creationflags=CREATE_NO_WINDOW).stdout
        rows = json.loads(out) if out.strip() else []
        if isinstance(rows, dict):
            rows = [rows]
        for r in rows:
            desc = (r.get("desc") or "")
            if any(h in desc.lower() for h in PIA_ADAPTER_HINTS):
                found[r.get("ip")] = desc
    except (OSError, ValueError, subprocess.TimeoutExpired):
        found = {}
    _adapter_cache.update(t=now, val=found)
    return found


def _route_source_ip():
    """The source IPv4 the routing table would pick for internet traffic.
    No packet is sent - connect() on UDP only selects a route."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.connect(("1.1.1.1", 53))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def tunnel_bind_ip():
    """The local IPv4 to bind peer traffic to, or None if there isn't a
    usable tunnel address. Never returns a non-PIA address."""
    pia = _pia_adapter_ips()
    if not pia:
        return None
    route = _route_source_ip()
    if route in pia:
        return route          # the tunnel is carrying the default route
    if len(pia) == 1:
        return next(iter(pia))
    return sorted(pia)[0]


def gate_ok():
    """THE single source of truth for 'may torrents run?'.

    Anything other than the literal 'Connected', plus a real tunnel IP, plus a
    bindable local tunnel address, is a NO. Called live (not cached) on every
    mutating torrent route so a VPN that dropped a millisecond ago cannot slip
    a torrent through.
    """
    return (vpn_state() == "Connected"
            and vpn_ip() is not None
            and tunnel_bind_ip() is not None)


def gate_reason():
    """Human-readable reason the gate is shut, or '' when it is open."""
    st = vpn_state()
    if st != "Connected":
        return f"VPN is {st} - turn on PIA before starting torrents."
    if vpn_ip() is None:
        return "VPN reports Connected but has no tunnel IP yet - hold on."
    if tunnel_bind_ip() is None:
        return ("PIA is connected but no local tunnel adapter address was found, "
                "so peer traffic has nothing safe to bind to. Torrents stay "
                "blocked rather than risk binding outside the tunnel.")
    return ""


# --------------------------------------------------------------------------
# Shared application state
# --------------------------------------------------------------------------
class AppState:
    def __init__(self):
        self.lock = threading.RLock()
        self.vpn = "Unknown"
        self.vpn_ip = None
        self.pub_ip = None
        self.region = "unknown"
        self.portforward = "Inactive"
        self.blocked = True
        self.banner = "Checking VPN..."
        self.bound_ip = None            # what Transmission is actually bound to
        self.bind_ip = None             # what it SHOULD be bound to (PIA adapter)
        self.tr_state = "stopped"       # stopped | starting | running | error
        self.tr_error = ""
        self.watchdog_paused = []       # hashes the watchdog stopped, for opt-in resume
        self.last_leak = None
        self.last_dns = None
        self.events = []                # rolling activity log for the UI
        self.monitor_alive = False

    def event(self, kind, msg):
        with self.lock:
            self.events.insert(0, {"t": time.strftime("%H:%M:%S"), "kind": kind, "msg": msg})
            del self.events[60:]
        log(f"{kind}: {msg}")

    def snapshot(self):
        with self.lock:
            return {
                "vpn": self.vpn,
                "vpn_ip": self.vpn_ip,
                "pub_ip": self.pub_ip,
                "region": self.region,
                "portforward": self.portforward,
                "blocked": self.blocked,
                "banner": self.banner,
                "bound_ip": self.bound_ip,
                "bind_ip": self.bind_ip,
                "tr_state": self.tr_state,
                "tr_error": self.tr_error,
                "watchdog_paused": list(self.watchdog_paused),
                "last_leak": self.last_leak,
                "last_dns": self.last_dns,
                "monitor_alive": self.monitor_alive,
                "events": list(self.events[:20]),
            }


STATE = AppState()
STOPPING = threading.Event()


# ==========================================================================
# PHASE 2 - TRANSMISSION: RPC CLIENT, DAEMON LIFECYCLE, GATED ADDS
# ==========================================================================

class TransmissionError(RuntimeError):
    pass


class TR:
    """Old-protocol Transmission RPC client. 409-aware at any time."""

    def __init__(self, url, auth):
        self.url = url
        self.auth = auth
        self.sid = ""
        self._lock = threading.Lock()

    def call(self, method, arguments=None, timeout=15, _depth=0):
        body = {"method": method, "arguments": arguments or {}}
        with self._lock:
            sid = self.sid
        try:
            r = requests.post(
                self.url, json=body,
                headers={"X-Transmission-Session-Id": sid},
                auth=self.auth, timeout=timeout,
            )
        except requests.RequestException as e:
            raise TransmissionError(f"RPC unreachable: {e}") from e

        if r.status_code == 409 and _depth < 3:
            # CSRF token handshake. Can recur at any point - the token rotates.
            new_sid = r.headers.get("X-Transmission-Session-Id", "")
            with self._lock:
                self.sid = new_sid
            return self.call(method, arguments, timeout, _depth + 1)
        if r.status_code == 401:
            raise TransmissionError("RPC authentication failed")
        if r.status_code != 200:
            raise TransmissionError(f"RPC HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError as e:
            raise TransmissionError("RPC returned non-JSON") from e
        if data.get("result") != "success":
            raise TransmissionError(str(data.get("result")))
        return data.get("arguments", {})

    def alive(self, timeout=4):
        try:
            self.call("session-get", {"fields": ["version"]}, timeout=timeout)
            return True
        except (TransmissionError, Exception):
            return False


def _rpc_credentials():
    """Read (or mint) the plaintext RPC password. Lives outside the vault.

    Transmission salts rpc-password in settings.json on every flush and the
    salted form cannot be reversed - so the plaintext has to be kept beside it
    for the shell to authenticate on a later run.
    """
    os.makedirs(APPDATA, exist_ok=True)
    if os.path.exists(RPC_AUTH_FILE):
        try:
            with open(RPC_AUTH_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("username") and d.get("password"):
                return d["username"], d["password"]
        except (OSError, ValueError):
            pass
    creds = {"username": "downloadfactory", "password": secrets.token_urlsafe(24)}
    with open(RPC_AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2)
    try:
        os.chmod(RPC_AUTH_FILE, 0o600)
    except OSError:
        pass
    return creds["username"], creds["password"]


TR_USER, TR_PASS = _rpc_credentials()
tr = TR(TR_RPC_URL, (TR_USER, TR_PASS))


def _port_answers(port, host="127.0.0.1", timeout=0.4):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _port_owner(port):
    """{pid, name, ppid, parent_name} for whatever is LISTENing on a port.

    Used to tell a genuinely orphaned Transmission (its owning shell died, so
    it is ours to reclaim) apart from one a live sibling shell is using, which
    must be left alone.
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"$c = Get-NetTCPConnection -LocalPort {port} -State Listen "
             f"-ErrorAction SilentlyContinue | Select-Object -First 1; "
             f"if ($c) {{ $p = Get-CimInstance Win32_Process -Filter "
             f"\"ProcessId=$($c.OwningProcess)\"; "
             f"$par = if ($p) {{ Get-CimInstance Win32_Process -Filter "
             f"\"ProcessId=$($p.ParentProcessId)\" }} else {{ $null }}; "
             f"[pscustomobject]@{{pid=$c.OwningProcess; name=$p.Name; "
             f"ppid=$p.ParentProcessId; parent_name=$par.Name}} | ConvertTo-Json -Compress }}"],
            capture_output=True, text=True, timeout=12,
            creationflags=CREATE_NO_WINDOW).stdout.strip()
        return json.loads(out) if out else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _kill_pid(pid):
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, timeout=10,
                       creationflags=CREATE_NO_WINDOW)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _existing_instance(port):
    """True if another DownloadFactory shell is already serving on this port."""
    try:
        r = requests.get(f"http://127.0.0.1:{port}/health", timeout=2)
        return r.json().get("app") == "DownloadFactory"
    except (requests.RequestException, ValueError):
        return False


class TransmissionDaemon:
    """Owns transmission-daemon.exe as a foreground child process.

    We deliberately do NOT use the Windows service the MSI registers: it runs
    as LocalService (can't write the user's folders) and its lifecycle is wrong
    for the gate. The installer's service is stopped + disabled at setup time.
    """

    def __init__(self):
        self.proc = None
        self.lock = threading.RLock()

    # -- settings.json -----------------------------------------------------
    def write_settings(self, bind_ipv4):
        """Rewrite settings.json. ONLY legal while the daemon is stopped.

        bind_ipv4 must never be empty or invalid: Transmission silently falls
        back to 0.0.0.0 (a full leak) in that case. When there is no VPN we
        deliberately bind 127.0.0.1 so peer binds FAIL instead of leaking.
        """
        if not bind_ipv4 or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", bind_ipv4):
            bind_ipv4 = "127.0.0.1"  # fail-closed, never blank
        os.makedirs(TR_CONFIG_DIR, exist_ok=True)
        os.makedirs(TR_DOWNLOAD_DIR, exist_ok=True)  # free-space RPC needs it to exist

        path = os.path.join(TR_CONFIG_DIR, "settings.json")
        settings = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
            except (OSError, ValueError):
                settings = {}

        settings.update({
            "rpc-authentication-required": True,
            "rpc-username": TR_USER,
            "rpc-password": TR_PASS,   # plaintext; the daemon salts it on flush
            "rpc-bind-address": "127.0.0.1",
            "rpc-whitelist": "127.0.0.1",
            "rpc-whitelist-enabled": True,
            "rpc-host-whitelist-enabled": False,
            "rpc-port": TR_RPC_PORT,
            "peer-port": int(CFG["transmission"]["peer_port"]),
            "download-dir": TR_DOWNLOAD_DIR,
            "incomplete-dir-enabled": False,
            "bind-address-ipv4": bind_ipv4,
            "bind-address-ipv6": "::1",   # kill IPv6 peer traffic outright
            "peer-port-random-on-start": False,
            "port-forwarding-enabled": False,  # no UPnP/NAT-PMP on the LAN router
        })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        return bind_ipv4

    # -- lifecycle ---------------------------------------------------------
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, bind_ipv4, paused=True):
        with self.lock:
            if self.running():
                return True
            if not os.path.exists(TR_DAEMON):
                STATE.tr_state = "error"
                STATE.tr_error = (
                    "transmission-daemon.exe not found. Install Transmission 4.1.3: "
                    "msiexec /i transmission-4.1.3-x64.msi ADDLOCAL=ALL /qn"
                )
                return False

            # A stale daemon (previous crash, or the MSI service) may hold the
            # RPC port. Ask it to close before we bind.
            if _port_answers(TR_RPC_PORT):
                STATE.event("transmission", f"port {TR_RPC_PORT} busy - asking the stale daemon to close")
                try:
                    tr.call("session-close", timeout=6)
                except TransmissionError:
                    pass
                for _ in range(25):
                    if not _port_answers(TR_RPC_PORT):
                        break
                    time.sleep(0.2)

                if _port_answers(TR_RPC_PORT):
                    # Still held. Work out WHOSE it is before doing anything:
                    # a daemon whose parent shell has died is an orphan and is
                    # ours to reclaim; one a live sibling shell owns is not.
                    own = _port_owner(TR_RPC_PORT) or {}
                    name = (own.get("name") or "").lower()
                    parent = (own.get("parent_name") or "").lower()
                    if "transmission-daemon" in name and not parent:
                        STATE.event("transmission",
                                    f"reclaiming orphaned daemon (pid {own.get('pid')}, "
                                    f"its shell is gone)")
                        _kill_pid(own.get("pid"))
                        for _ in range(25):
                            if not _port_answers(TR_RPC_PORT):
                                break
                            time.sleep(0.2)

                if _port_answers(TR_RPC_PORT):
                    own = _port_owner(TR_RPC_PORT) or {}
                    parent = (own.get("parent_name") or "").lower()
                    if "python" in parent:
                        STATE.tr_state = "error"
                        STATE.tr_error = (
                            f"Another DownloadFactory (PID {own.get('ppid')}) is already "
                            f"running and owns Transmission on port {TR_RPC_PORT}. Close "
                            f"that window and press Retry - only one copy can run at once.")
                    else:
                        STATE.tr_state = "error"
                        STATE.tr_error = (
                            f"Port {TR_RPC_PORT} is held by "
                            f"{own.get('name') or 'another process'} "
                            f"(PID {own.get('pid')}) that we do not own. Close it (or "
                            f"disable the Transmission service) and retry.")
                    return False

            STATE.tr_state = "starting"
            STATE.tr_error = ""
            actual = self.write_settings(bind_ipv4)
            cmd = [TR_DAEMON, "-f", "-g", TR_CONFIG_DIR,
                   "-p", str(TR_RPC_PORT), "-r", "127.0.0.1", "-a", "127.0.0.1"]
            if paused:
                cmd.append("--paused")
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    creationflags=CREATE_NO_WINDOW,
                )
            except OSError as e:
                STATE.tr_state = "error"
                STATE.tr_error = f"could not launch the daemon: {e}"
                return False

            threading.Thread(target=self._drain, daemon=True).start()

            for _ in range(75):  # up to ~30 s
                if self.proc.poll() is not None:
                    STATE.tr_state = "error"
                    STATE.tr_error = f"daemon exited immediately (rc={self.proc.returncode})"
                    return False
                if tr.alive(timeout=2):
                    STATE.tr_state = "running"
                    STATE.bound_ip = actual
                    STATE.event("transmission", f"daemon up, peer traffic bound to {actual}")
                    return True
                time.sleep(0.4)

            STATE.tr_state = "error"
            STATE.tr_error = "daemon started but RPC never answered"
            return False

    def _drain(self):
        """Keep the child's stdout pipe empty and surface bind failures."""
        p = self.proc
        try:
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                low = line.lower()
                if "couldn't bind" in low or "no network connections possible" in low:
                    STATE.event("transmission", line[:220])
        except (ValueError, OSError):
            pass

    def stop(self, timeout=20):
        """Graceful stop. MUST be graceful: on Windows terminate() is
        TerminateProcess, which the daemon cannot catch - it would never flush
        settings.json, losing the runtime peer-port and resume state."""
        with self.lock:
            if not self.running():
                self.proc = None
                STATE.tr_state = "stopped"
                return True
            try:
                tr.call("session-close", timeout=6)
            except TransmissionError:
                pass
            t0 = time.time()
            while time.time() - t0 < timeout:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.2)
            if self.proc.poll() is None:
                STATE.event("transmission", "daemon ignored session-close; terminating")
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=10)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        self.proc.kill()
                    except OSError:
                        pass
            self.proc = None
            STATE.tr_state = "stopped"
            # Give Windows a moment to release the listener before any rebind.
            for _ in range(20):
                if not _port_answers(TR_RPC_PORT):
                    break
                time.sleep(0.2)
            return True

    def rebind(self, new_ip):
        """bind-address-ipv4 cannot be set over RPC and a foreground Windows
        daemon has no live reload: stop -> rewrite settings.json -> start."""
        with self.lock:
            was_running = self.running()
            STATE.event("transmission", f"rebinding peer traffic to {new_ip or '127.0.0.1'}")
            if was_running:
                self.stop()
            ok = self.start(new_ip, paused=True)
            if not ok:
                STATE.event("transmission", f"rebind failed: {STATE.tr_error}")
            return ok


DAEMON = TransmissionDaemon()


def tr_stop_all():
    """The gate's panic action. No ids = every torrent."""
    try:
        tr.call("torrent-stop", timeout=8)
        return True
    except TransmissionError as e:
        STATE.event("gate", f"stop-all failed ({e})")
        return False


def tr_list():
    fields = ["id", "name", "status", "percentDone", "rateDownload", "rateUpload",
              "eta", "totalSize", "downloadDir", "isFinished", "error",
              "errorString", "hashString"]
    return tr.call("torrent-get", {"fields": fields}, timeout=10).get("torrents", [])


def apply_port_forward():
    """Push PIA's forwarded port into Transmission when there is one."""
    pf = pia_portforward()
    with STATE.lock:
        STATE.portforward = pf
    if not isinstance(pf, int):
        return
    try:
        tr.call("session-set", {"peer-port": pf}, timeout=8)
        STATE.event("portforward", f"peer-port set to {pf}")
        try:
            res = tr.call("port-test", timeout=25)
            STATE.event("portforward", f"port-test: {'open' if res.get('port-is-open') else 'closed'}")
        except TransmissionError as e:
            # Observed live: "Couldn't test port: No Response (0)" is a normal
            # result, not a crash - it just means the check could not complete.
            STATE.event("portforward", f"port-test inconclusive ({e})")
    except TransmissionError as e:
        STATE.event("portforward", f"could not apply forwarded port ({e})")


# --------------------------------------------------------------------------
# The watchdog - the gate's enforcement arm
# --------------------------------------------------------------------------
def on_state_change(state):
    """Handle one connectionstate transition. Fail-closed on everything."""
    with STATE.lock:
        prev = STATE.vpn
        STATE.vpn = state
    if state == prev:
        return

    if state == "Connected":
        ip = vpn_ip()
        bind = tunnel_bind_ip()
        with STATE.lock:
            STATE.vpn_ip = ip
            STATE.bind_ip = bind
            STATE.region = pia_region()
        STATE.event("gate", f"VPN Connected (endpoint {ip}, binding to {bind})")
        if ip is None or bind is None:
            with STATE.lock:
                STATE.blocked = True
                STATE.banner = (gate_reason() or
                                "VPN reports Connected but has no usable tunnel address yet.")
            return
        if bind != STATE.bound_ip:
            DAEMON.rebind(bind)
        elif not DAEMON.running():
            DAEMON.start(bind, paused=True)
        apply_port_forward()
        with STATE.lock:
            STATE.pub_ip = pub_ip()
            STATE.blocked = False
            STATE.banner = ""
        # Torrents stay paused by design; the user resumes. Opt-in auto-resume
        # only ever touches the exact set the watchdog itself paused.
        if CFG["pia"].get("auto_resume_after_reconnect"):
            with STATE.lock:
                hashes = list(STATE.watchdog_paused)
                STATE.watchdog_paused = []
            if hashes:
                try:
                    tr.call("torrent-start", {"ids": hashes}, timeout=10)
                    STATE.event("gate", f"auto-resumed {len(hashes)} torrent(s)")
                except TransmissionError as e:
                    STATE.event("gate", f"auto-resume failed ({e})")
    else:
        # ANY non-Connected state, including Unknown from a dead piactl.
        paused_now = []
        try:
            paused_now = [t["hashString"] for t in tr_list()
                          if t.get("status") not in (0,)]
        except TransmissionError:
            pass
        tr_stop_all()
        with STATE.lock:
            STATE.vpn_ip = None
            STATE.pub_ip = None
            STATE.blocked = True
            STATE.banner = f"VPN is {state} - torrents paused. Turn PIA back on."
            for h in paused_now:
                if h not in STATE.watchdog_paused:
                    STATE.watchdog_paused.append(h)
        STATE.event("gate", f"BLOCKED - VPN {state}; all torrents stopped")


def watchdog():
    """Supervise `piactl monitor connectionstate` for the app's whole life.

    piactl prints the current value immediately and one line per change,
    line-flushed, so this is a true event stream rather than a poll. If the
    monitor dies (PIA service restart -> exit code 3) we treat that as
    not-connected and respawn with backoff.
    """
    backoff = 1.0
    while not STOPPING.is_set():
        p = None
        try:
            p = subprocess.Popen(
                [PIACTL, "monitor", "connectionstate"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1, creationflags=CREATE_NO_WINDOW,
            )
            with STATE.lock:
                STATE.monitor_alive = True
            backoff = 1.0
            for line in p.stdout:
                if STOPPING.is_set():
                    break
                line = line.strip()
                if line:
                    on_state_change(line)
        except (OSError, ValueError) as e:
            STATE.event("gate", f"monitor could not start ({e}) - treating as not connected")
        finally:
            with STATE.lock:
                STATE.monitor_alive = False
            if p is not None:
                try:
                    p.terminate()
                except OSError:
                    pass
        if STOPPING.is_set():
            break
        # Monitor died: fail closed, then respawn with backoff.
        on_state_change("Unknown")
        STOPPING.wait(backoff)
        backoff = min(backoff * 2, 30.0)


def poll_secondary():
    """Refresh the values piactl does not stream on connectionstate - and
    reconcile the cached state against a live one-shot query.

    The reconcile matters: the gate itself calls piactl live on every mutating
    route, so it stays correct no matter what. But the BANNER and the status
    pill are driven by the cached value, and that value only ever moved when
    the monitor emitted a line. If the monitor wedged or piactl went away
    while the stream sat open, the UI kept showing a green "Connected" pill
    over a gate that was actually shut. Failing closed has to include what the
    user is being told, not just what the server does.
    """
    while not STOPPING.is_set():
        try:
            live = vpn_state()
            with STATE.lock:
                cached = STATE.vpn
            if live != cached and cached != "__init__":
                STATE.event("gate", f"state reconciled by poll: {cached} -> {live}")
                on_state_change(live)
                STOPPING.wait(10)
                continue
            connected = live == "Connected"
            if connected:
                ip, pub, pf = vpn_ip(), pub_ip(), pia_portforward()
                bind = tunnel_bind_ip()
                with STATE.lock:
                    STATE.vpn_ip, STATE.pub_ip, STATE.portforward = ip, pub, pf
                    STATE.bind_ip = bind
                # A silent tunnel-adapter change (server hop) must rebind.
                if bind and bind != STATE.bound_ip and DAEMON.running():
                    STATE.event("gate", f"tunnel address changed {STATE.bound_ip} -> {bind}")
                    DAEMON.rebind(bind)
            else:
                with STATE.lock:
                    STATE.portforward = pia_portforward()
        except Exception as e:  # a monitor thread must never die
            log(f"secondary poll error: {e}")
        STOPPING.wait(10)


# ==========================================================================
# PHASE 3 - VIDEO WORKER (YT-DLP GUI v1.4)
# ==========================================================================
class YtdlpWorker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.port = int(cfg.get("port", 7331))
        self.script = _expand(os.path.join(HERE, cfg.get("script", "")))
        self.exe = _expand(os.path.join(HERE, cfg.get("exe", "")))
        self.proc = None
        self.error = ""
        self.adopted = False

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/"

    def health(self, timeout=2):
        try:
            r = requests.get(f"{self.url}health", timeout=timeout)
            if r.status_code == 200:
                return r.json()
        except (requests.RequestException, ValueError):
            pass
        return None

    def start(self):
        if self.health():
            self.adopted = True   # already running (dev server, earlier session)
            self.error = ""
            return True
        cmds = []
        if os.path.exists(self.script):
            cmds.append([sys.executable, self.script, "--no-browser", "--port", str(self.port)])
        if os.path.exists(self.exe):
            cmds.append([self.exe, "--no-browser", "--port", str(self.port)])
        if not cmds:
            self.error = f"YT-DLP GUI not found at {self.script}"
            return False
        for cmd in cmds:
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, cwd=os.path.dirname(cmd[0 if cmd[0] == self.exe else 1]),
                    creationflags=CREATE_NO_WINDOW,
                )
            except OSError as e:
                self.error = f"{os.path.basename(cmd[0])}: {e}"
                continue
            for _ in range(90):  # first run may install ffmpeg/node via winget
                if self.proc.poll() is not None:
                    break
                if self.health():
                    self.error = ""
                    STATE.event("video", f"yt-dlp worker up on {self.port}")
                    return True
                time.sleep(0.5)
            self.error = "worker started but /health never answered"
        return False

    def _session_token(self):
        """YT-DLP GUI v1.4 gates /shutdown behind an X-YTG-Token whose value is
        a per-process uuid4 embedded only in the page it serves. A bare POST
        gets 403 and the worker keeps running, so read the token back off the
        page we are already allowed to fetch."""
        try:
            r = requests.get(self.url, timeout=4)
            m = re.search(r"const\s+TOKEN\s*=\s*'([0-9a-fA-F]{32})'", r.text)
            return m.group(1) if m else None
        except requests.RequestException:
            return None

    def stop(self):
        if self.adopted and self.proc is None:
            # Someone else's instance was already running - not ours to kill.
            return
        try:
            tok = self._session_token()
            requests.post(f"{self.url}shutdown", timeout=4,
                          headers={"X-YTG-Token": tok} if tok else {})
        except requests.RequestException:
            pass
        if self.proc and self.proc.poll() is None:
            time.sleep(0.8)
            if self.proc.poll() is None:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=6)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        self.proc.kill()
                    except OSError:
                        pass
        self.proc = None

    def status(self):
        h = self.health()
        return {
            "enabled": bool(self.cfg.get("enabled", True)),
            "up": h is not None,
            "version": (h or {}).get("version"),
            "url": self.url,
            "port": self.port,
            "error": self.error,
            "script": self.script,
            "adopted": self.adopted,
        }


# ==========================================================================
# PHASE 4 - GALLERIES WORKER (Hitomi Downloader, owner-supplied)
# ==========================================================================
HITOMI_MISSING_MSG = (
    "DownloadFactory does not ship Hitomi Downloader - the upstream GitHub repo "
    "was DMCA'd in March 2026 and returns HTTP 451, and mirror downloads are a "
    "malware vector. Point me at your own hitomi_downloader_GUI.exe via the "
    "\"hitomi\".\"exe\" key in config.json, then enable its HTTP API under "
    "Options -> Settings -> Advanced -> HTTP API."
)


class HitomiWorker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.exe = _expand(cfg.get("exe", "")) if cfg.get("exe") else ""
        self.ports = list(cfg.get("api_ports", [6975, 6976, 6977, 6978]))
        self.proc = None
        self.api_port = None
        self.error = ""

    def have_exe(self):
        return bool(self.exe) and os.path.exists(self.exe)

    def probe(self):
        """Find the built-in HTTP API. Undocumented (the wiki is 451), so we
        only check that something HTTP-shaped answers on the expected ports."""
        for p in self.ports:
            if not _port_answers(p, timeout=0.25):
                continue
            try:
                r = requests.get(f"http://127.0.0.1:{p}/", timeout=2)
                if r.status_code < 500:
                    self.api_port = p
                    return p
            except requests.RequestException:
                continue
        self.api_port = None
        return None

    def launch(self):
        if not self.have_exe():
            self.error = HITOMI_MISSING_MSG
            return False
        if self.probe():
            return True
        try:
            self.proc = subprocess.Popen(
                [self.exe, "--tray"], cwd=os.path.dirname(self.exe),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except OSError as e:
            self.error = f"could not launch Hitomi: {e}"
            return False
        for _ in range(40):
            if self.probe():
                self.error = ""
                STATE.event("galleries", f"Hitomi API found on {self.api_port}")
                return True
            time.sleep(0.5)
        self.error = ("Hitomi launched but no HTTP API answered on "
                      f"{self.ports}. Enable Options -> Settings -> Advanced -> HTTP API.")
        return False

    def send_url(self, url):
        """Enqueue a URL. Never accepts magnets - those belong to the gate."""
        if not self.have_exe():
            return False, HITOMI_MISSING_MSG
        try:
            subprocess.Popen([self.exe, url, "--tray"], cwd=os.path.dirname(self.exe),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL)
            return True, "sent to Hitomi"
        except OSError as e:
            return False, str(e)

    def stop(self):
        # Hitomi is the owner's own app with its own tray lifecycle; we only
        # close instances we started ourselves.
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=6)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.proc.kill()
                except OSError:
                    pass
        self.proc = None

    def status(self):
        port = self.probe()
        if not self.have_exe():
            msg = HITOMI_MISSING_MSG
        elif port:
            msg = ""
        else:
            msg = self.error or (
                "Hitomi is configured but its HTTP API is not answering on "
                f"{self.ports}. Launch it below, then enable Options -> Settings "
                "-> Advanced -> HTTP API (it binds 127.0.0.1:6975). Expect a "
                "SmartScreen prompt and a Windows Firewall prompt the first time.")
        return {
            "enabled": bool(self.cfg.get("enabled", True)),
            "have_exe": self.have_exe(),
            "exe": self.exe,
            "api_port": port,
            "url": f"http://127.0.0.1:{port}/" if port else None,
            "up": port is not None,
            "error": msg,
            "launched_by_us": self.proc is not None and self.proc.poll() is None,
        }


VIDEO = YtdlpWorker(CFG["ytdlp"])
GALLERIES = HitomiWorker(CFG["hitomi"])


# ==========================================================================
# ipleak.net - leak verification, done SERVER-SIDE so it reflects this
# machine's egress and resolvers, not the browser's.
# ==========================================================================
IPLEAK_UA = {"User-Agent": f"DownloadFactory/{DF_VERSION}"}


def leak_ip():
    out = {"ok": False, "ip": None, "isp": None, "asn": None,
           "country": None, "city": None, "source": "ipleak.net", "error": ""}
    try:
        r = requests.get("https://ipleak.net/json/", headers=IPLEAK_UA, timeout=12)
        r.raise_for_status()
        d = r.json()
        out.update(ok=True, ip=d.get("ip"), isp=d.get("isp_name"),
                   asn=d.get("as_number"), country=d.get("country_name"),
                   city=d.get("city_name"))
        return out
    except (requests.RequestException, ValueError) as e:
        out["error"] = str(e)
    try:  # documented fallback; ipleak is best-effort and unauthenticated
        r = requests.get("https://api.ipify.org?format=json", headers=IPLEAK_UA, timeout=8)
        r.raise_for_status()
        out.update(ok=True, ip=r.json().get("ip"), source="api.ipify.org", error="")
    except (requests.RequestException, ValueError) as e:
        out["error"] = f"{out['error']} / ipify: {e}"
    return out


def _geo(ip):
    try:
        r = requests.get(f"https://ipleak.net/json/{ip}", headers=IPLEAK_UA, timeout=10)
        r.raise_for_status()
        d = r.json()
        return {"ip": ip, "isp": d.get("isp_name"), "asn": d.get("as_number"),
                "country": d.get("country_name")}
    except (requests.RequestException, ValueError):
        return {"ip": ip, "isp": None, "asn": None, "country": None}


def leak_dns(rounds=8):
    session = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(40))
    resolvers = {}
    errors = []
    for n in range(1, rounds + 1):
        try:
            r = requests.get(f"https://{session}-{n}.ipleak.net/dnsdetection/",
                             headers=IPLEAK_UA, timeout=10)
            if r.status_code != 200:
                errors.append(f"n={n} HTTP {r.status_code}")
                continue
            d = r.json()
            # The 'ip' field is an empty LIST when nothing was recorded and a
            # DICT {resolverIP: hits} when populated. Guard the shape.
            ips = d.get("ip") if isinstance(d.get("ip"), dict) else {}
            for k, v in ips.items():
                resolvers[k] = max(resolvers.get(k, 0), v if isinstance(v, int) else 0)
        except (requests.RequestException, ValueError) as e:
            errors.append(f"n={n} {e}")
    return {"session": session, "resolvers": [_geo(ip) for ip in resolvers],
            "count": len(resolvers), "errors": errors}


# The EMPTY state was captured verbatim from the live endpoint. The DETECTED
# state could not be observed without announcing to ipleak's tracker, and the
# site's own CSS (table.data / .data td) argues the results render as a table,
# not as the free text "IP: ... Port: ..." the build guide assumed. So we do
# not bet on one regex: strip the known-noise magnet link, then harvest any
# address-shaped token from what remains, and ALWAYS hand the raw fragment
# back to the UI so a human can confirm with their own eyes.
_RE_EMPTY = re.compile(r"No data just now from the above magnet url", re.I)
_RE_MAGNET_ANCHOR = re.compile(r"<a\b[^>]*href=['\"]magnet:[^'\"]*['\"][^>]*>.*?</a>",
                               re.I | re.S)
_RE_TAG = re.compile(r"<[^>]+>")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
_RE_LABELLED_PORT = re.compile(r"port\D{0,16}?(\d{1,5})", re.I)
_RE_IP_COLON_PORT = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})[:\s]+(\d{2,5})\b")


def _valid_ipv4(s):
    try:
        return all(0 <= int(p) <= 255 for p in s.split(".")) and len(s.split(".")) == 4
    except ValueError:
        return False


def _parse_probe_html(html):
    """Pure parser, split out of torrent_probe_poll so it is unit-testable."""
    out = {"detected": False, "ip": None, "port": None, "empty": False,
           "error": "", "candidates": [], "raw": ""}
    if _RE_EMPTY.search(html):
        out["empty"] = True
        out["raw"] = _RE_TAG.sub(" ", html)[:400].strip()
        return out

    # Drop the "add this Magnet Link" anchor - its href carries the hash and
    # the tracker URL, neither of which is a detected peer address.
    body = _RE_MAGNET_ANCHOR.sub(" ", html)
    text = _RE_TAG.sub(" ", body)
    out["raw"] = " ".join(text.split())[:600]

    pair = _RE_IP_COLON_PORT.search(text)
    ips = [ip for ip in _RE_IPV4.findall(text) if _valid_ipv4(ip)]
    ips += _RE_IPV6.findall(text)
    # De-dupe, preserve order.
    seen, ordered = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    out["candidates"] = ordered

    if pair:
        out.update(detected=True, ip=pair.group(1), port=int(pair.group(2)))
    elif ordered:
        out.update(detected=True, ip=ordered[0])
        m = _RE_LABELLED_PORT.search(text)
        if m and 0 < int(m.group(1)) <= 65535:
            out["port"] = int(m.group(1))
    else:
        out["empty"] = True
    return out


def torrent_probe_poll(thash):
    try:
        r = requests.get(f"https://ipleak.net/?thash={thash}&details=1",
                         headers=IPLEAK_UA, timeout=15)
        r.raise_for_status()
    except requests.RequestException as e:
        return {"detected": False, "ip": None, "port": None, "empty": False,
                "error": str(e), "candidates": [], "raw": ""}
    return _parse_probe_html(r.text)


# ==========================================================================
# FLASK SHELL
# ==========================================================================
app = Flask(__name__)
# Key order is load-bearing for the Video tab: the worker's QUALITY_OPTIONS is
# ordered Best -> 1080p -> ... and the first entry is the default selection.
# Flask 3 sorts keys by default, which silently made "1080p" the default.
try:
    app.json.sort_keys = False          # Flask >= 2.3
except AttributeError:                  # pragma: no cover - older Flask
    app.config["JSON_SORT_KEYS"] = False

STATUS_LABELS = {0: "stopped", 1: "queued-verify", 2: "verifying",
                 3: "queued-download", 4: "downloading", 5: "queued-seed", 6: "seeding"}


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


@app.after_request
def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return Response(render_page(), mimetype="text/html")


@app.route("/logo.png")
def logo():
    if os.path.exists(LOGO_PNG):
        return send_file(LOGO_PNG, mimetype="image/png")
    return ("", 404)


@app.route("/health")
def health():
    return jsonify(app="DownloadFactory", version=DF_VERSION)


@app.route("/api/state")
def api_state():
    s = STATE.snapshot()
    s["version"] = DF_VERSION
    s["gate_open"] = not s["blocked"]
    s["workers"] = {"video": VIDEO.status(), "galleries": GALLERIES.status()}
    s["transmission"] = {
        "installed": os.path.exists(TR_DAEMON),
        "daemon": TR_DAEMON,
        "state": s["tr_state"],
        "error": s["tr_error"],
        "rpc_port": TR_RPC_PORT,
        "download_dir": TR_DOWNLOAD_DIR,
        "install_hint": "msiexec /i transmission-4.1.3-x64.msi ADDLOCAL=ALL /qn",
    }
    return jsonify(s)


# ---- VPN ------------------------------------------------------------------
@app.post("/api/vpn/connect")
def api_vpn_connect():
    if CFG["pia"].get("request_port_forward"):
        _piactl("set", "requestportforward", "true")
    if vpn_state() == "Connected":
        return jsonify(ok=True, note="already connected")
    rc, out = _piactl("connect", timeout=30)
    if rc == 4:
        return jsonify(ok=False, error="PIA needs its GUI running, or run: piactl background enable")
    if rc == 5:
        return jsonify(ok=False, error="Not logged in - sign in with the PIA app once.")
    return jsonify(ok=(rc == 0), error="" if rc == 0 else f"piactl connect rc={rc} {out}")


@app.post("/api/vpn/disconnect")
def api_vpn_disconnect():
    rc, out = _piactl("disconnect", timeout=30)
    return jsonify(ok=(rc == 0), error="" if rc == 0 else f"rc={rc} {out}")


@app.get("/api/vpn/refresh")
def api_vpn_refresh():
    st = vpn_state()
    on_state_change(st)
    with STATE.lock:
        STATE.vpn_ip, STATE.pub_ip = vpn_ip(), pub_ip()
        STATE.bind_ip = tunnel_bind_ip()
        STATE.region, STATE.portforward = pia_region(), pia_portforward()
    return jsonify(STATE.snapshot())


# ---- Torrents (GATED) -----------------------------------------------------
@app.post("/api/torrent/add")
def api_torrent_add():
    """The ONLY path that adds a torrent. Server-side refusal is authoritative:
    hitting this route directly with the VPN off must start nothing."""
    if not gate_ok():
        return jsonify(blocked=True, ok=False, reason=gate_reason() or
                       "VPN is not connected. Turn on PIA before starting torrents."), 200

    payload = request.get_json(silent=True) or {}
    magnet = (payload.get("magnet") or "").strip()
    b64 = payload.get("metainfo")
    if not magnet and not b64 and request.files.get("torrent"):
        b64 = base64.b64encode(request.files["torrent"].read()).decode()
    if not magnet and not b64:
        return jsonify(ok=False, error="give me a magnet link or a .torrent file"), 400
    if magnet and not magnet.lower().startswith("magnet:"):
        return jsonify(ok=False, error="that is not a magnet link"), 400

    if not DAEMON.running():
        if not DAEMON.start(tunnel_bind_ip(), paused=False):
            return jsonify(ok=False, error=STATE.tr_error or "Transmission is not running"), 200

    args = {"paused": False, "download-dir": TR_DOWNLOAD_DIR}
    if magnet:
        args["filename"] = magnet
    else:
        args["metainfo"] = b64
    try:
        res = tr.call("torrent-add", args, timeout=25)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200
    added = res.get("torrent-added") or res.get("torrent-duplicate")
    if not added:
        return jsonify(ok=False, error="Transmission accepted nothing"), 200
    dup = "torrent-duplicate" in res
    STATE.event("torrent", f"{'duplicate' if dup else 'added'}: {added.get('name')}")
    return jsonify(ok=True, duplicate=dup, hash=added.get("hashString"),
                   name=added.get("name"), id=added.get("id"))


@app.get("/api/torrent/list")
def api_torrent_list():
    if not DAEMON.running():
        return jsonify(ok=False, torrents=[], daemon=False, error=STATE.tr_error)
    try:
        rows = []
        for t in tr_list():
            rows.append({
                "hash": t.get("hashString"),
                "id": t.get("id"),
                "name": t.get("name"),
                "status": t.get("status"),
                "statusLabel": STATUS_LABELS.get(t.get("status"), "?"),
                "percent": round((t.get("percentDone") or 0) * 100, 1),
                "down": human_bytes(t.get("rateDownload")) + "/s",
                "up": human_bytes(t.get("rateUpload")) + "/s",
                "downRaw": t.get("rateDownload") or 0,
                "size": human_bytes(t.get("totalSize")),
                "eta": ("-" if (t.get("eta") or -1) < 0 else _fmt_eta(t["eta"])),
                "error": t.get("error") or 0,
                "errorString": t.get("errorString") or "",
                "finished": bool(t.get("isFinished")),
            })
        return jsonify(ok=True, daemon=True, torrents=rows)
    except TransmissionError as e:
        return jsonify(ok=False, daemon=True, torrents=[], error=str(e))


def _fmt_eta(secs):
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    if secs < 86400:
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    return f"{secs // 86400}d"


@app.post("/api/torrent/start")
def api_torrent_start():
    if not gate_ok():
        return jsonify(blocked=True, ok=False, reason=gate_reason()), 200
    ids = (request.get_json(silent=True) or {}).get("ids")
    try:
        tr.call("torrent-start", {"ids": ids} if ids else {}, timeout=10)
        if ids:
            with STATE.lock:
                STATE.watchdog_paused = [h for h in STATE.watchdog_paused if h not in ids]
        return jsonify(ok=True)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200


@app.post("/api/torrent/stop")
def api_torrent_stop():
    ids = (request.get_json(silent=True) or {}).get("ids")
    try:
        tr.call("torrent-stop", {"ids": ids} if ids else {}, timeout=10)
        return jsonify(ok=True)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200


@app.post("/api/torrent/remove")
def api_torrent_remove():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids")
    if not ids:
        return jsonify(ok=False, error="no ids"), 400
    try:
        tr.call("torrent-remove",
                {"ids": ids, "delete-local-data": bool(body.get("deleteData"))}, timeout=15)
        return jsonify(ok=True)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200


@app.post("/api/transmission/start")
def api_tr_start():
    ok = DAEMON.start(tunnel_bind_ip() or "127.0.0.1", paused=True)
    return jsonify(ok=ok, error=STATE.tr_error)


@app.post("/api/transmission/stop")
def api_tr_stop():
    DAEMON.stop()
    return jsonify(ok=True)


# ---- Leak checks ----------------------------------------------------------
def _baseline_isp():
    """The real ISP/ASN, recorded the first time we see an egress while the VPN
    is off. That - not piactl - is what a leak has to be measured against."""
    try:
        with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("real_isp") or {}
    except (OSError, ValueError):
        return {}


_endpoint_asn_cache = {"ip": None, "asn": None}


def _endpoint_asn():
    """ASN of the PIA server we are tunnelled to (from piactl's vpnip).

    An egress on that same ASN is positive proof the tunnel is carrying
    traffic, and unlike the real-ISP baseline it needs no prior VPN-off run.
    """
    ip = vpn_ip()
    if not ip:
        return None
    if _endpoint_asn_cache["ip"] == ip:
        return _endpoint_asn_cache["asn"]
    asn = _geo(ip).get("asn")
    _endpoint_asn_cache.update(ip=ip, asn=asn)
    return asn


def _remember_baseline(res):
    try:
        os.makedirs(APPDATA, exist_ok=True)
        data = {}
        if os.path.exists(RUNTIME_FILE):
            with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        data["real_isp"] = {"ip": res.get("ip"), "asn": res.get("asn"), "isp": res.get("isp")}
        with open(RUNTIME_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except (OSError, ValueError):
        pass


@app.get("/api/leak/ip")
def api_leak_ip():
    """Verdict logic, rewritten after a live false positive.

    The naive check - "ipleak's egress must equal `piactl get pubip`" - cried
    LEAK on a perfectly healthy OpenVPN tunnel, because PIA's `pubip` was
    reporting the REAL ISP address while ipleak correctly saw the VPN exit.
    piactl's pubip is advisory at best; the egress ipleak actually observes is
    the ground truth. So a leak is now defined as "the observed egress is my
    real address / my real ISP", not "it disagrees with piactl".
    """
    res = leak_ip()
    st = vpn_state()
    res["vpn_state"] = st
    res["pia_pubip"] = pub_ip()
    base = _baseline_isp()
    res["baseline"] = base or None

    if st != "Connected":
        # VPN deliberately off: record what "real" looks like, and say so
        # plainly rather than calling the user's own IP a leak.
        if res.get("ok") and res.get("asn"):
            _remember_baseline(res)
            res["baseline"] = _baseline_isp()
        res["verdict"] = "novpn"
        res["matches_vpn"] = False
        res["detail"] = "VPN is off, so this is your real IP - nothing is leaking."
    elif not res.get("ok"):
        res["verdict"] = "unknown"
        res["matches_vpn"] = False
        res["detail"] = "Could not reach ipleak.net or the fallback."
    elif base and (res.get("asn") == base.get("asn") or res.get("ip") == base.get("ip")):
        res["verdict"] = "leak"
        res["matches_vpn"] = False
        res["detail"] = (f"Egress is on your REAL ISP ({res.get('isp')}) - traffic is "
                         f"bypassing the tunnel. This is a genuine leak.")
    elif res.get("pia_pubip") and res["ip"] == res["pia_pubip"]:
        res["verdict"] = "vpn"
        res["matches_vpn"] = True
        res["detail"] = "Egress matches PIA's reported public IP."
    else:
        # Positive proof, independent of any baseline: does the egress sit in
        # the same network as the PIA endpoint we are tunnelled to? If so the
        # tunnel is certainly carrying traffic.
        endpoint_asn = _endpoint_asn()
        if endpoint_asn and res.get("asn") == endpoint_asn:
            res["verdict"] = "vpn"
            res["matches_vpn"] = True
            res["detail"] = (f"Egress is on the same network as the PIA server we are "
                             f"connected to ({res.get('isp')}, AS{endpoint_asn}). The "
                             f"tunnel is holding."
                             + (" (piactl's pubip disagrees, which is common on OpenVPN "
                                "- the observed egress is authoritative.)"
                                if res.get("pia_pubip") and res["ip"] != res["pia_pubip"] else ""))
        elif base:
            res["verdict"] = "vpn"
            res["matches_vpn"] = True
            res["detail"] = (f"Egress is {res.get('isp') or 'a VPN host'}, not your real "
                             f"ISP ({base.get('isp')}). The tunnel is holding.")
        else:
            # No baseline AND no endpoint match: we genuinely cannot prove this
            # either way. Saying "holding" here would be a green light we have
            # not earned - a real leak would land in exactly this branch.
            res["verdict"] = "unknown"
            res["matches_vpn"] = False
            res["detail"] = (f"Egress is {res.get('isp') or 'unknown'} (AS{res.get('asn')}), "
                             "which is neither your PIA server's network nor a known "
                             "baseline. Run this check once with the VPN OFF so I can "
                             "learn what your real ISP looks like, then re-run it.")

    res["checked"] = time.strftime("%H:%M:%S")
    with STATE.lock:
        STATE.last_leak = res
    return jsonify(res)


@app.get("/api/leak/dns")
def api_leak_dns():
    res = leak_dns()
    res["checked"] = time.strftime("%H:%M:%S")
    with STATE.lock:
        STATE.last_dns = res
    return jsonify(res)


@app.post("/api/leak/torrent/start")
def api_leak_torrent_start():
    """Announce a throwaway hash to ipleak's tracker and see which IP it sees.

    This deliberately goes through the SAME gated add path as any other
    torrent - with the VPN off it is refused and nothing is ever announced.
    """
    if not gate_ok():
        return jsonify(blocked=True, ok=False,
                       reason=(gate_reason() or "VPN not connected") +
                              " The probe is refused too, so nothing announces."), 200
    thash = secrets.token_hex(20)
    magnet = (f"magnet:?xt=urn:btih:{thash}"
              f"&tr=https://ipleak.net/announce.php%3Fh%3D{thash}"
              f"&dn=ipleak.net+torrent+detection")
    if not DAEMON.running():
        DAEMON.start(tunnel_bind_ip(), paused=False)
    try:
        res = tr.call("torrent-add", {"filename": magnet, "paused": False,
                                      "download-dir": TR_DOWNLOAD_DIR}, timeout=25)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200
    added = res.get("torrent-added") or res.get("torrent-duplicate")
    STATE.event("leak", f"torrent-address probe announced ({thash[:12]}...)")
    return jsonify(ok=True, thash=thash, id=added.get("id"), hash=added.get("hashString"))


@app.get("/api/leak/torrent/poll")
def api_leak_torrent_poll():
    thash = request.args.get("thash", "")
    if not re.fullmatch(r"[0-9a-f]{40}", thash):
        return jsonify(ok=False, error="bad thash"), 400
    res = torrent_probe_poll(thash)
    res["ok"] = True
    res["pia_pubip"] = pub_ip()
    if res.get("detected") and res.get("ip"):
        res["match"] = (res["ip"] == res["pia_pubip"])
    return jsonify(res)


@app.post("/api/leak/torrent/stop")
def api_leak_torrent_stop():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or ([body["id"]] if body.get("id") is not None else None)
    if not ids:
        return jsonify(ok=False, error="no ids"), 400
    try:
        tr.call("torrent-remove", {"ids": ids, "delete-local-data": True}, timeout=15)
    except TransmissionError as e:
        return jsonify(ok=False, error=str(e)), 200
    return jsonify(ok=True)


# ---- Galleries ------------------------------------------------------------
@app.post("/api/hitomi/launch")
def api_hitomi_launch():
    ok = GALLERIES.launch()
    return jsonify(ok=ok, **GALLERIES.status())


@app.post("/api/hitomi/send")
def api_hitomi_send():
    url = ((request.get_json(silent=True) or {}).get("url") or "").strip()
    if not url:
        return jsonify(ok=False, error="no URL"), 400
    # Magnets and .torrent files ALWAYS belong to the gated Transmission path.
    if url.lower().startswith("magnet:") or url.lower().endswith(".torrent"):
        return jsonify(ok=False, routed="torrents",
                       error="That is a torrent - it goes to the Torrents tab, "
                             "behind the VPN gate. Hitomi never sees magnets."), 200
    if urlparse(url).scheme not in ("http", "https"):
        return jsonify(ok=False, error="only http/https URLs"), 400
    ok, msg = GALLERIES.send_url(url)
    return jsonify(ok=ok, message=msg if ok else "", error="" if ok else msg)


# ---- Video ----------------------------------------------------------------
# The Video tab is DownloadFactory's own UI drawn in the Factory theme, but the
# ENGINE is still the untouched YT-DLP GUI worker - we proxy to its HTTP API
# rather than reimplementing it, so its cookie snapshot-isolation, signed-out
# detection and bundled JS runtime all still do the work.
#
# Two things force a proxy rather than direct browser calls:
#   * every real route is gated behind X-YTG-Token, a per-process uuid4 that
#     exists only inside the HTML the worker serves, and
#   * the worker sets no CORS headers, so a page on :8133 cannot read :7331.
_VMETA = {"port": None, "token": None, "qualities": {}, "browsers": {},
          "default_browser": "", "cookiefile": "", "folder": "", "ffmpeg": True}
_vmeta_lock = threading.Lock()
_RE_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean_err(msg):
    """yt-dlp colours its messages; the worker only strips the leading
    'ERROR:' so raw ANSI escapes reach us and would render as mojibake."""
    return _RE_ANSI.sub("", str(msg or "")).replace("ERROR:", "").strip()


def video_meta(force=False):
    """Scrape the worker's page for its token and its option maps.

    The quality list is built at the worker's import time and flips shape
    depending on whether ffmpeg was on PATH, so it is read from the page
    rather than hardcoded here.
    """
    with _vmeta_lock:
        if not force and _VMETA["token"] and _VMETA["port"] == VIDEO.port:
            return _VMETA
        try:
            html = requests.get(VIDEO.url, timeout=8).text
        except requests.RequestException:
            return _VMETA
        m = re.search(r"const\s+TOKEN\s*=\s*'([0-9a-fA-F]{32})'", html)
        if m:
            _VMETA["token"] = m.group(1)
            _VMETA["port"] = VIDEO.port
        for key, pat in (("qualities", r"const\s+QUALITIES\s*=\s*(\{.*?\});"),
                         ("browsers", r"const\s+BROWSERS\s*=\s*(\{.*?\});")):
            mm = re.search(pat, html, re.S)
            if mm:
                try:
                    _VMETA[key] = json.loads(mm.group(1))
                except ValueError:
                    pass
        mm = re.search(r"const\s+DEFAULT_BROWSER\s*=\s*'([^']*)'", html)
        if mm:
            _VMETA["default_browser"] = mm.group(1)
        mm = re.search(r'id="cookiefile"[^>]*\bvalue="([^"]*)"', html)
        if mm:
            _VMETA["cookiefile"] = (mm.group(1).replace("&amp;", "&")
                                    .replace("&lt;", "<").replace("&gt;", ">")
                                    .replace("&quot;", '"').replace("&#39;", "'"))
        _VMETA["ffmpeg"] = "ffmpeg missing" not in html
        return _VMETA


def _video_req(method, path, *, json_body=None, timeout=90, retry=True):
    """Call the worker with the session token, re-scraping once on a 403."""
    meta = video_meta()
    headers = {"X-YTG-Token": meta.get("token") or ""}
    r = requests.request(method, VIDEO.url.rstrip("/") + path,
                         json=json_body, headers=headers, timeout=timeout)
    if r.status_code == 403 and retry:
        video_meta(force=True)          # worker restarted -> new token
        return _video_req(method, path, json_body=json_body,
                          timeout=timeout, retry=False)
    return r


@app.post("/api/video/start")
def api_video_start():
    ok = VIDEO.start()
    if ok:
        video_meta(force=True)
    return jsonify(ok=ok, **VIDEO.status())


@app.get("/api/video/options")
def api_video_options():
    """Everything the native Video pane needs to draw itself."""
    st = VIDEO.status()
    if not st["up"]:
        return jsonify(up=False, error=st.get("error") or "worker not running")
    meta = video_meta()
    folder = meta.get("folder") or ""
    if not folder:
        try:
            folder = requests.get(VIDEO.url + "default-folder", timeout=6).json().get("path", "")
            meta["folder"] = folder
        except (requests.RequestException, ValueError):
            folder = ""
    return jsonify(up=True, version=st.get("version"),
                   qualities=meta.get("qualities") or {},
                   browsers=meta.get("browsers") or {},
                   default_browser=meta.get("default_browser") or "",
                   cookiefile=meta.get("cookiefile") or "",
                   folder=folder, ffmpeg=meta.get("ffmpeg", True))


# Cookie jars are credentials: they live under %LOCALAPPDATA%, never in the
# vault folder that syncs to other machines.
COOKIE_DIR = os.path.join(APPDATA, "cookies")
_YT_SESSION_KEYS = ("SID", "SAPISID", "__Secure-1PSID", "__Secure-1PAPISID", "LOGIN_INFO")
MAX_COOKIE_BYTES = 2 * 1024 * 1024


def _looks_like_cookiejar(text):
    """Netscape cookies.txt: a header line, or TSV rows of >= 6 fields."""
    if text.lstrip().lower().startswith("# netscape http cookie file"):
        return True
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if len(line.split("\t")) >= 6:
            return True
    return False


def _cookiejar_report(text):
    """What's actually in the jar, so the user learns it now and not after a
    failed download."""
    domains, has_yt_session = set(), False
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        domains.add(parts[0].lstrip("."))
        if parts[5].strip() in _YT_SESSION_KEYS:
            has_yt_session = True
    return {"domains": sorted(domains)[:8], "domain_count": len(domains),
            "youtube_session": has_yt_session}


def resolve_cookiefile(raw):
    """(abs_path, error). Resolves relative paths HERE rather than letting the
    worker resolve them against its own working directory - that is what
    produced 'Cookies file not found: ...\\YT-DLP GUI\\Downloads'."""
    cf = (raw or "").strip().strip('"').strip("'")
    if not cf:
        return "", ""
    p = os.path.expanduser(os.path.expandvars(cf))
    if not os.path.isabs(p):
        for base in (COOKIE_DIR, os.path.expanduser("~/Downloads"),
                     os.path.expanduser("~/Desktop"), os.path.expanduser("~")):
            cand = os.path.join(base, p)
            if os.path.isfile(cand):
                return os.path.abspath(cand), ""
        return "", (f"'{cf}' is a relative path and I couldn't find it in your "
                    f"Downloads, Desktop or home folder. Drop the file on the "
                    f"cookies box instead, or give a full path.")
    p = os.path.abspath(p)
    if not os.path.isfile(p):
        return "", f"Cookies file not found: {p}"
    return p, ""


@app.post("/api/video/cookies")
def api_video_cookies():
    """Take a dropped cookies.txt and materialise it somewhere the worker can
    read. The browser never exposes a real path for a dropped file, so the
    content is uploaded and written out here."""
    body = request.get_json(silent=True) or {}
    name = os.path.basename(body.get("name") or "cookies.txt")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "cookies.txt"
    if not name.lower().endswith(".txt"):
        name += ".txt"
    b64 = body.get("content") or ""
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        return jsonify(ok=False, error="could not read that file"), 400
    if len(raw) > MAX_COOKIE_BYTES:
        return jsonify(ok=False, error="that file is far too big to be a cookie jar"), 400
    text = raw.decode("utf-8", errors="replace")
    if not _looks_like_cookiejar(text):
        return jsonify(ok=False, error=(
            "That doesn't look like a Netscape cookies.txt — no header line and no "
            "tab-separated cookie rows. Export it with a cookies.txt browser "
            "extension rather than saving the page.")), 200

    os.makedirs(COOKIE_DIR, exist_ok=True)
    path = os.path.join(COOKIE_DIR, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    rep = _cookiejar_report(text)
    STATE.event("video", f"cookie jar stored ({name}, {rep['domain_count']} domain(s))")
    return jsonify(ok=True, path=path, name=name, **rep)


@app.post("/api/video/probe")
def api_video_probe():
    body = request.get_json(silent=True) or {}
    if not (body.get("url") or "").strip():
        return jsonify(error="No URL"), 400
    cookiefile, cerr = resolve_cookiefile(body.get("cookiefile"))
    if cerr:
        return jsonify(error=cerr), 200
    try:
        r = _video_req("POST", "/probe", json_body={
            "url": body.get("url", ""), "browser": body.get("browser", ""),
            "cookiefile": cookiefile}, timeout=90)
        d = r.json()
        if isinstance(d, dict) and d.get("error"):
            d["error"] = _clean_err(d["error"])
        return jsonify(d), (200 if r.status_code == 200 else r.status_code)
    except (requests.RequestException, ValueError) as e:
        return jsonify(error=f"worker unreachable: {e}"), 200


@app.post("/api/video/download")
def api_video_download():
    body = request.get_json(silent=True) or {}
    fmt = body.get("format") or ""
    if not (body.get("url") or "").strip() or not fmt:
        return jsonify(error="url and format required"), 400
    cookiefile, cerr = resolve_cookiefile(body.get("cookiefile"))
    if cerr:
        return jsonify(error=cerr), 200
    folder = (body.get("folder") or "").strip()
    if folder:
        folder = os.path.abspath(os.path.expanduser(os.path.expandvars(folder)))
        if not os.path.isdir(folder):
            return jsonify(error=f"Save-to folder does not exist: {folder}"), 200
    payload = {
        "url": body["url"].strip(),
        "format": fmt,
        "folder": folder,
        "browser": body.get("browser", ""),
        "cookiefile": cookiefile,
        # The worker never infers this - it must be computed exactly as the
        # original UI does, or MP3 silently downloads raw audio unconverted.
        "is_audio": ("bestaudio" in fmt and "bestvideo" not in fmt),
    }
    try:
        r = _video_req("POST", "/download", json_body=payload, timeout=30)
        return jsonify(r.json()), (200 if r.status_code == 200 else r.status_code)
    except (requests.RequestException, ValueError) as e:
        return jsonify(error=f"worker unreachable: {e}"), 200


@app.get("/api/video/events/<job_id>")
def api_video_events(job_id):
    """Byte-for-byte SSE passthrough from the worker.

    The upstream stream needs no token. It ends by simply closing after a
    terminal done/error frame, so the generator just runs dry - the browser
    side is responsible for closing its EventSource so it does not
    auto-reconnect into a 'Job not found'.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{8}", job_id):
        return ("bad job id", 400)

    def relay():
        try:
            with requests.get(f"{VIDEO.url}events/{job_id}",
                              stream=True, timeout=(10, 400)) as up:
                for chunk in up.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk
        except requests.RequestException as e:
            payload = json.dumps({"type": "error", "msg": f"worker stream lost: {e}"})
            yield f"data: {payload}\n\n".encode()

    return Response(relay(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/video/cancel/<job_id>")
def api_video_cancel(job_id):
    if not re.fullmatch(r"[0-9a-fA-F]{8}", job_id):
        return jsonify(error="bad job id"), 400
    try:
        r = _video_req("POST", f"/cancel/{job_id}", timeout=15)
        return jsonify(r.json())
    except (requests.RequestException, ValueError) as e:
        return jsonify(ok=False, error=str(e)), 200


@app.post("/api/video/open-folder")
def api_video_open_folder():
    body = request.get_json(silent=True) or {}
    try:
        r = _video_req("POST", "/open-folder",
                       json_body={"path": body.get("path") or ""}, timeout=15)
        return jsonify(r.json()), (200 if r.status_code == 200 else r.status_code)
    except (requests.RequestException, ValueError) as e:
        return jsonify(error=str(e)), 200


# ---- Shutdown -------------------------------------------------------------
@app.post("/api/shutdown")
def api_shutdown():
    threading.Thread(target=_shutdown_everything, daemon=True).start()
    return jsonify(ok=True)


def _shutdown_everything():
    time.sleep(0.4)
    shutdown_all()
    os._exit(0)


def shutdown_all():
    log("shutting down...")
    STOPPING.set()
    try:
        VIDEO.stop()
    except Exception as e:
        log(f"video stop: {e}")
    try:
        GALLERIES.stop()
    except Exception as e:
        log(f"galleries stop: {e}")
    try:
        DAEMON.stop()
    except Exception as e:
        log(f"transmission stop: {e}")
    log("clean.")


# ==========================================================================
# HTML  (injected below - single file, inline CSS/JS, no CDNs)
# ==========================================================================
# PALETTE - sampled from DownloadFactory Logo 0.1.png at full resolution
# (2000x2000 RGB, 263 distinct values), by pixel count, not by eye:
#
#   field  #d9d9d9  97.57% of pixels    (guide guessed #d5d5d5 - close)
#   green  #137f1f   1.13%  wordmark    (guide guessed #1f9d2b - 34.5 off)
#   blue   #1f80ff   0.80%  frame + V1.0 mark  (guide guessed #2f80ed)
#   red    #ff2828   0.05%  vertical hairline  (guide guessed #e23b3b)
#   ink    ABSENT - zero pixels have max(R,G,B) < 80. The logo is a flat
#          four-colour design with NO dark ink, so --ink below is CHOSEN,
#          not sampled, and is documented as such in the README.
#
# The three logo inks are bright, so on the #d9d9d9 field they clear AA as
# fills and rules but NOT as small text (green 3.6:1, blue 2.7:1, red 2.7:1).
# Each therefore has a darkened text-safe sibling (--green-ink / --blue-ink /
# --red-ink), all >= 4.9:1 on the field. Measured ratios sit beside each token.
#
# No CDN, no webfont: a leak-checking tool must not phone fonts.googleapis.com
# on every page load - that request would itself be an egress the user did not
# ask for. The sibling apps' token stacks are reused verbatim, so the fonts are
# used when installed and degrade to Segoe UI / Cascadia Mono when not.

PAGE = """<!DOCTYPE html>
<!-- DownloadFactory v__DF_VERSION__ - single file, inline CSS/JS, no CDNs. -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DownloadFactory v__DF_VERSION__</title>
<!-- Drawn glyph, not a downscale of the logo: at 16px the full mark collapses
     into a grey square with a blue edge. Frame + green dot + red tick reads. -->
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23d9d9d9'/%3E%3Crect x='4.5' y='5.5' width='23' height='21' fill='none' stroke='%231f80ff' stroke-width='2.5'/%3E%3Ccircle cx='17' cy='15' r='4.6' fill='%23137f1f'/%3E%3Crect x='9' y='9' width='1.8' height='13' fill='%23ff2828'/%3E%3C/svg%3E">
<style>
  :root {
    /* Sampled from DownloadFactory Logo 0.1.png - see the note above. */
    --paper: #d9d9d9;        /* logo field - page background */
    --card: #e6e6e6;         /* raised surface */
    --well: #efefef;         /* inputs, wells, log boxes */
    --line: #bcbcbc;         /* hairline borders */
    --line-strong: #9a9a9a;

    --ink: #16141a;          /* CHOSEN, not sampled - the logo has no ink */
    --ink-soft: #46434c;
    --muted: #6b6770;

    /* The logo inks. Signal only: green = safe/go, red = blocked/leak,
       blue = structure. If a screenshot looks colourful, it is wrong. */
    --green: #137f1f;
    --blue:  #1f80ff;
    --red:   #ff2828;
    /* Text-safe darkenings of the same hues (>= 4.9:1 on --paper). */
    --green-ink: #0d6416;
    --blue-ink:  #0a52b8;
    --red-ink:   #b21212;

    --mono: 'JetBrains Mono', 'Cascadia Mono', Consolas, monospace;
    --sans: 'Space Grotesk', 'Segoe UI', system-ui, sans-serif;
    --r: 2px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--paper); color: var(--ink); font-family: var(--sans);
         min-height: 100vh; -webkit-font-smoothing: antialiased; }
  .container { max-width: 1120px; margin: 0 auto; padding: 34px 24px 80px; }
  code, .mono { font-family: var(--mono); }
  .num { font-variant-numeric: tabular-nums; font-family: var(--mono); }
  button { font-family: var(--sans); cursor: pointer; }
  a { color: var(--blue-ink); }

  /* Header - a miniature of the logo: blue frame, green wordmark, red rule */
  header { display: flex; align-items: flex-end; gap: 18px; flex-wrap: wrap;
           margin-bottom: 20px; padding-bottom: 18px; border-bottom: 1px solid var(--line); }
  .logo-frame { border: 1.5px solid var(--blue); border-radius: var(--r);
                padding: 12px 18px 10px; flex-shrink: 0; }
  .logo-word { font-size: 24px; font-weight: 700; letter-spacing: 1px;
               color: var(--green-ink); line-height: 1; }
  .logo-sub { display: flex; align-items: center; gap: 7px; margin-top: 5px;
              font-size: 10px; font-weight: 600; letter-spacing: 4px; color: var(--green-ink); }
  .logo-rule { width: 1.5px; height: 12px; background: var(--red); flex-shrink: 0; }
  .tagline { font-size: 12px; color: var(--muted); letter-spacing: .4px; padding-bottom: 3px; }
  .version { font-family: var(--mono); font-size: 11px; color: var(--blue-ink);
             margin-left: auto; letter-spacing: 2px; padding-bottom: 3px; }

  /* Persistent VPN bar - the app's heartbeat, never hidden behind a tab */
  .vpnbar { display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
            background: var(--card); border: 1px solid var(--line);
            border-left: 3px solid var(--line-strong);
            border-radius: var(--r); padding: 11px 14px; margin-bottom: 18px; }
  .vpnbar.up { border-left-color: var(--green); }
  .vpnbar.down { border-left-color: var(--red); }
  .pill { display: inline-flex; align-items: center; gap: 8px; font-size: 13px;
          font-weight: 600; letter-spacing: .3px; padding: 6px 12px;
          border-radius: var(--r); color: #fff; white-space: nowrap; }
  .pill.up { background: var(--green); }
  .pill.down { background: var(--red-ink); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
  .vfact { font-size: 12px; color: var(--ink-soft); display: flex; gap: 6px; align-items: baseline; }
  .vfact b { font-weight: 600; color: var(--muted); font-size: 10px;
             letter-spacing: 1.2px; text-transform: uppercase; }
  .chip { font-size: 11px; font-weight: 700; letter-spacing: .6px; padding: 3px 7px;
          border-radius: var(--r); text-transform: uppercase; }
  .chip.ok { background: var(--green); color: #fff; }
  .chip.bad { background: var(--red-ink); color: #fff; }
  .chip.idle { background: var(--well); color: var(--muted); border: 1px solid var(--line); }
  .spacer { margin-left: auto; }

  /* Buttons */
  .btn { border: 1px solid var(--blue-ink); background: var(--blue-ink); color: #fff;
         font-size: 12px; font-weight: 600; letter-spacing: .5px; padding: 8px 14px;
         border-radius: var(--r); transition: filter .15s; }
  .btn:hover { filter: brightness(1.12); }
  .btn:disabled { opacity: .45; cursor: not-allowed; filter: none; }
  .btn.ghost { background: transparent; color: var(--blue-ink); }
  .btn.go { background: var(--green); border-color: var(--green); }
  .btn.danger { background: var(--red-ink); border-color: var(--red-ink); }
  .btn.small { padding: 5px 9px; font-size: 11px; }

  /* Tabs - flat underline */
  .tabs { display: flex; gap: 26px; margin-bottom: 22px; border-bottom: 1px solid var(--line); }
  .tab { background: none; border: none; padding: 10px 2px 12px; font-size: 13px;
         font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase;
         color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px;
         transition: color .15s, border-color .15s; }
  .tab:hover { color: var(--ink); }
  .tab.active { color: var(--ink); border-bottom-color: var(--blue); }
  .tab .badge { font-family: var(--mono); font-size: 10px; margin-left: 6px;
                color: var(--blue-ink); }
  .tab-content { display: none; }
  .tab-content.active { display: block; animation: fadeIn .22s ease-out; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); }
                      to { opacity: 1; transform: translateY(0); } }

  /* Cards, banners, wells */
  .card { background: var(--card); border: 1px solid var(--line);
          border-radius: var(--r); padding: 16px 18px; margin-bottom: 16px; }
  .card h3 { font-size: 12px; font-weight: 700; letter-spacing: 1.4px;
             text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }
  .banner { border: 1px solid var(--red-ink); border-left: 3px solid var(--red-ink);
            background: var(--card); border-radius: var(--r); padding: 14px 16px;
            margin-bottom: 16px; }
  .banner .bt { font-size: 14px; font-weight: 700; color: var(--red-ink); margin-bottom: 5px; }
  .banner .bd { font-size: 13px; color: var(--ink-soft); line-height: 1.5; }
  .banner.pulse { animation: pulseOnce .5s ease-out 1; }
  @keyframes pulseOnce { 0% { background: #f3d6d6; } 100% { background: var(--card); } }
  .note { font-size: 12px; color: var(--muted); line-height: 1.6; }

  input[type=text], textarea, input[type=url] {
    width: 100%; background: var(--well); border: 1px solid var(--line);
    border-radius: var(--r); padding: 9px 11px; font-family: var(--mono);
    font-size: 13px; color: var(--ink); }
  input:focus, textarea:focus { outline: 2px solid var(--blue); outline-offset: -1px; }
  .row { display: flex; gap: 10px; align-items: center; }
  .row > input { flex: 1; }

  .drop { border: 1px dashed var(--line-strong); border-radius: var(--r);
          padding: 14px; text-align: center; font-size: 12px; color: var(--muted);
          margin-top: 10px; }
  .drop.over { border-color: var(--blue); color: var(--blue-ink); }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-size: 10px; letter-spacing: 1.2px; text-transform: uppercase;
       color: var(--muted); font-weight: 700; padding: 6px 8px;
       border-bottom: 1px solid var(--line); }
  td { padding: 8px; border-bottom: 1px solid var(--line); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .bar { height: 4px; background: var(--well); border-radius: 2px; overflow: hidden;
         min-width: 90px; }
  .bar i { display: block; height: 100%; background: var(--green); }
  .name { font-weight: 600; max-width: 320px; overflow: hidden;
          text-overflow: ellipsis; white-space: nowrap; }
  .st { font-size: 11px; letter-spacing: .4px; color: var(--muted); text-transform: uppercase; }
  .st.dl { color: var(--green-ink); font-weight: 700; }
  .st.err { color: var(--red-ink); font-weight: 700; }

  iframe { width: 100%; height: 74vh; border: 1px solid var(--line);
           border-radius: var(--r); background: var(--well); }

  /* Video pane — native controls, same flat language as the rest */
  .opt { display: flex; align-items: center; gap: 12px; margin: 14px 0 8px; }
  .optlabel { font-size: 10px; font-weight: 700; letter-spacing: 1.2px;
              text-transform: uppercase; color: var(--muted); flex-shrink: 0; }
  .pills { display: flex; gap: 8px; flex-wrap: wrap; }
  .pillbtn { background: var(--well); border: 1px solid var(--line); color: var(--ink-soft);
             font-size: 12px; font-weight: 600; padding: 6px 13px; border-radius: var(--r);
             transition: border-color .15s, color .15s; }
  .pillbtn:hover { color: var(--ink); border-color: var(--line-strong); }
  .pillbtn.on { border-color: var(--blue); color: var(--blue-ink); font-weight: 700; }
  .preview { display: flex; gap: 14px; align-items: flex-start; margin-top: 12px;
             padding: 12px; background: var(--well); border: 1px solid var(--line);
             border-radius: var(--r); }
  .preview img { width: 128px; height: 72px; object-fit: cover; border-radius: var(--r);
                 border: 1px solid var(--line); flex-shrink: 0; background: var(--card); }
  .preview .pt { font-weight: 600; font-size: 14px; line-height: 1.35; }
  .preview .pm { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .job { border: 1px solid var(--line); border-radius: var(--r); padding: 12px 14px;
         margin-bottom: 10px; background: var(--well); }
  .job.done { border-left: 3px solid var(--green); }
  .job.err  { border-left: 3px solid var(--red-ink); }
  .job .jt { font-weight: 600; font-size: 13px; margin-bottom: 7px; word-break: break-word; }
  .job .jm { font-size: 11.5px; color: var(--muted); font-family: var(--mono);
             margin-top: 6px; display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
  .job .bar { min-width: 100%; height: 5px; }
  .linky { color: var(--blue-ink); text-decoration: underline; cursor: pointer; }
  /* flex-wrap + min-width:0 are load-bearing: a long cookie path is one
     unbreakable flex item and pushed the whole page into horizontal scroll */
  .cookiechip { display: flex; align-items: center; gap: 10px; margin-top: 9px;
                flex-wrap: wrap; font-size: 12px; padding: 8px 11px;
                border-radius: var(--r); background: var(--well);
                border: 1px solid var(--line); max-width: 100%; }
  .cookiechip.ok  { border-left: 3px solid var(--green); }
  .cookiechip.warn{ border-left: 3px solid var(--red-ink); }
  .cookiechip .cf { font-family: var(--mono); font-size: 11.5px; word-break: break-all;
                    min-width: 0; flex: 1 1 240px; color: var(--muted); }
  .log { background: var(--well); border: 1px solid var(--line); border-radius: var(--r);
         padding: 10px 12px; font-family: var(--mono); font-size: 11.5px;
         color: var(--ink-soft); max-height: 190px; overflow-y: auto; line-height: 1.65; }
  .log b { color: var(--muted); font-weight: 400; }
  footer { margin-top: 30px; padding-top: 14px; border-top: 1px solid var(--line);
           font-size: 11px; color: var(--muted); font-family: var(--mono);
           display: flex; gap: 16px; flex-wrap: wrap; }
  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 5px 12px; font-size: 12.5px; }
  .kv b { color: var(--muted); font-weight: 600; font-size: 10px;
          letter-spacing: 1.1px; text-transform: uppercase; padding-top: 2px; }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="logo-frame">
      <div class="logo-word">DOWNLOAD</div>
      <div class="logo-sub"><span class="logo-rule"></span><span>FACTORY</span></div>
    </div>
    <div class="tagline">four downloaders, one console &mdash; torrents behind a hard VPN gate</div>
    <div class="version">V__DF_VERSION__</div>
  </header>

  <!-- Persistent VPN status bar -->
  <div class="vpnbar" id="vpnbar">
    <span class="pill down" id="vpnpill"><span class="dot"></span><span id="vpntext">checking...</span></span>
    <div class="vfact"><b>egress</b><span class="num" id="egress">-</span><span class="chip idle" id="egresschip">unchecked</span></div>
    <div class="vfact"><b>tunnel</b><span class="num" id="tunnel">-</span></div>
    <div class="vfact"><b>bound</b><span class="num" id="bound">-</span></div>
    <div class="vfact"><b>pf</b><span class="num" id="pf">-</span></div>
    <div class="spacer"></div>
    <button class="btn go" id="btnconnect">Connect</button>
    <button class="btn ghost" id="btndisconnect">Disconnect</button>
  </div>

  <div class="tabs">
    <button class="tab" data-tab="video">Video</button>
    <button class="tab active" data-tab="torrents">Torrents<span class="badge" id="tcount"></span></button>
    <button class="tab" data-tab="galleries">Galleries</button>
    <button class="tab" data-tab="leak">VPN &amp; Leak</button>
  </div>

  <!-- VIDEO — DownloadFactory's own UI; the YT-DLP GUI worker is the engine -->
  <div class="tab-content" id="tab-video">
    <div id="videodown" style="display:none"></div>
    <div id="videopane" style="display:none">
      <div class="card">
        <h3>Add a video</h3>
        <div class="row">
          <input type="text" id="vurl" placeholder="Paste a video URL — YouTube, X, Instagram, Reddit…">
          <button class="btn ghost" id="vpaste">Paste</button>
        </div>
        <div id="vpreview"></div>

        <div class="opt"><span class="optlabel">Quality</span><div class="pills" id="vquality"></div></div>
        <div class="opt"><span class="optlabel">Cookies</span><div class="pills" id="vcookies"></div></div>
        <div class="drop" id="vcookiedrop">
          <b>Drop a cookies.txt here</b> — or <span class="linky" id="vcookiepick">choose a file</span>
          <input type="file" id="vcookieinput" accept=".txt,text/plain" style="display:none">
        </div>
        <input type="text" id="vcookiefile" placeholder="…or type a path to a cookies.txt file (overrides the browser)">
        <div id="vcookiestatus"></div>
        <p class="note">Signs requests in to beat YouTube's “confirm you're not a bot”. A
        <b>cookies.txt</b> file is the reliable route — it works with the browser open, and this
        box auto-fills if one is found. The browser picker needs that browser <b>fully closed</b>.
        A dropped jar is copied to <code>%LOCALAPPDATA%\\DownloadFactory\\cookies\\</code> —
        never into the vault.</p>

        <div class="opt"><span class="optlabel">Save to</span></div>
        <input type="text" id="vfolder" placeholder="download folder">

        <div style="margin-top:14px">
          <button class="btn go" id="vgo" style="width:100%;padding:11px">Download</button>
        </div>
        <div class="note" id="vmsg" style="margin-top:8px"></div>
      </div>

      <div class="card" id="vjobscard" style="display:none">
        <h3>Downloads
          <button class="btn small ghost" id="vclear"
                  style="float:right;margin-top:-4px">Clear finished</button>
        </h3>
        <div id="vjobs"></div>
      </div>
      <div class="note mono" id="vfooter"></div>
    </div>
  </div>

  <!-- TORRENTS -->
  <div class="tab-content active" id="tab-torrents">
    <div id="gatearea"></div>
    <div class="card" id="trstatus" style="display:none"></div>
    <div class="card">
      <h3>Active torrents</h3>
      <div id="trlist"><div class="note">loading...</div></div>
    </div>
  </div>

  <!-- GALLERIES -->
  <div class="tab-content" id="tab-galleries">
    <div id="galleryarea"></div>
  </div>

  <!-- VPN & LEAK -->
  <div class="tab-content" id="tab-leak">
    <div class="card">
      <h3>Connection</h3>
      <div class="kv">
        <b>state</b><span class="num" id="lk-state">-</span>
        <b>region</b><span class="num" id="lk-region">-</span>
        <b>tunnel ip</b><span class="num" id="lk-vpnip">-</span>
        <b>public ip</b><span class="num" id="lk-pubip">-</span>
        <b>port forward</b><span class="num" id="lk-pf">-</span>
        <b>peer bind</b><span class="num" id="lk-bound">-</span>
        <b>watchdog</b><span class="num" id="lk-mon">-</span>
      </div>
      <p class="note" style="margin-top:10px">PIA's kill switch and split tunnel are not scriptable &mdash;
      set them once in the PIA app (Settings &rarr; Privacy). See the README.</p>
    </div>

    <div class="card">
      <h3>Egress &amp; DNS</h3>
      <div class="row">
        <button class="btn" id="btnleakip">Run IP check</button>
        <button class="btn" id="btnleakdns">Run DNS-leak check</button>
      </div>
      <div id="leakout" class="log" style="margin-top:12px">no check run yet.</div>
    </div>

    <div class="card">
      <h3>Torrent address verification</h3>
      <p class="note">Announces a throwaway hash to ipleak.net's tracker through the
      <b>same gated path</b> as any torrent, then compares the IP the tracker saw against
      PIA's public IP. With the VPN off this is refused, so nothing ever announces.</p>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="btntorrentprobe">Verify torrent IP</button>
        <button class="btn ghost small" id="btnprobestop" style="display:none">Stop probe</button>
      </div>
      <div id="probeout" class="log" style="margin-top:12px">not run.</div>
    </div>
  </div>

  <div class="card">
    <h3>Activity</h3>
    <div class="log" id="events"></div>
  </div>

  <footer>
    <span>DownloadFactory v__DF_VERSION__</span>
    <span id="f-shell">shell 127.0.0.1</span>
    <span id="f-tr">transmission -</span>
    <span id="f-video">video -</span>
    <span id="f-gal">galleries -</span>
  </footer>
</div>

<script>
const $ = (id) => document.getElementById(id);
let STATE = null, probe = null, bannerShown = false;

/* ---- tabs ---- */
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('tab-' + t.dataset.tab).classList.add('active');
  if (t.dataset.tab === 'video') mountVideo();
  if (t.dataset.tab === 'galleries') mountGalleries();
});

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stripAnsi = (s) => String(s == null ? '' : s)
  .replace(/\\u001b\\[[0-9;]*m/g, '').replace(/\\x1b\\[[0-9;]*m/g, '')
  .replace(/ERROR:/g, '').trim();

async function jget(u) { const r = await fetch(u); return r.json(); }
async function jpost(u, b) {
  const r = await fetch(u, {method: 'POST', headers: {'Content-Type': 'application/json'},
                           body: JSON.stringify(b || {})});
  return r.json();
}

/* ---- state poll ---- */
async function tick() {
  try { STATE = await jget('/api/state'); render(); } catch (e) {}
}

function render() {
  const s = STATE; if (!s) return;
  const up = s.vpn === 'Connected' && !!s.vpn_ip;
  $('vpnbar').className = 'vpnbar ' + (up ? 'up' : 'down');
  $('vpnpill').className = 'pill ' + (up ? 'up' : 'down');
  $('vpntext').textContent = up ? ('VPN Connected — ' + (s.region || '?'))
                                : ('VPN ' + (s.vpn === '__init__' ? 'checking' : s.vpn));
  $('tunnel').textContent = s.vpn_ip || '—';
  $('bound').textContent = s.bound_ip || '—';
  $('pf').textContent = (typeof s.portforward === 'number') ? s.portforward : (s.portforward || '—');

  const lk = s.last_leak;
  if (lk && lk.ip) {
    $('egress').textContent = lk.ip + (lk.isp ? '  ' + lk.isp : '');
    /* Only call it a LEAK when the VPN claims to be up. With PIA off this is
       simply the real IP, and crying leak there would train the user to
       ignore the one colour that has to mean something. */
    const v = lk.verdict || (lk.matches_vpn ? 'vpn' : (up ? 'leak' : 'novpn'));
    const chipmap = {vpn:  ['chip ok',   'via VPN'],
                     leak: ['chip bad',  'LEAK'],
                     novpn:['chip idle', 'no VPN — real IP'],
                     unknown:['chip idle','check failed']};
    const [cc, ct] = chipmap[v] || chipmap.unknown;
    $('egresschip').className = cc;
    $('egresschip').textContent = ct;
    $('egresschip').title = lk.detail || '';
  } else {
    $('egress').textContent = '—';
    $('egresschip').className = 'chip idle';
    $('egresschip').textContent = 'unchecked';
  }

  /* gate area */
  const g = $('gatearea');
  if (!up) {
    if (!bannerShown) { bannerShown = true; }
    g.innerHTML = '<div class="banner pulse"><div class="bt">VPN required</div>' +
      '<div class="bd">' + esc(s.banner || 'Torrents are blocked until PIA is connected.') +
      ' The server refuses every add while the VPN is down &mdash; the button below is just a courtesy.' +
      '</div><div style="margin-top:11px"><button class="btn go" onclick="doConnect()">Connect PIA</button></div></div>';
  } else {
    bannerShown = false;
    if (!g.dataset.addbox) {
      g.dataset.addbox = '1';
      g.innerHTML = '<div class="card"><h3>Add a torrent</h3>' +
        '<div class="row"><input type="text" id="magnet" placeholder="magnet:?xt=urn:btih:...">' +
        '<button class="btn" id="btnadd">Add</button></div>' +
        '<div class="drop" id="drop">or drop a .torrent file here</div>' +
        '<div class="note" id="addmsg" style="margin-top:8px"></div></div>';
      wireAdd();
    }
  }
  if (!up) g.dataset.addbox = '';

  /* transmission health */
  const tr = s.transmission, box = $('trstatus');
  if (!tr.installed || tr.state === 'error') {
    box.style.display = '';
    box.innerHTML = '<h3>Transmission</h3><div class="note">' + esc(tr.error || 'not installed') +
      (tr.installed ? '' : '<br><br><code>' + esc(tr.install_hint) + '</code>') +
      '</div><div style="margin-top:10px"><button class="btn small" onclick="jpost(\\'/api/transmission/start\\').then(tick)">Retry</button></div>';
  } else { box.style.display = 'none'; }

  /* leak tab facts */
  $('lk-state').textContent = s.vpn;
  $('lk-region').textContent = s.region || '—';
  $('lk-vpnip').textContent = s.vpn_ip || '—';
  $('lk-pubip').textContent = s.pub_ip || '—';
  $('lk-pf').textContent = (typeof s.portforward === 'number')
      ? s.portforward + ' (forwarded)'
      : (s.portforward || '—') + (s.portforward === 'Unavailable'
          ? ' — US regions never forward; pick a non-US PIA region' : '');
  $('lk-bound').textContent = s.bound_ip || '—';
  $('lk-mon').textContent = s.monitor_alive ? 'monitor alive' : 'monitor down (treated as not connected)';

  /* events */
  $('events').innerHTML = (s.events || []).map(e =>
      '<div><b>' + esc(e.t) + '</b> [' + esc(e.kind) + '] ' + esc(e.msg) + '</div>').join('')
      || '<div class="note">nothing yet.</div>';

  $('f-tr').textContent = 'transmission ' + tr.state;
  $('f-video').textContent = 'video ' + (s.workers.video.up ? 'up v' + (s.workers.video.version || '?') : 'down');
  $('f-gal').textContent = 'galleries ' + (s.workers.galleries.up ? 'up :' + s.workers.galleries.api_port : 'off');
}

/* ---- VPN controls ---- */
async function doConnect() {
  const r = await jpost('/api/vpn/connect');
  if (!r.ok && r.error) alert(r.error);
  setTimeout(tick, 900);
}
$('btnconnect').onclick = doConnect;
$('btndisconnect').onclick = async () => { await jpost('/api/vpn/disconnect'); setTimeout(tick, 900); };

/* ---- torrents ---- */
function wireAdd() {
  const add = async (body) => {
    const r = await jpost('/api/torrent/add', body);
    const m = $('addmsg');
    if (r.blocked) { m.innerHTML = '<b style="color:var(--red-ink)">BLOCKED &mdash; ' + esc(r.reason) + '</b>'; }
    else if (!r.ok) { m.innerHTML = '<b style="color:var(--red-ink)">' + esc(r.error) + '</b>'; }
    else { m.textContent = (r.duplicate ? 'already had ' : 'added ') + r.name; $('magnet').value = ''; }
    loadTorrents();
  };
  $('btnadd').onclick = () => { const v = $('magnet').value.trim(); if (v) add({magnet: v}); };
  $('magnet').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnadd').click(); });
  const d = $('drop');
  d.ondragover = e => { e.preventDefault(); d.classList.add('over'); };
  d.ondragleave = () => d.classList.remove('over');
  d.ondrop = e => {
    e.preventDefault(); d.classList.remove('over');
    const f = e.dataTransfer.files[0]; if (!f) return;
    const fr = new FileReader();
    fr.onload = () => add({metainfo: fr.result.split(',')[1]});
    fr.readAsDataURL(f);
  };
}

async function loadTorrents() {
  let r; try { r = await jget('/api/torrent/list'); } catch (e) { return; }
  const box = $('trlist');
  $('tcount').textContent = (r.torrents && r.torrents.length) ? r.torrents.length : '';
  if (!r.daemon) { box.innerHTML = '<div class="note">Transmission is not running.</div>'; return; }
  if (!r.torrents.length) { box.innerHTML = '<div class="note">no torrents.</div>'; return; }
  box.innerHTML = '<table><tr><th>name</th><th>status</th><th>progress</th><th>down</th>' +
    '<th>up</th><th>eta</th><th>size</th><th></th></tr>' +
    r.torrents.map(t => {
      const bad = t.error && t.error !== 0;
      const cls = bad ? 'st err' : (t.status === 4 ? 'st dl' : 'st');
      const label = bad ? 'error' : t.statusLabel;
      return '<tr><td class="name" title="' + esc(t.name) + '">' + esc(t.name) + '</td>' +
        '<td><span class="' + cls + '">' + esc(label) + '</span>' +
        (bad ? '<div class="note" style="font-size:11px">' + esc(t.errorString) +
               ' &mdash; if rates are 0 right after a VPN change, this is the peer bind failing (safe).</div>' : '') + '</td>' +
        '<td><div class="bar"><i style="width:' + t.percent + '%"></i></div>' +
        '<span class="num" style="font-size:11px">' + t.percent + '%</span></td>' +
        '<td class="num">' + esc(t.down) + '</td><td class="num">' + esc(t.up) + '</td>' +
        '<td class="num">' + esc(t.eta) + '</td><td class="num">' + esc(t.size) + '</td>' +
        '<td style="white-space:nowrap">' +
        (t.status === 0 ? '<button class="btn small go" onclick="trAct(\\'start\\',' + t.id + ')">Start</button>'
                        : '<button class="btn small ghost" onclick="trAct(\\'stop\\',' + t.id + ')">Stop</button>') +
        ' <button class="btn small danger" onclick="trRemove(' + t.id + ')">Remove</button></td></tr>';
    }).join('') + '</table>';
}

async function trAct(what, id) {
  const r = await jpost('/api/torrent/' + what, {ids: [id]});
  if (r.blocked) alert('BLOCKED - ' + r.reason);
  loadTorrents();
}
async function trRemove(id) {
  const del = confirm('Remove this torrent?\\n\\nOK = also delete downloaded data.\\nCancel = keep the files.');
  await jpost('/api/torrent/remove', {ids: [id], deleteData: del});
  loadTorrents();
}

/* ---- Video: native pane over the yt-dlp worker ---- */
let VOPTS = null, vfmt = null, vbrowser = null, vjobs = {}, vprobeSeq = 0, vprobeTimer = null;

async function mountVideo() {
  const up = STATE && STATE.workers.video.up;
  $('videopane').style.display = up ? '' : 'none';
  $('videodown').style.display = up ? 'none' : '';
  if (!up) {
    VOPTS = null;
    $('videodown').innerHTML = '<div class="card"><h3>Video worker</h3><div class="note">' +
      esc((STATE && STATE.workers.video.error) || 'The YT-DLP GUI worker is not running.') +
      '</div><div style="margin-top:10px"><button class="btn" onclick="retryVideo(this)">Start worker</button></div></div>';
    return;
  }
  if (VOPTS) {
    // the folder can end up blank if the worker was still booting on the
    // first mount - refill it rather than silently sending an empty path
    if (!$('vfolder').value) $('vfolder').value = VOPTS.folder || '';
    return;
  }
  const o = await jget('/api/video/options');
  if (!o.up) { VOPTS = null; return; }
  VOPTS = o;
  /* Quality + cookie options come from the worker because its list flips
     shape depending on whether ffmpeg was present when it started. */
  const q = $('vquality'); q.innerHTML = '';
  Object.entries(o.qualities || {}).forEach(([label, val], i) => {
    const b = document.createElement('button');
    b.className = 'pillbtn' + (i === 0 ? ' on' : '');
    b.textContent = label;
    if (i === 0) vfmt = val;
    b.onclick = () => { vfmt = val;
      q.querySelectorAll('.pillbtn').forEach(x => x.classList.remove('on'));
      b.classList.add('on'); };
    q.appendChild(b);
  });
  const c = $('vcookies'); c.innerHTML = '';
  Object.entries(o.browsers || {}).forEach(([label, val]) => {
    const b = document.createElement('button');
    const isDef = val === (o.default_browser || '');
    b.className = 'pillbtn' + (isDef ? ' on' : '');
    b.textContent = label;
    if (isDef) vbrowser = val;
    b.onclick = () => { vbrowser = val;
      c.querySelectorAll('.pillbtn').forEach(x => x.classList.remove('on'));
      b.classList.add('on'); };
    c.appendChild(b);
  });
  if (vbrowser === null) vbrowser = o.default_browser || '';
  $('vcookiefile').value = o.cookiefile || '';
  $('vfolder').value = o.folder || '';
  $('vfooter').textContent = 'engine: yt-dlp-gui v' + (o.version || '?') +
    ' on 127.0.0.1:' + (STATE.workers.video.port) +
    (o.ffmpeg ? ' · ffmpeg ready' : ' · ffmpeg MISSING (fewer qualities, no mp3)');
}
async function retryVideo(b) { b.disabled = true; b.textContent = 'starting...';
  await jpost('/api/video/start'); await tick(); await mountVideo(); }

/* ---- cookies: drag-and-drop ---- */
/* A dropped file has no real path in the browser, so the bytes are uploaded
   and written out under %LOCALAPPDATA% where the worker can read them. */
async function acceptCookieFile(file) {
  const st = $('vcookiestatus');
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    st.innerHTML = '<div class="cookiechip warn">That file is far too big to be a cookie jar.</div>';
    return;
  }
  st.innerHTML = '<div class="cookiechip">reading ' + esc(file.name) + '…</div>';
  const b64 = await new Promise(res => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result.split(',')[1]);
    fr.readAsDataURL(file);
  });
  const r = await jpost('/api/video/cookies', {name: file.name, content: b64});
  if (!r.ok) {
    st.innerHTML = '<div class="cookiechip warn">' + esc(r.error || 'could not use that file') + '</div>';
    return;
  }
  $('vcookiefile').value = r.path;
  /* Selecting a file means the browser picker must not also apply. */
  vbrowser = '';
  const cp = $('vcookies');
  cp.querySelectorAll('.pillbtn').forEach(x =>
    x.classList.toggle('on', x.textContent === 'None'));
  const good = r.youtube_session;
  st.innerHTML = '<div class="cookiechip ' + (good ? 'ok' : 'warn') + '">' +
    '<span>' + (good ? '✓ signed-in YouTube session found'
                     : '⚠ no signed-in YouTube session in this jar') + '</span>' +
    '<span class="note">' + r.domain_count + ' domain(s)</span>' +
    '<span class="cf">' + esc(r.path) + '</span>' +
    '<button class="btn small ghost" onclick="clearCookieFile()">Clear</button></div>' +
    (good ? '' : '<p class="note">YouTube will likely still ask you to confirm you are not a bot. ' +
      'Re-export from a <b>private window</b> while signed in to youtube.com.</p>');
}
function clearCookieFile() {
  $('vcookiefile').value = '';
  $('vcookiestatus').innerHTML = '';
}
const vcd = $('vcookiedrop');
vcd.ondragover = e => { e.preventDefault(); vcd.classList.add('over'); };
vcd.ondragleave = () => vcd.classList.remove('over');
vcd.ondrop = e => {
  e.preventDefault(); vcd.classList.remove('over');
  acceptCookieFile(e.dataTransfer.files[0]);
};
$('vcookiepick').onclick = () => $('vcookieinput').click();
$('vcookieinput').onchange = e => acceptCookieFile(e.target.files[0]);
/* Dropping a file anywhere else must not navigate the page away — that is
   what turned an earlier drag attempt into a bare filename in the text box. */
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', e => e.preventDefault());

$('vpaste').onclick = async () => {
  try { $('vurl').value = await navigator.clipboard.readText(); vprobe(); }
  catch (e) { $('vmsg').textContent = 'clipboard blocked — paste with Ctrl+V'; }
};
$('vurl').addEventListener('input', () => {
  clearTimeout(vprobeTimer); vprobeTimer = setTimeout(vprobe, 500);
});
$('vurl').addEventListener('keydown', e => { if (e.key === 'Enter') $('vgo').click(); });

async function vprobe() {
  const u = $('vurl').value.trim();
  const box = $('vpreview');
  if (!u) { box.innerHTML = ''; return; }
  const seq = ++vprobeSeq;
  box.innerHTML = '<div class="note" style="margin-top:10px">reading…</div>';
  const d = await jpost('/api/video/probe', {url: u, browser: vbrowser || '',
                                             cookiefile: $('vcookiefile').value.trim()});
  if (seq !== vprobeSeq) return;              // a newer probe won
  if (d.error) {
    box.innerHTML = '<div class="preview"><div><div class="pt" style="color:var(--red-ink)">' +
      esc(d.error) + '</div></div></div>';
    return;
  }
  box.innerHTML = '<div class="preview">' +
    (d.thumbnail ? '<img src="' + esc(d.thumbnail) + '" alt="">' : '') +
    '<div><div class="pt">' + esc(d.title) + '</div><div class="pm">' +
    esc([d.uploader, d.duration, d.site].filter(Boolean).join(' · ')) + '</div></div></div>';
}

$('vgo').onclick = async () => {
  const u = $('vurl').value.trim();
  if (!u) { $('vmsg').textContent = 'paste a URL first'; return; }
  if (!vfmt) { $('vmsg').textContent = 'pick a quality'; return; }
  $('vmsg').textContent = '';
  const r = await jpost('/api/video/download', {
    url: u, format: vfmt, folder: $('vfolder').value.trim(),
    browser: vbrowser || '', cookiefile: $('vcookiefile').value.trim()});
  if (r.error || !r.job_id) { $('vmsg').innerHTML =
      '<b style="color:var(--red-ink)">' + esc(r.error || 'no job id') + '</b>'; return; }
  $('vurl').value = ''; $('vpreview').innerHTML = '';
  startJob(r.job_id, u);
};

function startJob(id, url) {
  $('vjobscard').style.display = '';
  const el = document.createElement('div');
  el.className = 'job'; el.id = 'job-' + id;
  el.innerHTML = '<div class="jt">' + esc(url) + '</div>' +
    '<div class="bar"><i style="width:0%"></i></div>' +
    '<div class="jm"><span class="stat">starting…</span>' +
    '<button class="btn small ghost" data-act="cancel">Cancel</button></div>';
  $('vjobs').prepend(el);
  const job = {id: id, el: el, es: null, finished: false, folder: ''};
  vjobs[id] = job;
  el.querySelector('[data-act=cancel]').onclick = () => cancelJob(id);

  /* The worker closes the stream after its terminal frame; EventSource would
     auto-reconnect into a "Job not found", so we close it ourselves. */
  const es = new EventSource('/api/video/events/' + id);
  job.es = es;
  es.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.type === 'ping') return;
    if (m.type === 'meta') {
      el.querySelector('.jt').textContent = m.title +
        (m.uploader ? '  —  ' + m.uploader : '');
    } else if (m.type === 'progress') {
      if (m.pct != null) el.querySelector('.bar i').style.width = m.pct + '%';
      el.querySelector('.stat').textContent = [
        m.pct != null ? m.pct.toFixed(1) + '%' : '', m.speed,
        m.eta ? 'ETA ' + m.eta : '', m.size].filter(Boolean).join('   ');
    } else if (m.type === 'status') {
      if (m.pct != null) el.querySelector('.bar i').style.width = m.pct + '%';
      el.querySelector('.stat').textContent = m.msg;
    } else if (m.type === 'done') {
      job.folder = m.folder || '';
      endJob(job, true, m.file || 'finished');
    } else if (m.type === 'error') {
      /* the SSE relay is a byte passthrough, so yt-dlp's ANSI colouring
         survives to here - strip it client-side as well */
      endJob(job, false, stripAnsi(m.msg) || 'failed');
    }
  };
  es.onerror = () => {
    if (!job.finished && job.es && job.es.readyState === EventSource.CLOSED)
      endJob(job, false, 'connection lost');
  };
}

function endJob(job, ok, text) {
  if (job.finished) return;
  job.finished = true;
  if (job.es) { job.es.close(); job.es = null; }
  const el = job.el;
  el.className = 'job ' + (ok ? 'done' : 'err');
  el.querySelector('.bar i').style.width = ok ? '100%' : el.querySelector('.bar i').style.width;
  if (ok) el.querySelector('.jt').textContent = text;
  el.querySelector('.jm').innerHTML =
    '<span class="stat" style="color:' + (ok ? 'var(--green-ink)' : 'var(--red-ink)') +
    ';font-weight:700">' + esc(ok ? 'done' : text) + '</span>' +
    (ok && job.folder ? ' <button class="btn small ghost" onclick="openFolder(\\'' +
      job.folder.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'") + '\\')">Open folder</button>' : '');
}

$('vclear').onclick = () => {
  Object.values(vjobs).filter(j => j.finished).forEach(j => {
    j.el.remove(); delete vjobs[j.id];
  });
  if (!Object.keys(vjobs).length) $('vjobscard').style.display = 'none';
};

async function cancelJob(id) {
  const job = vjobs[id]; if (!job) return;
  job.el.querySelector('.stat').textContent = 'cancelling…';
  await jpost('/api/video/cancel/' + id);   /* the Cancelled. frame confirms it */
}
async function openFolder(p) { await jpost('/api/video/open-folder', {path: p}); }

function mountGalleries() {
  const s = STATE; if (!s) return;
  const g = s.workers.galleries, box = $('galleryarea');
  const sender = '<div class="card"><h3>Send a URL to Hitomi</h3>' +
    '<div class="row"><input type="text" id="hurl" placeholder="https://...">' +
    '<button class="btn" onclick="hsend()">Send</button></div>' +
    '<div class="note" id="hmsg" style="margin-top:8px">Magnets and .torrent files are never accepted here &mdash; ' +
    'they are routed to the Torrents tab so they stay behind the VPN gate.</div></div>';
  if (g.up) {
    box.innerHTML = sender + '<iframe src="' + g.url + '" title="Hitomi Downloader"></iframe>';
  } else if (g.have_exe) {
    box.innerHTML = sender + '<div class="card"><h3>Hitomi</h3><div class="note">' + esc(g.error) +
      '</div><div style="margin-top:10px"><button class="btn" onclick="hlaunch(this)">Launch Hitomi</button></div></div>';
  } else {
    box.innerHTML = '<div class="card"><h3>Hitomi Downloader not configured</h3>' +
      '<div class="note">' + esc(g.error) + '</div></div>';
  }
}
async function hlaunch(b) { b.disabled = true; b.textContent = 'launching...';
  await jpost('/api/hitomi/launch'); await tick(); mountGalleries(); }
async function hsend() {
  const u = $('hurl').value.trim(); if (!u) return;
  const r = await jpost('/api/hitomi/send', {url: u});
  $('hmsg').innerHTML = r.ok ? esc(r.message)
    : '<b style="color:var(--red-ink)">' + esc(r.error) + '</b>';
  if (r.ok) $('hurl').value = '';
}

/* ---- leak checks ---- */
$('btnleakip').onclick = async (e) => {
  e.target.disabled = true; $('leakout').textContent = 'checking egress...';
  const r = await jget('/api/leak/ip');
  const col = {vpn: 'var(--green-ink)', leak: 'var(--red-ink)',
               novpn: 'var(--muted)', unknown: 'var(--muted)'}[r.verdict] || 'var(--muted)';
  const head = {vpn: 'VPN HOLDING', leak: 'LEAK', novpn: 'NO VPN',
                unknown: 'INCONCLUSIVE'}[r.verdict] || '';
  $('leakout').innerHTML =
    '<div><b>' + esc(r.checked) + '</b> egress via ' + esc(r.source) + '</div>' +
    '<div>ip        ' + esc(r.ip || '?') + '</div>' +
    '<div>isp       ' + esc(r.isp || '?') + '  (AS' + esc(r.asn || '?') + ')</div>' +
    '<div>where     ' + esc([r.city, r.country].filter(Boolean).join(', ') || '?') + '</div>' +
    '<div>piactl    ' + esc(r.pia_pubip || 'Unknown') + '  <span class="note">(advisory only)</span></div>' +
    (r.baseline && r.baseline.isp
      ? '<div>your isp  ' + esc(r.baseline.isp) + ' (AS' + esc(r.baseline.asn) + ')</div>' : '') +
    '<div style="color:' + col + ';font-weight:700;margin-top:4px">' + esc(head) + '</div>' +
    '<div class="note">' + esc(r.detail || '') + '</div>' +
    (r.error ? '<div>err ' + esc(r.error) + '</div>' : '');
  e.target.disabled = false; tick();
};

$('btnleakdns').onclick = async (e) => {
  e.target.disabled = true; $('leakout').textContent = 'probing 8 DNS detection hostnames...';
  const r = await jget('/api/leak/dns');
  $('leakout').innerHTML = '<div><b>' + esc(r.checked) + '</b> ' + r.count + ' resolver(s) seen</div>' +
    (r.resolvers.length ? r.resolvers.map(x =>
      '<div>' + esc(x.ip) + '  ' + esc(x.isp || '?') + ' (AS' + esc(x.asn || '?') + ') ' +
      esc(x.country || '') + '</div>').join('')
      : '<div>no resolvers recorded (ipleak saw nothing)</div>') +
    '<div class="note">A resolver on your real ISP rather than PIA means DNS is leaking.</div>' +
    (r.errors && r.errors.length ? '<div>errors: ' + esc(r.errors.join('; ')) + '</div>' : '');
  e.target.disabled = false;
};

$('btntorrentprobe').onclick = async (e) => {
  e.target.disabled = true;
  $('probeout').textContent = 'adding probe torrent through the gate...';
  const r = await jpost('/api/leak/torrent/start');
  if (r.blocked) {
    $('probeout').innerHTML = '<b style="color:var(--red-ink)">BLOCKED &mdash; ' + esc(r.reason) + '</b>';
    e.target.disabled = false; return;
  }
  if (!r.ok) { $('probeout').textContent = 'error: ' + (r.error || '?'); e.target.disabled = false; return; }
  probe = r; $('btnprobestop').style.display = '';
  $('probeout').textContent = 'announced ' + r.thash.slice(0, 16) + '... polling ipleak every 10s';
  let n = 0;
  probe.timer = setInterval(async () => {
    n++;
    const p = await jget('/api/leak/torrent/poll?thash=' + probe.thash);
    if (p.detected) {
      const good = p.match;
      $('probeout').innerHTML =
        '<div>announced IP  ' + esc(p.ip) + (p.port ? ':' + p.port : '') + '</div>' +
        '<div>piactl pubip  ' + esc(p.pia_pubip || '?') + '</div>' +
        '<div style="font-weight:700;color:' + (good ? 'var(--green-ink)' : 'var(--red-ink)') + '">' +
        (good ? 'MATCH — the tracker sees the VPN, not you' : 'MISMATCH — possible LEAK') + '</div>' +
        (p.candidates && p.candidates.length > 1
          ? '<div class="note">other addresses in the response: ' + esc(p.candidates.slice(1).join(', ')) + '</div>' : '') +
        '<div class="note">raw: ' + esc(p.raw) + '</div>';
      stopProbe();
    } else {
      $('probeout').textContent = 'waiting for the tracker to see the announce... (' + (n * 10) + 's)' +
        (p.error ? '  [' + p.error + ']' : '');
      if (n >= 18) { $('probeout').textContent += ' — gave up after 3 minutes.'; stopProbe(); }
    }
  }, 10000);
};
function stopProbe() {
  if (!probe) return;
  clearInterval(probe.timer);
  if (probe.id != null) jpost('/api/leak/torrent/stop', {id: probe.id});
  probe = null;
  $('btnprobestop').style.display = 'none';
  $('btntorrentprobe').disabled = false;
  loadTorrents();
}
$('btnprobestop').onclick = stopProbe;

/* ---- boot ---- */
tick().then(() => { loadTorrents(); mountVideo(); });
setInterval(tick, 2000);
setInterval(() => { if ($('tab-torrents').classList.contains('active')) loadTorrents(); }, 1800);
window.addEventListener('beforeunload', () => { if (probe) stopProbe(); });
</script>
</body>
</html>
"""


def render_page():
    return PAGE.replace("__DF_VERSION__", DF_VERSION)


# ==========================================================================
# Headless self-tests (--selftest): the gate must be provably fail-closed.
# ==========================================================================
def selftest():
    global PIACTL
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(f"{name}{(' - ' + detail) if detail else ''}")
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")

    print(f"\nDownloadFactory {DF_VERSION} self-test\n" + "-" * 58)
    print("piactl / gate")
    st = vpn_state()
    check("vpn_state() returns a string", isinstance(st, str) and st != "", st)
    ip = vpn_ip()
    check("vpn_ip() is None or an IPv4",
          ip is None or bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip)), str(ip))
    check("gate_ok() agrees with state+ip",
          gate_ok() == (st == "Connected" and ip is not None), str(gate_ok()))
    if st != "Connected":
        check("gate is SHUT while VPN is not Connected", gate_ok() is False)
        check("gate_reason() explains why", bool(gate_reason()), gate_reason())

    print("fail-closed")
    real = PIACTL
    PIACTL = r"C:\definitely\not\here\piactl.exe"
    try:
        check("bogus piactl -> state Unknown", vpn_state() == "Unknown")
        check("bogus piactl -> vpn_ip None", vpn_ip() is None)
        check("bogus piactl -> gate SHUT", gate_ok() is False)
        check("bogus piactl never raises", True)
    finally:
        PIACTL = real
    check("piactl restored", vpn_state() == st)

    print("settings.json writer")
    # Redirect the writer at a scratch dir. Without this the self-test
    # rewrites the REAL Transmission config while the app may be running, and
    # leaves bind-address-ipv4 pinned to 127.0.0.1 - i.e. running --selftest
    # would quietly break torrents on the next daemon restart.
    global TR_CONFIG_DIR, TR_DOWNLOAD_DIR
    real_cfg, real_dl = TR_CONFIG_DIR, TR_DOWNLOAD_DIR
    import tempfile
    scratch = tempfile.mkdtemp(prefix="df-selftest-")
    TR_CONFIG_DIR = os.path.join(scratch, "transmission")
    TR_DOWNLOAD_DIR = os.path.join(scratch, "dl")
    try:
        for bad in ("", None, "not-an-ip", "999.999.1.1x"):
            got = DAEMON.write_settings(bad)
            check(f"invalid bind {bad!r} -> 127.0.0.1 (never blank/0.0.0.0)",
                  got == "127.0.0.1", got)
        got = DAEMON.write_settings("10.20.30.40")
        check("valid bind is honoured", got == "10.20.30.40", got)
        s = json.load(open(os.path.join(TR_CONFIG_DIR, "settings.json"), encoding="utf-8"))
        check("bind-address-ipv6 pinned to ::1", s.get("bind-address-ipv6") == "::1")
        check("rpc bound to loopback", s.get("rpc-bind-address") == "127.0.0.1")
        check("rpc auth required", s.get("rpc-authentication-required") is True)
    finally:
        TR_CONFIG_DIR, TR_DOWNLOAD_DIR = real_cfg, real_dl
        shutil.rmtree(scratch, ignore_errors=True)
    check("self-test left the real config untouched",
          not os.path.exists(os.path.join(TR_CONFIG_DIR, "settings.json"))
          or json.load(open(os.path.join(TR_CONFIG_DIR, "settings.json"),
                            encoding="utf-8")).get("bind-address-ipv4") != "10.20.30.40")

    print("tunnel bind address")
    tb = tunnel_bind_ip()
    check("tunnel_bind_ip() is None or a real local IPv4",
          tb is None or bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", tb)), str(tb))
    if tb:
        check("it is NOT piactl's server-side vpnip", tb != vpn_ip(),
              f"bind={tb} vpnip={vpn_ip()}")
        check("it sits on a PIA adapter", tb in _pia_adapter_ips(),
              str(list(_pia_adapter_ips().values()))[:70])

    print("secrets discipline")
    check("no rpc password in the vault folder", not _folder_has_secret(HERE))
    check("rpc-auth file lives under LOCALAPPDATA", RPC_AUTH_FILE.startswith(APPDATA))
    cfgtxt = open(CONFIG_PATH, encoding="utf-8").read() if os.path.exists(CONFIG_PATH) else ""
    check("config.json holds no password", TR_PASS not in cfgtxt)

    print("gate state machine (simulated transitions)")
    calls = []
    import types
    real_stop, real_list = globals()["tr_stop_all"], globals()["tr_list"]
    globals()["tr_stop_all"] = lambda: (calls.append("stop-all"), True)[1]
    globals()["tr_list"] = lambda: []
    try:
        STATE.vpn = "Connected"
        on_state_change("Interrupted")
        check("Connected -> Interrupted stops all torrents", "stop-all" in calls)
        check("state marked BLOCKED", STATE.blocked is True)
        check("banner names the state", "Interrupted" in STATE.banner, STATE.banner)
        calls.clear()
        on_state_change("Disconnecting")
        check("any non-Connected state also stops all", "stop-all" in calls)
        calls.clear()
        on_state_change("Unknown")
        check("Unknown (dead piactl) is treated as down", "stop-all" in calls and STATE.blocked)
    finally:
        globals()["tr_stop_all"], globals()["tr_list"] = real_stop, real_list
        STATE.vpn, STATE.blocked = st, st != "Connected"

    print("ipleak parsing")
    # The live empty-state body, captured verbatim from ipleak.net.
    empty = (
        "<div class='docs_center'>Add <a class='link_button' href='magnet:?xt=urn:btih:"
        "2260f6ed3f28b29fb2f03035df780a595c3e646d&tr=https://ipleak.net/announce.php"
        "%3Fh%3D2260f6ed3f28b29fb2f03035df780a595c3e646d&dn=ipleak.net+torrent+detection'>"
        "this Magnet Link</a> to your torrent client and wait for the results below.</div>"
        "<div class='docs_center'>No data just now from the above magnet url.</div>"
        "<div class='docs_verbose'>Updated every 10 seconds.</div>")
    r1 = _parse_probe_html(empty)
    check("live empty-state body recognised", r1["empty"] and not r1["detected"])
    check("empty state yields no false IP", r1["ip"] is None, str(r1["ip"]))

    # The detected markup is UNVERIFIED upstream, so prove both plausible
    # shapes parse: the guide's free text AND the table the site's CSS implies.
    free = ("<div class='docs_center'>Add <a href='magnet:?xt=urn:btih:aa'>this Magnet"
            " Link</a> ...</div>IP: <a href='/?q=1.2.3.4'>1.2.3.4</a>, Port: <b>51413</b>")
    r2 = _parse_probe_html(free)
    check("free-text shape parsed", r2["detected"] and r2["ip"] == "1.2.3.4", str(r2["ip"]))
    check("free-text port parsed", r2["port"] == 51413, str(r2.get("port")))

    table = ("<div class='docs_center'>Add <a href='magnet:?xt=urn:btih:bb'>this Magnet"
             " Link</a> ...</div><table class='data'><tr><th>IP</th><th>Port</th>"
             "<th>Country</th></tr><tr><td>203.0.113.9</td><td>51999</td>"
             "<td>Netherlands</td></tr></table>")
    r3 = _parse_probe_html(table)
    check("table shape parsed (guide's regex would miss this)",
          r3["detected"] and r3["ip"] == "203.0.113.9", str(r3["ip"]))
    check("table port parsed", r3["port"] == 51999, str(r3.get("port")))
    check("raw evidence always returned for human review", bool(r3["raw"]))
    check("magnet href never mistaken for a peer address",
          all("btih" not in c for c in r3["candidates"]))
    check("dns [] shape guarded", _dns_shape({"ip": []}) == {})
    check("dns {} shape read", _dns_shape({"ip": {"8.8.8.8": 3}}) == {"8.8.8.8": 3})

    print("version discipline")
    check("DF_VERSION is 1.0", DF_VERSION == "1.0")
    check("filename carries the version", "1.0" in os.path.basename(__file__))
    check("HTML carries the version", f"v{DF_VERSION}" in render_page())
    check("HTML header comment carries it", f"DownloadFactory v{DF_VERSION}" in render_page())

    print("-" * 58)
    print(f"{len(passed)} passed, {len(failed)} failed")
    for f in failed:
        print(f"  FAILED: {f}")
    return 0 if not failed else 1


def _dns_shape(d):
    return d.get("ip") if isinstance(d.get("ip"), dict) else {}


def _folder_has_secret(folder):
    """True if the generated RPC password appears anywhere in this folder."""
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", "build", "dist")]
        for fn in files:
            p = os.path.join(root, fn)
            try:
                if os.path.getsize(p) > 4_000_000:
                    continue
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    if TR_PASS in f.read():
                        return True
            except OSError:
                continue
    return False


# ==========================================================================
# main
# ==========================================================================
def _find_free_port(preferred):
    for p in [preferred] + list(range(preferred + 1, preferred + 20)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return preferred


def boot_background():
    """Start the spine before the first request lands."""
    st = vpn_state()
    with STATE.lock:
        STATE.vpn = "__init__"      # force on_state_change to run the transition
        STATE.region = pia_region()
        STATE.portforward = pia_portforward()
    threading.Thread(target=watchdog, daemon=True, name="vpn-watchdog").start()
    threading.Thread(target=poll_secondary, daemon=True, name="vpn-poll").start()

    # Transmission comes up bound fail-closed; the watchdog rebinds it when the
    # tunnel appears. With no VPN it starts --paused on 127.0.0.1: peer binds
    # fail (traffic stalls) instead of leaking to 0.0.0.0.
    if os.path.exists(TR_DAEMON):
        threading.Thread(
            target=lambda: DAEMON.start(
                (tunnel_bind_ip() or "127.0.0.1") if st == "Connected" else "127.0.0.1",
                paused=True),
            daemon=True, name="tr-boot").start()
    else:
        STATE.tr_state = "error"
        STATE.tr_error = ("Transmission is not installed. Run:  msiexec /i "
                          "transmission-4.1.3-x64.msi ADDLOCAL=ALL /qn   then stop and "
                          "disable its Windows service.")

    if CFG["ytdlp"].get("enabled") and CFG["ytdlp"].get("launch_on_start", True):
        threading.Thread(target=VIDEO.start, daemon=True, name="video-boot").start()
    if CFG["hitomi"].get("enabled") and CFG["hitomi"].get("launch_on_start"):
        threading.Thread(target=GALLERIES.launch, daemon=True, name="hitomi-boot").start()


def main():
    ap = argparse.ArgumentParser(description=f"DownloadFactory v{DF_VERSION}")
    ap.add_argument("--port", type=int, default=int(CFG.get("shell_port", 8133)))
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser")
    ap.add_argument("--selftest", action="store_true", help="run headless self-tests and exit")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    # Single instance. Transmission's RPC port is fixed, so a second shell can
    # never own the daemon - it just port-hops to 8134 and then loops forever
    # on "port 9091 is held by another Transmission". Detect the sibling and
    # hand the user over to it instead of starting a doomed second copy.
    if _existing_instance(args.port):
        print(f"DownloadFactory is already running on http://127.0.0.1:{args.port} "
              f"- opening that one instead of starting a second copy.")
        if not args.no_browser:
            webbrowser.open(f"http://127.0.0.1:{args.port}/")
        sys.exit(0)

    port = _find_free_port(args.port)
    if port != args.port:
        print(f"note: port {args.port} is taken by something else; using {port}.")
    print("=" * 62)
    print(f"  DownloadFactory v{DF_VERSION}  -  http://127.0.0.1:{port}")
    print("=" * 62)
    print(f"  torrent gate : HARD, fail-closed (PIA must report 'Connected')")
    print(f"  transmission : {'found' if os.path.exists(TR_DAEMON) else 'NOT INSTALLED'}"
          f"  (RPC 127.0.0.1:{TR_RPC_PORT})")
    print(f"  piactl       : {'found' if os.path.exists(PIACTL) else 'NOT FOUND'}  "
          f"(state now: {vpn_state()})")
    print(f"  video worker : 127.0.0.1:{VIDEO.port}   galleries: {GALLERIES.ports}")
    print(f"  state/config : {APPDATA}")
    print("=" * 62, flush=True)

    boot_background()

    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()

    try:
        app.run(host="127.0.0.1", port=port, threaded=True,
                debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_all()


if __name__ == "__main__":
    main()
