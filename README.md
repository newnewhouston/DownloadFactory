# DownloadFactory v1.0

One Factory-line console that unifies four downloaders behind a single local page,
with a **hard, fail-closed VPN gate on torrents**.

```bash
Start DownloadFactory.bat
```

Then open <http://127.0.0.1:8133>. Flags: `--port N`, `--no-browser`, `--selftest`.

---

## What it is

| Tab | What runs there | Gated? |
|---|---|---|
| **Video** | DownloadFactory's own UI, driving the YT-DLP GUI v1.4 worker on `127.0.0.1:7331` over its HTTP API | no (HTTP) |
| **Torrents** | Transmission 4.1.3 daemon, spawned by this app and driven over RPC | **YES — hard gate** |
| **Galleries** | Hitomi Downloader (your own exe), HTTP API on `127.0.0.1:6975`, embedded in an iframe | no (HTTP) |
| **VPN & Leak** | PIA control via `piactl` + ipleak.net egress / DNS / torrent-address verification | — |

DownloadFactory owns the shell, the gate, the Transmission lifecycle, the leak checks, and
the Video tab's interface. The download *engines* are never reimplemented — yt-dlp runs
inside the real YT-DLP GUI worker process, so its hard-won fixes (cookie
snapshot-isolation, signed-out detection, the bundled JS runtime for YouTube's "n"
challenge) all still do the work.

**The Video tab is native, not an iframe.** It draws its own controls in the Factory theme
and proxies to the worker's HTTP API. Two things make the proxy necessary rather than
optional: every real worker route is gated behind `X-YTG-Token`, a per-process uuid4 that
exists only inside the HTML the worker serves, and the worker sets no CORS headers, so a
page on `:8133` cannot call `:7331` directly. DownloadFactory scrapes the token from the
worker's page and re-scrapes automatically on a 403 (i.e. after a worker restart).

The quality and cookie options are **scraped from the worker, not hardcoded** — its quality
list is built at its own import time and changes shape depending on whether ffmpeg was on
PATH, so hardcoding it would silently offer options the engine can't honour.

### Cookies: drag and drop

Drop a `cookies.txt` onto the drop zone in the Video tab (or click *choose a file*). The
browser never exposes a real path for a dropped file, so the contents are uploaded to the
local shell and written to **`%LOCALAPPDATA%\DownloadFactory\cookies\`** — a credential,
so never into the vault folder that syncs to other machines. The resolved path is filled in
for you and the browser picker switches to *None*, since a file overrides it anyway.

On drop it tells you what it got, before you waste a download finding out:

- **✓ signed-in YouTube session found** — the jar contains `SID` / `SAPISID` /
  `__Secure-1PSID` / `__Secure-1PAPISID` / `LOGIN_INFO`.
- **⚠ no signed-in YouTube session** — it parsed as a cookie jar, but YouTube will still
  demand you confirm you're not a bot. Re-export from a **private window** while signed in.
- Anything that isn't a Netscape `cookies.txt` (no header line, no tab-separated rows) is
  rejected outright rather than handed to yt-dlp.

Typing a path still works. Relative paths are resolved **here** — against the cookie store,
your Downloads, Desktop, then home — instead of being passed through to the worker, whose
working directory is its own install folder. That mismatch is what produced errors like
`Cookies file not found: ...\YT-DLP GUI\Downloads`. A missing file or a non-existent
save-to folder is now caught and named before the job is dispatched.

---

## The gate — exact behaviour

**The gate is the product.** It is enforced in the Flask routes, not in the UI. Hitting
the API directly with the VPN down starts nothing; the disabled button is only a courtesy.

`gate_ok()` is the single source of truth and is called **live** on every mutating torrent
route — never cached, so a tunnel that dropped a moment ago cannot slip a torrent through:

```python
gate_ok() = (piactl get connectionstate == "Connected") and (piactl get vpnip != "Unknown")
```

Anything else — `Disconnected`, `Connecting`, `Interrupted`, `Reconnecting`,
`Disconnecting`, a piactl timeout, a missing piactl, a dead monitor — is **not connected**.

| Event | What happens |
|---|---|
| Add / start a torrent while not Connected | Route returns `blocked:true`, nothing starts, red gate banner |
| Daemon starts with no VPN | Binds `bind-address-ipv4 = 127.0.0.1` and starts `--paused`. Peer binds *fail* (traffic stalls) rather than leaking |
| VPN drops mid-download | Watchdog stops **all** torrents within one monitor tick, raises the banner, records what it paused |
| VPN reconnects on a new tunnel IP | Daemon is stopped → `settings.json` rewritten → daemon restarted, now bound to the new IP. Torrents stay **paused**; you resume them |
| `piactl` disappears, hangs, or the monitor dies | Treated as not-connected. Blocks and pauses. Never fails open |

Two bindings do the actual leak prevention:

- `bind-address-ipv4` = **the local IPv4 assigned to PIA's own tunnel adapter**. This binds
  the peer listener, **outbound** peer sockets, UDP/DHT and tracker announces. It is never
  left blank — a blank or invalid value makes Transmission silently bind `0.0.0.0`, which
  is a full leak. A valid-but-unassigned IP instead makes binds *fail*, which is the safe
  direction.
- `bind-address-ipv6` = `::1`, because IPv4-only binding still lets IPv6 peers out.

> **Not `piactl get vpnip`.** On OpenVPN that returns the *server-side* endpoint (e.g.
> `212.32.69.17`), which is not assigned to any local interface. Binding to it makes
> Transmission fail every connection with
> `Couldn't obtain source address in any IP protocol, no network connections possible` —
> torrents are accepted, sit at 0 peers forever and never move. DownloadFactory instead
> enumerates network adapters, keeps only PIA's own (`Private Internet Access Network
> Adapter` on OpenVPN, `wgpia0` on WireGuard), and binds the address the routing table
> actually selects for internet traffic on that adapter. **It will only ever return an
> address that sits on a PIA adapter**, so it can never fall back to the LAN address and
> leak. If no PIA adapter address can be found, the gate stays shut and says so rather
> than letting torrents stall silently.

**Stop is never gated.** You can always stop a torrent, whatever the VPN is doing.

### What the gate does *not* cover

DNS for tracker hostnames is not bound by `bind-address-ipv4` — rely on PIA's DNS and the
kill switch. Video and Galleries are HTTP and deliberately **not** hard-gated.

---

## Set-up you must do yourself (not scriptable)

1. **PIA kill switch** — PIA app → Settings → Privacy → **Advanced Kill Switch**. This
   enforces VPN-required even when the PIA app is closed. It is a WFP firewall rule and
   cannot be set from `piactl`.
2. **Split tunnel** — add `transmission-daemon.exe` to **Only VPN**.
   ⚠️ Putting `transmission-daemon.exe` or `python.exe` on **Bypass VPN** defeats this
   entire app.
3. **Headless connect** — run `piactl background enable` once if you want the Connect
   button to work with the PIA GUI closed. Without it, `piactl connect` returns
   "requires client" and the UI tells you so.
4. **Port forwarding** — PIA never forwards ports on **US regions** (this machine's region
   is `auto`). Pick a non-US region if you want it, and set
   `"request_port_forward": true` in `config.json`. When a port appears it is pushed into
   Transmission via `session-set peer-port` and then `port-test`ed.
5. **Hitomi** — enable *Options → Settings → Advanced → HTTP API* in Hitomi itself. Expect
   a SmartScreen prompt and a Windows Firewall prompt the first time.

---

## Ports

| Port | What |
|---|---|
| 8133 | DownloadFactory shell (this app) |
| 9091 | Transmission RPC (loopback only, auth required) |
| 7331 | YT-DLP GUI worker |
| 6975–6978 | Hitomi Downloader HTTP API (probed in order) |
| 51413 | Transmission **peer** port — the only intentionally reachable port, and only via the VPN |

Everything binds `127.0.0.1`. No LAN exposure, no cloud.

**Only one copy can run at a time.** Transmission's RPC port is fixed, so a second shell
could never own the daemon — it would just take the next free shell port and then loop
forever on *"port 9091 is held by another Transmission"*. Launching a second copy now
detects the first, opens the browser at it, and exits.

If Transmission's port is held by a daemon whose shell has since died, DownloadFactory
reclaims that orphan automatically. If it's held by a **live** sibling shell, it says so and
names the PID instead of fighting over it.

---

## config.json

Non-secret settings only. This folder syncs to other machines and is read by Claude
sessions, so **nothing secret is ever written here**.

| Key | Meaning |
|---|---|
| `shell_port` | Shell port (default 8133; auto-hops if busy) |
| `transmission.daemon` | Path to `transmission-daemon.exe` |
| `transmission.rpc_port` / `peer_port` | 9091 / 51413 |
| `transmission.download_dir` | Where torrents land |
| `pia.piactl` | Path to `piactl.exe` |
| `pia.request_port_forward` | Ask PIA for a forwarded port on connect |
| `pia.auto_resume_after_reconnect` | **Default false.** When true, a reconnect resumes *only* the torrents the watchdog itself paused |
| `ytdlp.script` / `.exe` / `.port` / `.launch_on_start` | The Video worker |
| `hitomi.exe` / `.api_ports` / `.launch_on_start` | The Galleries worker |

### Where the secrets live

`%LOCALAPPDATA%\DownloadFactory\`

- `rpc-auth.json` — the generated Transmission RPC username + plaintext password.
  It has to be kept: Transmission **salts** `rpc-password` in its own `settings.json` on
  every flush, and the salted form cannot be reversed, so the plaintext is needed to
  authenticate on a later run.
- `transmission\settings.json` — Transmission's config, including the salted password.

PIA credentials are never touched by this app. It only calls `piactl connect/disconnect/
get/monitor`.

---

## Verifying it actually works

**VPN & Leak tab → Run IP check** — server-side (so it reflects *this machine's* egress,
which is what a background downloader actually uses, not the browser's).

The verdict is **not** "does the egress match `piactl get pubip`". That test produces false
LEAK alarms on a perfectly healthy tunnel, because PIA's `pubip` frequently reports the
real ISP address on OpenVPN while the traffic is genuinely tunnelled. What ipleak actually
observes is the ground truth; `piactl`'s value is shown but treated as advisory. So:

| Verdict | Means |
|---|---|
| `VPN HOLDING` | Egress is not your real ISP. The tunnel is carrying traffic |
| `LEAK` | Egress is on your **real ISP's ASN** (or is your real IP) while the VPN claims to be up. This is the real thing |
| `NO VPN` | PIA is off — this is your own IP, and nothing is wrong |

Your real ISP/ASN is learned automatically the first time a check runs with the VPN off,
and cached in `%LOCALAPPDATA%\DownloadFactory\runtime.json` as the baseline to compare
against.

**Run DNS-leak check** — 8 random `<session>-N.ipleak.net/dnsdetection/` lookups, then
geolocates every resolver that answered. A resolver on your real ISP rather than PIA means
DNS is leaking.

**Verify torrent IP** — the money feature. Generates a throwaway 40-hex hash, announces it
to ipleak's tracker **through the same gated add path** as any other torrent, then polls
every 10 s and compares the IP the tracker saw against `piactl get pubip`. Match = the
tunnel is holding. With the VPN off the probe is refused, so nothing ever announces.

Run `py -3 "DownloadFactory 1.0.py" --selftest` for 40 headless assertions covering the
gate, fail-closed behaviour, the settings writer, secret hygiene and the ipleak parsers.

---

## Known upstream issues (not bugs in this app)

- **Hitomi Downloader is unmaintained and unhosted.** The KurtBestor GitHub repo was
  DMCA'd (FAKKU, anti-circumvention) on 2026-03-30 and returns HTTP 451 — repo, releases,
  wiki and issues are all gone. Last stable is v4.2 (2024-10-27). **DownloadFactory never
  downloads it from anywhere**: the mirrors are a malware vector, so you supply the exe.
  Hitomi also self-updates its yt-dlp/ffmpeg components from that now-451 GitHub and can
  throw `zipfile.BadZipFile` doing so. Expect AV false positives on the unsigned
  PyInstaller exe.
- **Hitomi's HTTP API is undocumented** (the wiki is 451). We probe 6975–6978 and embed
  its own Web UI rather than guessing at endpoints. "Send URL" shells the exe directly.
- **Magnets never go to Hitomi.** Its clipboard monitor can recognise magnet links, so the
  Galleries route explicitly refuses magnets and `.torrent` URLs and points you at the
  Torrents tab. Every torrent stays on the gated path.
- **Transmission's Windows service is disabled on purpose.** The MSI registers an
  auto-start service running as `LocalService`, which cannot write your user folders and
  has the wrong lifecycle for the gate. Setup ran
  `sc.exe stop Transmission` + `sc.exe config Transmission start= disabled`; this app
  spawns its own foreground daemon instead.

---

## Design notes

**Palette.** Sampled from `DownloadFactory Logo 0.1.png` at full resolution (2000×2000,
263 distinct RGB values) by pixel count, not by eye:

| Role | Hex | Share |
|---|---|---|
| field | `#d9d9d9` | 97.57% |
| wordmark green | `#137f1f` | 1.13% |
| frame blue | `#1f80ff` | 0.80% |
| rule red | `#ff2828` | 0.045% |
| ink | **absent** | 0% |

The logo has **no dark ink** — zero pixels have `max(R,G,B) < 80`. `--ink: #16141a` is
therefore **chosen, not sampled**, and is labelled as such in the source.

All three logo inks are bright, so on the `#d9d9d9` field they clear AA as fills and rules
but **not** as small text (green 3.6:1, blue 2.7:1, red 2.7:1). Each has a darkened
text-safe sibling — `--green-ink #0d6416`, `--blue-ink #0a52b8`, `--red-ink #b21212` — all
≥ 4.9:1. Colour is signal only: **green = safe/go, red = blocked/leak, blue = structure.**
If a screenshot looks colourful, it's wrong.

**No CDN, no webfont.** The sibling Factory apps pull Space Grotesk / JetBrains Mono from
Google Fonts. This one does not: a leak-checking tool must not phone
`fonts.googleapis.com` on every page load — that request is itself an egress the user
didn't ask for, and it would sit outside the tunnel if the browser is split-tunnelled. The
same token stacks are used, so the fonts render when installed and fall back to
Segoe UI / Cascadia Mono when not (neither is installed on this machine today).

Single file, inline CSS/JS, `flask` + `requests` only. No torrent library — raw `requests`
against Transmission's old bespoke RPC protocol, which is still supported in 4.1.x and is
the most compatible choice.
