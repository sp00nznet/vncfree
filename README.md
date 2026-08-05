# vncfree

A free VNC client for Windows. No subscription, no ad-gated download, no account.

## Why

RealVNC puts its **server** behind a subscription. UltraVNC's download page makes you
sit through an ad. VNC is a 1998 protocol with a published spec — nobody should be
renting it to you.

**Honest caveat, up front:** free VNC *viewers* already exist and are genuinely good —
[TigerVNC](https://tigervnc.org) and [TightVNC](https://www.tightvnc.com) both ship
free, open-source, ad-free Windows viewers. If you just need to connect to something
today, use one of those. The real gap is on the *server* side, which is exactly what
RealVNC charges for. This repo is a from-scratch viewer first, because the protocol
work is shared with a server and it's the easier half to get right.

## Status

Milestone 1 — **done**. Live window showing the remote desktop, updating continuously.
Verified end to end against a real TigerVNC server.

```
# live window
cargo run --release -- 192.168.1.50:5900

# headless: grab one frame and exit
cargo run --release -- 192.168.1.50:5900 frame.ppm
```

Password comes from the `VNC_PASSWORD` env var (not argv — argv is visible to every
process on the box). Escape or closing the window quits.

It is view-only right now — keyboard and mouse are milestone 2.

## Roadmap

| # | Milestone | State |
|---|-----------|-------|
| 0 | RFB 3.8 handshake, VNC auth, Raw encoding, one frame to disk | done |
| 1 | Window: continuous incremental updates on screen | done |
| 2 | Input: keyboard + mouse back to the server | next |
| 3 | Encodings: CopyRect, then Tight or ZRLE (Raw is ~8 MB/frame at 1080p) | |
| 4 | Quality-of-life: reconnect, scaling, clipboard, saved hosts | |
| 5 | Maybe a server. This is the part people actually can't get for free. | |

## Design notes

- **Rust**, single static `.exe`. No .NET runtime, no Python, no installer.
- **Two dependencies**: `des` (VNC auth) and `minifb` (window + framebuffer blit).
  RFB itself is hand-rolled over `std::net::TcpStream` — the spec is small and the
  crates that wrap it are larger than the protocol. On Windows `minifb` compiles 7
  crates; its x11/wayland/sdl2 deps are target-gated and never built.
- We force our own pixel format (32bpp LE, shifts 16/8/0) at connect time, so every
  pixel arrives as `0x00RRGGBB` — which is also exactly minifb's buffer layout, so
  there is no format-translation layer anywhere in the program.
- Networking runs on its own thread. An incremental `FramebufferUpdateRequest` blocks
  for as long as the remote screen is idle, and the UI thread must never block on
  that. The two share one `Mutex<Vec<u32>>`.
- Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.

## Known limits

- RFB 3.8 only. Older servers (3.3/3.7) negotiate security differently.
- Raw encoding only — fine on a LAN, painful over the internet. That's milestone 3.
- No TLS. VNC auth is DES-based and weak by modern standards; tunnel over SSH or a
  VPN if the link isn't trusted.

## Testing against a real server

Any RFB 3.8 server works. What this repo is developed against, via WSL:

```sh
sudo apt-get install -y tigervnc-standalone-server x11-xserver-utils
Xtigervnc :1 -geometry 800x600 -depth 24 -SecurityTypes None -rfbport 5900 &
DISPLAY=:1 xsetroot -solid "rgb:20/40/80"     # a known colour to verify against
```

Then `vncfree 127.0.0.1:5900 test.ppm` and check the PPM's pixels are `20 40 80`.
A red/blue channel swap shows up immediately as `80 40 20`, which a screenshot-only
check would miss.

Note: pass colours as `rgb:20/40/80`, not `#204080`. PowerShell strips `#` from
native-command arguments, and the resulting silent `xsetroot` failure looks exactly
like a broken decoder (a black screen).

## License

TBD — will be MIT or BSD-2. The whole point is that nobody pays for this.
