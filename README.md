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

Milestone 0 — **done**. Connects, authenticates, pulls one frame, writes a PPM.

```
cargo run --release -- 192.168.1.50:5900 frame.ppm
```

Password comes from the `VNC_PASSWORD` env var (not argv — argv is visible to every
process on the box).

## Roadmap

| # | Milestone | State |
|---|-----------|-------|
| 0 | RFB 3.8 handshake, VNC auth, Raw encoding, one frame to disk | done |
| 1 | Window: continuous incremental updates on screen | next |
| 2 | Input: keyboard + mouse back to the server | |
| 3 | Encodings: CopyRect, then Tight or ZRLE (Raw is ~8 MB/frame at 1080p) | |
| 4 | Quality-of-life: reconnect, scaling, clipboard, saved hosts | |
| 5 | Maybe a server. This is the part people actually can't get for free. | |

## Design notes

- **Rust**, single static `.exe`. No .NET runtime, no Python, no installer.
- **One dependency** (`des`, for VNC auth). RFB itself is hand-rolled over
  `std::net::TcpStream` — the spec is small and the crates that wrap it are larger
  than the protocol.
- We force our own pixel format (32bpp LE, shifts 16/8/0) at connect time, so every
  pixel arrives as `0x00RRGGBB` and there is no format-translation layer at all.
- Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.

## Known limits

- RFB 3.8 only. Older servers (3.3/3.7) negotiate security differently.
- Raw encoding only — fine on a LAN, painful over the internet. That's milestone 3.
- No TLS. VNC auth is DES-based and weak by modern standards; tunnel over SSH or a
  VPN if the link isn't trusted.

## Testing against a real server

Any RFB 3.8 server works. Easiest local options:

- TightVNC Server (free, Windows)
- `x11vnc` or `docker run -p 5900:5900 ...` in WSL

## License

TBD — will be MIT or BSD-2. The whole point is that nobody pays for this.
