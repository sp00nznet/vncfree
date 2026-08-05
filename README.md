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

Milestone 2 — **done**. A usable remote desktop: live window, keyboard and mouse.
Verified end to end against a real TigerVNC server.

```
# live window, full control
cargo run --release -- 192.168.1.50:5900

# headless: grab one frame and exit
cargo run --release -- 192.168.1.50:5900 frame.ppm
```

Password comes from the `VNC_PASSWORD` env var (not argv — argv is visible to every
process on the box). Close the window to quit; Escape is forwarded to the remote
machine, so it can't also be the quit key.

Input notes:

- Mouse position, all three buttons, and the scroll wheel (RFB has no scroll message —
  the wheel is buttons 4 and 5, clicked and released).
- Keys are sent as X11 keysyms. Releases repeat the exact keysym sent on press, so
  letting go of shift first can't leave a capital letter stuck down.
- Losing window focus releases every held key. Without that, alt-tabbing while holding
  a modifier strands it down on the remote machine.

## Connecting to a Mac

macOS Screen Sharing is a real RFB server but differs in two ways that matter:

1. **It announces `RFB 003.889`, not `003.008`.** vncfree replies `003.008`, which makes
   it fall back to standard RFB 3.8. Handled — no action needed.
2. **Authentication.** By default a Mac authenticates against macOS user accounts using
   Apple's Diffie-Hellman scheme (security type 30), which vncfree does not implement.
   Fix it on the Mac: System Settings > General > Sharing > Screen Sharing > (i) >
   enable **"VNC viewers may control screen with password"** and set a password. That
   switches the Mac to standard VNC auth, which works today. vncfree prints exactly
   this instruction if it sees type 30, rather than a bare protocol error.

VNC auth keys are DES and effectively 8 characters — a longer password is silently
truncated, so pick 8 meaningful ones.

The Windows key sends `Super_L`, which macOS maps to **Command** — so Cmd-C and Cmd-Tab
work from a Windows keyboard. Alt sends `Alt_L`, which arrives as Option. This mapping
is from the spec and is not yet confirmed against a physical Mac.

## Roadmap

| # | Milestone | State |
|---|-----------|-------|
| 0 | RFB 3.8 handshake, VNC auth, Raw encoding, one frame to disk | done |
| 1 | Window: continuous incremental updates on screen | done |
| 2 | Input: keyboard + mouse back to the server | done |
| 3 | Encodings: CopyRect, then Tight or ZRLE (Raw is ~8 MB/frame at 1080p) | next |
| 4 | Apple Diffie-Hellman auth (type 30), so a Mac needs no setting changed | |
| 5 | Quality-of-life: reconnect, scaling, clipboard, saved hosts | |
| 6 | Maybe a server. This is the part people actually can't get for free. | |

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
- Both threads write to the socket — update requests from one, input events from the
  other — so the write half sits behind its own mutex. A half-written message would
  desync the protocol permanently.
- Input presses are processed before releases. A key tapped and released inside a
  single 60fps frame appears in both lists, and handling the release first sends an up
  against an empty held-map followed by a down that never gets released.
- Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.

## Known limits

- RFB 3.8 or later. Older servers (3.3/3.7) negotiate security differently.
- Raw encoding only — fine on a LAN, painful over the internet. That's milestone 3.
- Apple Diffie-Hellman auth (type 30) is not implemented; see the Mac section above.
- US keyboard layout. Non-US punctuation needs minifb's character callback rather than
  the static keysym table.
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

To check input, run `xev -root > /tmp/xev.log` on the remote display and confirm the
keysyms it logs match what you typed, and read the pointer back with
`DISPLAY=:1 xdotool getmouselocation`. Two warnings, both of which cost real time:

- Synthetic Windows input (`SendKeys`, and `SendInput` even when it reports success)
  does **not** reach a minifb window. Test the keyboard by typing at it yourself, or by
  driving the RFB messages directly. An automated key-injection harness will look like
  a broken client when it is really a broken test.
- An idle Xtigervnc with no client can pin its pointer at one spot and override
  `xdotool mousemove`. Confirm that behaviour with vncfree *not* running before
  concluding the client mis-mapped a coordinate.

Note: pass colours as `rgb:20/40/80`, not `#204080`. PowerShell strips `#` from
native-command arguments, and the resulting silent `xsetroot` failure looks exactly
like a broken decoder (a black screen).

## License

TBD — will be MIT or BSD-2. The whole point is that nobody pays for this.
