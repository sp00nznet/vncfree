# vncfree

A free, modern, open-source VNC client for Windows 11. MIT licensed. Free forever.
No spyware, no bundled junk, no "free trial" nag screens, no telemetry, no accounts,
no subscription, no ad-gated download.

## Why

The state of free VNC software in 2026 is a disgrace.

RealVNC puts its **server** behind a subscription. UltraVNC makes you sit through an
ad to download it. TightVNC's Windows installer pushes a server on you when all you
wanted was a viewer. Meanwhile the "premium" options charge a recurring fee for
software that has not meaningfully changed since 2008.

This shouldn't be a market. RFB is a published protocol from 1998. The spec is a few
dozen pages, it is stable, and it is free to read. Remote desktop is a solved
engineering problem.

So here's the deal: vncfree is MIT licensed, the code lives on GitHub, and anyone can
build it, fork it, ship it or audit it. It is one self-contained `.exe` — no
installer, no service, no server pushed on you, nothing running when you close the
window. **If anyone tries to sell you this software, they're scamming you. Walk away.**

Sibling project to [futureburn](https://github.com/sp00nznet/futureburn), same attitude.

### Prior art, credit where due

[TigerVNC](https://tigervnc.org) and [TightVNC](https://www.tightvnc.com) are genuinely
free and open source, and both are fine software — the complaint above is about how
TightVNC is *packaged*, not about its licence. If you need a mature, battle-tested
viewer today, use TigerVNC. vncfree exists because a viewer should be a single
executable you can drop on a machine and delete afterwards, and because the protocol
work is shared with a server — which is the half nobody gives away.

## Status

Milestone 4 — **done**. A usable remote desktop: live window, keyboard and mouse, Mac
support, and ZRLE compression so it is usable over a real network. Verified end to end
against both a real TigerVNC server and real macOS 15.7.3 Screen Sharing.

```
# live window, full control
cargo run --release -- 192.168.1.50:5900

# headless: grab one frame and exit
cargo run --release -- 192.168.1.50:5900 frame.ppm
```

Credentials come from the `VNC_PASSWORD` and `VNC_USERNAME` env vars (not argv — argv is
visible to every process on the box). `VNC_USERNAME` is only needed for a Mac. Close the
window to quit; Escape is forwarded to the remote machine, so it can't also be the quit
key.

Input notes:

- Mouse position, all three buttons, and the scroll wheel (RFB has no scroll message —
  the wheel is buttons 4 and 5, clicked and released).
- Keys are sent as X11 keysyms. Releases repeat the exact keysym sent on press, so
  letting go of shift first can't leave a capital letter stuck down.
- Losing window focus releases every held key. Without that, alt-tabbing while holding
  a modifier strands it down on the remote machine.

## Connecting to a Mac

**Nothing needs changing on the Mac.** Turn on Screen Sharing and connect with your
macOS account:

```powershell
$env:VNC_USERNAME = 'yourmacuser'
$env:VNC_PASSWORD = 'your account password'
vncfree 192.168.1.20:5900
```

Two macOS-specific things are handled:

1. **It announces `RFB 003.889`, not `003.008`.** vncfree replies `003.008`, which makes
   it fall back to standard RFB 3.8.
2. **Apple Diffie-Hellman authentication (security type 30)**, which is what Screen
   Sharing offers by default so it can check real macOS account credentials. The server
   sends a generator, key length, prime and its public key; we do the DH exchange, MD5
   the shared secret into an AES-128 key, and send back the username and password
   encrypted in a 128-byte blob followed by our public key. Full account passwords work
   — no 8-character DES limit.

If instead you enable "VNC viewers may control screen with password" on the Mac, that
switches it to standard VNC auth (security type 2), which also works — but note those
passwords are DES and effectively 8 characters, silently truncated beyond that.

The Windows key sends `Super_L`, which macOS maps to **Command** — so Cmd-C and Cmd-Tab
work from a Windows keyboard. Alt sends `Alt_L`, which arrives as Option.

### If the Mac says "Authentication or authorization failure"

This appears *after* the Diffie-Hellman exchange has already succeeded, so it means the
Mac read your credentials and refused them — not that anything is wrong with the
protocol. The cause is almost always Remote Management's own access list.

**Being in the `com.apple.access_screensharing` group is not sufficient.** On macOS
15.7.3 an account that could SSH in, was an admin, and was in that group was still
refused. What fixed it was System Settings > General > Sharing > **Remote Management** >
ⓘ, switching "Allow access for" from *All users* to *Only these users* with the account
listed explicitly. Ticking Observe/Control for the account is worth checking too.

The equivalent from a terminal:

```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -configure -users <shortname> -access -on -privs -all -restart -agent
```

If the security types offered include 33/35/36 but not 2, it is Remote Management that
is switched on rather than Screen Sharing. Run with `VNC_DEBUG=1` to see the server
version, the types offered and which one was chosen — none of that is otherwise visible.

### Verification status

**Confirmed working against real macOS 15.7.3 (Sequoia).** The server announces
`RFB 003.889`, we negotiate down to 3.8, it offers `[30, 33, 36, 35]`, we select 30, the
Diffie-Hellman exchange completes with generator 2 and a 128-byte key, and the session
authenticates and delivers a 1920x1080 desktop.

The crypto is additionally covered by a round-trip test that plays the server side
(proving the DH maths, MD5-to-AES key derivation and blob layout), and the wire format
matches [neatvnc](https://github.com/any1/neatvnc)'s server-side implementation and the
[RFB protocol document](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst).

The keysym-to-Command mapping is still spec-only — no key has yet been pressed on a Mac.

## Roadmap

| # | Milestone | State |
|---|-----------|-------|
| 0 | RFB 3.8 handshake, VNC auth, Raw encoding, one frame to disk | done |
| 1 | Window: continuous incremental updates on screen | done |
| 2 | Input: keyboard + mouse back to the server | done |
| 3 | Apple Diffie-Hellman auth (type 30), so a Mac needs no setting changed | done |
| 4 | Encodings: CopyRect and ZRLE (Raw is ~8 MB/frame at 1080p) | done |
| 5 | Quality-of-life: reconnect, scaling, clipboard, saved hosts | next |
| 6 | Maybe a server. This is the part people actually can't get for free. | |

## Design notes

- **Rust**, single static `.exe`. No .NET runtime, no Python, no installer.
- **Dependencies only where hand-rolling would be reckless**: `minifb` (window +
  framebuffer blit) and the crypto the auth schemes require — `des`, `aes`, `md-5`,
  `num-bigint` and `getrandom`. RFB itself is hand-rolled over `std::net::TcpStream`;
  the spec is small and the crates that wrap it are larger than the protocol. Ciphers
  and 1024-bit modular exponentiation are the opposite case: writing those by hand is
  how you ship a subtly broken one. `aes` and `des` are pinned to the same `cipher 0.4`
  generation so there is one copy in the tree.
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
- ZRLE's zlib stream spans the whole connection, not one rectangle. A decoder that
  resets it per rectangle decodes the first one correctly and then emits garbage
  forever, so the inflater lives in `Decoder` alongside the connection.
- `VNC_RAW_ONLY=1` forces Raw and disables ZRLE and CopyRect. When a screen looks
  wrong, this answers "is it my decoder or the server?" in one run.
- Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.

## Known limits

- RFB 3.8 or later. Older servers (3.3/3.7) negotiate security differently.
- Encodings are Raw, CopyRect and ZRLE. No Tight — it needs four persistent zlib
  streams and a JPEG decoder, and ZRLE gets most of the win. If a server offers Tight
  but not ZRLE we fall back to Raw and still work, just slowly.
- ZRLE is verified on a real 1920x1080 macOS desktop (all 256 byte values present, so
  raw tiles and large palettes are genuinely exercised), decoding to a pixel-accurate
  image.
- US keyboard layout. Non-US punctuation needs minifb's character callback rather than
  the static keysym table.
- No TLS. Apple DH protects the credentials in transit but not the session, and
  classic VNC auth is DES and weak by modern standards. Neither encrypts the
  framebuffer or your keystrokes — tunnel over SSH or a VPN if the link isn't trusted.
- The DH exchange is unauthenticated, so it stops eavesdroppers but not an active
  machine-in-the-middle. Same caveat as every other VNC client doing type 30.

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

MIT. See [LICENSE](LICENSE). Free forever, for everyone. The whole point is that
nobody pays for this.
