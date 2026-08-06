# vncfree

A free, modern, open-source VNC **client and server** for Windows 11. MIT licensed.
Free forever. No spyware, no bundled junk, no "free trial" nag screens, no telemetry,
no accounts, no subscription, no ad-gated download.

Two self-contained executables. Run them, close them, delete them. No installer, no
service, nothing running when you are not using it.

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

Milestone 8 — **done**. A client and a server, both with a window you can just double
click. Verified end to end against a real TigerVNC server, real macOS 15.7.3 Screen
Sharing, and each other.

Run `vncfree.exe` with no arguments and it asks where to connect. Run
`vncfree-server.exe` with no password set and it asks for one, with **Start server**
greyed out until you type it.

Everything is still driveable from a script or a shortcut — the dialogs only appear
when the arguments and environment variables are absent:

```
# live window, full control
vncfree 192.168.1.50:5900

# headless: grab one frame and exit
vncfree 192.168.1.50:5900 frame.ppm
```

Credentials come from the `VNC_PASSWORD` and `VNC_USERNAME` env vars (not argv — argv is
visible to every process on the box). `VNC_USERNAME` is only needed for a Mac. Close the
window to quit; Escape is forwarded to the remote machine, so it can't also be the quit
key.

Everything is configured with environment variables — there is no config file and
nothing is written to disk:

| Variable | Effect |
|---|---|
| `VNC_PASSWORD` | Password. Required by most servers. |
| `VNC_USERNAME` | macOS account name. Only needed for a Mac. |
| `VNC_VIEW_ONLY=1` | Watch without sending input. Also blocks clipboard writes. |
| `VNC_RAW_ONLY=1` | Disable ZRLE and CopyRect. For "is it my decoder or the server?" |
| `VNC_DEBUG=1` | Print the negotiated version, security types and clipboard traffic. |
| `VNC_BIND` | Server only. Where to listen; default `0.0.0.0:5900`. |

**Clipboard** is shared both ways, as Latin-1 with LF endings per the RFB spec, so CRs
are stripped on the way out and restored on the way in. The local clipboard is polled
twice a second while the window has focus — which is exactly when it matters, since you
focus the window to paste into it. Connecting does *not* push your clipboard at the
remote machine; the poll is seeded at startup so it only sends genuine changes.

**Reconnect** is automatic, with backoff from 1s up to 15s, and the title bar shows
`[reconnecting]`. A resolution change across the reconnect is handled — the framebuffer
is reallocated rather than assuming the old size.

Input notes:

- Mouse position, all three buttons, and the scroll wheel (RFB has no scroll message —
  the wheel is buttons 4 and 5, clicked and released).
- Keys are sent as X11 keysyms. Releases repeat the exact keysym sent on press, so
  letting go of shift first can't leave a capital letter stuck down.
- Losing window focus releases every held key. Without that, alt-tabbing while holding
  a modifier strands it down on the remote machine.

## The server

```powershell
$env:VNC_PASSWORD = 'up to 8 chars'
vncfree-server            # serves 0.0.0.0:5900
$env:VNC_BIND = '127.0.0.1:5900'   # or pick where to listen
```

**It will not start without `VNC_PASSWORD`.** An open VNC port hands the whole desktop
to anyone who can reach it, and defaulting to "no password" is exactly the decision
that makes remote-access software dangerous. It offers only VNC authentication, so
there is no unauthenticated path at all.

- Captures with GDI `BitBlt` into a DIB, which already holds `0x00RRGGBB` pixels, so
  the framebuffer needs no conversion in either direction.
- The process is marked DPI-aware, so a 4K screen at 200% scaling is captured as real
  3840x2160 pixels rather than a blurry upscale of 1920x1080.
- The cursor is composited in by hand with `DrawIconEx`. `BitBlt` does not include it,
  and a remote desktop with no visible pointer is close to unusable.
- Only changed 64-pixel tiles are sent, with horizontally adjacent tiles merged into
  runs. Without merging a full-screen change at 1080p is 510 separate rectangles.
- Encodes ZRLE when the client asks for it, falling back to Raw otherwise. A full
  3840x2160 screen measured **33,177,616 bytes as Raw and 258,871 as ZRLE — 0.8%, a
  128x reduction** — which is the difference between "LAN only" and actually usable.
- Input is injected with `SendInput`, and the pointer with `SetPhysicalCursorPos` —
  see the DPI note in "Known limits".

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
| 5 | Clipboard, automatic reconnect, view-only mode | done |
| 6 | A server: capture, input injection, clipboard. The part nobody gives away. | done |
| 7 | Server-side ZRLE, so the server is usable off the LAN too | done |
| 8 | A GUI for both, so neither needs environment variables or a terminal | done |
| 9 | Go public, tag a release, attach the binaries | next |

Saved hosts were considered and dropped: a desktop shortcut with the arguments already
does it, and a config file format is a lot of surface for no new capability.

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
- The dialogs are plain Win32, not a UI toolkit. The whole interface is a few labelled
  text boxes and a button; `egui` and friends would add hundreds of crates and several
  megabytes to a program whose entire pitch is one small self-contained exe. They cost
  no new dependencies at all, since `windows-sys` was already here for the server.
- The dialog raises its DPI awareness per *thread*, not per process, so it renders
  crisply on a high-DPI screen without changing how the client's session window is
  treated. Without it the dialog is bitmap-scaled and blurry at 200%.
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
- **Clipboard does not work against macOS.** Verified working both directions against
  TigerVNC, but macOS Screen Sharing neither applies our `ClientCutText` to its
  pasteboard nor sends `ServerCutText` when its own clipboard changes — it appears to
  use a proprietary extension instead. `VNC_DEBUG=1` will show the message being sent.
- The server encodes ZRLE and Raw, but not CopyRect, so dragging a window costs real
  bytes rather than a "copy this block" instruction. It also emits only three of the
  five ZRLE subencodings (solid, packed palette, raw), skipping the two RLE forms.
  Both are further squeezes, not compatibility gaps.
- The server shares the primary monitor only, and does not follow a resolution change
  while a client is connected.
- Windows DPI gotcha, in case it bites elsewhere: `SendInput` with
  `MOUSEEVENTF_ABSOLUTE` maps its 0..65535 range onto the **logical** desktop, so on a
  200% display every injected coordinate lands at half the intended position. The
  framebuffer is in physical pixels, so the pointer uses `SetPhysicalCursorPos`
  instead. Beware measuring this from a DPI-unaware process — `GetCursorPos` there
  reports logical coordinates and makes a correct fix look broken.
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

## Building and releases

```
cargo build --release
```

Produces two self-contained executables with no runtime to install:
`target/release/vncfree.exe` (client) and `target/release/vncfree-server.exe`. Shared
RFB protocol pieces live in `src/lib.rs`; decoding belongs to the client and encoding
to the server, so those stay in their own binaries. CI builds it on every push and runs `cargo fmt --check`, `clippy -D warnings`
and the tests; pushing a `v*` tag attaches the exe to a GitHub release. GitHub Actions
is free with unlimited minutes for public repositories, so the binary on the Releases
page costs nothing to produce and nobody has to trust a build from anywhere else.

## License

MIT. See [LICENSE](LICENSE). Free forever, for everyone. The whole point is that
nobody pays for this.
