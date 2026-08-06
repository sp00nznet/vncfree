# vncfree

A free, modern, open-source VNC **client and server** for Windows 11. MIT licensed.
Free forever. No spyware, no bundled junk, no "free trial" nag screens, no telemetry,
no accounts, no subscription, no ad-gated download.

Two self-contained executables. Run them, close them, delete them. No installer, no
service, nothing running when you are not using it.

## Why

The state of free VNC software in 2026 is a disgrace.

RealVNC puts its **server** behind a subscription. UltraVNC makes you sit through an ad
to download it. TightVNC's Windows installer pushes a server on you when all you wanted
was a viewer. Meanwhile the "premium" options charge a recurring fee for software that
has not meaningfully changed since 2008.

This shouldn't be a market. RFB is a published protocol from 1998. The spec is a few
dozen pages, it is stable, and it is free to read. Remote desktop is a solved
engineering problem.

So here's the deal: vncfree is MIT licensed, the code lives on GitHub, and anyone can
build it, fork it, ship it or audit it. **If anyone tries to sell you this software,
they're scamming you. Walk away.**

Sibling project to [futureburn](https://github.com/sp00nznet/futureburn), same attitude.

### Prior art, credit where due

[TigerVNC](https://tigervnc.org) and [TightVNC](https://www.tightvnc.com) are genuinely
free and open source, and both are fine software — the complaint above is about how
TightVNC is *packaged*, not about its licence. If you need a mature, battle-tested
viewer today, use TigerVNC. vncfree exists because a viewer should be a single
executable you can drop on a machine and delete afterwards — and because the server is
the half everyone charges for, so that one is free here too.

## Use it

Double click either one and it asks what it needs.

- **`vncfree.exe`** — asks for an address, an optional username and a password.
- **`vncfree-server.exe`** — shows this machine's address on the local network and asks
  for a password. **Start server** stays greyed out until you type one.

Both are equally driveable from a script or a shortcut; the dialogs only appear when
the arguments and environment variables are absent.

```powershell
vncfree 192.168.1.50:5900              # connect
vncfree 192.168.1.50:5900 frame.ppm    # grab one frame headless and exit

$env:VNC_PASSWORD = 'up to 8 chars'
vncfree-server                          # share this screen on 0.0.0.0:5900
```

Close the client window to quit — Escape is forwarded to the remote machine, so it
can't also be the quit key.

### Settings

All environment variables. There is no config file and nothing is written to disk.

| Variable | Effect |
|---|---|
| `VNC_PASSWORD` | Password. The server refuses to start without one. |
| `VNC_USERNAME` | macOS account name. Only needed for a Mac. |
| `VNC_BIND` | Server only. Where to listen; default `0.0.0.0:5900`. |
| `VNC_VIEW_ONLY=1` | Watch without sending input. Also blocks clipboard writes. |
| `VNC_RAW_ONLY=1` | Disable ZRLE and CopyRect. Answers "is it my decoder or the server?" |
| `VNC_DEBUG=1` | Print the negotiated version, security types and clipboard traffic. |

Credentials come from the environment rather than the command line, because argv is
visible to every process on the machine.

## What it does

| | |
|---|---|
| **Client** | Live window, keyboard, mouse, shared clipboard, automatic reconnect with backoff, view-only mode |
| **Server** | Screen capture with the cursor, keyboard and mouse injection, clipboard, mandatory password |
| **Encodings** | Raw, CopyRect, ZRLE. A full 3840x2160 screen is 33,177,616 bytes as Raw and 258,871 as ZRLE — 0.8%, a 128x reduction. Scrolling is sent as a move: one measured run shifted 3,974,784 pixels for 64 bytes |
| **Authentication** | VNC (DES) and Apple Diffie-Hellman, so a **Mac needs nothing changed** |
| **Verified against** | TigerVNC, real macOS 15.7.3 Screen Sharing, and itself |

**The server will not start without a password.** An open VNC port hands the whole
desktop to anyone who can reach it, and defaulting to "no password" is exactly the
decision that makes remote-access software dangerous. It offers only VNC
authentication, so there is no unauthenticated path at all.

## Known limits

- **No TLS.** Apple DH protects the credentials in transit but not the session, and
  classic VNC auth is DES and weak by modern standards. Neither encrypts the
  framebuffer or your keystrokes — **tunnel over SSH or a VPN if the link isn't
  trusted**, and don't port-forward this to the internet.
- **Clipboard does not work against macOS.** It works both directions against TigerVNC,
  but macOS appears to use a proprietary extension. See [docs/macos.md](docs/macos.md).
- RFB 3.8 or later. Older servers (3.3/3.7) negotiate security differently.
- No Tight encoding, and the server's CopyRect covers vertical scrolling but not a
  window dragged sideways. Compatibility is unaffected — these cost bytes, not
  connections.
- The server shares the primary monitor only, and does not follow a resolution change
  while a client is connected.
- US keyboard layout for non-alphanumeric keys.

## Documentation

- **[docs/macos.md](docs/macos.md)** — connecting to a Mac, what to do when it refuses
  you, and exactly what has been tested.
- **[docs/design.md](docs/design.md)** — how it is put together, why each dependency is
  there, and the traps that cost real time.
- **[docs/testing.md](docs/testing.md)** — standing up a real server to test against,
  and the harness mistakes that make correct code look broken.
- **[docs/roadmap.md](docs/roadmap.md)** — what is done, and what might come next.

## Building

```
cargo build --release
```

Produces `target/release/vncfree.exe` and `target/release/vncfree-server.exe`, with no
runtime to install.

Or grab them from [Releases](https://github.com/sp00nznet/vncfree/releases) — built by
CI straight from a tag, so nobody has to trust a binary from anywhere else.

## License

MIT. See [LICENSE](LICENSE). Free forever, for everyone. The whole point is that nobody
pays for this.
