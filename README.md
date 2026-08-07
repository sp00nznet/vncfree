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
| `VNC_TLS` | `offer` (default), `require` or `off`. On the client, `require` refuses to connect to a server that will not encrypt. |
| `VNC_RAW_ONLY=1` | Disable ZRLE and CopyRect. Answers "is it my decoder or the server?" |
| `VNC_DEBUG=1` | Print the negotiated version, security types and clipboard traffic. |
| `VNC_CAPTURE=gdi` | Server only. Force `BitBlt` instead of Desktop Duplication. |
| `VNC_MONITOR=all` | Server only. Share every display as one screen, not just the primary. |
| `VNC_NO_PIPELINE=1` | Client only. Ask for each frame only after decoding the last. Slower; for servers that mishandle an early request. |

Credentials come from the environment rather than the command line, because argv is
visible to every process on the machine.

## What it does

| | |
|---|---|
| **Client** | Live window, keyboard, mouse, shared clipboard, automatic reconnect with backoff, view-only mode. **Ctrl-Shift-V** types the local clipboard at the remote machine, for servers that will not share one |
| **Server** | Desktop Duplication capture with the cursor, keyboard and mouse injection, clipboard, mandatory password. An idle desktop costs about 20x less CPU than the `BitBlt` it falls back to |
| **Encodings** | Raw, CopyRect, ZRLE. A full 3840x2160 screen is 33,177,616 bytes as Raw and 258,871 as ZRLE — 0.8%, a 128x reduction. Scrolling is sent as a move: one measured run shifted 3,974,784 pixels for 64 bytes |
| **Authentication** | VNC (DES) and Apple Diffie-Hellman, so a **Mac needs nothing changed** |
| **Encryption** | TLS 1.3 over VeNCrypt, on by default, with the password exchanged inside it. `VNC_TLS=require` refuses to fall back |
| **Verified against** | TigerVNC, real macOS 15.7.3 Screen Sharing, macOS's own client, and itself |

Both ends speak RFB 3.3, 3.7 and 3.8. That means **the viewer built into every Mac can
connect to the server** — Screen Sharing.app asks for 3.3 and would otherwise be locked
out — and the client is not fussy about what it connects to either.

**The server will not start without a password.** An open VNC port hands the whole
desktop to anyone who can reach it, and defaulting to "no password" is exactly the
decision that makes remote-access software dangerous. It offers only VNC
authentication, so there is no unauthenticated path at all.

## Known limits

- **TLS encrypts the session but does not prove who is on the other end.** Both ends
  print the certificate's fingerprint; if they match, nobody is sitting in the middle.
  Nothing checks that for you, because there is no certificate authority for a program
  someone started on a desktop five minutes ago. A server that offers both encrypted
  and unencrypted connections can also be pushed to the unencrypted one by someone in
  the middle — `VNC_TLS=require` at either end removes that choice. **Still don't
  port-forward this to the internet**: tunnel over SSH or a VPN.
- **Encryption needs both ends to be vncfree.** VeNCrypt's other TLS modes use
  anonymous Diffie-Hellman, which cannot detect anyone in the middle at all and which
  no current TLS library implements; vncfree speaks the X509 form instead. Against
  another client or server the connection falls back to plain VNC auth, which is DES
  and weak by modern standards.
- **A Mac connection is not encrypted.** macOS offers Apple Diffie-Hellman, not
  VeNCrypt. That protects the credentials in transit but not the session.
- **Clipboard does not work against macOS, and cannot.** It works both directions
  against TigerVNC, but macOS puts clipboard sharing on Apple Remote Desktop's own
  channel (port 3283) rather than on the VNC connection — established by watching both
  directions and Apple's own client. **Ctrl-Shift-V types the local clipboard at the
  remote machine instead**, which works anywhere. See [docs/macos.md](docs/macos.md).
- No Tight encoding, and the server's CopyRect covers vertical scrolling but not a
  window dragged sideways. Compatibility is unaffected — these cost bytes, not
  connections.
- The server shares the primary monitor by default; `VNC_MONITOR=all` shares every
  display as one screen. **That has not been tested against a real second monitor** —
  only one display was attached to the development machine — and sharing more than one
  falls back to `BitBlt`, because Desktop Duplication works per output.
- The server follows a resolution change, but a client that did not ask for
  DesktopSize cannot be told, so that session ends and has to reconnect — vncfree's own
  client reconnects by itself.
- **Ctrl and Alt shortcuts assume a US layout.** Ordinary typing follows whatever
  layout Windows is set to, including AltGr and dead keys, but a shortcut is sent by
  physical key position — Ctrl-C is the key where a US keyboard has C. That is usually
  what people want from a shortcut and is what most viewers do.
- Holding a character key sends repeats rather than one long press, because Windows
  reports the repeats. Fine for typing, not for holding a key down in a game.

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
