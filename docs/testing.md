# Testing

```
cargo test
```

Everything below is about testing against something real, which is where the actual
bugs were.

## A real server to point at

Any RFB 3.8 server works. What this repo is developed against, via WSL:

```sh
sudo apt-get install -y tigervnc-standalone-server x11-xserver-utils
Xtigervnc :1 -geometry 800x600 -depth 24 -SecurityTypes None -rfbport 5900 &
DISPLAY=:1 xsetroot -solid "rgb:20/40/80"     # a known colour to verify against
```

Then `vncfree 127.0.0.1:5900 test.ppm` and check the PPM's pixels are `20 40 80`. A
red/blue channel swap shows up immediately as `80 40 20`, which a screenshot-only check
would miss.

Pass colours as `rgb:20/40/80`, **not** `#204080`. PowerShell strips `#` from
native-command arguments, and the resulting silent `xsetroot` failure looks exactly
like a broken decoder — a black screen.

## Checking an encoding is right

Grab the same screen twice, once with `VNC_RAW_ONLY=1` and once without, and compare
the files. They must be byte-identical. Take a third Raw grab to prove the screen was
static, otherwise a difference might just be the clock ticking.

That is how the client's ZRLE decoder and the server's ZRLE encoder were both checked:
identical output at 3840x2160, with the debug line confirming which encoding was
actually negotiated. Without that confirmation the comparison passes trivially when the
server quietly falls back to Raw.

## Traps in the test harness itself

These each cost real time, and each one made correct code look broken:

- **Synthetic Windows input does not reach these windows.** `SendKeys`, and `SendInput`
  even when it reports every event accepted, reached neither the minifb session window
  nor the Win32 dialogs on the development machine. Test input by typing at it
  yourself, or by driving the RFB messages directly over a socket. An automated
  key-injection harness will look like a broken client when it is really a broken test.
- **Measure DPI-sensitive things from a DPI-aware process.** `GetCursorPos` in a
  DPI-unaware script reports logical coordinates, so a correctly injected pointer looks
  like it landed at half the right position. The authoritative reading came from
  querying the cursor *inside* the DPI-aware server, where the set and the read share a
  coordinate space.
- **An idle Xtigervnc can pin its pointer.** With no client connected it overrode
  `xdotool mousemove` entirely. Confirm that behaviour with vncfree *not* running before
  concluding the client mis-mapped a coordinate.
- **`pbpaste` over SSH needs a full path or a login shell**, and quoting through
  PowerShell → WSL → SSH mangles enough that a missing binary reads as an empty
  clipboard. Pipe a script file to `bash -s` rather than nesting quotes three deep.
- **`cargo` writes progress to stderr.** In PowerShell 5.1, `2>&1` on a native command
  poisons `$?`, so a green build reports failure. Do not trust `$?` after redirecting.

## Verifying the Mac path

Requires a real Mac; see [macos.md](macos.md) for what has been confirmed and what has
not. `VNC_DEBUG=1` prints the negotiated version, the security types offered and which
one was chosen, which is the only way to see why a Mac refused a connection.
