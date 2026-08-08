# Roadmap

| # | Milestone | State |
|---|-----------|-------|
| 0 | RFB 3.8 handshake, VNC auth, Raw encoding, one frame to disk | done |
| 1 | Window: continuous incremental updates on screen | done |
| 2 | Input: keyboard + mouse back to the server | done |
| 3 | Apple Diffie-Hellman auth, so a Mac needs no setting changed | done |
| 4 | Encodings: CopyRect and ZRLE | done |
| 5 | Clipboard, automatic reconnect, view-only mode | done |
| 6 | A server: capture, input injection, clipboard | done |
| 7 | Server-side ZRLE, so the server is usable off the LAN too | done |
| 8 | A GUI for both, so neither needs a terminal | done |
| 9 | Go public, tag a release, attach the binaries | done |
| 10 | CopyRect on the server: send scrolling as a move, not as pixels | done |
| 11 | RFB 3.3, so macOS's own Screen Sharing client can connect to the server | done |
| 12 | Desktop Duplication capture, ~20x less CPU on an idle desktop | done |
| 13 | Dirty and move rectangles, so the framebuffer is not diffed against itself | done |
| 14 | Latency: pipelined requests, partial copies, and the server request race | done |
| 15 | Ctrl-Shift-V types the clipboard, for servers that will not share one | done |
| 16 | Following a resolution change, via the DesktopSize pseudo-encoding | done |
| 17 | Multi-monitor: `VNC_MONITOR=all` shares every display as one screen | done |
| 18 | The last two ZRLE subencodings, and costing all five instead of guessing | done |
| 19 | TLS, via VeNCrypt, so the session is not readable by anyone on the network | done |
| 20 | Client-side RFB 3.3 and 3.7, so old servers are not locked out either | done |
| 21 | Non-US keyboard layouts, via the layout Windows has already applied | done |
| 22 | Tight decoding, so servers that speak nothing better are not stuck on Raw | done |
| 23 | A remembered certificate per host, so a changed one is refused | done |
| 24 | Continuous updates, so the server stops waiting to be asked for each frame | done |
| 25 | A locally drawn pointer, so the mouse stops waiting for a round trip | done |
| 26 | A security pass: bounded reads, rate-limited passwords, a written threat model | done |
| 27 | An icon on each executable | done |
| 28 | Measuring where the time goes, and the server sleeping through half of it | done |

## Ideas, not commitments

Roughly in the order they would earn their keep:

- ~~**Clipboard against macOS.**~~ Investigated and closed: macOS runs clipboard
  sharing over Apple Remote Desktop's channel on port 3283, not over VNC at all, so
  there is nothing to implement on the RFB side. See [macos.md](macos.md). A bridge
  over SSH using `pbcopy`/`pbpaste` would be a fraction of the effort if it is wanted.
- **CursorPos (-232), so a pointer moved at the far end is visible again.** Drawing the
  pointer locally is what makes it feel instant, and the cost is that the remote
  machine's own mouse movement no longer shows. This is the pseudo-encoding that puts
  that back without giving up the latency.
- **Tight *encoding*, on the server.** The client decodes it now; producing it means a
  JPEG encoder, for a squeeze on top of the ZRLE the server already sends. Low value,
  high weight.
- **A way to verify the *first* connection.** Trust on first use catches anyone who
  starts intercepting later, but the first certificate from a host is still taken on
  faith. Comparing the printed fingerprints by hand is the only answer today. Anything
  better means a shared secret or an authority, and the password is already the shared
  secret - deriving the certificate from it is the interesting idea here.
