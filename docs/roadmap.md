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

## Ideas, not commitments

Roughly in the order they would earn their keep:

- ~~**Clipboard against macOS.**~~ Investigated and closed: macOS runs clipboard
  sharing over Apple Remote Desktop's channel on port 3283, not over VNC at all, so
  there is nothing to implement on the RFB side. See [macos.md](macos.md). A bridge
  over SSH using `pbcopy`/`pbpaste` would be a fraction of the effort if it is wanted.
- **Non-US keyboard layouts.** Punctuation currently comes from a static US keysym
  table; minifb's character callback would handle the rest.
- **Client-side RFB 3.3 and 3.7.** The server speaks 3.3 so macOS's viewer can connect;
  the client still requires 3.8 or later from a server. Worth doing if something real
  turns out to refuse us.
- **Tight encoding.** Four persistent zlib streams and a JPEG decoder for a squeeze on
  top of ZRLE. Low value, high effort.
- **Somewhere to keep a known fingerprint.** TLS is in, but the certificate is
  self-signed and comparing the two printed fingerprints is a manual step. Remembering
  one per host, the way SSH does, would make a changed certificate something the
  program notices rather than something the user has to. It needs a file on disk, which
  is a promise this program currently makes a point of not breaking.
