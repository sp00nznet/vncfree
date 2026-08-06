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

## Ideas, not commitments

Roughly in the order they would earn their keep:

- ~~**Clipboard against macOS.**~~ Investigated and closed: macOS runs clipboard
  sharing over Apple Remote Desktop's channel on port 3283, not over VNC at all, so
  there is nothing to implement on the RFB side. See [macos.md](macos.md). A bridge
  over SSH using `pbcopy`/`pbpaste` would be a fraction of the effort if it is wanted.
- **Two-dimensional motion.** CopyRect currently covers vertical scrolling. A window
  dragged sideways still costs pixels. Best solved by taking move rectangles from the
  Desktop Duplication API rather than by searching for motion.
- **The two remaining ZRLE subencodings.** Plain and palette RLE, on top of the solid,
  packed-palette and raw forms the encoder already produces. Bytes, not compatibility.
- **Multi-monitor.** The server shares the primary display only. Duplication is already
  per-output, so most of the work is deciding what to do about a client that expects
  one rectangular screen.
- **Following a resolution change** while a client is connected. The client already
  handles the framebuffer resizing across a reconnect; the server just never tells it.
- **Non-US keyboard layouts.** Punctuation currently comes from a static US keysym
  table; minifb's character callback would handle the rest.
- **Older RFB versions.** 3.3 and 3.7 negotiate security differently. Only worth doing
  if something real turns out to refuse us.
- **Tight encoding.** Four persistent zlib streams and a JPEG decoder for a squeeze on
  top of ZRLE. Low value, high effort.
- **TLS.** Neither auth scheme encrypts the session. Tunnelling over SSH or a VPN is
  the honest answer today, and VeNCrypt would be the proper fix.
