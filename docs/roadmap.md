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

## Ideas, not commitments

Roughly in the order they would earn their keep:

- **CopyRect on the server.** Dragging a window currently costs real bytes instead of a
  "copy this block from over there" instruction. Cheap to add, immediately visible.
- **Clipboard against macOS.** Works both directions against TigerVNC; macOS appears to
  use a proprietary extension instead of the standard messages. Needs reverse
  engineering, or Apple's extended clipboard pseudo-encoding.
- **The two remaining ZRLE subencodings.** Plain and palette RLE, on top of the solid,
  packed-palette and raw forms the encoder already produces. Bytes, not compatibility.
- **Desktop Duplication API for capture.** GDI `BitBlt` is simple and works everywhere;
  DXGI is faster and hands back dirty rectangles, which would pair well with the tile
  diffing already in place.
- **Multi-monitor.** The server shares the primary display only.
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
