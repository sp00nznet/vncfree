# Design notes

Why things are the way they are, and the traps that cost real time getting here.

## Shape

Rust, two self-contained executables, no runtime to install. Shared RFB protocol
pieces live in `src/lib.rs`; decoding a rectangle belongs to the client and encoding
one belongs to the server, so those stay in their own binaries. What they genuinely
share is the wire primitives, the framebuffer layout, the VNC-auth key derivation (one
side answers the challenge, the other sets it) and the clipboard text encoding.

```
src/lib.rs         shared protocol
src/gui.rs         the native dialog, shared
src/bin/client.rs  viewer
src/bin/server.rs  screen sharing
```

## Dependencies

Only where hand-rolling would be reckless:

| Crate | Why |
|---|---|
| `des`, `aes`, `md-5`, `num-bigint`, `getrandom` | The auth schemes. Ciphers and 1024-bit modular exponentiation are exactly the place where writing your own ships a subtly broken one. |
| `flate2` | ZRLE is deflate over run-length-encoded tiles. |
| `minifb` | A window and a `u32` framebuffer to blit into. Nothing else. |
| `arboard` | Clipboard, with the image-format support turned off. |
| `windows-sys` | Screen capture, input injection and the dialogs. |
| `windows` | Desktop Duplication only. It is COM, and `windows-sys` has no COM support — several hundred lines of hand-written vtable calls in unsafe code, against a crate that brings reference counting and `QueryInterface`. Worth it when the alternative is managing COM lifetimes by hand. |

RFB itself is hand-rolled over `std::net::TcpStream` — the spec is small and the crates
that wrap it are larger than the protocol. `aes` and `des` are pinned to the same
`cipher 0.4` generation so there is one copy in the tree rather than two.

The dialogs are plain Win32 rather than a UI toolkit. The whole interface is a few
labelled text boxes and a button; `egui` and friends would add hundreds of crates and
several megabytes to a program whose entire pitch is a small self-contained exe. They
cost no new dependencies at all, since `windows-sys` was already here for the server.

## One pixel format, no translation

Both ends force 32bpp little-endian with shifts 16/8/0, so a pixel is `0x00RRGGBB`.
That is also exactly minifb's buffer layout *and* exactly what a Windows 32bpp `BI_RGB`
DIB already contains, so there is no format-translation layer anywhere in the program.
The server still composes on the way out using whatever shifts the client asked for, so
an unusual client works too.

## Threading

Networking runs on its own thread. An incremental `FramebufferUpdateRequest` blocks for
as long as the remote screen is idle, and the UI thread must never block on that. The
two share one `Mutex<Screen>`.

Both threads write to the socket — update requests from one, input and clipboard from
the other — so the write half sits behind its own mutex. A half-written message would
desync the protocol permanently. It is an `Option<TcpStream>` that is only published
once the handshake fully succeeds, so input raised during a reconnect is dropped
instead of being written into a half-open connection.

The window only re-blits when a frame actually arrived. Pushing an unchanged 1080p
buffer 60 times a second is megabytes of scaling and GDI work for nothing, and it holds
the frame lock the network thread is waiting on.

## Things that bite

- **ZRLE's zlib stream spans the connection, not a rectangle.** Restarting it per
  rectangle decodes the first one correctly and then emits garbage forever. Both the
  decoder and the encoder keep one stream for the session.
- **`FlushCompress::Sync` never reports being finished.** Once input is drained it
  emits a fresh sync marker on every call, so a loop waiting for "no more output" spins
  forever. Flush exactly once. This cost 1767 seconds of CPU in a test helper before it
  was caught.
- **Input presses must be processed before releases.** A key tapped and released inside
  a single 60fps frame appears in both lists, and handling the release first sends an
  up against an empty held-map followed by a down that never gets released.
- **Releases must repeat the keysym captured at press time.** Letting go of shift first
  otherwise sends `A` down and `a` up, stranding the capital.
- **`SendInput` with `MOUSEEVENTF_ABSOLUTE` maps onto the *logical* desktop.** On a
  200% display every injected coordinate lands at half the intended position, because
  the framebuffer is in physical pixels. The pointer uses `SetPhysicalCursorPos`
  instead. Beware measuring this from a DPI-unaware process — `GetCursorPos` there
  reports logical coordinates and makes a correct fix look broken.
- **Neither capture route includes the cursor.** It is composited in by hand with
  `DrawIconEx`; a remote desktop with no visible pointer is close to unusable. Both
  routes fill the same DIB precisely so that one piece of code can do this.
- **Desktop Duplication reports pointer-only frames.** They carry no desktop image and
  their texture is empty, so copying one paints the screen black — which is exactly
  what it did until `LastPresentTime` was checked. On a mostly-idle desktop these are
  most of the frames.
- **Duplication reports changes, so the first frame has to come from somewhere.** It
  has nothing to report a change *from* until something is drawn, so the very first
  capture is a `BitBlt` and duplication updates it thereafter. Without that, a client
  connecting to an idle machine gets a black screen.
- **Output 0 is not necessarily the primary display.** `EnumOutputs` is in the
  adapter's order, not Windows'. The outputs are searched for one whose desktop
  coordinates start at the origin and match the screen size, because capturing the
  wrong monitor produces a perfectly valid image of entirely the wrong screen.
- **The GPU picks its own row stride**, usually wider than the image. Copying
  `width * height` in one go shears the picture; copy row by row.
- **A DIB's top byte is undefined.** Mask it, or pixels compare unequal frame to frame
  and every tile looks changed.
- **Scroll detection must look at the busiest column range, not the union of changed
  rectangles.** The union spans from the leftmost change to the rightmost, swallowing
  the static desktop in between; rows of that area differ from one another, so every
  row comparison fails and no scroll is ever found. Costing an hour of "why does this
  never fire".
- **Probe more than one row when hunting for a shift.** A terminal or a document is
  mostly background, so a single probe row frequently lands on a blank line whose
  matches are all unrelated blank lines elsewhere.
- **A scroll candidate is verified pixel by pixel before it is used.** Row hashes only
  nominate; a CopyRect built on a hash collision would corrupt the client's screen
  with no way for it to notice.
- **The dialog raises DPI awareness per *thread*, not per process.** That keeps it
  crisp at 200% without changing how the client's session window is treated. Per
  process would have altered a tested rendering path for a cosmetic gain.
- **Connecting has a 10 second timeout.** The OS default is around twenty seconds of
  nothing at all, which reads as the program having hung.

## Deliberate omissions

- **Tight encoding.** Four persistent zlib streams and a JPEG decoder, and ZRLE gets
  most of the win.
- **Two-dimensional motion search.** The server spots vertical scrolling, not a window
  being dragged sideways. Finding arbitrary movement is motion estimation, which is
  expensive to do and dangerous to get wrong; the Desktop Duplication API hands out
  move rectangles for free and is the right way in if this ever matters.
- **The two RLE ZRLE subencodings.** The encoder emits solid, packed palette and raw.
  The client decodes all five, so this only ever costs bytes, never compatibility.
- **Saved hosts.** A desktop shortcut with the arguments already does it, and a config
  file format is a lot of surface for no new capability.
- **A public IP readout in the server dialog.** Finding one means asking a third-party
  server, which sits badly with a program that promises no telemetry, and a label
  advertising where to reach a DES-authenticated VNC server is not a thing to put in
  front of people.

Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.
