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

## Latency

RFB is request-driven: the server sends a frame only when the client has asked for
one. That makes *when* the client asks the whole story.

The client asks for the next frame the moment an update starts arriving — right after
reading the rectangle count, before decoding any of it. Waiting until the update is
decoded and copied leaves the server idle for all of that time, so every frame costs a
round trip **plus** the client's own work instead of overlapping the two. On a link
with real latency that is the difference between a session that feels live and one
that feels like a slideshow. `VNC_NO_PIPELINE=1` turns it off, which is worth having
because a server with the bug described next will stall if the client pipelines.

The client also copies only the regions an update actually touched into the buffer the
drawing thread reads. Copying the whole framebuffer is 8MB per frame at 1080p and 33MB
at 4K, nearly all of it unchanged.

**The server had a race that throttled every client.** It cleared the
"client wants a frame" flag *after* sending an update. A client that asks for the next
frame while the current one is still going out — which is what any client wanting more
than one frame per round trip does — had its request wiped by that store, and the
session stalled until it happened to ask again. The flag is now consumed before
capturing, so a request arriving mid-send survives. Measured on loopback with a
scrolling terminal, that alone took the frame rate from **1 fps to 20**.

That one is worth remembering as a shape: an atomic flag written by one thread and
cleared by another after a long operation will lose anything that arrives during the
operation. Consume it up front instead.

## Following a resolution change

The desktop can change size underneath a live session, and everything from the capture
surface to the client's framebuffer is built for the old one. The server polls the
screen size each frame, rebuilds the capture, and sends the DesktopSize
pseudo-encoding (-223) ahead of a full frame — size first, then the pixels that assume
it.

DesktopSize is not a picture. The rectangle header carries the new size and there is no
body, so the client has to act on it *before* the bounds check that every other
rectangle goes through: a screen that grew is by definition outside the framebuffer it
is replacing.

A client that never asked for -223 cannot be told, and there is no way to keep serving
it correctly. That session ends with an explanatory error, which is honest and lands
somewhere useful — a reconnect negotiates the new size properly, and vncfree's own
client reconnects by itself.

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
- **Windows reports a *move* only for things like a dragged window.** A terminal or a
  document scrolling comes back as ordinary dirty regions, so taking duplication's
  report at face value throws away the scroll detection and sends megabytes of pixels
  a CopyRect would have moved for nothing. Past an eighth of the screen changing it is
  worth spending a comparison to go looking. Measured on a scrolling terminal, that is
  the difference between about 170KB and 48KB per frame.
- **Duplication's rectangles describe the desktop, which does not include the cursor.**
  Nothing else would ever report that the pointer moved, so the cursor's own box is
  tracked and both where it was and where it now is are repainted. Otherwise it smears
  across the client's screen.

## Checking that the rectangles are honest

Trusting the capture to have reported every change is the whole point of using it, and
also how it would fail silently: a missed region leaves stale pixels on the client with
nothing to ever correct them. Under `VNC_DEBUG` the server does the comparison anyway
and reports any changed pixel the rectangles did not cover.

That check has to be pixel accurate. Asking whether each changed region sits inside a
*single* rectangle reports over a hundred false alarms in a few seconds, because two
adjacent rectangles routinely cover a region between them.
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
