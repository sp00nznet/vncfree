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
src/wire.rs        the transport: a socket, or a socket with TLS over it
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
| `rustls`, `rcgen`, `sha2` | TLS, the self-signed certificate it presents, and the fingerprint of it. Built with `ring` rather than `aws-lc-rs` so the build needs no cmake or nasm. |
| `jpeg-decoder` | Client only. Tight rectangles can arrive as JPEG, and a baseline JPEG decoder is not a thing to hand-roll. Default features off, so it brings no thread pool. |
| `embed-resource` | Build only. A Windows icon is a linked resource, and this one gives each binary a *different* one. Failure downgrades to a warning — see [assets/README.md](../assets/README.md). |
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

Continuous updates (-313) remove the request from the loop entirely: the server sends
changes as they happen and the client stops asking. There is no field anywhere that
advertises server support — an unprompted `EndOfContinuousUpdates` *is* the
announcement, and a client that has never heard of it simply ignores an unknown message
type, which is what makes the offer safe to make to anyone.

That saving is invisible on loopback, where the round trip it removes costs nothing, and
a frame-rate comparison there measures noise. It is worth exactly one round trip per
frame, which is the whole point on a link that has any.

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

## Tight, and why only one direction

The client decodes Tight; the server does not produce it. That asymmetry is the whole
point of implementing it. Plenty of servers speak Tight and not ZRLE — TightVNC's own
among them — and against those the client used to fall all the way back to Raw. Going
the other way buys nothing: our server already sends ZRLE, which is a comparable size
and lossless, and encoding Tight properly means carrying a JPEG *encoder*.

The format is fiddlier than ZRLE and most of the fiddliness is silent:

- **TPIXEL is red, green, blue.** ZRLE's CPIXEL, in the same decoder, is blue, green,
  red — it keeps the byte order of the pixel format, while Tight's spec states the
  order outright. Reusing the ZRLE reader swaps every red and blue and still decodes
  perfectly cleanly.
- **Four zlib streams**, each spanning the connection like ZRLE's one, with the server
  restarting whichever it likes via the low nibble of the control byte.
- **The palette is not compressed.** It sits between the filter byte and the compressed
  block, so it has to be read before the block's length is even known.
- **Under twelve bytes nothing is compressed and no length is sent** — the rectangle's
  own size says how much there is. A small rectangle takes a different path through the
  decoder than a large one containing the same picture.
- **Two-colour palettes are one bit per pixel with every row padded to a byte**, so a
  rectangle whose width is not a multiple of eight is where that goes wrong.

Because a decoder can pass by never being handed the hard cases, `VNC_DEBUG` prints
which form each rectangle used, and [testing.md](testing.md) records how to make a real
TigerVNC send each one.

JPEG is the only lossy thing vncfree will ever display, and only because a server chose
to send it. The client does not ask for a quality level unless told to, which is what
keeps TigerVNC sending lossless Tight; `VNC_QUALITY` is there for a link slow enough
that the trade is worth making.

## Keyboard layouts belong to Windows, not to us

minifb identifies keys by **scancode**, so `Key::Key2` is the key in that physical
position whatever is printed on it. Which character that produces is the layout's
business: on a UK keyboard that key is `"` rather than `@`, and on a German one `@` is
not reachable without AltGr at all. A table can only ever encode one layout, and the
one it encoded was US.

Windows has already applied the layout, the dead keys and AltGr by the time it sends
`WM_CHAR`, so anything that produces a character now takes its keysym from there —
minifb's input callback — and the table is left to the keys that produce no character.
Each key must take exactly one of those routes: on both it types twice, on neither it
does nothing, and both read as a broken keyboard rather than a mismatched list, so a
test pins the two lists against each other.

Three things this has to get right:

- **Ctrl and Alt still use the table.** Ctrl-C should be Ctrl-C wherever the C key
  physically sits, and Windows reports the character for a Ctrl combination as an
  unusable control code anyway.
- **AltGr is right Alt plus a synthetic left Ctrl.** Forwarding those would turn every
  AltGr character into a Ctrl-Alt shortcut on the far end, so while AltGr is down the
  modifiers it invents are held back and only the character reaches the server.
- **`WM_CHAR` does deliver control codes**, whatever minifb's documentation says, so
  they are filtered here. Enter, Tab, Backspace and Escape are keys, and letting the
  control code through as well would send each of them twice.

Characters go down and straight back up, because the callback reports that something
was typed rather than that a key is being held — Windows repeats it by itself while the
key stays down. That is right for typing and wrong for holding a key down in a game,
which is not what this is for.

## The three RFB versions, and where they differ

Both ends speak 3.3, 3.7 and 3.8. The version reply is a *choice* and may not exceed
what the server offered, so a 3.3 server has to be answered with 3.3; anything at or
above 8 is answered with 8, which is what makes Apple's `RFB 003.889` fall back to
behaving like an ordinary 3.8 server.

The differences are small and every one of them fails the same way — a client waiting
for bytes that are never coming, against a server waiting for the bytes it should have
sent instead. That reads as a hung network rather than a protocol mistake:

- **3.3 states the security type in one word rather than offering a list**, and takes no
  answer. Sending the one-byte choice anyway puts a stray byte exactly where the server
  expects ClientInit.
- **Before 3.8, a security type of None is followed by nothing at all.** The
  initialisation phase starts immediately, so waiting for a SecurityResult deadlocks.
- **A failed SecurityResult carries a reason string only from 3.8.** Older servers just
  hang up, so asking for the reason turns a clear "wrong password" into a stall.

Because every one of those is a deadlock rather than a wrong answer, `tests/` stands up
a real server of each version and runs the actual client binary through a whole session
against it, down to checking the pixels that come out the other end. Those servers set
a read timeout for the same reason: without one, a regression would hang the test suite
instead of failing it.

## TLS, and the one thing it cannot do

The session is encrypted with TLS 1.3, negotiated through VeNCrypt (security type 19)
and using the X509Vnc subtype: TLS first, then the ordinary VNC password exchange
inside it.

VeNCrypt's other TLS subtypes authenticate the server with **anonymous**
Diffie-Hellman. That encrypts the traffic and offers no way whatsoever to tell whether
you are talking to the server or to someone relaying for it, which is why no current
TLS library implements it — rustls included. A self-signed certificate is the same
amount of trust with a fingerprint attached that can actually be compared, so that is
what this uses.

The client accepts whatever certificate it is shown on the **first** connection to an
address. That reads like a hole and is worth being exact about: there is no certificate
authority for a program somebody started on a desktop five minutes ago, so refusing
unsigned certificates would mean refusing every server. The choice is not between
trusting it and verifying it, it is between trusting it and staying unencrypted.
Signatures are still checked properly — skipping those would let anyone replay a
certificate they hold no key for, which is weaker again.

What closes most of the gap is remembering it. The fingerprint goes into `known_hosts`,
and a later connection showing a different one is **refused**, not warned about, because
a warning that can be clicked past is one that will be. That is SSH's model and it has
the same limit: the first connection is still taken on faith, but anyone who starts
intercepting an established connection is caught.

For that to be worth anything the server's identity has to hold still, so its
certificate is made once on first run and kept in `server-cert`. This is the only reason
the program writes anything to disk at all. A certificate regenerated per connection
gives a different fingerprint on every reconnect, and one regenerated per *start* cries
wolf after every ordinary restart — a check that fires constantly for innocent reasons
is one people learn to ignore, which is worse than no check. `VNC_STATE=off` restores
the write-nothing behaviour, at the cost of both properties.

Two files, both plain and both deletable, and the format of the certificate blob is a
length-prefixed pair of DER blobs rather than PEM: rcgen hands out DER and rustls takes
DER, so going via PEM would mean carrying a base64 decoder to read back something no
person needs to read.

Both ends default to *offering* encryption rather than requiring it, because a client
that has never heard of VeNCrypt still has to be able to connect — macOS's own viewer
speaks RFB 3.3, which has no security negotiation at all. That leaves a downgrade open:
anyone in the middle can strip the encrypted option from a list that also contains an
unencrypted one. `VNC_TLS=require` removes the choice, at either end.

### The transport is two halves, not one stream

Everything above `src/wire.rs` reads and writes through `impl Read` and `impl Write`
and never learns which it got. That is the only reason TLS was a contained change: the
protocol code did not move.

What did have to change is how the two halves are obtained. Both programs run a reader
and a writer concurrently and used to get them by duplicating the socket with
`try_clone`. A TLS session cannot be duplicated — rustls keeps one connection object
holding the state for both directions. So each half keeps its own socket handle and
they share the session behind a mutex, which means the blocking wait for bytes still
happens *outside* the lock and only the encryption and decryption are serialised. A
reader parked on an idle screen must never be able to stop the other thread sending a
mouse movement, and there is a test that fails if that inverts.

Three things in rustls's low-level API cost real time here, all of which produce
symptoms that point somewhere else entirely:

- **It caps the plaintext it will buffer** — 64KB by default — and then accepts no
  more. A framebuffer update is routinely larger, so handing it a whole frame fails
  partway with `failed to write whole buffer`, which reads as a network fault. Fill,
  flush to the socket, repeat.
- **`read_tls` takes only as much ciphertext as it can hold**, which is regularly less
  than one socket read returned. Dropping the remainder corrupts the stream from that
  point on, and it surfaces as a decrypt failure much later, with nothing pointing at
  the read that lost the bytes.
- **`read_tls` and `process_new_packets` must alternate.** Two reads in a row fail with
  `message buffer full`.

Each of those was found by a test that now stays: a 300KB write, a message split across
records, and a blocked reader that must not block a writer.

## Costing the ZRLE subencodings instead of guessing

Every one of ZRLE's five subencodings is legal for every tile, so the encoder has to
choose. The obvious way is a rule of thumb — "few enough runs, use RLE" — and it is
wrong in a way that never shows up: the output stays perfectly valid, so a threshold
tuned on one kind of picture quietly picks a form several times too big for another.
An early gate here would have sent a two-colour tile as palette RLE at roughly five
times the size of the bit-packed form it should have used.

So each form is *costed* in bytes from the palette and the runs, both of which are
counted once, and the cheapest wins. It is less code than the thresholds it replaced
and there is nothing left to tune.

The costing is also what decides how far the palette scan runs. The packed form
indexes at most 16 colours, but palette RLE indexes up to 127, so the scan goes to 127
— a tile with 40 colours arriving in runs is far better off indexed than spelled out.
That is the band where palette RLE earns its keep at all: below 17 colours the packed
form is almost always smaller, and above 127 there is no palette to index.

Measured against the same pixels on a real desktop, the two new forms take about 3–5%
off a full frame. Modest, because a desktop full of photographs and antialiased text
has few long runs; flat-coloured content is where they pay.

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
- **Saved hosts.** A desktop shortcut with the arguments already does it, and a config
  file format is a lot of surface for no new capability.
- **A public IP readout in the server dialog.** Finding one means asking a third-party
  server, which sits badly with a program that promises no telemetry, and a label
  advertising where to reach a DES-authenticated VNC server is not a thing to put in
  front of people.

Deliberate shortcuts are marked `// ponytail:` in the source with their upgrade path.
