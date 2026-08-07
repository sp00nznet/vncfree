# Security

What this program hands over, what protects it, and what does not. Written plainly
because a remote-desktop tool that is vague about this is not worth trusting.

## What the server actually gives away

**Everything the logged-in user can do.** Whoever gets past the password sees the
screen, moves the mouse, types, and reads and writes the clipboard, as that user. There
is no restricted mode, no per-permission model, and no audit trail beyond what the
server prints to its console. `VNC_VIEW_ONLY=1` is a *client-side* courtesy for the
person running the viewer; it is not a restriction the server enforces.

So the password is the whole boundary. Treat it as the password to that desktop,
because that is what it is.

## What protects it

| | |
|---|---|
| **In transit** | TLS 1.3, on by default, negotiated through VeNCrypt. The password is exchanged inside it. |
| **Server identity** | A self-signed certificate, kept across restarts. The client remembers it per address and refuses to connect if it changes. |
| **The password** | VNC authentication: a DES challenge-response. |
| **Guessing** | Each failure from an address pushes back when that address may try again, up to 30 seconds. |

## What does not protect it

- **The first connection to a server is taken on trust.** There is no certificate
  authority for a program someone started on a desktop five minutes ago, so the first
  certificate cannot be checked against anything. After that a change is refused. If
  the first connection matters, compare the fingerprints both ends print.
- **VNC authentication is weak.** DES, and only the first **8 characters** of the
  password are used at all — everything after that is ignored, so a 20-character
  passphrase is an 8-character password. It is the only scheme the protocol offers that
  every client understands, which is why it is here. Inside TLS the exchange is not
  visible to the network; without TLS it is, and a captured exchange can be attacked
  offline at leisure.
- **A server that offers both encrypted and unencrypted connections can be pushed to
  the unencrypted one** by somebody in the middle, because the choice is the client's
  and the list is not signed. `VNC_TLS=require` at either end removes the choice.
- **A Mac connection is not encrypted.** macOS offers Apple Diffie-Hellman, not
  VeNCrypt. That protects the credentials in transit and nothing else.
- **Nothing here defends the machine against the person who logged in.** If someone has
  the password they are that user.

## Do not put this on the internet

The dialog says so and this says so again. An 8-character DES password on a public port
guarding a whole desktop is not a defensible position, whatever the encryption is doing.
Tunnel it over SSH or a VPN, where the VNC password stops being the only thing between a
stranger and the machine.

## What has been hardened, and against what

These are the things the code does deliberately rather than by accident:

- **No length is trusted before the bytes behind it arrive.** Every length on this wire
  is a `u16` or `u32` chosen by the peer, and the obvious `vec![0; n]` hands four
  gigabytes of the process to anyone who sends four bytes saying so. On the client that
  was reachable *before any password was exchanged*, since a server states its refusal
  reason with one of these. Reads now grow as bytes actually turn up, so claiming four
  gigabytes costs the peer four gigabytes of sending.
- **Sizes that have a sane bound have one.** A screen (a claimed 65535x65535 desktop is
  a 17GB allocation), a pointer, a clipboard, and a line of text.
- **Every rectangle is checked against the framebuffer** before it is decoded into it,
  including a CopyRect's *source*, and every palette index and run length inside ZRLE
  and Tight. A malicious server should not be able to make the client write outside its
  own buffer or read a colour it was never sent.
- **The password comparison does not exit early**, so how long it takes says nothing
  about how much of the response was right.
- **Failed passwords are rate limited per source address**, and refused rather than
  delayed — holding the connection open on a timer would be a thread per attacker, which
  trades a defence against guessing for a cheaper way to exhaust the machine. One
  address guessing does not lock anyone else out.

## Where the risk is concentrated

`unsafe` is confined to the Windows API calls: screen capture, input injection and the
dialogs, all in `src/bin/server.rs` and `src/gui.rs`. It is driven by *local* values —
screen geometry, cursor bitmaps, window handles — not by anything off the wire. The
values a peer does control that reach it are a keysym, a pointer coordinate and a button
mask; the keysym goes through a total match with no indexing, and the other two are
scalars handed to Windows. There is no path from a network byte to a raw pointer.

`cargo audit` runs in CI against every push, so a published advisory against anything in
the dependency tree turns up there rather than in a user's hands.

## Reporting something

Open an issue. This is a small program with no users to coordinate with and nothing to
embargo, and a public issue gets it fixed faster than a private one.
