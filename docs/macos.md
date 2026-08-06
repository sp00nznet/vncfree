# Connecting to a Mac

**Nothing needs changing on the Mac.** Turn on Screen Sharing and connect with your
macOS account — put the account's short name (what `whoami` prints) in the Username
box, or set `VNC_USERNAME`.

```powershell
$env:VNC_USERNAME = 'yourmacuser'
$env:VNC_PASSWORD = 'your account password'
vncfree 192.168.1.20:5900
```

Two macOS-specific things are handled:

1. **It announces `RFB 003.889`, not `003.008`.** vncfree replies `003.008`, which
   makes it fall back to standard RFB 3.8.
2. **Apple Diffie-Hellman authentication (security type 30)**, which is what Screen
   Sharing offers by default so it can check real macOS account credentials. The server
   sends a generator, key length, prime and its public key; we do the DH exchange, MD5
   the shared secret into an AES-128 key, and send back the username and password
   encrypted in a 128-byte blob followed by our public key. Full account passwords
   work — no 8-character DES limit.

If instead you enable "VNC viewers may control screen with password" on the Mac, that
switches it to standard VNC auth (security type 2), which also works — but those
passwords are DES and effectively 8 characters, silently truncated beyond that.

The Windows key sends `Super_L`, which macOS maps to **Command**, so Cmd-C and Cmd-Tab
work from a Windows keyboard. Alt sends `Alt_L`, which arrives as Option.

## "Authentication or authorization failure"

This appears *after* the Diffie-Hellman exchange has already succeeded, so it means the
Mac read your credentials and refused them — nothing is wrong with the protocol. The
cause is almost always Remote Management's own access list.

**Being in the `com.apple.access_screensharing` group is not sufficient.** On macOS
15.7.3 an account that could SSH in, was an admin, and was in that group was still
refused. What fixed it was System Settings → General → Sharing → **Remote Management**
→ ⓘ, switching "Allow access for" from *All users* to *Only these users* with the
account listed explicitly. Ticking Observe/Control for the account is worth checking
too.

The equivalent from a terminal:

```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -configure -users <shortname> -access -on -privs -all -restart -agent
```

If the security types offered include 33/35/36 but not 2, it is Remote Management that
is switched on rather than Screen Sharing. Run with `VNC_DEBUG=1` to see the server
version, the types offered and which one was chosen — none of that is otherwise
visible.

## What has actually been tested

**Confirmed working against real macOS 15.7.3 (Sequoia).** The server announces
`RFB 003.889`, we negotiate down to 3.8, it offers `[30, 33, 36, 35]`, we select 30,
the Diffie-Hellman exchange completes with generator 2 and a 128-byte key, and the
session authenticates and delivers a 1920x1080 desktop. Keyboard input reaches the Mac
— confirmed by typing into a login field over the connection.

The crypto is additionally covered by a round-trip test that plays the server side
(proving the DH maths, MD5-to-AES key derivation and blob layout), and the wire format
matches [neatvnc](https://github.com/any1/neatvnc)'s server-side implementation and the
[RFB protocol document](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst).

## Clipboard: why it cannot work over VNC

**macOS clipboard sharing is not part of its VNC service.** This was chased down rather
than guessed at, and the conclusion is that no amount of RFB work will get it.

What was established:

1. Our `ClientCutText` reaches the Mac (`VNC_DEBUG=1` shows it sent) and is ignored.
   The same message works both directions against TigerVNC, so the message itself is
   correct.
2. macOS never sends `ServerCutText`, however much its pasteboard changes.
3. Pointing macOS's **own** Screen Sharing client at `vncfree-server` and changing the
   Mac's clipboard produced no clipboard message either — not the standard one, and
   nothing unrecognised. Apple's client does not put the clipboard on the RFB
   connection at all.
4. The Mac listens on **port 3283, TCP and UDP**, alongside 5900. That is Apple Remote
   Desktop's control channel, and it is where clipboard, file transfer and remote
   commands live.

Both directions being silent is the tell: there is nothing to decode on 5900, because
the clipboard was never there. Supporting it would mean implementing Apple's
proprietary, undocumented ARD protocol on 3283 — a different protocol that happens to
ship alongside VNC, not an extension of it.

If you have SSH to the Mac (likely, if you are administering it), a small bridge using
`pbcopy` and `pbpaste` is a far better use of the effort than reverse engineering 3283.

### Getting text onto a Mac anyway: Ctrl-Shift-V

Since typing *is* something the protocol does, the client can type the clipboard
instead of sharing it. Copy on Windows, focus the vncfree window, press
**Ctrl-Shift-V**, and the text is sent one key at a time.

Deliberately not Cmd-V or Ctrl-V. Those still legitimately paste the *remote*
machine's own clipboard, which works, and taking them over would break something that
already worked. The modifiers you are holding are released on the remote first, or
every character would arrive as a shortcut.

It types at about a hundred characters a second and stops at 4000, so it is for a
password or a URL or a block of config, not for moving a file around. Text only, and
the remote has to have focus somewhere that accepts typing.

## Apple's pseudo-encodings

Captured by pointing macOS's Screen Sharing client at `vncfree-server` and logging what
it asked for:

```
1011, 1002, 6, 16, -239, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110
```

`6` is zlib, `16` is ZRLE, `-239` is Cursor and `-223` is DesktopSize. The rest are
Apple's own. Advertising them to the Mac's server makes it send them, and their bodies
begin with a `u16` length, so they can be stepped over without understanding them.
Decoded so far:

| Encoding | Contents |
|---|---|
| 1104 | Cursor. Rectangle carries the hotspot and size, with an empty body. |
| 1105 | Display geometry: pixel size, a scale factor as an IEEE-754 double, display id. |
| 1107 | Four 4-byte entries `10 08 fd 00` … `fd 03`. Looks like a capability list. |
| 1109 | Keyboard layout, as the string `com.apple.keylayout.US`. |
| 1110 | Machine model, as the string `iMacPro1,1`. |

None of them is the clipboard. They are recorded here because working this out took a
live Mac, and the next person should not have to repeat it.

## Talking to Apple's client

`vncfree-server` speaks RFB 3.3 as well as 3.8, because macOS's Screen Sharing client
asks for **3.3** and 3.3 has no security negotiation — the server states the type as a
`u32` and that is that. Without it, every Mac's built-in viewer is locked out. With it,
Screen Sharing.app connects and renders happily over ZRLE.
