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

**Clipboard does not work against macOS.** It is verified working both directions
against TigerVNC, but macOS Screen Sharing neither applies our `ClientCutText` to its
pasteboard nor sends `ServerCutText` when its own clipboard changes — it appears to use
a proprietary extension instead. `VNC_DEBUG=1` shows the message going out.
