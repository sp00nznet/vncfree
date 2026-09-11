# Windows setup: one-click connections and surviving a reinstall

`vncfree.exe` itself needs nothing installed - see the main
[README](../README.md). This is about the layer most people want on top of
that: a saved password and a desktop/Start Menu icon per Mac, set up so a
Windows reinstall costs five minutes to recreate rather than losing the
whole arrangement.

## Set up one Mac

```powershell
powershell -ExecutionPolicy Bypass -File scripts\add-mac.ps1 -MacHost okzulu2.local -User yourmacusername
```

This prompts for the password once (never typed anywhere it would persist -
not a script argument, not chat, not shell history), then:

- saves it at `~\.vncfree\<host>.pw.txt`, encrypted with this Windows
  account's own DPAPI key
- installs `scripts\vnc-connect.ps1` and `scripts\vnc-save-credential.ps1`
  into `~\bin`
- writes a no-argument wrapper, `~\bin\vnc-<host>.ps1`
- creates a Desktop and Start Menu shortcut pointing at that wrapper, using
  `vncfree.exe`'s icon

Run it again for every other Mac. Pinning a shortcut to the taskbar is a
manual step (right-click it → **Pin to taskbar**) - Microsoft removed the
way to do that from a script.

## Why the password doesn't survive a reinstall

DPAPI encryption is tied to the specific Windows installation and user
profile that created it. Reinstalling Windows - even "keep my files" - gets
you a new DPAPI key, so `~\.vncfree\*.pw.txt` from before decrypts to
nothing. That's by design: the alternative is a password sitting in plain
text somewhere, which is worse.

Nothing is actually lost, though - the fix is `add-mac.ps1` again, once per
Mac, which is a password prompt and a few seconds.

## Recovering after a reinstall

```powershell
git clone https://github.com/<your-fork>/vncfree
cd vncfree
cargo build --release
powershell -ExecutionPolicy Bypass -File scripts\add-mac.ps1 -MacHost okzulu2.local -User yourmacusername
# repeat add-mac.ps1 for every other Mac
```

That's the whole recovery: nothing about this setup lives anywhere but the
repo (which carries its own scaling fix - see below) and the one Windows
feature that cannot be exported, DPAPI.

## Smart App Control

Windows 11 ships with Smart App Control, which spends a while in
"Evaluating" learning what you run, then locks itself to permanently On or
Off. Once On, it blocks unsigned executables outright - including anything
you build yourself with `cargo build` - and there is no per-app exception
list and no supported way to turn it back off short of reinstalling
Windows. A self-signed certificate trusted in your own local certificate
store does not satisfy it; only a certificate that chains to a CA it
already recognises does.

If you build `vncfree` yourself rather than using a
[release](https://github.com/sp00nznet/vncfree/releases) - which are built
by CI and not something Smart App Control has any reason to trust more -
and it gets blocked, that's this feature, working as designed. The
practical options are the same two as any locally-built unsigned tool on a
locked machine: buy a real code-signing certificate, or turn Smart App
Control off while it is still in its evaluation window, immediately after a
fresh install, before it locks.

## Why the window needed a scaling patch

Not really "setup," but the reason `cargo build` on this project pulls in a
vendored copy of `minifb` rather than the plain crates.io one: connecting
to a Retina Mac hands over a framebuffer at its full physical pixel count -
double what its resolution setting looks like, in each direction - and the
session window opens sized to fit the local screen rather than that full
buffer. `minifb`'s Windows backend draws that scaled-down picture through
GDI's `StretchDIBits` without ever setting a stretch mode, which defaults
to dropping and duplicating pixels with no filtering - fine at 1:1, visibly
grainy at any other scale. The vendored copy under `vendor/minifb-0.28.0`
sets `HALFTONE` before the stretch instead. See `Cargo.toml`'s
`[patch.crates-io]` section.
