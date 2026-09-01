# Why these projects exist

There is a category of Windows software that should not be a market.

It has a shape, and once you have seen it you cannot stop seeing it:

1. **The problem is solved and the solution is published.** RFB is a protocol
   from 1998. MS-PST is a several-hundred-page specification Microsoft puts on
   its own website. SCSI MMC, VSS, VHDX, `AttachVirtualDisk`, the ATA and NVMe
   sanitize commands — documented, stable, and in most cases already sitting
   inside Windows, paid for, waiting to be called.
2. **Somebody charges $50–$300 for the integration anyway.** Not for research,
   not for a hard algorithm. For wiring together published things and putting a
   three-pane window on top.
3. **The payment prompt is placed where it hurts most.** The tool reads your
   dead mailbox and shows you your own email — then asks for money before it
   will save it. The backup software makes the image for free and paywalls the
   restore. The recovery tool lists the files it found and charges to copy them
   out. The price is not attached to the work. It is attached to your worst day.

Step 3 is the part worth being angry about. Every one of those products is
perfectly legal and most are competently written. But charging at the exact
moment someone has lost their mail, their drive, or their only copy of
something is not selling a tool. It is selling relief from a situation you are
already in, and the shape of that transaction has more in common with a ransom
note than its vendors would like to admit. The difference — an important one —
is that these companies did not cause the disaster. They just queue up next to
it.

None of that requires a conspiracy. It is what happens when a solved problem
meets an audience that is panicking and does not know the spec is public.

## So: read the spec, call the API, give it away

That is the entire method. There is no clever part.

- Read the published specification, or the documented OS API, or both.
- Implement it properly, and check the result against the reference
  implementation rather than against our own parser.
- Ship one executable. No installer, no service, no account, no telemetry, no
  nag screen, no crippled free tier, no feature that exists only to be
  withheld.
- Say plainly what is *not* proven yet, instead of letting a feature list imply
  it.
- MIT. Forever.

If any of these projects ever grows a "pro" edition, a licence key, or a
progress bar that stops at 90%, something has gone wrong and you should fork it.

## On somebody reselling this

MIT means anyone can take this code, rename it, wrap it in an installer and
charge for it. That is not a loophole, it is the licence working as intended,
and it is fine.

The defence was never the licence. The defence is that the free original stays
up, stays buildable, and stays easy to find. Someone can sell a copy of this;
nobody can make the free one stop existing. If you paid for something that
turned out to be one of these projects with a new icon, you were not robbed of
anything except money you did not need to spend — and the source you already
own is right here.

## What this is not

This is not an argument that software should be free, that developers should
work unpaid, or that every paid tool is a scam. Plenty of software earns its
price. Commercial support, hardware, integration work and genuinely hard
engineering are all worth paying for.

The complaint is narrower and it is specific: **a published spec, plus an OS
feature you already own, plus a paywall on the restore button.** That is the
thing these projects exist to delete.

Where a genuinely free and open alternative already exists and is good, it gets
credited in the README rather than competed with — TigerVNC, libpff and others
got there first, and said so out loud.

## The projects

| | |
|---|---|
| [bulkhead](https://github.com/sp00nznet/bulkhead) | Block-level backup, recovery and certified secure erase for Windows. Imaging via VSS and VHDX, partition rebuild, undelete and carve, ext2/3/4 + XFS + HFS+ reading. |
| [futureburn](https://github.com/sp00nznet/futureburn) | CD/DVD/Blu-ray burning, ripping, image conversion and mounting. CLI and GUI. |
| [pstfree](https://github.com/sp00nznet/pstfree) | Read, export and repair Outlook PST/OST files. No Outlook, no licence, no password prompt. |
| [vncfree](https://github.com/sp00nznet/vncfree) | VNC client *and* server for Windows. No subscription, no ad-gated download. |

Same attitude, same licence, same promise: nobody pays for this.
