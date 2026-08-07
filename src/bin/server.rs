//! vncfree-server - a free VNC (RFB) server for Windows.
//!
//! Shares your screen and accepts keyboard and mouse. No installer, no service, no
//! account: run the exe, it serves while it is running, close it and nothing is left
//! behind. A password is mandatory - see the note in `run`.
//!
//! Capture is Desktop Duplication where it is available and GDI BitBlt otherwise,
//! both landing in a DIB that already holds 0x00RRGGBB pixels, so the framebuffer
//! needs no conversion. Input is injected with SendInput.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress};
use vncfree::{blob, cut_text_msg, debug, from_latin1, rd, u16r, u32r, u8r, vnc_des};
use vncfree::{Res, Screen, PIXEL_FORMAT};

mod dxgi {
    //! Screen capture through Desktop Duplication.
    //!
    //! `BitBlt` copies the whole screen every time it is asked, whether or not
    //! anything changed, and then the framebuffer has to be diffed to find out what
    //! did. Desktop Duplication instead hands over a frame only when the desktop
    //! actually changes, which is both faster and quieter on an idle machine.
    //!
    //! This is COM, so the objects here are reference counted and released in the
    //! order they are dropped. Failure is normal and expected - see the caller.

    use vncfree::Res;
    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::Win32::Graphics::Direct3D11::*;
    use windows::Win32::Graphics::Dxgi::Common::*;
    use windows::Win32::Graphics::Dxgi::*;

    pub struct Duplicator {
        w: usize,
        h: usize,
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        dupl: IDXGIOutputDuplication,
        /// A CPU-readable copy target. The duplicated frame lives in GPU memory that
        /// cannot be mapped directly, so each frame is copied into this first.
        staging: ID3D11Texture2D,
        holding: bool,
    }

    impl Duplicator {
        pub fn new(ox: i32, oy: i32, w: usize, h: usize) -> Res<Duplicator> {
            unsafe {
                let mut device = None;
                let mut context = None;
                D3D11CreateDevice(
                    None,
                    D3D_DRIVER_TYPE_HARDWARE,
                    windows::Win32::Foundation::HMODULE::default(),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )?;
                let device: ID3D11Device = device.ok_or("no D3D11 device")?;
                let context: ID3D11DeviceContext = context.ok_or("no D3D11 context")?;

                // Walk device -> adapter -> outputs, and take the one that actually is
                // the primary display. Output 0 is not necessarily it: with more than
                // one monitor the enumeration order is the adapter's, not Windows'.
                // Capturing the wrong monitor produces a perfectly valid image of
                // entirely the wrong screen.
                let dxgi_device: IDXGIDevice = device.cast()?;
                let adapter = dxgi_device.GetAdapter()?;
                let mut chosen = None;
                for i in 0.. {
                    let Ok(output) = adapter.EnumOutputs(i) else {
                        break;
                    };
                    let desc = output.GetDesc()?;
                    let r = desc.DesktopCoordinates;
                    let (ow, oh) = ((r.right - r.left) as usize, (r.bottom - r.top) as usize);
                    if super::debug() {
                        eprintln!("[debug] dxgi output {i}: {ow}x{oh} at {},{}", r.left, r.top);
                    }
                    // Duplication covers one output, so it can only serve a shared
                    // region that is exactly one monitor - the same one, in the same
                    // place. Sharing several monitors matches nothing here and falls
                    // back to BitBlt.
                    if r.left == ox && r.top == oy && ow == w && oh == h {
                        chosen = Some(output);
                        break;
                    }
                }
                let output = chosen.ok_or_else(|| {
                    format!("no single output matches the shared region {w}x{h} at {ox},{oy}")
                })?;
                let output1: IDXGIOutput1 = output.cast()?;
                let dupl = output1.DuplicateOutput(&device)?;

                // BGRA to match the DIB exactly, so the copy out is a straight memcpy
                // per row rather than a per-pixel shuffle.
                let desc = D3D11_TEXTURE2D_DESC {
                    Width: w as u32,
                    Height: h as u32,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    SampleDesc: DXGI_SAMPLE_DESC {
                        Count: 1,
                        Quality: 0,
                    },
                    Usage: D3D11_USAGE_STAGING,
                    BindFlags: 0,
                    CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                    MiscFlags: 0,
                };
                let mut staging = None;
                device.CreateTexture2D(&desc, None, Some(&mut staging))?;
                let staging = staging.ok_or("no staging texture")?;

                Ok(Duplicator {
                    w,
                    h,
                    device,
                    context,
                    dupl,
                    staging,
                    holding: false,
                })
            }
        }

        /// Fill `dst` with the current screen and append what changed to `parts`.
        ///
        /// Returns false when nothing changed within the timeout, which leaves both
        /// arguments untouched and is not an error.
        pub fn frame(&mut self, dst: &mut [u32], parts: &mut Vec<super::Part>) -> Res<bool> {
            unsafe {
                if self.holding {
                    // Every acquired frame must be released before the next is asked
                    // for, or AcquireNextFrame fails from then on.
                    let _ = self.dupl.ReleaseFrame();
                    self.holding = false;
                }

                let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
                let mut resource = None;
                match self.dupl.AcquireNextFrame(15, &mut info, &mut resource) {
                    Ok(()) => {}
                    // Nobody drew anything. Perfectly normal on an idle desktop.
                    Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(false),
                    Err(e) => return Err(e.into()),
                }
                self.holding = true;

                // A frame arrives when the pointer moves as well as when something is
                // drawn, and a pointer-only frame carries no desktop image - its
                // texture is empty. Copying it anyway paints the screen black, which
                // is exactly what it did. LastPresentTime is what tells them apart.
                let redrawn = info.LastPresentTime != 0;
                let pointer_moved = info.LastMouseUpdateTime != 0;
                if redrawn {
                    let frame: ID3D11Texture2D = resource.ok_or("no frame resource")?.cast()?;
                    self.context.CopyResource(&self.staging, &frame);

                    let mut map = D3D11_MAPPED_SUBRESOURCE::default();
                    self.context
                        .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut map))?;
                    // The GPU picks its own row stride, usually wider than the image;
                    // copying width*height in one go would shear the picture.
                    let stride = map.RowPitch as usize / 4;
                    let src = std::slice::from_raw_parts(map.pData as *const u32, stride * self.h);
                    for y in 0..self.h {
                        dst[y * self.w..(y + 1) * self.w]
                            .copy_from_slice(&src[y * stride..y * stride + self.w]);
                    }
                    self.context.Unmap(&self.staging, 0);
                    self.collect(&info, parts)?;
                }
                // A moved pointer still changes the picture, because the cursor is
                // composited into the framebuffer.
                Ok(redrawn || pointer_moved)
            }
        }

        /// Read the metadata describing what changed: which regions merely moved, and
        /// which were redrawn. This is the whole reason for using duplication over
        /// BitBlt - it removes the need to compare two framebuffers to find out.
        ///
        /// Move rectangles must come first: they describe the screen as it was being
        /// rearranged, and the dirty rectangles are what was painted afterwards.
        fn collect(&self, info: &DXGI_OUTDUPL_FRAME_INFO, parts: &mut Vec<super::Part>) -> Res<()> {
            unsafe {
                if info.TotalMetadataBufferSize == 0 {
                    return Ok(());
                }
                let mut meta = vec![0u8; info.TotalMetadataBufferSize as usize];
                let clamp = |r: windows::Win32::Foundation::RECT| {
                    let x = r.left.max(0) as usize;
                    let y = r.top.max(0) as usize;
                    let right = (r.right.max(0) as usize).min(self.w);
                    let bottom = (r.bottom.max(0) as usize).min(self.h);
                    (x, y, right.saturating_sub(x), bottom.saturating_sub(y))
                };

                let mut used = 0u32;
                self.dupl.GetFrameMoveRects(
                    meta.len() as u32,
                    meta.as_mut_ptr() as *mut DXGI_OUTDUPL_MOVE_RECT,
                    &mut used,
                )?;
                let n = used as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
                // Copied out before the buffer is reused for the dirty rectangles.
                let moves: Vec<DXGI_OUTDUPL_MOVE_RECT> =
                    std::slice::from_raw_parts(meta.as_ptr() as *const DXGI_OUTDUPL_MOVE_RECT, n)
                        .to_vec();
                for m in moves {
                    let (x, y, w, h) = clamp(m.DestinationRect);
                    if w > 0 && h > 0 {
                        parts.push(super::Part::Copy {
                            x,
                            y,
                            w,
                            h,
                            sx: m.SourcePoint.x.max(0) as usize,
                            sy: m.SourcePoint.y.max(0) as usize,
                        });
                    }
                }

                self.dupl.GetFrameDirtyRects(
                    meta.len() as u32,
                    meta.as_mut_ptr() as *mut windows::Win32::Foundation::RECT,
                    &mut used,
                )?;
                let n = used as usize / std::mem::size_of::<windows::Win32::Foundation::RECT>();
                let dirty = std::slice::from_raw_parts(
                    meta.as_ptr() as *const windows::Win32::Foundation::RECT,
                    n,
                );
                for r in dirty {
                    let (x, y, w, h) = clamp(*r);
                    if w > 0 && h > 0 {
                        parts.push(super::Part::Pixels { x, y, w, h });
                    }
                }
                Ok(())
            }
        }
    }

    impl Drop for Duplicator {
        fn drop(&mut self) {
            unsafe {
                if self.holding {
                    let _ = self.dupl.ReleaseFrame();
                }
            }
            // device, context, dupl and staging release themselves.
            let _ = &self.device;
            let _ = &self.context;
        }
    }
}

mod win {
    //! The only unsafe in the project: screen capture and input injection.
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::HiDpi::*;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    /// Without this the desktop is reported and captured at its scaled size on a
    /// high-DPI display, so the image is blurry and the pointer lands in the wrong
    /// place.
    pub fn become_dpi_aware() {
        unsafe {
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
    }

    /// The region to share, in physical screen coordinates: origin then size.
    ///
    /// `VNC_MONITOR=all` shares every display as one wide screen. The default is the
    /// primary only, deliberately: sharing more of someone's desk than they asked for
    /// is not a good surprise, and the framebuffer of three monitors is three times
    /// the pixels to encode and send.
    ///
    /// The virtual desktop's origin is not necessarily 0,0 - a monitor placed to the
    /// left of the primary gives it a negative x - so the origin has to be carried
    /// around rather than assumed.
    pub fn share_region() -> (i32, i32, usize, usize) {
        unsafe {
            if std::env::var("VNC_MONITOR")
                .map(|v| v == "all")
                .unwrap_or(false)
            {
                (
                    GetSystemMetrics(SM_XVIRTUALSCREEN),
                    GetSystemMetrics(SM_YVIRTUALSCREEN),
                    GetSystemMetrics(SM_CXVIRTUALSCREEN) as usize,
                    GetSystemMetrics(SM_CYVIRTUALSCREEN) as usize,
                )
            } else {
                (
                    0,
                    0,
                    GetSystemMetrics(SM_CXSCREEN) as usize,
                    GetSystemMetrics(SM_CYSCREEN) as usize,
                )
            }
        }
    }

    /// Read the pointer's current picture, for a client that draws it itself.
    ///
    /// Returns the shape and the `HCURSOR` it came from. That handle is the change
    /// detector: Windows hands out the same one for the same cursor, so comparing it
    /// costs nothing and re-reading two bitmaps every frame is avoided.
    ///
    /// Transparency is where cursors are awkward. A modern one is a 32bpp colour bitmap
    /// with a real alpha channel; an old one has no colour bitmap at all and instead a
    /// double-height monochrome mask, AND above XOR, where AND says what shows through.
    /// Both still turn up, so both are handled.
    pub fn cursor_shape() -> Option<(super::Cursor, isize)> {
        unsafe {
            let mut ci: CURSORINFO = zeroed();
            ci.cbSize = size_of::<CURSORINFO>() as u32;
            if GetCursorInfo(&mut ci) == 0 || ci.flags != CURSOR_SHOWING || ci.hCursor.is_null() {
                return None;
            }
            let mut ii: ICONINFO = zeroed();
            if GetIconInfo(ci.hCursor, &mut ii) == 0 {
                return None;
            }
            let drop = |ii: &ICONINFO| {
                if !ii.hbmColor.is_null() {
                    DeleteObject(ii.hbmColor as HGDIOBJ);
                }
                if !ii.hbmMask.is_null() {
                    DeleteObject(ii.hbmMask as HGDIOBJ);
                }
            };

            let mut bm: BITMAP = zeroed();
            let src = if ii.hbmColor.is_null() {
                ii.hbmMask
            } else {
                ii.hbmColor
            };
            if GetObjectW(
                src as HGDIOBJ,
                size_of::<BITMAP>() as i32,
                (&mut bm as *mut BITMAP).cast(),
            ) == 0
            {
                drop(&ii);
                return None;
            }
            let w = bm.bmWidth.max(0) as usize;
            // A monochrome cursor's mask holds both halves stacked, so the shape is
            // half as tall as the bitmap.
            let h = if ii.hbmColor.is_null() {
                (bm.bmHeight.max(0) as usize) / 2
            } else {
                bm.bmHeight.max(0) as usize
            };
            if w == 0 || h == 0 || w > 256 || h > 256 {
                drop(&ii);
                return None;
            }

            let read = |bmp: HBITMAP, rows: usize| -> Option<Vec<u32>> {
                let mut bi: BITMAPINFO = zeroed();
                bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
                bi.bmiHeader.biWidth = w as i32;
                // Negative height asks for top-down rows, matching everything else here.
                bi.bmiHeader.biHeight = -(rows as i32);
                bi.bmiHeader.biPlanes = 1;
                bi.bmiHeader.biBitCount = 32;
                bi.bmiHeader.biCompression = BI_RGB;
                let mut out = vec![0u32; w * rows];
                let dc = CreateCompatibleDC(null_mut());
                let got = GetDIBits(
                    dc,
                    bmp,
                    0,
                    rows as u32,
                    out.as_mut_ptr().cast(),
                    &mut bi,
                    DIB_RGB_COLORS,
                );
                DeleteDC(dc);
                (got != 0).then_some(out)
            };

            let stride = w.div_ceil(8);
            let mut mask = vec![0u8; stride * h];
            let mut px = vec![0u32; w * h];
            let mut set = |i: usize| mask[i / w * stride + (i % w) / 8] |= 0x80 >> (i % w % 8);

            if ii.hbmColor.is_null() {
                // Monochrome: AND on top, XOR underneath. Where AND is 0 the pixel is
                // drawn, and XOR then chooses black or white.
                let both = read(ii.hbmMask, h * 2)?;
                for i in 0..w * h {
                    if both[i] & 0x00FF_FFFF == 0 {
                        set(i);
                        px[i] = if both[w * h + i] & 0x00FF_FFFF != 0 {
                            0x00FF_FFFF
                        } else {
                            0
                        };
                    }
                }
            } else {
                let colour = read(ii.hbmColor, h)?;
                let opaque = colour.iter().any(|p| p >> 24 != 0);
                // Some colour cursors leave alpha zero throughout and mean it to be
                // ignored; those still have a usable AND mask.
                let and = if opaque { None } else { read(ii.hbmMask, h) };
                for i in 0..w * h {
                    let visible = match &and {
                        Some(a) => a[i] & 0x00FF_FFFF == 0,
                        None => colour[i] >> 24 >= 128,
                    };
                    if visible {
                        set(i);
                        px[i] = colour[i] & 0x00FF_FFFF;
                    }
                }
            }

            let shape = super::Cursor {
                w,
                h,
                hot_x: ii.xHotspot as usize,
                hot_y: ii.yHotspot as usize,
                px,
                mask,
            };
            drop(&ii);
            Some((shape, ci.hCursor as isize))
        }
    }

    /// A reusable capture surface. Creating the DIB once and re-filling it is far
    /// cheaper than building one per frame.
    ///
    /// Pixels come from Desktop Duplication when it is available and from `BitBlt`
    /// otherwise, but either way they land in this same DIB, so the cursor is
    /// composited by one piece of code regardless.
    pub struct Capture {
        w: usize,
        h: usize,
        /// Where the shared region starts on the physical desktop. Zero for the
        /// primary display, and possibly negative when sharing every monitor.
        ox: i32,
        oy: i32,
        screen: HDC,
        mem: HDC,
        bitmap: HBITMAP,
        bits: *mut u32,
        dxgi: Option<super::dxgi::Duplicator>,
        /// Whether the DIB has ever held a real frame. Desktop Duplication reports
        /// "nothing changed" on an idle desktop, which is only a safe answer once
        /// there is something to have not changed from.
        primed: bool,
        /// Where the cursor was painted last time. Duplication describes the desktop,
        /// which does not include the cursor, so nothing else would ever report that
        /// the pointer moved and it would smear across the client's screen.
        cursor: Option<(usize, usize, usize, usize)>,
    }

    impl Capture {
        pub fn new(ox: i32, oy: i32, w: usize, h: usize) -> Option<Capture> {
            unsafe {
                let screen = GetDC(null_mut());
                let mem = CreateCompatibleDC(screen);
                let mut bmi: BITMAPINFO = zeroed();
                bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
                bmi.bmiHeader.biWidth = w as i32;
                // Negative height asks for a top-down DIB, so row 0 is the top of the
                // screen and the rows already match RFB's order.
                bmi.bmiHeader.biHeight = -(h as i32);
                bmi.bmiHeader.biPlanes = 1;
                bmi.bmiHeader.biBitCount = 32;
                bmi.bmiHeader.biCompression = BI_RGB;
                let mut bits: *mut core::ffi::c_void = null_mut();
                let bitmap = CreateDIBSection(mem, &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
                if bitmap.is_null() || bits.is_null() {
                    return None;
                }
                SelectObject(mem, bitmap as HGDIOBJ);

                // Desktop Duplication is preferred: it wakes only when the screen
                // actually changes, and it reports which parts. It can legitimately
                // fail - no GPU access from this session, a driver that declines,
                // another program already duplicating - so GDI stays as the fallback
                // rather than being ripped out.
                // ponytail: duplication is per-output, so it only covers a shared
                // region that is exactly one monitor. Sharing several falls back to
                // BitBlt, which costs the idle-CPU and dirty-rectangle wins. Running
                // one duplicator per output and compositing them is the upgrade.
                let dxgi = if std::env::var("VNC_CAPTURE")
                    .map(|v| v == "gdi")
                    .unwrap_or(false)
                {
                    eprintln!("VNC_CAPTURE=gdi: using BitBlt");
                    None
                } else {
                    match super::dxgi::Duplicator::new(ox, oy, w, h) {
                        Ok(d) => Some(d),
                        Err(e) => {
                            eprintln!("desktop duplication unavailable, using BitBlt: {e}");
                            None
                        }
                    }
                };
                if dxgi.is_some() && super::debug() {
                    eprintln!("[debug] capturing with Desktop Duplication");
                }

                Some(Capture {
                    w,
                    h,
                    ox,
                    oy,
                    screen,
                    mem,
                    bitmap,
                    bits: bits as *mut u32,
                    dxgi,
                    primed: false,
                    cursor: None,
                })
            }
        }

        /// Copy the screen into `dst`, and say whether anything might have changed.
        ///
        /// Desktop Duplication knows when the desktop is idle and says so, which lets
        /// the caller skip diffing a screen that provably did not move. `BitBlt` has
        /// no such knowledge, so on that path the answer is always "maybe".
        ///
        /// The cursor is drawn in by hand either way: neither capture route includes
        /// it, and a remote desktop with no visible pointer is close to unusable.
        /// Unless `paint_cursor` is false, which means the client is drawing it locally
        /// and baking it into the picture would show two of them.
        pub fn grab(&mut self, dst: &mut [u32], paint_cursor: bool) -> super::Frame {
            unsafe {
                let rows = std::slice::from_raw_parts_mut(self.bits, self.w * self.h);
                // The source offset is the shared region's origin on the desktop,
                // which is not 0,0 when a monitor sits left of or above the primary.
                let blit = |c: &Capture| {
                    BitBlt(
                        c.mem, 0, 0, c.w as i32, c.h as i32, c.screen, c.ox, c.oy, SRCCOPY,
                    );
                };

                let mut parts = Vec::new();
                let mut changed = false;
                let mut precise = self.dxgi.is_some();

                // Duplication only ever reports *changes*, so the first frame has to
                // come from somewhere. Take it from BitBlt and let duplication update
                // it from then on - and that first frame is a whole screen, not a set
                // of rectangles.
                if !self.primed {
                    blit(self);
                    self.primed = true;
                    changed = true;
                    precise = false;
                }

                match self.dxgi.as_mut() {
                    Some(d) => match d.frame(rows, &mut parts) {
                        Ok(moved) => changed |= moved,
                        Err(e) => {
                            // A duplication can be lost at any time - a resolution
                            // change, a full-screen game taking the output, the
                            // session locking. Fall back rather than dying.
                            eprintln!("desktop duplication stopped, using BitBlt: {e}");
                            self.dxgi = None;
                            blit(self);
                            changed = true;
                            precise = false;
                        }
                    },
                    // BitBlt cannot tell us whether anything moved, so assume it did.
                    None => {
                        blit(self);
                        changed = true;
                        precise = false;
                    }
                }

                if !changed {
                    return super::Frame::Unchanged;
                }

                let mut ci: CURSORINFO = zeroed();
                ci.cbSize = size_of::<CURSORINFO>() as u32;
                let mut now = None;
                if paint_cursor && GetCursorInfo(&mut ci) != 0 && ci.flags == CURSOR_SHOWING {
                    let mut ii: ICONINFO = zeroed();
                    if GetIconInfo(ci.hCursor, &mut ii) != 0 {
                        // The cursor position is on the desktop; the DIB starts at the
                        // shared region's origin.
                        let (x, y) = (
                            ci.ptScreenPos.x - ii.xHotspot as i32 - self.ox,
                            ci.ptScreenPos.y - ii.yHotspot as i32 - self.oy,
                        );
                        DrawIconEx(self.mem, x, y, ci.hCursor, 0, 0, 0, null_mut(), DI_NORMAL);
                        if !ii.hbmColor.is_null() {
                            DeleteObject(ii.hbmColor as HGDIOBJ);
                        }
                        if !ii.hbmMask.is_null() {
                            DeleteObject(ii.hbmMask as HGDIOBJ);
                        }
                        // A generous box rather than the exact icon size. Cursors are
                        // small, so over-reporting costs a rounding error of pixels
                        // and saves asking the bitmap how big it is.
                        now = Some(self.clamp_rect(x - 4, y - 4, 136, 136));
                    }
                }
                // Both where it was and where it is now have to be repainted, or the
                // old one stays on the client's screen forever.
                if precise {
                    for r in [self.cursor, now].into_iter().flatten() {
                        parts.push(super::Part::Pixels {
                            x: r.0,
                            y: r.1,
                            w: r.2,
                            h: r.3,
                        });
                    }
                }
                self.cursor = now;
                // The DIB's top byte is undefined; mask it so pixels compare equal
                // frame to frame instead of producing phantom changes.
                let src = std::slice::from_raw_parts(self.bits, self.w * self.h);
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = s & 0x00FF_FFFF;
                }
                if precise {
                    super::Frame::Known(parts)
                } else {
                    super::Frame::Unknown
                }
            }
        }

        fn clamp_rect(&self, x: i32, y: i32, w: i32, h: i32) -> (usize, usize, usize, usize) {
            let x0 = x.max(0) as usize;
            let y0 = y.max(0) as usize;
            let x1 = ((x + w).max(0) as usize).min(self.w);
            let y1 = ((y + h).max(0) as usize).min(self.h);
            (x0, y0, x1.saturating_sub(x0), y1.saturating_sub(y0))
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            unsafe {
                DeleteObject(self.bitmap as HGDIOBJ);
                DeleteDC(self.mem);
                ReleaseDC(null_mut(), self.screen);
            }
        }
    }

    fn send(inputs: &[INPUT]) {
        unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                size_of::<INPUT>() as i32,
            );
        }
    }

    /// X11 keysym to Windows virtual key. Letters and digits map to real VKs so that
    /// Ctrl-C and friends reach applications as shortcuts; anything else printable is
    /// injected as a Unicode character, which sidesteps keyboard-layout differences
    /// entirely. Returns None for keysyms with no virtual key.
    fn vk_for(sym: u32) -> Option<u16> {
        Some(match sym {
            0x61..=0x7a => (sym - 0x61 + 0x41) as u16, // a-z -> VK_A..VK_Z
            0x41..=0x5a => sym as u16,                 // A-Z already are the VK values
            0x30..=0x39 => sym as u16,                 // 0-9
            0x20 => VK_SPACE,
            0xff08 => VK_BACK,
            0xff09 => VK_TAB,
            0xff0d => VK_RETURN,
            0xff1b => VK_ESCAPE,
            0xff50 => VK_HOME,
            0xff51 => VK_LEFT,
            0xff52 => VK_UP,
            0xff53 => VK_RIGHT,
            0xff54 => VK_DOWN,
            0xff55 => VK_PRIOR,
            0xff56 => VK_NEXT,
            0xff57 => VK_END,
            0xff63 => VK_INSERT,
            0xffff => VK_DELETE,
            0xff13 => VK_PAUSE,
            0xff14 => VK_SCROLL,
            0xff7f => VK_NUMLOCK,
            0xffe5 => VK_CAPITAL,
            0xffe1 => VK_LSHIFT,
            0xffe2 => VK_RSHIFT,
            0xffe3 => VK_LCONTROL,
            0xffe4 => VK_RCONTROL,
            0xffe9 => VK_LMENU,
            0xffea => VK_RMENU,
            0xffeb => VK_LWIN,
            0xffec => VK_RWIN,
            0xffbe..=0xffc9 => (sym - 0xffbe) as u16 + VK_F1,
            _ => return None,
        })
    }

    /// Inject a keysym. `shift_held` says whether the client has told us shift is
    /// down, because an uppercase keysym means the character, not the key: pressing
    /// the A key without shift types a lowercase 'a'. A client typing normally sends
    /// Shift itself, but one synthesising text - pasting, say - sends only the
    /// character, and would otherwise get lowercase.
    pub fn inject_key_shifted(sym: u32, down: bool, shift_held: bool) {
        let needs_shift = (0x41..=0x5a).contains(&sym) && !shift_held;
        if needs_shift && down {
            inject_key(0xffe1, true);
        }
        inject_key(sym, down);
        if needs_shift && !down {
            inject_key(0xffe1, false);
        }
    }

    pub fn inject_key(sym: u32, down: bool) {
        let mut i: INPUT = unsafe { zeroed() };
        i.r#type = INPUT_KEYBOARD;
        match vk_for(sym) {
            Some(vk) => {
                i.Anonymous.ki.wVk = vk;
                i.Anonymous.ki.dwFlags = if down { 0 } else { KEYEVENTF_KEYUP };
            }
            // Printable but unmapped: type the character itself.
            None if sym < 0x1_0000 => {
                i.Anonymous.ki.wScan = sym as u16;
                i.Anonymous.ki.dwFlags = KEYEVENTF_UNICODE | if down { 0 } else { KEYEVENTF_KEYUP };
            }
            None => return,
        }
        send(&[i]);
    }

    /// Our framebuffer is in physical pixels, so the pointer must be placed in
    /// physical pixels. SendInput's MOUSEEVENTF_ABSOLUTE is not the way to do that:
    /// its 0..65535 range maps onto the *logical* desktop, so on a 200% display every
    /// coordinate lands at half the intended position. SetPhysicalCursorPos takes
    /// physical pixels directly and still raises the usual mouse-move messages.
    pub fn move_pointer(x: u16, y: u16, ox: i32, oy: i32) {
        unsafe {
            // The client's coordinates are relative to the shared region, which does
            // not start at the desktop's origin when a monitor sits left of the
            // primary - there, x=0 is a negative desktop coordinate.
            SetPhysicalCursorPos(ox + x as i32, oy + y as i32);
        }
    }

    pub fn buttons(prev: u8, now: u8) {
        // Bits 0-2 are left/middle/right; 3-4 are the wheel, which RFB models as a
        // button being clicked rather than as a scroll message.
        for (bit, down, up) in [
            (0u8, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            (1, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
            (2, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        ] {
            let (was, is) = (prev & (1 << bit) != 0, now & (1 << bit) != 0);
            if was != is {
                let mut i: INPUT = unsafe { zeroed() };
                i.r#type = INPUT_MOUSE;
                i.Anonymous.mi.dwFlags = if is { down } else { up };
                send(&[i]);
            }
        }
        for (bit, delta) in [(3u8, 120i32), (4, -120)] {
            if now & (1 << bit) != 0 && prev & (1 << bit) == 0 {
                let mut i: INPUT = unsafe { zeroed() };
                i.r#type = INPUT_MOUSE;
                i.Anonymous.mi.mouseData = delta as u32;
                i.Anonymous.mi.dwFlags = MOUSEEVENTF_WHEEL;
                send(&[i]);
            }
        }
    }
}

/// The pixel format the client asked for. We always hold 0x00RRGGBB internally and
/// compose on the way out, so a client wanting different shifts still works.
#[derive(Clone, Copy, Debug)]
struct PixFmt {
    big_endian: bool,
    rshift: u32,
    gshift: u32,
    bshift: u32,
}

impl Default for PixFmt {
    fn default() -> PixFmt {
        PixFmt {
            big_endian: false,
            rshift: 16,
            gshift: 8,
            bshift: 0,
        }
    }
}

impl PixFmt {
    fn parse(f: &[u8]) -> Res<PixFmt> {
        let (bpp, truecolour) = (f[0], f[3]);
        if bpp != 32 || truecolour == 0 {
            return Err(format!(
                "client asked for {bpp}bpp truecolour={truecolour}; vncfree-server only \
                 serves 32bpp true colour"
            )
            .into());
        }
        Ok(PixFmt {
            big_endian: f[2] != 0,
            rshift: f[10] as u32,
            gshift: f[11] as u32,
            bshift: f[12] as u32,
        })
    }

    fn pixel(&self, p: u32) -> [u8; 4] {
        let v = ((p >> 16) & 255) << self.rshift
            | ((p >> 8) & 255) << self.gshift
            | (p & 255) << self.bshift;
        if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    /// A ZRLE "compressed pixel": the same pixel minus its unused byte. This is only
    /// legal when all the colour fits in the low three bytes, which it does for any
    /// shift of 16 or less. A client using an exotic layout gets Raw instead.
    fn cpixel(&self, p: u32) -> Option<[u8; 3]> {
        if self.rshift > 16 || self.gshift > 16 || self.bshift > 16 {
            return None;
        }
        let b = self.pixel(p);
        Some(if self.big_endian {
            [b[1], b[2], b[3]]
        } else {
            [b[0], b[1], b[2]]
        })
    }
}

/// What a capture managed to say about a frame.
enum Frame {
    /// Nothing was drawn and the pointer did not move.
    Unchanged,
    /// Exactly these regions moved or were repainted. Desktop Duplication knows this;
    /// it is the reason the framebuffer no longer has to be diffed against itself.
    Known(Vec<Part>),
    /// The capture cannot say, so the frames have to be compared. This is BitBlt.
    Unknown,
}

/// One piece of an update. A Copy tells the client to move something it already has,
/// which costs four bytes instead of the pixels.
#[derive(Debug, PartialEq)]
enum Part {
    Copy {
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        sx: usize,
        sy: usize,
    },
    Pixels {
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    },
    /// DesktopSize: not a picture, but the way to tell a client the screen resolution
    /// changed. The rectangle header carries the new size and there is no body.
    Resize { w: usize, h: usize },
    /// CursorShape: the pointer's picture, for a client that draws it itself. The
    /// rectangle header carries the hot spot in place of a position.
    Cursor(Cursor),
}

/// The pointer's picture, ready to send. `mask` is one bit per pixel, most significant
/// first, each row padded to a byte - which is what RFB wants and is why a cursor's
/// soft edges cannot survive the trip: a pixel is drawn or it is not.
#[derive(Clone, PartialEq, Debug)]
struct Cursor {
    w: usize,
    h: usize,
    hot_x: usize,
    hot_y: usize,
    px: Vec<u32>,
    mask: Vec<u8>,
}

const TILE: usize = 64;

/// Scrolling less than this is not worth a CopyRect, and the search is skipped.
const MIN_SCROLL: usize = 64;

/// How many rows to probe when hunting for a shift. One is not enough: a terminal or
/// a document is mostly background, so a single probe frequently lands on a blank row
/// whose matches are all unrelated blank rows elsewhere.
const PROBES: usize = 8;

/// Hash one row, but only the columns in `cols`. Scrolling almost always happens
/// inside a window, so the desktop either side of it does not move; hashing whole rows
/// would only ever spot a scroll spanning the entire screen.
fn row_hash(px: &[u32], w: usize, y: usize, cols: (usize, usize)) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &p in &px[y * w + cols.0..y * w + cols.1] {
        h ^= p as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn rows_match(
    prev: &[u32],
    cur: &[u32],
    w: usize,
    cols: (usize, usize),
    sy: usize,
    dy: usize,
    n: usize,
) -> bool {
    (0..n).all(|i| {
        prev[(sy + i) * w + cols.0..(sy + i) * w + cols.1]
            == cur[(dy + i) * w + cols.0..(dy + i) * w + cols.1]
    })
}

/// Find a band of rows within `cols` that simply moved vertically - in other words,
/// scrolling, which is where CopyRect earns its keep.
///
/// Row hashes only propose a candidate; the winner is then compared pixel for pixel
/// before it is used. A CopyRect based on a hash collision would corrupt the client's
/// screen with no way for it to notice, so guessing is not acceptable here.
///
/// Returns (destination y, source y, height).
fn find_scroll(
    prev: &[u32],
    cur: &[u32],
    w: usize,
    h: usize,
    cols: (usize, usize),
) -> Option<(usize, usize, usize)> {
    if h < MIN_SCROLL || cols.1 <= cols.0 {
        return None;
    }
    let ph: Vec<u64> = (0..h).map(|y| row_hash(prev, w, y, cols)).collect();
    let ch: Vec<u64> = (0..h).map(|y| row_hash(cur, w, y, cols)).collect();

    let first = (0..h).find(|&y| ph[y] != ch[y])?;
    let last = (0..h).rev().find(|&y| ph[y] != ch[y])?;
    if last - first + 1 < MIN_SCROLL {
        return None;
    }
    // Several probe rows spread through the changed band, not one. A single probe
    // lands on a blank row often enough to matter - a terminal or a document is mostly
    // background - and every candidate it then finds is an unrelated blank row.
    let mut best: Option<(usize, usize, usize)> = None;
    for k in 0..PROBES {
        let probe = first + (last - first) * k / (PROBES - 1);
        let mut tried = 0;
        for src in 0..h {
            if ph[src] != ch[probe] {
                continue;
            }
            // Cap the candidates per probe so a screen of identical rows cannot make
            // this crawl.
            tried += 1;
            if tried > 8 {
                break;
            }
            if src == probe {
                continue;
            }
            // How far the content moved. Row y of the new frame should equal row
            // y - shift of the old one.
            let shift = probe as isize - src as isize;
            let source_of = |y: usize| -> Option<usize> {
                let s = y as isize - shift;
                (s >= 0 && (s as usize) < h).then_some(s as usize)
            };

            // Grow a run of rows around the probe that all agree on this shift.
            let (mut a, mut b) = (probe, probe);
            while a > 0 && source_of(a - 1).is_some_and(|s| ch[a - 1] == ph[s]) {
                a -= 1;
            }
            while b + 1 < h && source_of(b + 1).is_some_and(|s| ch[b + 1] == ph[s]) {
                b += 1;
            }
            let n = b - a + 1;
            if n >= MIN_SCROLL && best.is_none_or(|(_, _, bn)| n > bn) {
                best = Some((a, source_of(a)?, n));
            }
        }
    }

    let (dst_y, src_y, n) = best?;
    // The expensive, and only trustworthy, part.
    rows_match(prev, cur, w, cols, src_y, dst_y, n).then_some((dst_y, src_y, n))
}

/// The column range that most of the change happened in.
///
/// Deliberately not the union of every changed rectangle: that spans from the leftmost
/// change to the rightmost, swallowing whatever static desktop sits between them. Rows
/// of that static area differ from each other, so including it makes every row
/// comparison fail and no scroll is ever found. A scrolling window instead produces
/// many rectangles sharing one exact column range, which is what this picks out.
fn dominant_cols(rects: &[(usize, usize, usize, usize)]) -> Option<(usize, usize)> {
    let mut groups: Vec<((usize, usize), usize)> = Vec::new();
    for &(x, _, w, h) in rects {
        let key = (x, x + w);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, area)) => *area += w * h,
            None => groups.push((key, w * h)),
        }
    }
    groups
        .into_iter()
        .max_by_key(|&(_, area)| area)
        .map(|(k, _)| k)
}

/// Changed regions between two frames, as 64-pixel tile rows with horizontally
/// adjacent tiles merged into runs. Merging matters: without it a full-screen change
/// at 1080p is 510 separate rectangles, each carrying its own header.
fn changed_rects(
    prev: &[u32],
    cur: &[u32],
    w: usize,
    h: usize,
) -> Vec<(usize, usize, usize, usize)> {
    let mut rects = Vec::new();
    let mut ty = 0;
    while ty < h {
        let th = TILE.min(h - ty);
        let mut tx = 0;
        let mut run: Option<usize> = None;
        while tx < w {
            let tw = TILE.min(w - tx);
            let changed = (0..th).any(|r| {
                let o = (ty + r) * w + tx;
                prev[o..o + tw] != cur[o..o + tw]
            });
            match (changed, run) {
                (true, None) => run = Some(tx),
                (false, Some(s)) => {
                    rects.push((s, ty, tx - s, th));
                    run = None;
                }
                _ => {}
            }
            tx += tw;
        }
        if let Some(s) = run {
            rects.push((s, ty, w - s, th));
        }
        ty += TILE;
    }
    rects
}

/// How many bytes `write_run` will spend on a run of this length.
fn run_bytes(len: usize) -> usize {
    1 + (len - 1) / 255
}

/// A ZRLE run length: one less than the length, in 255-sized instalments, so a run of
/// 256 goes out as 255 then 0. Only ever called for runs of two or more.
fn write_run(out: &mut Vec<u8>, len: usize) {
    let mut left = len - 1;
    while left >= 255 {
        out.push(255);
        left -= 255;
    }
    out.push(left as u8);
}

/// Encode one 64x64 (or smaller, at the edges) ZRLE tile, picking whichever of the
/// five subencodings is smallest for it: solid, packed palette, plain RLE, palette
/// RLE, or raw.
///
/// Every subencoding is legal for every tile, so rather than guess from thresholds,
/// each one is *costed* from the colours and runs already counted and the cheapest
/// wins. Thresholds are where this kind of code goes wrong quietly: a rule of thumb
/// tuned on a photo picks a form five times too big for a terminal, and nothing ever
/// reports it, because the output is still correct.
fn encode_tile(out: &mut Vec<u8>, s: &Screen, x: usize, y: usize, w: usize, h: usize, f: &PixFmt) {
    let at = |row: usize, col: usize| s.px[(y + row) * s.w + x + col];

    // Distinct colours, giving up once a palette would be too large to be worth it.
    let mut palette: Vec<u32> = Vec::new();
    'scan: for row in 0..h {
        for col in 0..w {
            let p = at(row, col);
            if !palette.contains(&p) {
                // 127 rather than 16: the packed form stops at 16, but palette RLE
                // indexes up to 127, and a tile with 40 colours in long runs is much
                // better off there than spelled out pixel by pixel.
                if palette.len() == 127 {
                    palette.clear();
                    break 'scan;
                }
                palette.push(p);
            }
        }
    }

    // Runs of one colour, in the order the pixels go out. Counted once and used by
    // every estimate below.
    let mut runs: Vec<(u32, usize)> = Vec::new();
    for row in 0..h {
        for col in 0..w {
            let p = at(row, col);
            match runs.last_mut() {
                Some((c, n)) if *c == p => *n += 1,
                _ => runs.push((p, 1)),
            }
        }
    }

    let n = palette.len();
    let bits = match n {
        2 => 1,
        3..=4 => 2,
        _ => 4,
    };

    // What each form would cost in bytes, not counting the subencoding byte they all
    // pay. MAX means this tile cannot use that form at all.
    let raw = 3 * w * h;
    let plain_rle: usize = runs.iter().map(|(_, l)| 3 + run_bytes(*l)).sum();
    let palette_rle = match n {
        // A lone pixel carries an index and no length, which is where this form beats
        // spelling the colour out per run.
        2..=127 => {
            3 * n
                + runs
                    .iter()
                    .map(|(_, l)| if *l == 1 { 1 } else { 1 + run_bytes(*l) })
                    .sum::<usize>()
        }
        _ => usize::MAX,
    };
    let packed = match n {
        // Every row restarts on a byte boundary, so the padding is per row, not per
        // tile - it is most of the cost of a narrow edge tile.
        2..=16 => 3 * n + h * (w * bits).div_ceil(8),
        _ => usize::MAX,
    };
    let best = raw.min(plain_rle).min(palette_rle).min(packed);

    if n == 1 {
        // One colour for the whole tile, which is most of a typical desktop, and
        // three bytes beats anything else here by construction.
        out.push(1);
        out.extend_from_slice(&f.cpixel(palette[0]).unwrap_or([0; 3]));
    } else if best == packed {
        out.push(n as u8);
        for c in &palette {
            out.extend_from_slice(&f.cpixel(*c).unwrap_or([0; 3]));
        }
        // Indices are packed most-significant-bit first.
        for row in 0..h {
            let (mut byte, mut used) = (0u8, 0);
            for col in 0..w {
                let idx = palette.iter().position(|&c| c == at(row, col)).unwrap() as u8;
                byte |= idx << (8 - bits - used);
                used += bits;
                if used == 8 {
                    out.push(byte);
                    byte = 0;
                    used = 0;
                }
            }
            if used > 0 {
                out.push(byte);
            }
        }
    } else if best == palette_rle {
        out.push(128 + n as u8);
        for c in &palette {
            out.extend_from_slice(&f.cpixel(*c).unwrap_or([0; 3]));
        }
        for (colour, len) in &runs {
            let idx = palette.iter().position(|c| c == colour).unwrap() as u8;
            if *len == 1 {
                out.push(idx);
            } else {
                out.push(idx | 0x80);
                write_run(out, *len);
            }
        }
    } else if best == plain_rle {
        // Too many colours to index, but the pixels still come in runs - a window
        // border over a busy background, where a photo or a gradient would not.
        out.push(128);
        for (colour, len) in &runs {
            out.extend_from_slice(&f.cpixel(*colour).unwrap_or([0; 3]));
            write_run(out, *len);
        }
    } else {
        // Nothing repeats enough to be worth describing. Spell every pixel out.
        out.push(0);
        for row in 0..h {
            for col in 0..w {
                out.extend_from_slice(&f.cpixel(at(row, col)).unwrap_or([0; 3]));
            }
        }
    }
}

/// Push bytes through the connection-wide deflate stream and flush so the client can
/// decode this rectangle immediately.
fn deflate(z: &mut Compress, input: &[u8]) -> Res<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 2 + 1024);
    let mut consumed = 0;
    while consumed < input.len() {
        if out.len() == out.capacity() {
            out.reserve(4096);
        }
        let in0 = z.total_in();
        z.compress_vec(&input[consumed..], &mut out, FlushCompress::None)?;
        consumed += (z.total_in() - in0) as usize;
        if z.total_in() == in0 && out.len() < out.capacity() {
            return Err("deflate stalled".into());
        }
    }
    // Exactly one sync flush. Calling Sync repeatedly emits a fresh marker every time
    // and never reports being finished, which is an easy infinite loop to write.
    loop {
        if out.len() == out.capacity() {
            out.reserve(4096);
        }
        let before = out.len();
        z.compress_vec(&[], &mut out, FlushCompress::Sync)?;
        if out.len() < out.capacity() || out.len() == before {
            return Ok(out);
        }
    }
}

/// Build one FramebufferUpdate. Copy parts become CopyRect; pixel parts become ZRLE
/// when a compressor is supplied and Raw otherwise.
fn update(z: Option<&mut Compress>, s: &Screen, parts: &[Part], fmt: &PixFmt) -> Res<Vec<u8>> {
    let mut out = vec![0u8, 0]; // FramebufferUpdate, padding
    out.extend_from_slice(&(parts.len() as u16).to_be_bytes());
    let mut z = z;
    for part in parts {
        let (x, y, w, h) = match *part {
            Part::Copy { x, y, w, h, .. } => (x, y, w, h),
            Part::Pixels { x, y, w, h } => (x, y, w, h),
            Part::Resize { w, h } => (0, 0, w, h),
            // The hot spot travels in the position fields. There is nowhere else for
            // it, and a cursor has no position on the framebuffer by definition.
            Part::Cursor(ref c) => (c.hot_x, c.hot_y, c.w, c.h),
        };
        out.extend_from_slice(&(x as u16).to_be_bytes());
        out.extend_from_slice(&(y as u16).to_be_bytes());
        out.extend_from_slice(&(w as u16).to_be_bytes());
        out.extend_from_slice(&(h as u16).to_be_bytes());
        match *part {
            Part::Resize { .. } => out.extend_from_slice(&(-223i32).to_be_bytes()),
            Part::Cursor(ref c) => {
                out.extend_from_slice(&(-239i32).to_be_bytes());
                for p in &c.px {
                    out.extend_from_slice(&fmt.pixel(*p));
                }
                out.extend_from_slice(&c.mask);
            }
            Part::Copy { sx, sy, .. } => {
                out.extend_from_slice(&1i32.to_be_bytes()); // CopyRect
                out.extend_from_slice(&(sx as u16).to_be_bytes());
                out.extend_from_slice(&(sy as u16).to_be_bytes());
            }
            Part::Pixels { .. } => match z.as_mut() {
                Some(z) => {
                    let mut tiles = Vec::new();
                    for ty in (0..h).step_by(64) {
                        for tx in (0..w).step_by(64) {
                            let (tw, th) = ((w - tx).min(64), (h - ty).min(64));
                            encode_tile(&mut tiles, s, x + tx, y + ty, tw, th, fmt);
                        }
                    }
                    let body = deflate(z, &tiles)?;
                    out.extend_from_slice(&16i32.to_be_bytes()); // ZRLE
                    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    out.extend_from_slice(&body);
                }
                None => {
                    out.extend_from_slice(&0i32.to_be_bytes()); // Raw
                    for row in y..y + h {
                        for col in x..x + w {
                            out.extend_from_slice(&fmt.pixel(s.px[row * s.w + col]));
                        }
                    }
                }
            },
        }
    }
    Ok(out)
}

/// Shared between a client's reader thread and its sender thread.
struct Shared {
    out: Mutex<vncfree::wire::WireWrite>,
    fmt: Mutex<PixFmt>,
    /// The client has an outstanding FramebufferUpdateRequest. RFB is request-driven:
    /// nothing may be sent until one arrives.
    wants: AtomicBool,
    /// The client's copy of the screen is valid, so only changes need to go out.
    incremental: AtomicBool,
    /// The client listed ZRLE in SetEncodings. Sending an encoding a client never
    /// asked for is a protocol violation, so Raw is the default until it does.
    zrle: AtomicBool,
    /// Likewise for CopyRect.
    copyrect: AtomicBool,
    /// The client asked for DesktopSize, so it can be told the resolution changed.
    /// One that did not has no way to follow, and the session has to end instead.
    resize: AtomicBool,
    /// The client turned on continuous updates, so frames go out as the screen changes
    /// rather than once per request. Saves a round trip per frame.
    continuous: AtomicBool,
    /// The client asked for CursorShape, so it draws the pointer itself and the
    /// captured picture must not have one baked into it.
    cursor: AtomicBool,
    alive: AtomicBool,
    clip: Mutex<String>,
}

/// Set once the password dialog has been used, which means the program was almost
/// certainly launched by double-clicking and has no console to print to.
static FROM_GUI: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        if FROM_GUI.load(Ordering::Relaxed) {
            vncfree::gui::alert("vncfree-server", &e.to_string());
        }
        std::process::exit(1);
    }
}

/// Ask for a password before serving anything. Shows this machine's address on the
/// local network so the person at the other end knows what to type.
///
/// No public IP is shown. Finding one means asking a third-party server, which sits
/// badly with a program that promises no telemetry, and putting a DES-authenticated
/// VNC server on the open internet is not something to encourage with a helpful
/// label. Tunnel it instead.
fn ask_for_password(bind: &str) -> Res<Option<(String, String)>> {
    let note = match vncfree::gui::lan_ip() {
        Some(ip) => format!(
            "This machine is {ip} on the local network.\n\
             Sessions are encrypted, but do not port-forward this.\n\
             Tunnel over SSH or a VPN."
        ),
        None => "Could not work out this machine's local address.".to_string(),
    };
    let mut fields = vec![
        vncfree::gui::Field::new("Password", true, true),
        vncfree::gui::Field::new("Listen on", false, true),
    ];
    fields[1].value = bind.to_string();
    let check: vncfree::gui::Validator =
        |f| vncfree::gui::check_host_port("Listen on", &f[1].value);
    if !vncfree::gui::form(
        "vncfree-server",
        &note,
        &mut fields,
        "Start server",
        Some(check),
    ) {
        return Ok(None);
    }
    Ok(Some((
        fields[0].value.clone(),
        fields[1].value.trim().to_string(),
    )))
}

fn run() -> Res<()> {
    win::become_dpi_aware();

    // A password is mandatory. An unauthenticated VNC server on a listening port
    // hands the whole desktop to anyone who can reach it, and defaulting to open is
    // exactly the decision that makes remote-access software dangerous.
    let mut password = std::env::var("VNC_PASSWORD").unwrap_or_default();
    let mut bind = std::env::var("VNC_BIND").unwrap_or_else(|_| "0.0.0.0:5900".into());

    // No password in the environment: ask for one. The dialog's Start button stays
    // disabled until a password is typed, so there is no path to an open server.
    if password.is_empty() {
        FROM_GUI.store(true, Ordering::Relaxed);
        match ask_for_password(&bind)? {
            Some((p, b)) => {
                password = p;
                bind = b;
            }
            None => return Ok(()), // window closed
        }
    }
    if password.is_empty() {
        return Err("set VNC_PASSWORD to a password of up to 8 characters.\n\
                    vncfree-server will not run without one - an open VNC port gives \
                    anyone who can reach it full control of this desktop.\n\
                    Note that VNC auth is DES and weak: tunnel over SSH or a VPN if \
                    the network is not trusted."
            .into());
    }
    if password.len() > 8 {
        eprintln!("warning: VNC auth uses only the first 8 characters of the password");
    }

    // One certificate for the life of the server, so the fingerprint printed here is
    // the one every client will see and can be compared against.
    let tls_mode = TlsMode::from_env()?;
    let me = match tls_mode {
        TlsMode::Off => None,
        _ => Some(Arc::new(vncfree::wire::Identity::new()?)),
    };

    let listener =
        TcpListener::bind(&bind).map_err(|e| format!("could not listen on {bind}: {e}"))?;
    let (ox, oy, w, h) = win::share_region();
    println!("vncfree-server listening on {bind}, sharing {w}x{h}");
    match &me {
        Some(me) => {
            println!(
                "TLS certificate {}\n  \
                 the client prints the same line - if they differ, something is sitting \
                 between you and it",
                me.fingerprint
            );
            if me.ephemeral {
                println!(
                    "  this certificate lasts only while the server runs, so clients \
                     will see a new one next time"
                );
            }
        }
        None => println!("VNC_TLS=off: this session will not be encrypted"),
    }

    for stream in listener.incoming() {
        let stream = stream?;
        let password = password.clone();
        let me = me.clone();
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        std::thread::spawn(move || {
            println!("client connected: {peer}");
            match serve(stream, &password, me.as_deref(), ox, oy, w, h) {
                Ok(()) => println!("client {peer} disconnected"),
                Err(e) => println!("client {peer} finished: {e}"),
            }
        });
    }
    Ok(())
}

fn serve(
    mut tcp: TcpStream,
    password: &str,
    me: Option<&vncfree::wire::Identity>,
    ox: i32,
    oy: i32,
    w: usize,
    h: usize,
) -> Res<()> {
    tcp.set_nodelay(true)?;

    // --- version ---
    tcp.write_all(b"RFB 003.008\n")?;
    let ver = String::from_utf8_lossy(&rd::<12>(&mut tcp)?)
        .trim_end()
        .to_string();
    if debug() {
        eprintln!("[debug] client speaks {ver:?}");
    }

    // The client picks the version, and may pick one older than ours. macOS's own
    // Screen Sharing client asks for 3.3, so refusing it would lock out the viewer
    // built into every Mac.
    let minor: u32 = ver
        .strip_prefix("RFB 003.")
        .and_then(|m| m.parse().ok())
        .unwrap_or(3);
    let old = minor < 7;

    // --- security ---
    // Whichever type is chosen, the password is checked the same way afterwards; all
    // that differs is whether the rest of the session is encrypted.
    let tls_mode = TlsMode::from_env()?;
    let mut encrypted = false;
    if old {
        // 3.3 has no negotiation: the server states the type as a u32, and that is it.
        // There is no way to offer TLS to a client this old.
        if tls_mode == TlsMode::Require {
            return Err(
                "a client asked for RFB 3.3, which cannot negotiate TLS, and \
                        VNC_TLS=require is set"
                    .into(),
            );
        }
        tcp.write_all(&2u32.to_be_bytes())?;
    } else {
        let mut offer = vec![2u8]; // 2 = VNC auth, unencrypted
        if tls_mode != TlsMode::Off {
            offer.insert(0, 19); // 19 = VeNCrypt
        }
        if tls_mode == TlsMode::Require {
            offer.retain(|&t| t == 19);
        }
        tcp.write_all(&[offer.len() as u8])?;
        tcp.write_all(&offer)?;
        match u8r(&mut tcp)? {
            19 if tls_mode != TlsMode::Off => encrypted = true,
            2 if tls_mode != TlsMode::Require => {}
            other => {
                return refuse(
                    &mut tcp,
                    old,
                    format!("security type {other} was not offered").as_bytes(),
                )
            }
        }
    }

    // From here on everything goes through the wire halves, which are either the plain
    // socket or the same socket with TLS over it.
    let (reader, mut out) = match (encrypted, me) {
        (true, Some(me)) => vencrypt(&mut tcp, me)?,
        _ => vncfree::wire::plain(tcp)?,
    };
    let mut r = std::io::BufReader::new(reader);

    let mut challenge = [0u8; 16];
    getrandom::fill(&mut challenge)?;
    out.write_all(&challenge)?;
    let answer = rd::<16>(&mut r)?;
    let mut expected = challenge;
    vnc_des(&mut expected, password);
    if answer != expected {
        return refuse(&mut out, old, b"authentication failed");
    }
    out.write_all(&0u32.to_be_bytes())?; // SecurityResult: OK

    // --- init ---
    let _shared_flag = u8r(&mut r)?;
    let name = format!("{} (vncfree)", hostname());
    let mut init = Vec::new();
    init.extend_from_slice(&(w as u16).to_be_bytes());
    init.extend_from_slice(&(h as u16).to_be_bytes());
    init.extend_from_slice(&PIXEL_FORMAT);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name.as_bytes());
    out.write_all(&init)?;

    let shared = Arc::new(Shared {
        out: Mutex::new(out),
        fmt: Mutex::new(PixFmt::default()),
        wants: AtomicBool::new(false),
        continuous: AtomicBool::new(false),
        cursor: AtomicBool::new(false),
        incremental: AtomicBool::new(false),
        zrle: AtomicBool::new(false),
        copyrect: AtomicBool::new(false),
        resize: AtomicBool::new(false),
        alive: AtomicBool::new(true),
        clip: Mutex::new(String::new()),
    });

    let sender = shared.clone();
    std::thread::spawn(move || {
        if let Err(e) = send_frames(&sender, ox, oy, w, h) {
            if sender.alive.load(Ordering::Relaxed) {
                eprintln!("sender stopped: {e}");
            }
        }
        sender.alive.store(false, Ordering::Relaxed);
    });

    let result = read_client(&mut r, &shared, ox, oy);
    shared.alive.store(false, Ordering::Relaxed);
    result
}

/// Whether this server offers, insists on, or refuses to encrypt.
#[derive(PartialEq, Clone, Copy)]
enum TlsMode {
    /// Offer both VeNCrypt and plain VNC auth, and let the client pick. The default,
    /// because a client that has never heard of VeNCrypt still has to be able to
    /// connect - macOS's own viewer among them.
    Offer,
    /// Offer VeNCrypt only. Anyone in the middle of the connection can strip an
    /// encrypted option out of a list that also contains an unencrypted one, so a
    /// session that must be private cannot be left to the client to choose.
    Require,
    Off,
}

impl TlsMode {
    fn from_env() -> Res<TlsMode> {
        match std::env::var("VNC_TLS").unwrap_or_default().as_str() {
            "" | "offer" => Ok(TlsMode::Offer),
            "require" => Ok(TlsMode::Require),
            "off" => Ok(TlsMode::Off),
            other => Err(format!("VNC_TLS={other:?}: expected offer, require or off").into()),
        }
    }
}

/// The VeNCrypt sub-negotiation, up to the point where TLS takes over.
///
/// Only X509Vnc is offered. The other half of VeNCrypt's TLS types authenticate the
/// server with anonymous Diffie-Hellman instead of a certificate, which no modern TLS
/// library will do - anonymous key exchange has no defence against someone sitting in
/// the middle at all, and rustls does not implement it. A self-signed certificate is
/// the same amount of trust with a fingerprint attached that can actually be compared.
fn vencrypt(
    tcp: &mut TcpStream,
    me: &vncfree::wire::Identity,
) -> Res<(vncfree::wire::WireRead, vncfree::wire::WireWrite)> {
    const X509_VNC: u32 = 261;

    tcp.write_all(&[0, 2])?; // the version we speak
    let theirs = rd::<2>(tcp)?;
    if theirs[0] != 0 || theirs[1] < 2 {
        tcp.write_all(&[1])?; // non-zero: no version in common
        return Err(format!(
            "client speaks VeNCrypt {}.{}, and this server needs 0.2",
            theirs[0], theirs[1]
        )
        .into());
    }
    tcp.write_all(&[0])?; // zero: that version is fine

    tcp.write_all(&[1])?; // a list of one subtype
    tcp.write_all(&X509_VNC.to_be_bytes())?;
    let chosen = u32r(tcp)?;
    if chosen != X509_VNC {
        // Unlike every other acknowledgement in RFB, *one* means success here.
        tcp.write_all(&[0])?;
        return Err(format!("client asked for VeNCrypt subtype {chosen}, not X509Vnc").into());
    }
    tcp.write_all(&[1])?;

    vncfree::wire::server(tcp.try_clone()?, me)
}

/// Say no. RFB 3.7 added the explanatory string; sending one to a 3.3 client would be
/// unexpected bytes on a connection it thinks is finished.
fn refuse(tcp: &mut impl Write, old: bool, reason: &[u8]) -> Res<()> {
    tcp.write_all(&1u32.to_be_bytes())?;
    if !old {
        tcp.write_all(&(reason.len() as u32).to_be_bytes())?;
        tcp.write_all(reason)?;
    }
    Err(String::from_utf8_lossy(reason).into_owned().into())
}

fn read_client(tcp: &mut impl Read, shared: &Arc<Shared>, ox: i32, oy: i32) -> Res<()> {
    let mut mask = 0u8;
    let mut shift_held = false;
    let mut board = arboard::Clipboard::new().ok();
    while shared.alive.load(Ordering::Relaxed) {
        match u8r(tcp)? {
            0 => {
                // SetPixelFormat: 3 padding then the 16-byte format.
                blob(tcp, 3)?;
                let f = blob(tcp, 16)?;
                *shared.fmt.lock().unwrap() = PixFmt::parse(&f)?;
                // The client's copy of the screen is now in the wrong format, so the
                // next update has to be a full one.
                shared.incremental.store(false, Ordering::Relaxed);
            }
            2 => {
                blob(tcp, 1)?;
                let n = u16r(tcp)? as usize;
                let list = blob(tcp, n * 4)?;
                let encs: Vec<i32> = list
                    .chunks(4)
                    .map(|c| i32::from_be_bytes(c.try_into().unwrap()))
                    .collect();
                shared.zrle.store(encs.contains(&16), Ordering::Relaxed);
                shared.copyrect.store(encs.contains(&1), Ordering::Relaxed);
                shared.resize.store(encs.contains(&-223), Ordering::Relaxed);
                shared.cursor.store(encs.contains(&-239), Ordering::Relaxed);
                if debug() {
                    eprintln!(
                        "[debug] client supports encodings {encs:?}, using {}{}",
                        if encs.contains(&16) { "ZRLE" } else { "Raw" },
                        if encs.contains(&1) { " + CopyRect" } else { "" }
                    );
                }
                // There is no field anywhere that says "this server does continuous
                // updates". Sending an unprompted EndOfContinuousUpdates *is* the
                // announcement, and a client that has never heard of it ignores an
                // unknown message type. Ours replies by turning them on.
                if encs.contains(&-313) {
                    shared.out.lock().unwrap().write_all(&[150])?;
                }
            }
            3 => {
                let incremental = u8r(tcp)? != 0;
                blob(tcp, 8)?; // x, y, w, h - we always answer for the whole screen
                if !incremental {
                    shared.incremental.store(false, Ordering::Relaxed);
                }
                shared.wants.store(true, Ordering::Relaxed);
            }
            150 => {
                // EnableContinuousUpdates: a flag, then the region. We always answer
                // for the whole screen, so the region is read and discarded like the
                // one on an ordinary update request.
                let on = u8r(tcp)? != 0;
                blob(tcp, 8)?;
                shared.continuous.store(on, Ordering::Relaxed);
                if debug() {
                    eprintln!(
                        "[debug] continuous updates {}",
                        if on { "on" } else { "off" }
                    );
                }
                if !on {
                    // Turning them off has to be acknowledged, or the client cannot
                    // know which updates were still in flight when it asked.
                    shared.out.lock().unwrap().write_all(&[150])?;
                }
            }
            4 => {
                let down = u8r(tcp)? != 0;
                blob(tcp, 2)?;
                let sym = u32r(tcp)?;
                if sym == 0xffe1 || sym == 0xffe2 {
                    shift_held = down;
                }
                win::inject_key_shifted(sym, down, shift_held);
            }
            5 => {
                let now = u8r(tcp)?;
                let (x, y) = (u16r(tcp)?, u16r(tcp)?);
                win::move_pointer(x, y, ox, oy);
                win::buttons(mask, now);
                mask = now;
            }
            6 => {
                blob(tcp, 3)?;
                let n = u32r(tcp)? as usize;
                let body = blob(tcp, n)?;
                let text = from_latin1(&body);
                *shared.clip.lock().unwrap() = text.clone();
                if let Some(b) = board.as_mut() {
                    let _ = b.set_text(text);
                }
            }
            other => {
                // We cannot skip a message whose length we do not know, so this ends
                // the connection either way. Dump what follows first: an unrecognised
                // type is exactly how a proprietary extension announces itself, and
                // the bytes are the only record of it.
                if debug() {
                    let mut peek = [0u8; 64];
                    let n = std::io::Read::read(tcp, &mut peek).unwrap_or(0);
                    eprintln!(
                        "[debug] unknown client message type {other}, next {n} bytes: {:02x?}",
                        &peek[..n]
                    );
                }
                return Err(format!("unknown client message type {other}").into());
            }
        }
    }
    Ok(())
}

fn send_frames(shared: &Arc<Shared>, ox: i32, oy: i32, w: usize, h: usize) -> Res<()> {
    let (mut ox, mut oy, mut w, mut h) = (ox, oy, w, h);
    let mut cur = Screen::new(w, h);
    let mut prev = Screen::new(w, h);
    let mut first = true;
    // The HCURSOR the client was last told about. Windows reuses the handle for the
    // same cursor, so this is the whole change detector.
    let mut last_cursor: Option<isize> = None;
    let mut cap = win::Capture::new(ox, oy, w, h).ok_or("could not create the capture surface")?;
    // One deflate stream for the whole connection. ZRLE's zlib state spans the
    // session, not a rectangle; restarting it per rectangle decodes the first one and
    // then produces garbage on the client forever.
    let mut deflater = Compress::new(Compression::default(), true);

    let mut board = arboard::Clipboard::new().ok();
    if let Some(b) = board.as_mut() {
        if let Ok(t) = b.get_text() {
            *shared.clip.lock().unwrap() = t;
        }
    }
    let mut clip_tick = 0u32;

    while shared.alive.load(Ordering::Relaxed) {
        // Our clipboard changing is worth telling the client about whether or not it
        // has an update outstanding.
        if clip_tick == 0 {
            clip_tick = 50;
            if let Some(b) = board.as_mut() {
                if let Ok(t) = b.get_text() {
                    let mut last = shared.clip.lock().unwrap();
                    if !t.is_empty() && *last != t {
                        *last = t.clone();
                        drop(last);
                        let mut m = cut_text_msg(&t);
                        m[0] = 3; // ServerCutText carries the same body
                        shared.out.lock().unwrap().write_all(&m)?;
                    }
                }
            }
        }
        clip_tick -= 1;

        // With continuous updates the client has said "just send me changes", so there
        // is no request to wait for and none to consume.
        let continuous = shared.continuous.load(Ordering::Relaxed);
        // Consume the outstanding request *before* capturing, not after sending.
        // A client that asks for the next frame while this one is still going out -
        // which is what any client wanting more than one frame per round trip does -
        // would otherwise have its request cleared by the store that followed the
        // send, and the session would stall until it happened to ask again.
        if !continuous && !shared.wants.swap(false, Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }

        // The desktop can change resolution underneath us, and everything from the
        // capture surface to the client's framebuffer is sized for the old one.
        let mut resized = false;
        let now = win::share_region();
        if now != (ox, oy, w, h) && now.2 > 0 && now.3 > 0 {
            if !shared.resize.load(Ordering::Relaxed) {
                // Nothing in the protocol lets us tell this client. Ending the session
                // is the honest move: a reconnect negotiates the new size properly,
                // and our own client reconnects by itself.
                return Err(format!(
                    "screen changed from {w}x{h} to {}x{} and this client did not ask \
                     for DesktopSize; reconnect to pick up the new size",
                    now.2, now.3
                )
                .into());
            }
            println!(
                "shared region is now {}x{} at {},{}",
                now.2, now.3, now.0, now.1
            );
            (ox, oy, w, h) = now;
            cur = Screen::new(w, h);
            prev = Screen::new(w, h);
            cap =
                win::Capture::new(ox, oy, w, h).ok_or("could not recreate the capture surface")?;
            resized = true;
        }

        let full = first || resized || !shared.incremental.load(Ordering::Relaxed);
        // A client that draws the pointer itself gets a picture without one in it.
        let local_cursor = shared.cursor.load(Ordering::Relaxed);

        // The shape only has to go out when it actually changes, which is rarely - the
        // handle Windows hands back is the same one for the same cursor, so this costs
        // a comparison rather than two bitmap reads a frame.
        let mut cursor_part = None;
        if local_cursor {
            match win::cursor_shape() {
                Some((shape, handle)) if Some(handle) != last_cursor => {
                    last_cursor = Some(handle);
                    cursor_part = Some(Part::Cursor(shape));
                }
                Some(_) => {}
                // The pointer is hidden - a full-screen video, or a text caret owning
                // it. Send an empty shape so the client stops drawing the old one.
                None if last_cursor.is_some() => {
                    last_cursor = None;
                    cursor_part = Some(Part::Cursor(Cursor {
                        w: 0,
                        h: 0,
                        hot_x: 0,
                        hot_y: 0,
                        px: Vec::new(),
                        mask: Vec::new(),
                    }));
                }
                None => {}
            }
        } else {
            last_cursor = None;
        }

        let reported = cap.grab(&mut cur.px, !local_cursor);
        if matches!(reported, Frame::Unchanged) && !full && cursor_part.is_none() {
            // The screen provably did not move, so there is nothing to diff and
            // nothing to send. Put the request back: it is still outstanding.
            if !continuous {
                shared.wants.store(true, Ordering::Relaxed);
            } else {
                // Nothing to hold on to instead, so this is also what stops the loop
                // spinning on an idle desktop.
                std::thread::sleep(Duration::from_millis(10));
            }
            continue;
        }
        // Windows reports a *move* only for things like a dragged window. A terminal
        // or a document scrolling comes back as ordinary dirty regions, so taking the
        // report at face value loses the scroll detection entirely and sends megabytes
        // of pixels that a CopyRect would have moved for nothing. Past this much
        // change it is worth spending a comparison to go looking.
        let trusted = match reported {
            Frame::Known(r) => {
                let dirty: usize = r
                    .iter()
                    .map(|p| match *p {
                        Part::Pixels { w, h, .. } => w * h,
                        _ => 0,
                    })
                    .sum();
                if dirty * 8 <= w * h {
                    Some(r)
                } else {
                    None
                }
            }
            _ => None,
        };

        let mut parts = Vec::new();

        if full {
            // The size change goes first, so the client has resized its framebuffer
            // before the pixels that assume the new size arrive.
            if resized {
                parts.push(Part::Resize { w, h });
            }
            parts.push(Part::Pixels { x: 0, y: 0, w, h });
        } else if let Some(reported) = trusted {
            // The capture said exactly what changed, so no comparison is needed. Move
            // rectangles are already CopyRects, in two dimensions rather than the
            // vertical-scroll guess a diff has to make.
            if shared.copyrect.load(Ordering::Relaxed) {
                parts = reported;
            } else {
                // A client that never asked for CopyRect gets the moved regions as
                // pixels instead; sending it an encoding it did not request is a
                // protocol violation.
                parts = reported
                    .into_iter()
                    .map(|p| match p {
                        Part::Copy { x, y, w, h, .. } => Part::Pixels { x, y, w, h },
                        other => other,
                    })
                    .collect();
            }
            // Trusting the capture to have told us everything is the whole point, and
            // also the way this fails silently: a missed region leaves stale pixels on
            // the client with nothing to correct them. Under VNC_DEBUG, do the diff
            // anyway and complain about anything the rectangles did not cover.
            if debug() {
                // Pixel accurate on purpose. Asking whether each changed region sits
                // inside a single rectangle gives false alarms whenever two adjacent
                // rectangles cover it between them.
                let mut covered = vec![false; w * h];
                for p in &parts {
                    let (px, py, pw, ph) = match *p {
                        Part::Copy { x, y, w, h, .. } => (x, y, w, h),
                        Part::Pixels { x, y, w, h } => (x, y, w, h),
                        // Not regions of the picture; nothing to have covered.
                        Part::Resize { .. } | Part::Cursor(_) => continue,
                    };
                    for row in py..py + ph {
                        covered[row * w + px..row * w + px + pw].fill(true);
                    }
                }
                let missed = (0..w * h)
                    .filter(|&i| prev.px[i] != cur.px[i] && !covered[i])
                    .count();
                if missed > 0 {
                    eprintln!("[debug] {missed} changed px not covered by the reported rects");
                }
            }
        } else {
            let mut rects = changed_rects(&prev.px, &cur.px, w, h);
            // Worth looking for a scroll only if the change is tall enough to contain
            // one. Gating on *area* instead would never fire: a scrolling window is a
            // couple of percent of a 4K desktop.
            let top = rects.iter().map(|r| r.1).min().unwrap_or(0);
            let bottom = rects.iter().map(|r| r.1 + r.3).max().unwrap_or(0);
            let cols = dominant_cols(&rects).unwrap_or((0, 0));
            if shared.copyrect.load(Ordering::Relaxed) && bottom - top >= MIN_SCROLL {
                if let Some((dst_y, src_y, n)) = find_scroll(&prev.px, &cur.px, w, h, cols) {
                    let cw = cols.1 - cols.0;
                    parts.push(Part::Copy {
                        x: cols.0,
                        y: dst_y,
                        w: cw,
                        h: n,
                        sx: cols.0,
                        sy: src_y,
                    });
                    // Apply it to our copy of what the client has, so the diff below
                    // describes only the difference genuinely left over. Source and
                    // destination overlap, so this goes via a scratch buffer.
                    let band: Vec<u32> = (0..n)
                        .flat_map(|i| {
                            prev.px[(src_y + i) * w + cols.0..(src_y + i) * w + cols.1].to_vec()
                        })
                        .collect();
                    for i in 0..n {
                        prev.px[(dst_y + i) * w + cols.0..(dst_y + i) * w + cols.1]
                            .copy_from_slice(&band[i * cw..(i + 1) * cw]);
                    }
                    rects = changed_rects(&prev.px, &cur.px, w, h);
                }
            }
            parts.extend(
                rects
                    .into_iter()
                    .map(|(x, y, w, h)| Part::Pixels { x, y, w, h }),
            );
        }

        // A new pointer shape is worth an update on its own, even on a still screen.
        parts.extend(cursor_part);

        if parts.is_empty() {
            // An incremental request stays outstanding until something actually
            // changes; answering with zero rectangles would spin the client.
            if !continuous {
                shared.wants.store(true, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }

        let fmt = *shared.fmt.lock().unwrap();
        // ZRLE needs both the client's blessing and a pixel layout that has a legal
        // 3-byte CPIXEL; otherwise fall back to Raw, which every client understands.
        let zrle_ok = shared.zrle.load(Ordering::Relaxed) && fmt.cpixel(0).is_some();
        let msg = update(
            if zrle_ok { Some(&mut deflater) } else { None },
            &cur,
            &parts,
            &fmt,
        )?;
        if debug() {
            let copied: usize = parts
                .iter()
                .filter_map(|p| match p {
                    Part::Copy { w, h, .. } => Some(w * h),
                    _ => None,
                })
                .sum();
            let pixels: usize = parts
                .iter()
                .filter_map(|p| match p {
                    Part::Pixels { w, h, .. } => Some(w * h),
                    _ => None,
                })
                .sum();
            if copied > 0 {
                eprintln!("[debug] copyrect moved {copied} px without sending them");
            }
            eprintln!(
                "[debug] update: {} rect(s), {pixels} px, {} bytes on the wire ({:.1}% of raw)",
                parts.len(),
                msg.len(),
                100.0 * msg.len() as f64 / (pixels * 4).max(1) as f64
            );
        }
        shared.out.lock().unwrap().write_all(&msg)?;

        prev.px.copy_from_slice(&cur.px);
        first = false;
        shared.incremental.store(true, Ordering::Relaxed);
    }
    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_frames_produce_no_rectangles() {
        let a = vec![0u32; 128 * 128];
        assert!(changed_rects(&a, &a, 128, 128).is_empty());
    }

    #[test]
    fn a_single_changed_pixel_yields_only_its_tile() {
        let a = vec![0u32; 128 * 128];
        let mut b = a.clone();
        b[70 * 128 + 70] = 1; // inside tile (1,1)
        assert_eq!(changed_rects(&a, &b, 128, 128), vec![(64, 64, 64, 64)]);
    }

    /// Adjacent changed tiles must merge, otherwise a full-screen change at 1080p is
    /// 510 rectangles each carrying its own 12-byte header.
    #[test]
    fn adjacent_tiles_merge_into_one_rectangle() {
        let a = vec![0u32; 192 * 64];
        let mut b = a.clone();
        b[..192].fill(1); // whole top row changed, spanning three tiles
        assert_eq!(changed_rects(&a, &b, 192, 64), vec![(0, 0, 192, 64)]);
    }

    /// A gap must split the run rather than swallowing the unchanged middle tile.
    #[test]
    fn a_gap_splits_the_run() {
        let a = vec![0u32; 192 * 64];
        let mut b = a.clone();
        b[0] = 1;
        b[130] = 1; // tiles 0 and 2 changed, tile 1 untouched
        assert_eq!(
            changed_rects(&a, &b, 192, 64),
            vec![(0, 0, 64, 64), (128, 0, 64, 64)]
        );
    }

    /// Edge tiles are partial when the screen is not a multiple of 64.
    #[test]
    fn edge_tiles_are_clipped_to_the_screen() {
        let (w, h) = (100usize, 70usize);
        let a = vec![0u32; w * h];
        let mut b = a.clone();
        b[69 * w + 99] = 1; // bottom-right corner
        assert_eq!(changed_rects(&a, &b, w, h), vec![(64, 64, 36, 6)]);
    }

    #[test]
    fn pixels_are_composed_using_the_clients_shifts() {
        let bgr = PixFmt::default(); // shifts 16/8/0, little-endian
        assert_eq!(bgr.pixel(0x00AA_BBCC), [0xCC, 0xBB, 0xAA, 0]);

        let swapped = PixFmt {
            big_endian: false,
            rshift: 0,
            gshift: 8,
            bshift: 16,
        };
        assert_eq!(swapped.pixel(0x00AA_BBCC), [0xAA, 0xBB, 0xCC, 0]);

        let be = PixFmt {
            big_endian: true,
            ..PixFmt::default()
        };
        assert_eq!(be.pixel(0x00AA_BBCC), [0, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn a_non_32bpp_client_is_refused_with_a_clear_message() {
        let mut f = PIXEL_FORMAT;
        f[0] = 16; // bits-per-pixel
        let e = PixFmt::parse(&f).unwrap_err().to_string();
        assert!(e.contains("32bpp"), "{e}");
        assert!(PixFmt::parse(&PIXEL_FORMAT).is_ok());
    }

    fn tile_of(px: &[u32], w: usize, h: usize) -> Vec<u8> {
        let s = Screen {
            w,
            h,
            px: px.to_vec(),
        };
        let mut out = Vec::new();
        encode_tile(&mut out, &s, 0, 0, w, h, &PixFmt::default());
        out
    }

    #[test]
    fn a_uniform_tile_becomes_one_solid_pixel() {
        let out = tile_of(&[0x00AA_BBCC; 16], 4, 4);
        // Subencoding 1, then a single CPIXEL as B, G, R.
        assert_eq!(out, vec![1, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn two_colours_pack_one_bit_per_pixel_msb_first() {
        // Row 0 is A,B,A,B and row 1 is B,B,A,A.
        let (a, b) = (0x0000_0001, 0x0000_0002);
        let out = tile_of(&[a, b, a, b, b, b, a, a], 4, 2);
        assert_eq!(out[0], 2, "palette of two");
        assert_eq!(&out[1..4], &[1, 0, 0], "first palette entry is A");
        assert_eq!(&out[4..7], &[2, 0, 0], "second is B");
        // 4 pixels at 1 bit each, MSB first, each row padded to its own byte.
        assert_eq!(out[7], 0b0101_0000, "row 0: A B A B");
        assert_eq!(out[8], 0b1100_0000, "row 1: B B A A");
        assert_eq!(out.len(), 9);
    }

    /// Four colours need two bits per index, still packed from the top of the byte.
    /// Sixteen pixels rather than four, because at four the palette costs more than
    /// the pixels it indexes and raw is genuinely the smaller answer.
    #[test]
    fn four_colours_pack_two_bits_per_pixel() {
        let px: Vec<u32> = (0..4).flat_map(|_| [1, 2, 3, 4]).collect();
        let out = tile_of(&px, 16, 1);
        assert_eq!(out[0], 4, "palette of four");
        assert_eq!(out.len(), 1 + 4 * 3 + 4, "four pixels to the byte");
        assert_eq!(out[13], 0b00_01_10_11);
    }

    /// Every pixel a different colour and no runs at all: nothing to index and
    /// nothing to run-length, so raw genuinely is the smallest.
    #[test]
    fn all_different_colours_falls_back_to_raw() {
        let px: Vec<u32> = (0..200u32).collect();
        let out = tile_of(&px, 200, 1);
        assert_eq!(out[0], 0, "raw subencoding");
        assert_eq!(out.len(), 1 + 200 * 3, "three bytes per pixel, no palette");
    }

    /// Too many colours to index, but arriving in long runs: plain RLE, which this
    /// encoder previously could not produce at all.
    #[test]
    fn many_colours_in_long_runs_use_plain_rle() {
        // 200 colours of 20 pixels each: 4000 pixels in 200 runs.
        let px: Vec<u32> = (0..200u32)
            .flat_map(|c| std::iter::repeat_n(c + 1, 20))
            .collect();
        let out = tile_of(&px, 4000, 1);
        assert_eq!(out[0], 128, "plain RLE");
        // Per run: three bytes of colour, then one length byte for a run of 20.
        assert_eq!(out.len(), 1 + 200 * 4);
        assert_eq!(out[4], 19, "the length is one *less* than the run");
        assert!(out.len() < 1 + 4000 * 3, "and it beats raw handily");
    }

    /// Palette RLE earns its keep between 17 and 127 colours: too many for the packed
    /// form, few enough to index, and repeating enough that an index per run beats a
    /// colour per run. Twenty colours, each appearing in ten separate runs.
    #[test]
    fn repeating_colours_in_runs_use_palette_rle() {
        let px: Vec<u32> = (0..10)
            .flat_map(|_| (0..20u32).flat_map(|c| std::iter::repeat_n(c + 1, 5)))
            .collect();
        let out = tile_of(&px, 1000, 1);
        assert_eq!(out[0], 128 + 20, "palette RLE, twenty colours");
        // Subencoding, twenty CPIXELs, then an index and a length for each of 200 runs.
        assert_eq!(out.len(), 1 + 20 * 3 + 200 * 2);
        assert_eq!(out[61], 0x80, "index 0 with the run bit set");
        assert_eq!(out[62], 4, "one less than five");
        assert!(out.len() < 1 + 200 * 4, "and it beats a colour per run");
    }

    /// A run longer than 255 goes out in instalments, ended by a byte under 255.
    #[test]
    fn long_runs_are_split_into_instalments() {
        let mut out = Vec::new();
        write_run(&mut out, 2);
        assert_eq!(out, [1]);
        out.clear();
        write_run(&mut out, 256);
        assert_eq!(out, [255, 0], "255, then the remainder");
        out.clear();
        write_run(&mut out, 600);
        assert_eq!(out, [255, 255, 89]);
        assert_eq!(
            1 + 255 + 255 + 89,
            600,
            "which is what the client will add up"
        );
    }

    /// CPIXELs drop the unused byte, and an exotic layout has none to drop.
    #[test]
    fn cpixel_drops_the_unused_byte_or_refuses() {
        assert_eq!(
            PixFmt::default().cpixel(0x00AA_BBCC),
            Some([0xCC, 0xBB, 0xAA])
        );
        let be = PixFmt {
            big_endian: true,
            ..PixFmt::default()
        };
        assert_eq!(be.cpixel(0x00AA_BBCC), Some([0xAA, 0xBB, 0xCC]));
        // Colour living in the top three bytes has no 3-byte little-endian form here.
        let high = PixFmt {
            big_endian: false,
            rshift: 24,
            gshift: 16,
            bshift: 8,
        };
        assert_eq!(high.cpixel(0x00AA_BBCC), None);
    }

    /// The deflate stream spans the connection, so a second rectangle must not
    /// restart it - and the helper must terminate, which an over-eager flush loop
    /// famously does not.
    #[test]
    fn deflate_is_streaming_and_terminates() {
        let mut z = Compress::new(Compression::default(), true);
        let first = deflate(&mut z, b"hello hello hello").unwrap();
        let second = deflate(&mut z, b"hello hello hello").unwrap();
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        // The second copy is cheaper because the first is still in the window.
        assert!(
            second.len() < first.len(),
            "{} vs {}",
            second.len(),
            first.len()
        );
    }

    /// A scrolled band must be found, and must be exactly right - the whole point of
    /// verifying pixels rather than trusting the row hashes.
    #[test]
    fn a_scrolled_band_is_found_and_reported_exactly() {
        let (w, h) = (8usize, 200usize);
        // Every row distinct, so a shift is unambiguous.
        let prev: Vec<u32> = (0..w * h).map(|i| (i / w) as u32 + 1).collect();
        // Scroll up by 10 rows: row y now holds what row y+10 held.
        let mut cur = vec![0u32; w * h];
        for y in 0..h - 10 {
            cur[y * w..(y + 1) * w].copy_from_slice(&prev[(y + 10) * w..(y + 11) * w]);
        }
        let (dst_y, src_y, n) =
            find_scroll(&prev, &cur, w, h, (0, w)).expect("should spot the scroll");
        assert_eq!(dst_y, 0);
        assert_eq!(src_y, 10);
        assert_eq!(n, h - 10, "the whole scrolled band");
        assert!(rows_match(&prev, &cur, w, (0, w), src_y, dst_y, n));
    }

    /// Scrolling inside a window: only some columns move, and the desktop either side
    /// stays put. Hashing whole rows would miss this entirely.
    #[test]
    fn a_scroll_inside_a_column_band_is_found() {
        let (w, h) = (40usize, 200usize);
        // Left third is a static "desktop" whose rows differ from each other - as a
        // real desktop's do - and the rest is a scrolling window.
        let band = (12usize, 40usize);
        let mut prev = vec![0u32; w * h];
        for y in 0..h {
            for x in 0..band.0 {
                prev[y * w + x] = 900_000 + (y as u32) * 7 + x as u32;
            }
            for x in band.0..band.1 {
                prev[y * w + x] = (y as u32 + 1) * 100 + x as u32;
            }
        }
        let mut cur = prev.clone();
        for y in 0..h - 10 {
            for x in band.0..band.1 {
                cur[y * w + x] = prev[(y + 10) * w + x];
            }
        }
        assert_eq!(
            find_scroll(&prev, &cur, w, h, (0, w)),
            None,
            "full-width hashing cannot see a windowed scroll"
        );
        let (dst_y, src_y, n) = find_scroll(&prev, &cur, w, h, band).expect("found in the band");
        assert_eq!((dst_y, src_y), (0, 10));
        assert_eq!(n, h - 10);
    }

    #[test]
    fn a_still_screen_and_a_tiny_change_are_not_scrolls() {
        let (w, h) = (8usize, 200usize);
        let a: Vec<u32> = (0..w * h).map(|i| (i / w) as u32 + 1).collect();
        assert_eq!(find_scroll(&a, &a, w, h, (0, w)), None, "nothing moved");

        let mut b = a.clone();
        b[100 * w + 3] = 99; // one pixel
        assert_eq!(
            find_scroll(&a, &b, w, h, (0, w)),
            None,
            "too small to be a scroll"
        );
    }

    /// The union would be (10, 108) here, dragging in the static desktop between the
    /// two changes and making every row comparison fail.
    #[test]
    fn dominant_columns_pick_the_busiest_band_not_the_union() {
        let rects = [
            (10, 0, 20, 64), // a scrolling window, three tile rows of it
            (10, 64, 20, 64),
            (10, 128, 20, 64),
            (100, 0, 8, 8), // something small twitching far away
        ];
        assert_eq!(dominant_cols(&rects), Some((10, 30)));
        assert_eq!(dominant_cols(&[]), None);
    }

    /// Rows that hash alike but differ must be rejected. A CopyRect built on a
    /// collision would corrupt the client's screen silently.
    #[test]
    fn a_band_that_only_looks_shifted_is_rejected() {
        let (w, h) = (8usize, 200usize);
        let prev: Vec<u32> = (0..w * h).map(|i| (i / w) as u32 + 1).collect();
        let mut cur = vec![0u32; w * h];
        for y in 0..h - 10 {
            cur[y * w..(y + 1) * w].copy_from_slice(&prev[(y + 10) * w..(y + 11) * w]);
        }
        // Corrupt one pixel inside the band so the pixel check must fail.
        cur[50 * w + 2] = 0xDEAD;
        assert!(!rows_match(&prev, &cur, w, (0, w), 10, 0, h - 10));
    }

    #[test]
    fn copyrect_costs_four_bytes_of_coordinates_and_no_pixels() {
        let s = Screen::new(64, 64);
        let parts = [Part::Copy {
            x: 0,
            y: 10,
            w: 64,
            h: 20,
            sx: 0,
            sy: 30,
        }];
        let msg = update(None, &s, &parts, &PixFmt::default()).unwrap();
        assert_eq!(msg[0], 0, "FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "one rectangle");
        assert_eq!(
            i32::from_be_bytes(msg[12..16].try_into().unwrap()),
            1,
            "CopyRect"
        );
        assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), 0, "source x");
        assert_eq!(u16::from_be_bytes([msg[18], msg[19]]), 30, "source y");
        assert_eq!(
            msg.len(),
            4 + 12 + 4,
            "header, rect, and just the source point"
        );
    }

    #[test]
    fn zrle_rect_header_is_well_formed() {
        let mut z = Compress::new(Compression::default(), true);
        let s = Screen::new(4, 4);
        let parts = [Part::Pixels {
            x: 0,
            y: 0,
            w: 4,
            h: 4,
        }];
        let msg = update(Some(&mut z), &s, &parts, &PixFmt::default()).unwrap();
        assert_eq!(msg[0], 0, "FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "one rectangle");
        assert_eq!(
            i32::from_be_bytes(msg[12..16].try_into().unwrap()),
            16,
            "ZRLE"
        );
        let len = u32::from_be_bytes(msg[16..20].try_into().unwrap()) as usize;
        assert_eq!(msg.len(), 20 + len, "body length must match the header");
    }

    #[test]
    fn raw_update_header_is_well_formed() {
        let s = Screen::new(2, 1);
        let parts = [Part::Pixels {
            x: 0,
            y: 0,
            w: 2,
            h: 1,
        }];
        let msg = update(None, &s, &parts, &PixFmt::default()).unwrap();
        assert_eq!(msg[0], 0, "FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "one rectangle");
        assert_eq!(u16::from_be_bytes([msg[8], msg[9]]), 2, "width");
        assert_eq!(
            i32::from_be_bytes(msg[12..16].try_into().unwrap()),
            0,
            "Raw"
        );
        assert_eq!(msg.len(), 4 + 12 + 2 * 4);
    }
}
