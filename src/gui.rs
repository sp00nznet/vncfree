//! A minimal native dialog, shared by the client and the server.
//!
//! Deliberately plain Win32 rather than a UI toolkit. The whole interface is a few
//! labelled text boxes and one button, and a real toolkit would add hundreds of
//! crates and several megabytes to a program whose entire pitch is one small
//! self-contained exe.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// One labelled input.
pub struct Field {
    pub label: &'static str,
    pub value: String,
    /// Show dots instead of characters.
    pub secret: bool,
    /// The action button stays disabled until every required field has something in
    /// it. This is how the server refuses to start without a password.
    pub required: bool,
}

impl Field {
    pub fn new(label: &'static str, secret: bool, required: bool) -> Field {
        Field {
            label,
            value: String::new(),
            secret,
            required,
        }
    }
}

struct State {
    edits: Vec<HWND>,
    button: HWND,
    fields: *mut Vec<Field>,
    ok: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_text(hwnd: HWND) -> String {
    unsafe {
        let n = GetWindowTextLengthW(hwnd);
        if n <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; n as usize + 1];
        let got = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        String::from_utf16_lossy(&buf[..got as usize])
    }
}

/// Whether the action button should be usable: every required field has something
/// other than whitespace in it. Kept separate from the window plumbing so it can be
/// tested - this is what stops the server being started without a password.
pub(crate) fn ready(fields: &[(bool, String)]) -> bool {
    fields
        .iter()
        .all(|(required, text)| !required || !text.trim().is_empty())
}

unsafe fn refresh_button(st: &State) {
    let fields = &*st.fields;
    let state: Vec<(bool, String)> = fields
        .iter()
        .zip(&st.edits)
        .map(|(f, &e)| (f.required, read_text(e)))
        .collect();
    EnableWindow(st.button, ready(&state) as i32);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let st = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut State;
    match msg {
        WM_COMMAND if !st.is_null() => {
            let code = (wp >> 16) as u32;
            let id = (wp & 0xffff) as u16;
            if code == EN_CHANGE {
                refresh_button(&*st);
            } else if code == BN_CLICKED && id == 1 {
                // Copy the box contents back out before the window goes away.
                let fields = &mut *(*st).fields;
                for (f, &e) in fields.iter_mut().zip(&(*st).edits) {
                    f.value = read_text(e);
                }
                (*st).ok = true;
                DestroyWindow(hwnd);
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

/// Show a modal form. Returns true if the user pressed the button, false if they
/// closed the window. Field values are written back in place.
///
/// Returns false immediately on a non-Windows build so callers can fall back to the
/// command line.
pub fn form(title: &str, note: &str, fields: &mut Vec<Field>, button: &str) -> bool {
    unsafe {
        // Per-thread rather than per-process, so the dialog renders crisply on a
        // high-DPI screen without changing how the rest of the program - notably the
        // client's session window - is treated. Restored before returning.
        let prev_dpi = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        let inst = GetModuleHandleW(null());
        let class = wide("vncfreeForm");

        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: inst,
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
        };
        RegisterClassW(&wc);

        // Everything below is in 96-dpi units and scaled once here, so the dialog is
        // the right physical size whether or not the process is DPI-aware.
        let s = |v: i32| v * GetDpiForSystem() as i32 / 96;
        let (pad, row, label_w, edit_w) = (s(12), s(28), s(90), s(230));
        // Tall enough for three wrapped lines; a clipped warning is worse than none.
        let note_h = if note.is_empty() {
            0
        } else {
            s(16) * (note.lines().count() as i32 + 1)
        };
        let width = pad * 3 + label_w + edit_w;
        let height = note_h + fields.len() as i32 * row + s(70);

        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide(title).as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width + s(16),
            height + s(39), // rough allowance for the title bar and borders
            null_mut(),
            null_mut(),
            inst,
            null_mut(),
        );
        if hwnd.is_null() {
            SetThreadDpiAwarenessContext(prev_dpi);
            return false;
        }

        let font = GetStockObject(DEFAULT_GUI_FONT);
        let set_font = |c: HWND| {
            SendMessageW(c, WM_SETFONT, font as WPARAM, 1);
        };

        let child = |style: u32, class: &str, text: &str, x, y, w, h, id: usize| -> HWND {
            CreateWindowExW(
                0,
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                w,
                h,
                hwnd,
                id as *mut c_void,
                inst,
                null_mut(),
            )
        };

        let mut y = pad;
        if !note.is_empty() {
            let c = child(0, "STATIC", note, pad, y, width - pad * 2, note_h, 0);
            set_font(c);
            y += note_h;
        }

        let mut edits = Vec::new();
        for (i, f) in fields.iter().enumerate() {
            let l = child(0, "STATIC", f.label, pad, y + s(4), label_w, s(20), 0);
            set_font(l);
            let extra = if f.secret { ES_PASSWORD as u32 } else { 0 };
            let e = child(
                WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32 | extra,
                "EDIT",
                &f.value,
                pad * 2 + label_w,
                y,
                edit_w,
                s(22),
                100 + i,
            );
            set_font(e);
            edits.push(e);
            y += row;
        }

        let btn = child(
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            "BUTTON",
            button,
            width - pad - s(110),
            y + s(8),
            s(110),
            s(26),
            1,
        );
        set_font(btn);

        let mut state = State {
            edits,
            button: btn,
            fields: fields as *mut _,
            ok: false,
        };
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, &mut state as *mut State as isize);
        refresh_button(&state);

        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        if let Some(&first) = state.edits.first() {
            SetFocus(first);
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            // IsDialogMessageW is what makes Tab move between boxes and Enter press
            // the default button; without it this is a window, not a dialog.
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        SetThreadDpiAwarenessContext(prev_dpi);
        state.ok
    }
}

/// This machine's address on the local network, worked out by asking the OS which
/// interface it would use to reach the internet. A UDP connect sends no packets, so
/// this is entirely offline and contacts nothing.
pub fn lan_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::ready;

    #[test]
    fn the_button_waits_for_every_required_field() {
        let req = |s: &str| (true, s.to_string());
        let opt = |s: &str| (false, s.to_string());

        assert!(!ready(&[req("")]), "empty required field must block");
        assert!(!ready(&[req("   ")]), "whitespace is not a password");
        assert!(ready(&[req("hunter2")]));
        // An optional field may be empty - the client's username is only for Macs.
        assert!(ready(&[req("host:5900"), opt("")]));
        // One missing required field is enough to block, wherever it sits.
        assert!(!ready(&[req("host:5900"), opt("bob"), req("")]));
        assert!(ready(&[req("host:5900"), opt("bob"), req("pw")]));
        assert!(ready(&[]), "a form with no fields is trivially ready");
    }
}
