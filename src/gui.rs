//! A minimal native dialog, shared by the client and the server.
//!
//! Deliberately plain Win32 rather than a UI toolkit. The whole interface is a few
//! labelled text boxes and one button, and a real toolkit would add hundreds of
//! crates and several megabytes to a program whose entire pitch is one small
//! self-contained exe.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetStockObject, GetSysColorBrush, SetBkMode, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH, HDC,
    TRANSPARENT,
};
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

/// Checks the form before it is accepted. Returns a complaint to show the user, or
/// None to let the dialog close.
pub type Validator = fn(&[Field]) -> Option<String>;

struct State {
    edits: Vec<HWND>,
    button: HWND,
    fields: *mut Vec<Field>,
    validate: Option<Validator>,
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
                // Complain and stay open rather than closing on a typo and reporting
                // it to a window that no longer exists.
                if let Some(problem) = (*st).validate.and_then(|v| v(fields)) {
                    alert("vncfree", &problem);
                    if let Some(&first) = (*st).edits.first() {
                        SetFocus(first);
                    }
                    return 0;
                }
                (*st).ok = true;
                DestroyWindow(hwnd);
            }
            0
        }
        // Labels otherwise paint themselves with the default dialog-grey brush, which
        // does not match the window behind them. Draw the text straight onto the
        // window background instead.
        WM_CTLCOLORSTATIC => {
            SetBkMode(wp as HDC, TRANSPARENT as i32);
            GetSysColorBrush(COLOR_WINDOW) as LRESULT
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
pub fn form(
    title: &str,
    note: &str,
    fields: &mut Vec<Field>,
    button: &str,
    validate: Option<Validator>,
) -> bool {
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
            validate,
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

/// Complain about anything that is obviously not `host:port`. Deliberately only a
/// syntax check: resolving a name would block the dialog on a DNS lookup, and a host
/// that does not answer is reported by the connection attempt anyway.
pub fn check_host_port(what: &str, value: &str) -> Option<String> {
    let value = value.trim();
    let Some((host, port)) = value.rsplit_once(':') else {
        return Some(format!(
            "{what} needs a port.\n\n\
             You typed \"{value}\".\nTry something like {value}:5900"
        ));
    };
    if host.is_empty() {
        return Some(format!("{what} is missing the host part before the colon."));
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => None,
        _ => Some(format!(
            "{what} has a bad port.\n\n\"{port}\" is not a number between 1 and 65535."
        )),
    }
}

/// Report a failure in a box. Launched from Explorer there is no console, so an
/// error printed to stderr goes nowhere and the program just seems to do nothing.
pub fn alert(title: &str, text: &str) {
    unsafe {
        MessageBoxW(
            null_mut(),
            wide(text).as_ptr(),
            wide(title).as_ptr(),
            // Without SETFOREGROUND the box can open behind whatever is on screen,
            // which looks exactly like the program having silently given up.
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
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

    /// The typo that started this: an address with no port at all.
    #[test]
    fn a_missing_or_bad_port_is_caught_before_the_dialog_closes() {
        use super::check_host_port;
        let m = check_host_port("The address", "192.168.100.").unwrap();
        assert!(m.contains("needs a port"), "{m}");
        assert!(m.contains("192.168.100.:5900"), "should suggest a fix: {m}");

        assert!(check_host_port("x", "host:0").unwrap().contains("bad port"));
        assert!(check_host_port("x", "host:99999")
            .unwrap()
            .contains("bad port"));
        assert!(check_host_port("x", "host:abc")
            .unwrap()
            .contains("bad port"));
        assert!(check_host_port("x", ":5900")
            .unwrap()
            .contains("missing the host"));

        assert_eq!(check_host_port("x", "192.168.1.50:5900"), None);
        assert_eq!(check_host_port("x", "  0.0.0.0:5900  "), None, "trims");
        assert_eq!(check_host_port("x", "myhost:5900"), None, "names are fine");
        assert_eq!(check_host_port("x", "host:65535"), None);
    }
}
