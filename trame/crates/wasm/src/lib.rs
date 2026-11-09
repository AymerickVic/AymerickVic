//! WebAssembly build of the Trame engine.
//!
//! Plain C ABI, no bindings generator: the page copies the capture into memory
//! obtained from `alloc`, calls a function, then reads the JSON answer from
//! `out_ptr()` / `out_len()`. Every call returns the answer length, or -1 when
//! the answer is an error object (`{"error": "..."}`).

use std::cell::RefCell;
use trame_core::Session;

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn answer(v: Result<serde_json::Value, String>) -> i32 {
    let (bytes, code) = match v {
        Ok(v) => (serde_json::to_vec(&v).unwrap_or_default(), 0),
        Err(e) => (
            serde_json::to_vec(&serde_json::json!({ "error": e })).unwrap_or_default(),
            -1,
        ),
    };
    let len = bytes.len() as i32;
    OUT.with(|o| *o.borrow_mut() = bytes);
    if code < 0 {
        -1
    } else {
        len
    }
}

fn with<F: FnOnce(&mut Session) -> Result<serde_json::Value, String>>(f: F) -> i32 {
    SESSION.with(|s| match s.borrow_mut().as_mut() {
        Some(s) => answer(f(s)),
        None => answer(Err("Aucune capture ouverte".into())),
    })
}

/// # Safety
/// `ptr` must come from [`alloc`] with the same `len`.
unsafe fn read_str(ptr: *mut u8, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    let bytes = Vec::from_raw_parts(ptr, len, len);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr` must come from [`alloc`] with the same `len`, and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn out_len() -> usize {
    OUT.with(|o| o.borrow().len())
}

/// Open a capture. Takes ownership of the buffer.
///
/// # Safety
/// `ptr` must come from [`alloc`] with the same `len`, filled with the file's bytes.
#[no_mangle]
pub unsafe extern "C" fn open(ptr: *mut u8, len: usize) -> i32 {
    let bytes = Vec::from_raw_parts(ptr, len, len.max(1));
    let r = Session::open(&bytes);
    drop(bytes);
    match r {
        Ok(s) => {
            let frames = s.len();
            SESSION.with(|cell| *cell.borrow_mut() = Some(s));
            answer(Ok(serde_json::json!({ "frames": frames })))
        }
        Err(e) => answer(Err(e.to_string())),
    }
}

#[no_mangle]
pub extern "C" fn overview() -> i32 {
    with(|s| Ok(s.overview()))
}

/// # Safety
/// `fptr`/`flen` must come from [`alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn rows(fptr: *mut u8, flen: usize, offset: u32, limit: u32) -> i32 {
    let filter = read_str(fptr, flen);
    with(|s| {
        s.rows(&filter, offset as usize, limit as usize)
            .map_err(|e| e.to_string())
    })
}

/// Check a filter without running it (live validation while typing).
///
/// # Safety
/// `fptr`/`flen` must come from [`alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn check_filter(fptr: *mut u8, flen: usize) -> i32 {
    let filter = read_str(fptr, flen);
    if filter.trim().is_empty() {
        return answer(Ok(serde_json::json!({ "ok": true })));
    }
    match trame_core::filter::Filter::parse(&filter) {
        Ok(_) => answer(Ok(serde_json::json!({ "ok": true }))),
        Err(e) => answer(Err(e.message)),
    }
}

/// # Safety
/// `fptr`/`flen` must come from [`alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn index_of(fptr: *mut u8, flen: usize, frame: u32) -> i32 {
    let filter = read_str(fptr, flen);
    with(|s| {
        s.index_of(&filter, frame)
            .map(|i| serde_json::json!({ "index": i }))
            .map_err(|e| e.to_string())
    })
}

#[no_mangle]
pub extern "C" fn frame(n: u32) -> i32 {
    with(|s| s.frame(n).ok_or_else(|| format!("Trame {n} introuvable")))
}

#[no_mangle]
pub extern "C" fn conversation(id: u32, max: u32) -> i32 {
    with(|s| {
        s.conversation(id, max as usize)
            .ok_or_else(|| format!("Conversation {id} introuvable"))
    })
}
