use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::piece_table::PieceTable;
use crate::parser::CrexSyntaxParser;

pub struct CrexBufferHandle {
    table: PieceTable,
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_create(initial_text: *const c_char) -> *mut CrexBufferHandle {
    let text = if initial_text.is_null() {
        ""
    } else {
        match CStr::from_ptr(initial_text).to_str() {
            Ok(s) => s,
            Err(_) => "",
        }
    };

    let handle = Box::new(CrexBufferHandle {
        table: PieceTable::new(text),
    });

    Box::into_raw(handle)
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_insert(
    handle: *mut CrexBufferHandle,
    offset: usize,
    text: *const c_char,
) {
    if handle.is_null() || text.is_null() {
        return;
    }

    if let Ok(slice) = CStr::from_ptr(text).to_str() {
        (*handle).table.insert(offset, slice);
    }
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_delete(
    handle: *mut CrexBufferHandle,
    offset: usize,
    length: usize,
) {
    if handle.is_null() {
        return;
    }

    (*handle).table.delete(offset, length);
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_get_text(handle: *const CrexBufferHandle) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }

    let text = (*handle).table.get_text();
    match CString::new(text) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_line_count(handle: *const CrexBufferHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    (*handle).table.line_count()
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_length(handle: *const CrexBufferHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    (*handle).table.len()
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_parse_ast(
    handle: *const CrexBufferHandle,
    language: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }

    let lang = if language.is_null() {
        "rust"
    } else {
        CStr::from_ptr(language).to_str().unwrap_or("rust")
    };

    let parser = CrexSyntaxParser::new(lang);
    let text = (*handle).table.get_text();
    let snapshot = parser.parse_tokens(&text);

    let json = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string());
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn crex_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn crex_buffer_free(handle: *mut CrexBufferHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}
