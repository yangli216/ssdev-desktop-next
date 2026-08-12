#[no_mangle]
pub extern "C" fn Add(left: usize, right: usize) -> usize {
    left + right
}

/// # Safety
///
/// `output` must point to a writable buffer of at least 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn FillBuffer(output: *mut u8) -> usize {
    let value = b"fixture-ok\0";
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len()) };
    value.len() - 1
}
