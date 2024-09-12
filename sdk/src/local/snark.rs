extern crate libc;
use libc::c_int;
use std::os::raw::c_char;

extern {
    fn Stark2Snark(inputdir: *const c_char, outputdir: *const c_char) -> c_int;
}

pub fn prove_snark(inputdir: &str, outputdir: &str) -> bool {

    let inputdir = std::ffi::CString::new(inputdir).unwrap();
    let outputdir = std::ffi::CString::new(outputdir).unwrap();
    let ret = unsafe {
        Stark2Snark(inputdir.as_ptr(), outputdir.as_ptr())
    };
    ret == 0
}