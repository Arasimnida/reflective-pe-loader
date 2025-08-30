use crate::LoaderError;
use pe_format::{PeImage, ImageImportDescriptor};
use std::ffi::CString;
use windows::{
    core::PCSTR,
    Win32::Foundation::HMODULE,
    Win32::System::LibraryLoader::{
        GetModuleHandleA,
        GetProcAddress
    },
};


const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
struct ImportByName<'a> {
    #[allow(dead_code)]
    hint: u16,
    name: &'a str,
}

pub fn resolve_imports(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    let Some(_dir) = img.dir(1) else { return Ok(()); };

    let Some(descs) = img.import_descriptors() else { return Ok(()); };

    for desc in descs {
        let dll_name_bytes = read_cstr_from_rva(img, desc.name)?;
        let dll_name = core::str::from_utf8(dll_name_bytes)
            .map_err(|_| LoaderError::Format("dll name not utf8"))?;

        let hmod = os_load_module(dll_name)?;

        let mut int_rva = desc.original_first_thunk;
        let mut iat_rva = desc.first_thunk;

        loop {
            let thunk_val = read_u64_from_file(img, int_rva)?;
            if thunk_val == 0 { break; }

            let addr: usize = if (thunk_val & IMAGE_ORDINAL_FLAG64) != 0 {
            let ord = (thunk_val & 0xFFFF) as u16;
            os_get_proc_by_ordinal(hmod, ord)?
        } else {
            let name_rva = (thunk_val & 0xFFFF_FFFF) as u32;
            let bin = read_import_by_name(img, name_rva)?;
            os_get_proc_by_name(hmod, bin.name)?
        };
        os_write_ptr64(base, iat_rva as usize, addr as u64)?;

            int_rva = int_rva.wrapping_add(8);
            iat_rva = iat_rva.wrapping_add(8);
        }
    }

    Ok(())
}

fn os_load_module(name_utf8: &str) -> Result<HMODULE, LoaderError> {
    let c = CString::new(name_utf8).map_err(|_| LoaderError::Format("dll name has interior NUL"))?;
    let h = unsafe { GetModuleHandleA(PCSTR(c.as_ptr() as _)) }
        .map_err(|_| LoaderError::Api("GetModuleHandleA failed"))?;
    Ok(h)
}

fn os_get_proc_by_name(hmod: HMODULE, name: &str) -> Result<usize, LoaderError> {
    let c = CString::new(name).map_err(|_| LoaderError::Format("proc name has interior NUL"))?;
    let p = unsafe { GetProcAddress(hmod, PCSTR(c.as_ptr() as _)) }
        .ok_or(LoaderError::Api("GetProcAddress (by name) returned NULL"))?;
    Ok(p as usize)
}

fn os_get_proc_by_ordinal(hmod: HMODULE, ordinal: u16) -> Result<usize, LoaderError> {
    let p = unsafe { GetProcAddress(hmod, PCSTR(ordinal as usize as _)) }
        .ok_or(LoaderError::Api("GetProcAddress (by ordinal) returned NULL"))?;
    Ok(p as usize)
}

fn os_write_ptr64(base: usize, iat_rva: usize, value: u64) -> Result<(), LoaderError> {
    unsafe {
        let p = (base as *mut u8).add(iat_rva) as *mut u64;
        core::ptr::write_unaligned(p, value);
    }
    Ok(())
}

fn read_cstr_from_rva<'a>(img: &'a PeImage, rva: u32) -> Result<&'a [u8], LoaderError> {
    let off = img.rva_to_offset(rva as usize)
        .ok_or(LoaderError::Format("cstr rva out of file"))?;
    let bytes = img.as_bytes();
    let mut end = off;
    while end < bytes.len() && bytes[end] != 0 { end += 1; }
    if end == bytes.len() {
        return Err(LoaderError::Format("unterminated cstr"));
    }
    Ok(&bytes[off..end])
}

fn read_u64_from_file(img: &PeImage, rva: u32) -> Result<u64, LoaderError> {
    let off = img.rva_to_offset(rva as usize)
        .ok_or(LoaderError::Format("u64 rva out of file"))?;
    let bytes = img.as_bytes();
    if off + 8 > bytes.len() { return Err(LoaderError::Format("u64 out of file")); }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..off+8]);
    Ok(u64::from_le_bytes(buf))
}

fn read_import_by_name<'a>(img: &'a PeImage, rva: u32) -> Result<ImportByName<'a>, LoaderError> {
    let off = img.rva_to_offset(rva as usize)
        .ok_or(LoaderError::Format("import-by-name rva out of file"))?;
    let bytes = img.as_bytes();
    if off + 2 > bytes.len() { return Err(LoaderError::Format("hint out of file")); }
    let hint = u16::from_le_bytes([bytes[off], bytes[off+1]]);
    let mut p = off + 2;
    while p < bytes.len() && bytes[p] != 0 { p += 1; }
    if p == bytes.len() { return Err(LoaderError::Format("name unterminated")); }
    let name = core::str::from_utf8(&bytes[off+2..p]).map_err(|_| LoaderError::Format("name not utf8"))?;
    Ok(ImportByName { hint, name })
}
