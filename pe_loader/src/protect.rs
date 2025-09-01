use crate::LoaderError;
use pe_format::PeImage;

use windows::Win32::System::Memory::{
    VirtualProtect, 
    PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, 
    PAGE_READWRITE, 
    PAGE_EXECUTE, 
    PAGE_EXECUTE_READ, 
    PAGE_EXECUTE_READWRITE
};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const PAGE_SIZE: usize = 0x1000;

fn map_section_protect(characteristics: u32) -> PAGE_PROTECTION_FLAGS {
    let r = (characteristics & IMAGE_SCN_MEM_READ)   != 0;
    let w = (characteristics & IMAGE_SCN_MEM_WRITE)  != 0;
    let x = (characteristics & IMAGE_SCN_MEM_EXECUTE)!= 0;

    match (r, w, x) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, true,  true) => PAGE_EXECUTE,
        (true, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (false, false, false) => PAGE_READONLY,
    }
}

fn os_protect(addr: usize, size: usize, prot: PAGE_PROTECTION_FLAGS) -> Result<(), LoaderError> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let ok = unsafe { VirtualProtect(addr as *const _, size, prot, &mut old) }.is_ok();
    if ok { Ok(()) } else { Err(LoaderError::Api("VirtualProtect failed")) }
}

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}

pub fn finalise_section_protections(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    let hdr_size = align_up(img.size_of_headers() as usize, PAGE_SIZE);
    if hdr_size != 0 {
        os_protect(base, hdr_size, PAGE_READONLY)?;
    }

    for s in img.sections() {
        let vaddr = s.virtual_address as usize;
        let vsize = s.virtual_size as usize;

        if vsize == 0 {
            continue;
        }

        let size = align_up(vsize, PAGE_SIZE);
        let prot = map_section_protect(s.characteristics);

        os_protect(base + vaddr, size, prot)?;
    }

    Ok(())
}
