use crate::LoaderError;
use pe_format::{PeImage, Arch};

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageBaseRelocation {
    virtual_address: u32, // Page RVA
    size_of_block: u32,   // = 8 + N * 2
}

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW:  u16 = 3;  // x86 (32-bit)
const IMAGE_REL_BASED_DIR64:    u16 = 10; // x64 (64-bit)

pub fn apply_relocations(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    let Some(reloc_dir) = img.dir(5) else { return Ok(()); };

    let dir_off = img.rva_to_offset(reloc_dir.virtual_address as usize)
        .ok_or(LoaderError::Format("reloc directory out of file"))?;
    let dir_bytes = img.as_bytes()
        .get(dir_off .. dir_off + reloc_dir.size as usize)
        .ok_or(LoaderError::Format("reloc directory size out of file"))?;

    let mut cursor = 0usize;
    while cursor + core::mem::size_of::<ImageBaseRelocation>() <= dir_bytes.len() {
        let block: ImageBaseRelocation = unsafe {
            core::ptr::read_unaligned(
                dir_bytes.as_ptr().add(cursor) as *const ImageBaseRelocation
            )
        };
        cursor += core::mem::size_of::<ImageBaseRelocation>();

        if block.size_of_block < 8 {
            return Err(LoaderError::Format("reloc block too small"));
        }
        let entries_bytes = (block.size_of_block as usize).saturating_sub(8);
        if cursor + entries_bytes > dir_bytes.len() {
            return Err(LoaderError::Format("reloc entries out of file"));
        }

        let entries_count = entries_bytes / 2;
        let entries_ptr = unsafe { dir_bytes.as_ptr().add(cursor) as *const u16 };

        for i in 0..entries_count {
            let entry = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
            let typ = entry >> 12;
            let ofs = (entry & 0x0FFF) as usize;

            match (img.arch(), typ) {
                (_, IMAGE_REL_BASED_ABSOLUTE) => {}
                (Arch::X64, IMAGE_REL_BASED_DIR64) => {
                    let target_rva = block.virtual_address as usize + ofs;
                    if target_rva + 8 > img.size_of_image() as usize {
                        return Err(LoaderError::Format("reloc target outside image"));
                    }
                    unsafe {
                        let p = (base as *mut u8).add(target_rva) as *mut u64;
                        let orig = core::ptr::read_unaligned(p);
                        let delta64 = (base as i64).wrapping_sub(img.preferred_base() as i64);
                        let patched = (orig as i64).wrapping_add(delta64) as u64;
                        core::ptr::write_unaligned(p, patched);
                    }
                }
                (Arch::X86, IMAGE_REL_BASED_HIGHLOW) => {
                    let target_rva = block.virtual_address as usize + ofs;
                    if target_rva + 4 > img.size_of_image() as usize {
                        return Err(LoaderError::Format("reloc target outside image"))
                    }
                    unsafe {
                        let p = (base as *mut u8).add(target_rva) as *mut u32;
                        let orig = core::ptr::read_unaligned(p);
                        let delta32 = ((base as i64) - (img.preferred_base() as i64)) as i32;
                        let patched = (orig as i32).wrapping_sub(delta32) as u32;
                        core::ptr::write_unaligned(p, patched);
                    }
                }
                _ => {
                    return Err(LoaderError::Map("unsupported relocation type"));
                }
            }
        }

        cursor += entries_bytes;
    }

    Ok(())
}
