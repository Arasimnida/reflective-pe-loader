use crate::LoaderError;
use pe_format::{PeImage, ImageSectionHeader};
use windows::Win32::System::Memory::{
    VirtualAlloc, 
    MEM_COMMIT, 
    MEM_RESERVE, 
    PAGE_READWRITE,
};

#[derive(Debug)]
pub struct CopyJob {
    pub dest_rva: u32,
    pub copy_len: usize,
    pub zero_tail: usize,
    pub src_offset: Option<(usize, usize)>,
    pub name: String,
}

fn build_copy_plan(img: &PeImage) -> Result<(usize, Vec<CopyJob>), LoaderError> {
    // Headers
    let headers_len = img.size_of_headers() as usize;

    // Sections
    let mut jobs = Vec::new();
    for sec in img.sections() {
        let vaddr = sec.virtual_address as u32;
        let vsize = sec.virtual_size as usize;
        let raw_off = sec.pointer_to_raw_data as usize;
        let raw_sz  = sec.size_of_raw_data as usize;

        if vsize == 0 { 
            continue;
        }
        let copy_len = raw_sz.min(vsize);
        let zero_tail = vsize.saturating_sub(copy_len);

        let src_offset = if copy_len > 0 {
            Some((raw_off, copy_len))
        } else {
            None
        };

        jobs.push(CopyJob {
            dest_rva: vaddr,
            copy_len,
            zero_tail,
            src_offset,
            name: section_name(sec),
        });
    }

    Ok((headers_len, jobs))
}

fn section_name(s: &ImageSectionHeader) -> String {
    let end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&s.name[..end]).to_string()
}

fn os_reserve(size: usize) -> Result<usize, LoaderError> {
    let ptr = unsafe {
        VirtualAlloc(
            None,
            size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if ptr.is_null() {
        Err(LoaderError::Api("VirtualAlloc failed"))
    } else {
        Ok(ptr as usize)
    }
}

fn os_write(base: usize, dest_rva: usize, src: &[u8]) -> Result<(), LoaderError> {
    if src.is_empty() {
        return Ok(());
    }

    let _ = dest_rva
        .checked_add(src.len())
        .ok_or(LoaderError::Map("destination range overflow"))?;

    unsafe {
        let dst = (base as *mut u8).add(dest_rva);
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
    Ok(())
}

pub fn copy_header_and_sections(img: &PeImage) -> Result<usize, LoaderError> {
    let size_of_image = img.size_of_image() as usize;
    let (headers_len, jobs) = build_copy_plan(img)?;

    let base = os_reserve(size_of_image)?;
    
    let hdr_end = headers_len.min(img.as_bytes().len());
    let hdr_src = &img.as_bytes()[..hdr_end];
    os_write(base, 0, hdr_src)?;
    
    for j in jobs {
        if let Some((off, len)) = j.src_offset {
            let end = off.checked_add(len).ok_or(LoaderError::Map("overflow"))?;
            if end > img.as_bytes().len() {
                return Err(LoaderError::Format("section raw range out of file"));
            }
            let src = &img.as_bytes()[off..end];
            os_write(base, j.dest_rva as usize, src)?;
        }
    }

    Ok(base)
}
