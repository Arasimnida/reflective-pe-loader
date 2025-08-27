mod types;
pub use types::*;

use core::mem::size_of;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeError {
    #[error("Buffer too small")]
    Bounds,
    #[error("Invalid DOS header (no MZ)")]
    BadDos,
    #[error("Invalid NT header (no PE)")]
    BadNt,
    #[error("Unsupported optional header magic (only PE32+ for now)")]
    UnsupportedMagic,
}

pub struct PeImage<'a> {
    data: &'a [u8],
    dos: ImageDosHeader,
    nt64: ImageNtHeaders64, // for PE32+ (x64)
    sections: Vec<ImageSectionHeader>,
}

impl<'a> PeImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        // DOS
        ensure_len(data, size_of::<ImageDosHeader>())?;
        let dos = unsafe { read_unaligned::<ImageDosHeader>(data, 0)? };
        if dos.e_magic != 0x5A4D { // 'MZ'
            return Err(PeError::BadDos);
        }

        // NT
        let nt_offset = dos.e_lfanew as usize;
        ensure_len_from(data, nt_offset, size_of::<ImageDosHeader>())?;
        let nt64 = unsafe { read_unaligned::<ImageNtHeaders64>(data, nt_offset)? };
        if nt64.signature != 0x00004550 { return Err(PeError::BadNt) };

        if nt64.optional_header.magic != 0x20B {
            return Err(PeError::UnsupportedMagic)
        }

        // Sections
        let num_sections = nt64.file_header.number_of_sections as usize;
        let size_opt = nt64.file_header.size_of_optional_header as usize;
        // + 4 since 'PE\0\0' is 4 bytes
        let sec_start = nt_offset + 4 + core::mem::size_of::<ImageFileHeader>() + size_opt;
        let sec_size = core::mem::size_of::<ImageSectionHeader>();
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let offset = sec_start + i * sec_size;
            ensure_len_from(data, offset, sec_size)?;
            let sh = unsafe { read_unaligned::<ImageSectionHeader>(data, offset)?};
            sections.push(sh);
        }

        Ok(PeImage { data, dos, nt64, sections })
    }

    pub fn sections(&self) -> &[ImageSectionHeader] { &self.sections }

    pub fn section_name(section: &ImageSectionHeader) -> &str {
        let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&section.name[..end]).unwrap_or("")
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn read_unaligned<T: Copy>(buf: &[u8], off: usize) -> Result<T, PeError> {
    ensure_len_from(buf, off, core::mem::size_of::<T>())?;
    Ok(core::ptr::read_unaligned(buf.as_ptr().add(off) as *const T))
}

fn ensure_len(buf: &[u8], need: usize) -> Result<(), PeError> {
    if buf.len() < need { Err(PeError::Bounds) } else { Ok(()) }
}

fn ensure_len_from(buf: &[u8], off: usize, need: usize) -> Result<(), PeError> {
    off.checked_add(need)
        .filter(|end| *end <= buf.len())
        .map(|_| ())
        .ok_or(PeError::Bounds)
}
