mod types;
pub use types::*;

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
    nt: NtHeaders,
    sections: Vec<ImageSectionHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch { X86, X64 }

enum NtHeaders {
    X64(ImageNtHeaders64),
    X86(ImageNtHeaders32),
}

impl<'a> PeImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        // DOS
        ensure_len(data, core::mem::size_of::<ImageDosHeader>())?;
        let dos = unsafe { read_unaligned::<ImageDosHeader>(data, 0)? };
        if dos.e_magic != 0x5A4D { // 'MZ'
            return Err(PeError::BadDos);
        }

        // NT
        let nt_offset = dos.e_lfanew as usize;
        let signature_offset = nt_offset;
        let file_header_offset = nt_offset + 4;
        let magic_offset = file_header_offset + core::mem::size_of::<ImageFileHeader>();
        ensure_len_from(data, nt_offset, 4 + size_of::<ImageFileHeader>() + 2)?;
        let signature = unsafe { read_unaligned::<u32>(data, signature_offset)? };
        if signature != 0x00004550 { return Err(PeError::BadNt) };
        let magic = unsafe { read_unaligned::<u16>(data, magic_offset)? };
        let nt = match magic {
            0x10B => {
                ensure_len_from(data, nt_offset, core::mem::size_of::<ImageNtHeaders32>())?;
                let nt32 = unsafe { read_unaligned::<ImageNtHeaders32>(data, nt_offset)? };
                NtHeaders::X86(nt32)
            }
            0x20B => {
                ensure_len_from(data, nt_offset, core::mem::size_of::<ImageNtHeaders64>())?;
                let nt64 = unsafe { read_unaligned::<ImageNtHeaders64>(data, nt_offset)? };
                NtHeaders::X64(nt64)
            }
            _ => return Err(PeError::UnsupportedMagic)
        };
        let (num_sections, size_opt) = match nt {
            NtHeaders::X64(ref nt64) => (nt64.file_header.number_of_sections as usize, nt64.file_header.size_of_optional_header as usize),
            NtHeaders::X86(ref nt32) => (nt32.file_header.number_of_sections as usize, nt32.file_header.size_of_optional_header as usize)
        };

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

        Ok(PeImage { data, dos, nt, sections })
    }

    pub fn sections(&self) -> &[ImageSectionHeader] { &self.sections }

    pub fn section_name(section: &ImageSectionHeader) -> &str {
        let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&section.name[..end]).unwrap_or("")
    }

    pub fn arch(&self) -> Arch { match self.nt { NtHeaders::X64(_) => Arch::X64, NtHeaders::X86(_) => Arch::X86 } }

    pub fn preferred_base(&self) -> u64 { match self.nt {
        NtHeaders::X64(ref nt) => nt.optional_header.image_base,
        NtHeaders::X86(ref nt) => nt.optional_header.image_base as u64
    }}

    pub fn size_of_image(&self) -> u32 { match self.nt {
        NtHeaders::X64(ref nt) => nt.optional_header.size_of_image,
        NtHeaders::X86(ref nt) => nt.optional_header.size_of_image
    }}

    pub fn size_of_headers(&self) -> u32 { match self.nt {
        NtHeaders::X64(ref nt) => nt.optional_header.size_of_headers,
        NtHeaders::X86(ref nt) => nt.optional_header.size_of_headers
    }}

    pub fn entry_rva(&self) -> u32 { match self.nt {
        NtHeaders::X64(ref nt) => nt.optional_header.address_of_entry_point,
        NtHeaders::X86(ref nt) => nt.optional_header.address_of_entry_point
    }}

    pub fn as_bytes(&self) -> &[u8] { self.data }

    // if rva < size of header then we return the offset
    pub fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        if rva < self.size_of_headers() as usize { return Some(rva); }
        for s in &self.sections {
            let va = s.virtual_address as usize;
            let vs = s.virtual_size as usize;
            if (va..va+vs).contains(&rva) {
                let delta = rva - va;
                let raw  = s.pointer_to_raw_data as usize;
                let raw_size = s.size_of_raw_data as usize;
                return (delta < raw_size).then_some(raw + delta);
            }
        }
        None 
    }

    pub fn rva_to_range(&self, rva: u32, size: usize) -> Option<&'a [u8]> {
        let off = self.rva_to_offset(rva as usize)?;
        self.data.get(off..off+size)
    }

    pub fn dir(&self, index: usize) -> Option<ImageDataDirectory> {
        let d = match self.nt {
            NtHeaders::X64(ref nt) => nt.optional_header.data_directory.get(index).copied(),
            NtHeaders::X86(ref nt) => nt.optional_header.data_directory.get(index).copied(),
        }?;
        (d.virtual_address != 0 && d.size != 0).then_some(d)
    }

    pub fn import_descriptors(&self) -> Option<&'a [ImageImportDescriptor]> {
        let dir = self.dir(1)?;
        let start = self.rva_to_offset(dir.virtual_address as usize)?;
        let bytes = self.data.get(start..start+dir.size as usize)?;
        let mut count = 0usize;
        let element = core::mem::size_of::<ImageImportDescriptor>();
        while (count + 1) * element <= bytes.len() {
            let offset = count * element;
            let descriptor = unsafe { &*(bytes.as_ptr().add(offset) as *const ImageImportDescriptor) };            
            if descriptor.original_first_thunk == 0 && descriptor.first_thunk == 0 && descriptor.name == 0 { break; }
            count += 1;
        }
        Some(unsafe {
            core::slice::from_raw_parts(bytes.as_ptr() as *const ImageImportDescriptor, count)
        })
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
