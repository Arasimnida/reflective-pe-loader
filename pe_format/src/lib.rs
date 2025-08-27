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
        
        Ok(PeImage { data, dos, nt64 })
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
