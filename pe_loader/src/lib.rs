use thiserror::Error;
use pe_format::PeImage;

pub mod copy;
pub mod imports;
pub mod protect;
pub mod reloc;
pub mod tls;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Windows API error: {0}")] Api(&'static str),
    #[error("Mapping error: {0}")]    Map(&'static str),
    #[error("Format error: {0}")]     Format(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection { R, RW, RX, RWX }

#[derive(Debug)]
pub struct LoadedImage {
    pub base: usize,
    pub entry: usize,
    pub tls_callbacks: Vec<usize>,
    pub is_dll: bool
}

pub fn map_image(img: &PeImage) -> Result<LoadedImage, LoaderError> {
    let base = copy::copy_header_and_sections(img)?;
    reloc::apply_relocations(img, base)?;
    imports::resolve_imports(img, base)?;
    protect::finalise_section_protections(img, base)?;
    let tls_callbacks = tls::collect_tls_callbacks(img, base)?;
    let entry = base + img.entry_rva() as usize;
    let is_dll = true; // to change in order to be able to load exe as well

    Ok(LoadedImage { base: base, entry: entry, tls_callbacks: tls_callbacks, is_dll: is_dll } )
}