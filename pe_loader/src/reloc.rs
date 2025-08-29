use crate::LoaderError;
use pe_format::PeImage;

pub fn apply_relocations(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    Err(LoaderError::Map("Not implemented reloc yet"))
}
