use crate::LoaderError;
use pe_format::PeImage;

pub fn copy_header_and_sections(img: &PeImage) -> Result<usize, LoaderError> {
    Err(LoaderError::Map("Not implemented copy yet"))
}
