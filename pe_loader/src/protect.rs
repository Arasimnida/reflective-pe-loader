use crate::{LoaderError};
use pe_format::PeImage;

pub fn finalise_sections_protections(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    Err(LoaderError::Map("Not implemented protect yet"))
}
