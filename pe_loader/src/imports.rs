use crate::LoaderError;
use pe_format::PeImage;

pub fn resolve_imports(img: &PeImage, base: usize) -> Result<(), LoaderError> {
    Err(LoaderError::Map("Not implemented imports yet"))
}
