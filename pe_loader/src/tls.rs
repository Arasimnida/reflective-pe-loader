use crate::LoaderError;
use pe_format::PeImage;

pub fn collect_tls_callbacks(img: &PeImage, base: usize) -> Result<Vec<usize>, LoaderError> {
    Err(LoaderError::Map("Not implemented tls callbacks yet"))
}
