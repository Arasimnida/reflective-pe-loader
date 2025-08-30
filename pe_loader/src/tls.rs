use crate::LoaderError;
use pe_format::{PeImage, ImageTlsDirectory64};

#[inline]
fn in_image_range(base: usize, size_of_image: usize, va: usize, need: usize) -> bool {
    let start = va.checked_sub(base);
    match start {
        Some(off) => off.checked_add(need).map_or(false, |end| end <= size_of_image),
        None => false,
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn read_u64_from_mapped(base: usize, rva: usize) -> u64 {
    let ptr = (base as *const u8).add(rva) as *const u64;
    core::ptr::read_unaligned(ptr)
}

pub fn collect_tls_callbacks(img: &PeImage, base: usize) -> Result<Vec<usize>, LoaderError> {
    let Some(dir) = img.dir(9) else {
        return Ok(Vec::new());
    };

    let size_of_image = img.size_of_image() as usize;
    let tls_rva = dir.virtual_address as usize;

    if tls_rva + core::mem::size_of::<ImageTlsDirectory64>() > size_of_image {
        return Err(LoaderError::Format("TLS directory outside image"));
    }

    let tls: ImageTlsDirectory64 = unsafe {
        let p = (base as *const u8).add(tls_rva) as *const ImageTlsDirectory64;
        core::ptr::read_unaligned(p)
    };

    let callbacks_va = tls.address_of_callbacks as usize;
    if callbacks_va == 0 {
        return Ok(Vec::new());
    }

    if !in_image_range(base, size_of_image, callbacks_va, 8) {
        return Err(LoaderError::Format("TLS callbacks array not in mapped image"));
    }

    let mut vec = Vec::new();
    let mut off = callbacks_va - base;
    loop {
        if off + 8 > size_of_image {
            return Err(LoaderError::Format("TLS callbacks array overruns image"));
        }
        let entry = unsafe { read_u64_from_mapped(base, off) };
        if entry == 0 {
            break;
        }
        vec.push(entry as usize);
        off += 8; //x64
    }

    Ok(vec)
}
