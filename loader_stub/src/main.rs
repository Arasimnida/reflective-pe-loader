use std::error::Error;
use pe_format::PeImage;
use pe_loader::{map_image, LoaderError};

pub mod utils;

fn main() -> Result<(), Box<dyn Error>> {
    let payload: &'static [u8] = include_bytes!("payload_messagebox.dll");

    let img = PeImage::parse(payload).map_err(|e| format!("PE parse error: {e}"))?;

    println!("== PE parse ==");
    println!("  Preferred ImageBase : 0x{:016X}", img.preferred_base());
    println!("  SizeOfImage         : 0x{:X}", img.size_of_image());
    println!("  SizeOfHeaders       : 0x{:X}", img.size_of_headers());
    println!("  Entry RVA           : 0x{:X}", img.entry_rva());
    println!("  Sections:");
    for s in img.sections() {
        let name = pe_format::PeImage::section_name(s);
        println!(
            "    {:<8} RVA=0x{:06X} VS=0x{:06X} RAW=0x{:06X} RS=0x{:06X} CHR=0x{:08X}",
            name,
            s.virtual_address,
            s.virtual_size,
            s.pointer_to_raw_data,
            s.size_of_raw_data,
            s.characteristics
        );
    }

    println!("\n== Manual map ==");
    let loaded = match map_image(&img) {
        Ok(li) => li,
        Err(e) => {
            match e {
                LoaderError::Api(msg)    => eprintln!("[API] {msg}"),
                LoaderError::Map(msg)    => eprintln!("[MAP] {msg}"),
                LoaderError::Format(msg) => eprintln!("[FMT] {msg}"),
            }
            return Err("map_image failed".into());
        }
    };

    println!("  Base effective        : 0x{:016X}", loaded.base);
    println!("  Entry VA (calculated) : 0x{:016X}", loaded.entry);
    println!("  TLS callbacks found   : {}", loaded.tls_callbacks.len());
    if !loaded.tls_callbacks.is_empty() {
        for (i, cb) in loaded.tls_callbacks.iter().enumerate() {
            println!("    TLS[{}] = 0x{:016X}", i, cb);
        }
    }
    println!("  Is DLL                : {}", loaded.is_dll);

    unsafe {
        type DllMain = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            u32,
            *mut core::ffi::c_void,
        ) -> i32;

        let entry_addr = loaded.entry as *const core::ffi::c_void;

        let dll_main: DllMain = core::mem::transmute(entry_addr);
        let ret = dll_main(loaded.base as _, 1, core::ptr::null_mut());

        assert!(ret != 0, "DllMain returned FALSE / loader aborts.");
    }
    Ok(())
}
