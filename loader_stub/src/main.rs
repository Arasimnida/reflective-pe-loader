use goblin::pe::PE;
use windows::Win32::System::Memory::{
    VirtualAlloc, 
    VirtualProtect, 
    MEM_COMMIT, 
    MEM_RESERVE,
    PAGE_EXECUTE_READ, 
    PAGE_READWRITE,
};

static PAYLOAD: &'static [u8] = include_bytes!("payload_messagebox.dll");

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn alloc_exec_region(size: usize) -> *mut u8 {
    let alloc_address = VirtualAlloc(
        None,
        size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );
    assert!(!alloc_address.is_null(), "VirtualAlloc failed!");

    return alloc_address as *mut u8;
}

fn main() {
    let pe = PE::parse(PAYLOAD).expect("Failed to parse DLL");
    let optional_header = pe.header.optional_header.expect("Failed to get OptionalHeader");
    //let standard_fields = optional_header.standard_fields;
    let size_of_headers = optional_header.windows_fields.size_of_headers as usize;
    let size_of_image = optional_header.windows_fields.size_of_image as usize;

    println!("PE size_of_image = {:#x}", size_of_image);
    println!("PE size_of_header = {:#x}", size_of_headers);
    let exec_region = unsafe { alloc_exec_region(size_of_image) };
    unsafe {
        std::ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), exec_region, size_of_headers);
    }
    println!("Copied {} bytes of headers", size_of_headers);

    for section in &pe.sections {
        let virtual_address = unsafe { exec_region.add(section.virtual_address as usize)};
        let raw_size = section.size_of_raw_data as usize;
        let raw_offset = section.pointer_to_raw_data as usize;

        if raw_size > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(PAYLOAD.as_ptr().add(raw_offset), virtual_address, raw_size);
            }
        }
        println!(
            "  Copied section {:8} @ {:p} ({} bytes)",
            section.name().unwrap_or("<?>"),
            virtual_address,
            raw_size
        );

        let virtual_size = section.virtual_size as usize;
        if virtual_size > raw_size {
            let bss_ptr = unsafe {
                virtual_address.add(raw_size)
            };
            let bss_size = virtual_size - raw_size;
            unsafe {
                std::ptr::write_bytes(bss_ptr, 0, bss_size);
            }
            println!(
                "  Zeroed BSS in {:8} @ {:p} ({} bytes)",
                section.name().unwrap_or("<?>"),
                bss_ptr,
                bss_size
            );
        }
    }

}
