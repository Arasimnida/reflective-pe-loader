use goblin::{elf::reloc, pe::{
    self, data_directories, PE
}};
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

fn rva_to_offset(pe: &PE, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let virtual_address = section.virtual_address as usize;
        let virtual_size = section.virtual_size as usize;
        let range = virtual_address..(virtual_address + virtual_size);
        if range.contains(&rva) {
            let delta = rva - virtual_address;
            let file_off = section.pointer_to_raw_data as usize + delta;
            return Some(file_off);
        }
    };
    None
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

    let preferred_base = optional_header.windows_fields.image_base as usize;
    let delta = (exec_region as usize) - preferred_base;

    let base_relocation_table = optional_header.data_directories.get_base_relocation_table().expect("Failed to get base relocation table");
    let reloc_virtual_address = base_relocation_table.virtual_address as usize;
    let reloc_size = base_relocation_table.size as usize;
    if (reloc_size == 0) ||(reloc_virtual_address == 0) {
        println!("No relocation present.")
    };
    let mut offset = rva_to_offset(&pe, reloc_virtual_address).expect("RVA to offset failed");
    let end = offset + reloc_size;

    const IMAGE_REL_BASED_DIR64: u16 = 10;
    while offset < end {
        let page_rva = u32::from_le_bytes(PAYLOAD[offset..(offset + 4)].try_into().unwrap()) as usize;
        let block_size = u32::from_le_bytes(PAYLOAD[(offset + 4)..(offset + 8)].try_into().unwrap()) as usize;
        let entries = (block_size - 8) / 2;
        let entries_ptr = PAYLOAD[(offset + 8)..].as_ptr() as *const u16;
        
        for i in 0..entries {
            let entry_raw = unsafe { *entries_ptr.add(i) };
            let entry_type = entry_raw >> 12;
            let entry_offset = (entry_raw & 0x0FFF) as usize;

            if entry_type == IMAGE_REL_BASED_DIR64 {
                unsafe {
                    let patch_ptr = exec_region.add(page_rva + entry_offset) as *mut u64;
                    let original_ptr = patch_ptr.read_unaligned();
                    let correction = original_ptr + delta as u64;
                    patch_ptr.write_unaligned(correction);
                }
            }
        }

        offset += block_size;
    }

}
