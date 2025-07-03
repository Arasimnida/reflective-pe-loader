use goblin::pe::{
    PE, 
    import::ImportDirectoryEntry,
};
use windows::{
    Win32::System::{
        Memory::{
            VirtualAlloc, 
            VirtualProtect, 
            MEM_COMMIT, 
            MEM_RESERVE,
            PAGE_EXECUTE_READ, 
            PAGE_READWRITE,
            PAGE_READONLY,
        },
        LibraryLoader::{
            GetModuleHandleA, 
            GetProcAddress
        },
    },
    core::PCSTR,
};
use scroll::{ctx::TryFromCtx, Endian};
use std::{ffi::CStr, usize};

static PAYLOAD: &'static [u8] = include_bytes!("payload_messagebox.dll");

#[repr(C)]
#[derive(Copy, Clone)]
struct ImageTlsDirectory64 {
    start_address_of_raw_data: u64,
    end_address_of_raw_data:   u64,
    address_of_index:          u64,
    address_of_callbacks:      u64,
    size_of_zero_fill:         u32,
    characteristics:           u32,
}

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

fn protect_section(base: *mut u8,
                   rva: usize,
                   size: usize,
                   characteristics: u32)
{
    let protect = if characteristics & 0x20000000 != 0 {        // EXECUTE
        PAGE_EXECUTE_READ
    } else if characteristics & 0x80000000 != 0 {               // WRITE
        PAGE_READWRITE
    } else {
        PAGE_READONLY
    };
    let mut old = PAGE_READWRITE;
    unsafe {
        let ok = VirtualProtect(
            base.add(rva) as *mut _,
            size,
            protect,
            &mut old,
        );
        assert!(ok.is_ok(), "VirtualProtect section failed");
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

fn main() {
    unsafe {
        let pe = PE::parse(PAYLOAD).expect("Failed to parse DLL");
        let optional_header = pe.header.optional_header.expect("Failed to get OptionalHeader");
        //let standard_fields = optional_header.standard_fields;
        let size_of_headers = optional_header.windows_fields.size_of_headers as usize;
        let size_of_image = optional_header.windows_fields.size_of_image as usize;

        println!("PE size_of_image = {:#x}", size_of_image);
        println!("PE size_of_header = {:#x}", size_of_headers);
        let exec_region = alloc_exec_region(size_of_image);
        std::ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), exec_region, size_of_headers);
        println!("Copied {} bytes of headers", size_of_headers);

        for section in &pe.sections {
            let virtual_address = exec_region.add(section.virtual_address as usize);
            let raw_size = section.size_of_raw_data as usize;
            let raw_offset = section.pointer_to_raw_data as usize;

            if raw_size > 0 {
                std::ptr::copy_nonoverlapping(
                    PAYLOAD.as_ptr().add(raw_offset), 
                    virtual_address, 
                    raw_size
                );
            }
            println!(
                "  Copied section {:8} @ {:p} ({} bytes)",
                section.name().unwrap_or("<?>"),
                virtual_address,
                raw_size
            );

            let virtual_size = section.virtual_size as usize;
            if virtual_size > raw_size {
                let bss_ptr = virtual_address.add(raw_size);
                let bss_size = virtual_size - raw_size;
                std::ptr::write_bytes(bss_ptr, 0, bss_size);
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
        if let Some(base_relocation_table) = optional_header.data_directories.get_base_relocation_table() {
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
                    let entry_raw = std::ptr::read_unaligned(entries_ptr.add(i));
                    let entry_type = entry_raw >> 12;
                    let entry_offset = (entry_raw & 0x0FFF) as usize;

                    if entry_type == IMAGE_REL_BASED_DIR64 {
                        let patch_ptr = exec_region.add(page_rva + entry_offset) as *mut u64;
                        let original_ptr = patch_ptr.read_unaligned();
                        let correction = original_ptr + delta as u64;
                        patch_ptr.write_unaligned(correction);
                    }
                }

                offset += block_size;
            }
        }

        let import_table = optional_header.data_directories.get_import_table().expect("Failed to get Import Table");
        let import_virtual_address = import_table.virtual_address as usize;
        let import_size = import_table.size as usize;
        let mut import_offset = rva_to_offset(&pe, import_virtual_address).expect("RVA to offset failed for Import Table");
        let import_end = import_size + import_offset;

        while import_offset < import_end {
            let (import_directory_entry, import_directory_size) = ImportDirectoryEntry::try_from_ctx(
                    &PAYLOAD[import_offset..], 
                    Endian::Little
                )
                .expect("Failed to parse ImportDirectoryEntry");
            if import_directory_entry.is_null() {
                break;
            }

            let name_rva = import_directory_entry.name_rva as usize;
            let name_offset = rva_to_offset(&pe, name_rva).expect("RVA Failed for dll name");
            let dll_name = CStr::from_ptr(PAYLOAD.as_ptr().add(name_offset) as *const i8);
            let h_module = GetModuleHandleA(PCSTR(dll_name.as_ptr() as _)).expect("GetModuleHandleA failed");
            
            let mut import_lookup_table_rva = import_directory_entry.import_lookup_table_rva as usize;
            if import_lookup_table_rva == 0 {
                import_lookup_table_rva = import_directory_entry.import_address_table_rva as usize;
            }
            
            let mut thunk_off = rva_to_offset(&pe, import_lookup_table_rva).expect("Invalid RVA for ILT/IAT");
            let mut iat_ptr = exec_region.add(import_directory_entry.import_address_table_rva as usize) as *mut u64;
            
            const ENTRY_SIZE: usize = 8;
            loop {
                let thunk_data = std::ptr::read_unaligned(PAYLOAD.as_ptr().add(thunk_off) as *const u64);
                if thunk_data == 0 {
                    break;
                }

                let function_address = if (thunk_data & (1 << 63)) != 0 {
                    let ordinal = (thunk_data & 0xFFFF) as u16;
                    let func_addr = GetProcAddress(h_module, PCSTR(ordinal as usize as _)).expect("GetProcAddress failed for ordinal name");
                    func_addr as u64
                } else {
                    let name_rva = (thunk_data & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                    let name_off = rva_to_offset(&pe, name_rva + 2).expect("Invalid RVA for function name");
                    let function_name = CStr::from_ptr(PAYLOAD.as_ptr().add(name_off) as *const i8);
                    let func_addr = GetProcAddress(h_module, PCSTR(function_name.as_ptr() as _)).expect("GetProcAddress failed for ordinal name");
                    func_addr as u64
                };

                std::ptr::write_unaligned(iat_ptr, function_address);

                thunk_off += ENTRY_SIZE;
                iat_ptr = (iat_ptr as *mut u8).add(ENTRY_SIZE) as *mut u64;
            }

            import_offset += import_directory_size;

        }
        println!("pretls");
        if let Some(tls_table) = optional_header.data_directories.get_tls_table() {
            let tls_table_virtual_address = tls_table.virtual_address as usize;
            if tls_table_virtual_address != 0 {
                let tls_table_offset = rva_to_offset(&pe, tls_table_virtual_address).expect("Invalid RVA for TLS Table");

                let tls = std::ptr::read_unaligned(PAYLOAD.as_ptr().add(tls_table_offset) as *const ImageTlsDirectory64);
                let mut table_address = tls.address_of_callbacks as usize;
                println!("{}", table_address);

                if table_address != 0 {
                        type TlsCallback = unsafe extern "system" fn(
                        *mut core::ffi::c_void,
                        u32,
                        *mut core::ffi::c_void,
                    );

                    while (table_address > preferred_base) && (table_address - preferred_base < size_of_image) {
                        let callback_virtual_address = std::ptr::read_unaligned(exec_region.add(table_address - preferred_base) as *const u64) as usize;
                        if callback_virtual_address == 0 { break; }

                        let callback_ptr = exec_region.add(callback_virtual_address - preferred_base);
                        let callback: TlsCallback = core::mem::transmute(callback_ptr);

                        if (callback_virtual_address < preferred_base) || (callback_virtual_address - preferred_base >= size_of_image) { break; }

                        callback(exec_region as _, 1, core::ptr::null_mut());
                        table_address += 8;
                    }
                }
            }
        }

        println!("Setting per-section protections…");
        for sect in &pe.sections {
            let characs = sect.characteristics;
            let vsize   = sect.virtual_size as usize;
            let vrva    = sect.virtual_address as usize;
            protect_section(exec_region, vrva, vsize, characs);
        }
        println!("All sections protected.");

        type DllMain = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            u32,
            *mut core::ffi::c_void,
        ) -> i32;
        
        let entry_point_virtual_address = optional_header.standard_fields.address_of_entry_point as usize;
        let entry_addr = exec_region.add(entry_point_virtual_address);

        let dll_main: DllMain = core::mem::transmute(entry_addr);
        let ret = dll_main(exec_region as _, 1, core::ptr::null_mut());

        assert!(ret != 0, "DllMain returned FALSE / loader aborts.");
    }
}
