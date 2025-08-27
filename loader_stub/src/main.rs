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
use sha2::{Sha256, Digest};

static PAYLOAD: &'static [u8] = include_bytes!("payload_messagebox.dll");

const HASH_KERNEL32_DLL: u32 = 0x4afb7610;
const HASH_GETPROCADDRESS: u32 = 0xb7c8436f;
const HASH_GETMODULEHANDLEA: u32 = 0x0f92ed7a;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut u8,
    pub entry_point: *mut u8,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

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

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
pub struct PebLdrData {
    pub reserved1: [u8; 8],
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
#[derive(Debug)]
struct ImageDosHeader {
    e_magic: u16,
    _unused: [u8; 58],
    e_lfanew: u32,
}

#[repr(C)]
#[derive(Debug)]
struct ImageFileHeader {
    _pad: [u8; 20], // on ne s’en sert pas ici
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Debug)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _pad: [u8; 12],
    characteristics: u32,
}

#[derive(Debug)]
struct ParsedPe<'a> {
    nt_headers: &'a ImageNtHeaders64,
    sections: &'a [ImageSectionHeader],
    num_sections: usize,
}

#[repr(C)]
#[derive(Debug)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp:      u32,
    forwarder_chain:      u32,
    name:                 u32,
    first_thunk:          u32,
}

#[repr(C)]
#[derive(Debug)]
struct ImageImportByName {
    hint: u16,
    name: [u8; 1], // début d'une chaîne C-string
}

#[derive(Debug)]
struct PeOptionalFields {
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    address_of_entry_point: u32,
}

fn get_optional_header_fields(pe: &ParsedPe) -> PeOptionalFields {
    let opt = &pe.nt_headers.optional_header;

    unsafe {
        let base = opt as *const _ as *const u8;

        let address_of_entry_point = core::ptr::read_unaligned(base.add(0x10) as *const u32);
        let image_base             = core::ptr::read_unaligned(base.add(0x18) as *const u64);
        let size_of_image          = core::ptr::read_unaligned(base.add(0x38) as *const u32);
        let size_of_headers        = core::ptr::read_unaligned(base.add(0x3C) as *const u32);

        PeOptionalFields {
            image_base,
            size_of_image,
            size_of_headers,
            address_of_entry_point,
        }
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn get_import_descriptors<'a>(pe: &ParsedPe<'a>, payload: &'a [u8]) -> Vec<&'a ImageImportDescriptor> {
    let dir = pe.nt_headers.optional_header.data_directory[1];
    if dir.virtual_address == 0 {
        println!("[!] No import directory.");
        return vec![];
    }

    let mut offset = match rva_to_offset_home(pe, dir.virtual_address as usize) {
        Some(o) => o,
        None => {
            println!("[!] Could not convert import RVA to file offset.");
            return vec![];
        }
    };

    let mut descriptors = Vec::new();
    let descriptor_size = std::mem::size_of::<ImageImportDescriptor>();
    let zero_desc = ImageImportDescriptor {
        original_first_thunk: 0,
        time_date_stamp:      0,
        forwarder_chain:      0,
        name:                 0,
        first_thunk:          0,
    };

    loop {
        if offset + descriptor_size > payload.len() {
            println!("[!] Import table overflow.");
            break;
        }

        let ptr = payload.as_ptr().add(offset) as *const ImageImportDescriptor;
        let desc = core::ptr::read_unaligned(ptr);

        if desc == zero_desc {
            break;
        }

        descriptors.push(&*ptr);
        offset += descriptor_size;
    }

    descriptors
}


#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn read_imported_functions<'a>(
    pe: &ParsedPe<'a>,
    payload: &'a [u8],
    descriptor: &ImageImportDescriptor,
) -> Vec<String> {
    let mut functions = Vec::new();

    let thunk_rva = if descriptor.original_first_thunk != 0 {
        descriptor.original_first_thunk as usize
    } else {
        descriptor.first_thunk as usize
    };

    let mut offset = match rva_to_offset_home(pe, thunk_rva) {
        Some(o) => o,
        None => return functions,
    };

    loop {
        if offset + 8 > payload.len() {
            break;
        }

        let thunk_data = *(payload.as_ptr().add(offset) as *const u64);
        if thunk_data == 0 {
            break;
        }

        if (thunk_data >> 63) != 0 {
            // Ordinal import
            functions.push(format!("Ordinal({})", thunk_data & 0xFFFF));
        } else {
            // By name
            let name_rva = (thunk_data & 0x7FFF_FFFF_FFFF_FFFF) as usize;
            let name_offset = match rva_to_offset_home(pe, name_rva) {
                Some(o) => o,
                None => break,
            };

            let name_ptr = payload.as_ptr().add(name_offset + 2); // Skip 2-byte hint
            let cstr = std::ffi::CStr::from_ptr(name_ptr as *const i8);
            if let Ok(s) = cstr.to_str() {
                functions.push(s.to_string());
            }
        }

        offset += 8;
    }

    functions
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn get_base_relocation_table<'a>(
    pe: &ParsedPe<'a>
) -> Option<(usize, usize)> {
    let dir = pe.nt_headers.optional_header.data_directory[5];

    if dir.virtual_address == 0 || dir.size == 0 {
        return None;
    }

    Some((dir.virtual_address as usize, dir.size as usize))
}


#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn parse_pe(payload: &[u8]) -> ParsedPe<'_> {
    let dos_ptr = payload.as_ptr() as *const ImageDosHeader;
    let dos = &*dos_ptr;
    assert_eq!(dos.e_magic, 0x5A4D, "Invalid DOS header (MZ)");

    let nt_offset = dos.e_lfanew as usize;
    println!("[dbg] NT headers offset = 0x{:x}", nt_offset);

    let nt_headers_ptr = payload.as_ptr().add(nt_offset) as *const ImageNtHeaders64;
    let nt_headers = &*nt_headers_ptr;
    assert_eq!(nt_headers.signature, 0x00004550, "Invalid NT header (PE)");

    // Lire le nombre de sections (ImageFileHeader offset 6)
    let ptr = payload.as_ptr().add(nt_offset + 6);
    let num_sections = u16::from_le_bytes([*ptr, *ptr.add(1)]) as usize;
    println!("[dbg] Number of sections = {}", num_sections);

    // Lire la taille de l'optional header à l'offset 20 (ImageFileHeader offset 16)
    let size_of_optional_header = u16::from_le_bytes([
        *payload.as_ptr().add(nt_offset + 20),
        *payload.as_ptr().add(nt_offset + 21),
    ]) as usize;
    println!("[dbg] Size of optional header = 0x{:x}", size_of_optional_header);

    let section_start = nt_offset + 4 + std::mem::size_of::<ImageFileHeader>() + size_of_optional_header;
    println!("[dbg] Section headers start = 0x{:x}", section_start);

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let offset = section_start + i * std::mem::size_of::<ImageSectionHeader>();
        if offset + std::mem::size_of::<ImageSectionHeader>() > payload.len() {
            println!("[!] Offset 0x{:x} for section {} out of bounds!", offset, i);
            break;
        }

        let section_ptr = payload.as_ptr().add(offset) as *const ImageSectionHeader;
        let section = std::ptr::read_unaligned(section_ptr);

        println!(
            "[dbg] Parsed section {:02}: name = {:?}, RVA = 0x{:x}, RAW = 0x{:x}, SIZE = 0x{:x}",
            i,
            section.name,
            section.virtual_address,
            section.pointer_to_raw_data,
            section.size_of_raw_data
        );

        sections.push(section);
    }

    ParsedPe {
        nt_headers,
        sections: Box::leak(sections.into_boxed_slice()),
        num_sections,
    }
}

fn section_name(section: &ImageSectionHeader) -> String {
    let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
    section.name[..end]
        .iter()
        .map(|&c| if c.is_ascii_graphic() || c == b' ' { c as char } else { '.' })
        .collect()
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

fn rva_to_offset_home(pe: &ParsedPe, rva: usize) -> Option<usize> {
    for section in pe.sections {
        let virtual_address = section.virtual_address as usize;
        let virtual_size = section.virtual_size as usize;
        let range = virtual_address..(virtual_address + virtual_size);
        if range.contains(&rva) {
            let delta = rva - virtual_address;
            let file_offset = section.pointer_to_raw_data as usize + delta;
            return Some(file_offset);
        }
    }
    None
}


#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn get_export_directory<'a>(pe: &ParsedPe<'a>, payload: &'a [u8]) -> Option<(&'a ImageExportDirectory, usize)> {
    let export_data = pe.nt_headers.optional_header.data_directory[0];

    if export_data.virtual_address == 0 {
        println!("[dbg] Export virtual address is null");
        return None;
    }
    if export_data.size == 0 {
        println!("[warn] Export size is 0, but RVA is valid — trying anyway");
    }

    let offset = rva_to_offset_home(pe, export_data.virtual_address as usize)?;
    if offset + std::mem::size_of::<ImageExportDirectory>() > payload.len() {
        println!("[dbg] offset+size = pb");
        return None;
    }

    let dir_ptr = payload.as_ptr().add(offset) as *const ImageExportDirectory;
    Some((&*dir_ptr, offset))
}

#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn unicode_to_string(unicode: &UnicodeString) -> String {
    let len = (unicode.length / 2) as usize;

    println!("    [dbg] unicode.length = {}", unicode.length);
    println!("    [dbg] unicode.buffer = {:p}", unicode.buffer);
    println!("    [dbg] slice size = {}", len);

    if unicode.buffer.is_null() || len == 0 || len > 512 {
        println!("    [err] Invalid unicode string parameters, skipping...");
        return String::new();
    }

    let slice = core::slice::from_raw_parts(unicode.buffer, len);
    String::from_utf16_lossy(slice)
}

fn hash_name(name: &str) -> u32 {
    let mut data = name.as_bytes().to_vec();

    for _ in 0..7 {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        data = hasher.finalize().to_vec();
    }

    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
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

#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn get_kernel32_base() -> *mut u8 {
    println!("\n========== [ get_kernel32_base() ] ==========");

    let peb_ptr = get_peb();
    println!("[*] PEB pointer               = {:p}", peb_ptr);

    let ldr_ptr_ptr = peb_ptr.add(0x18) as *const *const PebLdrData;
    let ldr_ptr = *ldr_ptr_ptr;
    println!("[*] Ldr pointer               = {:p}", ldr_ptr);

    let list_head = (ldr_ptr as *const u8).add(0x10) as *const ListEntry;
    println!("[*] List head                 = {:p}", list_head);

    let mut current = (*list_head).flink as *const ListEntry;
    let list_head_ptr = list_head as *const ListEntry;
    let mut i = 0;

    loop {
        if current.is_null() || current == list_head_ptr {
            break;
        }
        println!("\n[*] Iteration {}", i);
        println!("    current_entry            = {:p}", current);

        let entry = current as *const LdrDataTableEntry;
        println!("    entry struct             = {:p}", entry);

        let name_unicode = &(*entry).base_dll_name;
        let name = unicode_to_string(name_unicode);
        let hash = hash_name(&name.to_ascii_lowercase());

        println!("    [dbg] unicode.length     = {}", name_unicode.length);
        println!("    [dbg] unicode.buffer     = {:p}", name_unicode.buffer);

        let len = (name_unicode.length / 2) as usize;
        for i in 0..len {
            let ch = *name_unicode.buffer.add(i);
            print!("{:04x} ", ch);
        }
        println!();

        println!("    DLL Name = {:<30} | Hash = 0x{:08x}", name, hash);

        if hash == HASH_KERNEL32_DLL {
            println!("\n[+] Found kernel32.dll at {:p}", (*entry).dll_base);
            return (*entry).dll_base;
        }

        current = (*current).flink as *const ListEntry;
        i += 1;

        if i > 100 {
            println!("[!] Exceeded 100 iterations — bail out.");
            break;
        }
    }

    println!("[!] kernel32.dll not found.");
    core::ptr::null_mut()
}

#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn check_peb_integrity() {
    println!("\n========== [ PEB Sanity Check ] ==========");

    let peb_ptr = get_peb();
    println!("[*] PEB pointer               = {:p}", peb_ptr);

    // 1. ImageBaseAddress — offset 0x10
    let image_base_ptr = *(peb_ptr.add(0x10) as *const *const u8);
    println!("[*] ImageBaseAddress          = {:p}", image_base_ptr);

    // 2. Ldr pointer — offset 0x18
    let ldr_ptr = *(peb_ptr.add(0x18) as *const *const u8);
    println!("[*] Ldr pointer               = {:p}", ldr_ptr);

    // 3. PEB first 0x30 bytes
    println!("\n[+] Raw PEB memory dump (0x30 bytes):");
    for i in 0..0x30 {
        let byte = *peb_ptr.add(i);
        print!("{:02x} ", byte);
        if i % 8 == 7 { println!(); }
    }

    // 4. LDR first 0x30 bytes
    println!("\n[+] Raw Ldr memory dump (0x30 bytes):");
    for i in 0..0x30 {
        let byte = *ldr_ptr.add(i);
        print!("{:02x} ", byte);
        if i % 8 == 7 { println!(); }
    }

    // 5. Local image base from code ptr
    let local_code_ptr = check_peb_integrity as *const ();
    println!("\n[*] Current module address    = {:p}", local_code_ptr);
    println!("=========================================\n");
}

fn main() {
    unsafe {
        check_peb_integrity();
        let k32 = get_kernel32_base();
        println!("kernel32 base = {:?}", k32);
        let pebis = parse_pe(PAYLOAD);
        let image_base = pebis.nt_headers.optional_header.data_directory[0].virtual_address;
        let size_of_image = pebis.nt_headers.optional_header.data_directory[0].size;
        println!("Export table RVA  = 0x{:x}", image_base);
        println!("Export table size = 0x{:x}", size_of_image);
        println!("Sections:");
        for sect in pebis.sections {
            println!("  {:8}  RVA: 0x{:x}  RAW: 0x{:x}  SIZE: 0x{:x}",
                section_name(sect),
                sect.virtual_address,
                sect.pointer_to_raw_data,
                sect.size_of_raw_data);
        }
        if let Some((export_dir, offset)) = get_export_directory(&pebis, PAYLOAD) {
            println!("\n[*] Export Directory found at file offset 0x{:x}", offset);
            println!("    Characteristics      : 0x{:08x}", export_dir.characteristics);
            println!("    TimeDateStamp        : 0x{:08x}", export_dir.time_date_stamp);
            println!("    MajorVersion         : {}", export_dir.major_version);
            println!("    MinorVersion         : {}", export_dir.minor_version);
            println!("    Name RVA             : 0x{:08x}", export_dir.name);
            println!("    Base Ordinal         : {}", export_dir.base);
            println!("    Number of Functions  : {}", export_dir.number_of_functions);
            println!("    Number of Names      : {}", export_dir.number_of_names);
            println!("    AddrOfFunctions RVA  : 0x{:08x}", export_dir.address_of_functions);
            println!("    AddrOfNames RVA      : 0x{:08x}", export_dir.address_of_names);
            println!("    AddrOfOrdinals RVA   : 0x{:08x}", export_dir.address_of_name_ordinals);
        } else {
            println!("[!] No export directory found.");
        }

        println!("\n========= [ Comparaison Goblin vs Maison ] =========");

        // Goblin
        let pe_goblin = PE::parse(PAYLOAD).expect("Goblin parse failed");
        let gob_header = pe_goblin.header.optional_header.as_ref().unwrap();
        let gob_image_base = gob_header.windows_fields.image_base;
        let gob_size_of_image = gob_header.windows_fields.size_of_image;
        let gob_size_of_headers = gob_header.windows_fields.size_of_headers;
        let gob_entry_point = gob_header.standard_fields.address_of_entry_point;

        // Maison
        let maison_fields = get_optional_header_fields(&pebis);

        println!("ImageBase           : goblin = 0x{:x}, maison = 0x{:x}",
            gob_image_base, maison_fields.image_base);
        println!("SizeOfImage         : goblin = 0x{:x}, maison = 0x{:x}",
            gob_size_of_image, maison_fields.size_of_image);
        println!("SizeOfHeaders       : goblin = 0x{:x}, maison = 0x{:x}",
            gob_size_of_headers, maison_fields.size_of_headers);
        println!("AddressOfEntryPoint : goblin = 0x{:x}, maison = 0x{:x}",
            gob_entry_point, maison_fields.address_of_entry_point);

        // Sections
        println!("\n========= [ Sections ] =========");
        for (i, sect) in pe_goblin.sections.iter().enumerate() {
            let home = &pebis.sections[i];
            println!(
                "[{:02}] GOBLIN: {:<8} RVA: 0x{:06x} SIZE: 0x{:06x} | HOME: {:<8} RVA: 0x{:06x} SIZE: 0x{:06x}",
                i,
                sect.name().unwrap_or("<?>"),
                sect.virtual_address,
                sect.virtual_size,
                section_name(home),
                home.virtual_address,
                home.virtual_size
            );
        }

        // Export
        let goblin_export = gob_header
            .data_directories
            .get_export_table()
            .expect("Pas de Export DataDirectory !");
        println!(
            "\n========= [ Export Directory DataDirectory ] =========\n\
             Goblin : RVA  = 0x{:08x}, Size = 0x{:08x}",
            goblin_export.virtual_address,
            goblin_export.size,
        );

        let maison_export = pebis
            .nt_headers
            .optional_header
            .data_directory[0];
        println!(
            "Maison : RVA  = 0x{:08x}, Size = 0x{:08x}",
            maison_export.virtual_address,
            maison_export.size
        );

        // Import
        let goblin_import = gob_header
            .data_directories
            .get_import_table()
            .expect("Pas de Import DataDirectory !");
        println!(
            "\n========= [ Import Directory DataDirectory ] =========\n\
             Goblin : RVA  = 0x{:08x}, Size = 0x{:08x}",
            goblin_import.virtual_address,
            goblin_import.size
        );

        // Comptage Goblin
        let goblin_count = pe_goblin.import_data.as_ref().map(|id| id.import_data.len()).unwrap_or(0);
        println!("Goblin: {} descriptors found.", goblin_count);

        // DataDirectory Maison
        let maison_import = pebis
            .nt_headers
            .optional_header
            .data_directory[1];
        println!(
            "Maison : RVA  = 0x{:08x}, Size = 0x{:08x}",
            maison_import.virtual_address,
            maison_import.size
        );

        // Comptage Maison
        let maison_descriptors = get_import_descriptors(&pebis, PAYLOAD);
        let maison_count = maison_descriptors.len();
        println!("Maison: {} descriptors found.", maison_count);

        // Reloc
        let goblin_reloc = gob_header.data_directories.get_base_relocation_table().unwrap();
        println!(
            "\n========= [ Relocation Directory ] =========\nGoblin: RVA = 0x{:x}, Size = 0x{:x}",
            goblin_reloc.virtual_address, goblin_reloc.size
        );
        if let Some((rva, size)) = get_base_relocation_table(&pebis) {
            println!("Maison: RVA = 0x{:x}, Size = 0x{:x}", rva, size);
        } else {
            println!("Maison: not found.");
        }

        println!("\n========= [ Suite code qui marche ] =========");

        
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
