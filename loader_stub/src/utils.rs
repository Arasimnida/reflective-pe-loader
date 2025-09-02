use sha2::{Sha256, Digest};

const HASH_KERNEL32_DLL: u32 = 0x4afb7610;
const HASH_GETPROCADDRESS: u32 = 0xb7c8436f;
const HASH_GETMODULEHANDLEA: u32 = 0x0f92ed7a;

#[repr(C)]
pub struct PebLdrData {
    pub reserved1: [u8; 8],
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

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

fn hash_name(name: &str) -> u32 {
    let mut data = name.as_bytes().to_vec();

    for _ in 0..7 {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        data = hasher.finalize().to_vec();
    }

    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
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
