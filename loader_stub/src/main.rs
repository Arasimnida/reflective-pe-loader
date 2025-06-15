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
}
