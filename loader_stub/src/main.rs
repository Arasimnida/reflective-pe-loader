use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};

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
    let size = 0x1000; // 4 KiB
    let exec_region = unsafe { alloc_exec_region(size) };
    println!("Allocated exec region at: {:p}", exec_region);

    unsafe {
        let mut old = PAGE_READWRITE;
        let success = VirtualProtect(
            exec_region as *mut _,
            size,
            PAGE_EXECUTE_READ,
            &mut old,
        );
        assert!(success.is_ok(), "VirtualProtect failed");
    }
    println!("Memory protection changed to RX.");
}
