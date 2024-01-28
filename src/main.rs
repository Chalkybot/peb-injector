use windows::Win32::System::Threading::{CreateProcessA, 
                                        PROCESS_CREATION_FLAGS,
                                        STARTUPINFOA,
                                        PROCESS_INFORMATION,
                                        OpenProcess,
                                        PROCESS_ACCESS_RIGHTS};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::Foundation::BOOL;
use windows::core::{PSTR, PCSTR};
use core::ffi::c_void;


fn main() {
    const SUSPENDED: u32 = 0x00000004;
    const PROCESS_VM_READ: u32 = 0x0010;
    let process_access_rights = PROCESS_ACCESS_RIGHTS(PROCESS_VM_READ);

    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_information = PROCESS_INFORMATION::default();

        let _result = CreateProcessA(
            PCSTR::null(),      
            PSTR("powershell sleep 10\0".as_ptr() as _ ),   // Command line
            None,                                           // Process security attributes
            None,                                           // Thread security attributes
            BOOL(0),                                        // Inherit handles
            PROCESS_CREATION_FLAGS(0),                      // Creation flags -> 0x00000004 is suspended mode.
                                                            // When creating the process in suspended mode, it does not
                                                            // show up in taskmgr?
            None,                                           // Environment
            None,                                           // Current directory
            &mut startup_info,
            &mut process_information,
        );
        let id = process_information.dwProcessId;
        
        println!("Process ID: {:?}", id);
        // Let's open a process handle:
        let process_handle = OpenProcess(
            process_access_rights, // [in] DWORD dwDesiredAccess,
            BOOL(0),    // [in] BOOL  bInheritHandle,
            id          // [in] DWORD dwProcessId
          );
        let base_address = 0x7ff6_0000 as *const c_void; // fix
        let lp_buffer = 0x0 as *mut c_void;
        let lp_number_of_bytes_read: Option<*mut usize> = None;

        let process_memory = ReadProcessMemory(
            process_handle.unwrap() ,// [in]  HANDLE  hProcess,
            base_address, // [in]  LPCVOID lpBaseAddress,
            lp_buffer,// [out] LPVOID  lpBuffer,
            4 as usize,// [in]  SIZE_T  nSize,
            lp_number_of_bytes_read// [out] SIZE_T  *lpNumberOfBytesRead
        );
        println!("{:?}", process_memory);
        
    }
}
