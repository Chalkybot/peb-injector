use windows::Win32::System::Threading::{CreateProcessA, 
                                        PROCESS_CREATION_FLAGS,
                                        STARTUPINFOA,
                                        PROCESS_INFORMATION,
                                        OpenProcess,
                                        PROCESS_ACCESS_RIGHTS,
                                        PROCESS_BASIC_INFORMATION,
                                        PEB,
                                        RTL_USER_PROCESS_PARAMETERS};
use windows::Wdk::System::Threading::{NtQueryInformationProcess,
                                      PROCESSINFOCLASS,
                                      };
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::core::{PSTR, PCSTR};
use core::ffi::c_void;

unsafe fn start_powershell(binary_name: &str, commandline_args: &str, 
                        process_information: &mut PROCESS_INFORMATION, 
                        startup_information: &STARTUPINFOA ) -> Result<(),()>{
    
    let process_name = format!("{binary_name} {commandline_args}\0");
    let started_process = CreateProcessA(
            PCSTR::null(),      
            PSTR(process_name.as_str().as_ptr() as _ ),   // Command line
            None,                                           // Process security attributes
            None,                                           // Thread security attributes
            BOOL(0),                                        // Inherit handles
            PROCESS_CREATION_FLAGS(0),                      // Creation flags -> 0x00000004 is suspended mode.
                                                            // When creating the process in suspended mode, it does not
                                                            // show up in taskmgr?
            None,                                           // Environment
            None,                                           // Current directory
            startup_information as *const _,
            process_information as *mut _,
    );
    match started_process {
        Ok(t) => return Ok(()),
        Err(_) => return Err(())
    }
}

unsafe fn read_process_memory(process_handle: HANDLE, address: *const c_void,
                              buffer_ptr: *mut c_void, length: usize, bytes_read: &mut usize) -> Result<(),()> {
    let process_memory = ReadProcessMemory(
                process_handle,
                address,
                buffer_ptr,
                length,
                Some(bytes_read),
        );
    match process_memory.is_ok() {
            true  => return Ok(()),
            false => return Err(())
    }       
}
 

fn main() {
    const SUSPENDED: u32 = 0x00000004;
    const PROCESS_VM_READ: u32 = 0xFFFF; // placeholder, correct rights are 0x0020 + whatever ntquery requires.
    let process_access_rights = PROCESS_ACCESS_RIGHTS(PROCESS_VM_READ);
    let mem_len = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
    
    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_information = PROCESS_INFORMATION::default();
        start_powershell("powershell", "sleep 10", &mut process_information, &startup_info);

        let id = process_information.dwProcessId; 
        println!("Process ID: {:?}", id);

        // Let's open a process handle:
        let process_handle = OpenProcess(
            process_access_rights, // [in] DWORD dwDesiredAccess,
            BOOL(0),    // [in] BOOL  bInheritHandle,
            id          // [in] DWORD dwProcessId
        );

        let process_info_class = PROCESSINFOCLASS(0); // Should return the location of the PEB block.
        let mut process_information = PROCESS_BASIC_INFORMATION::default();
        let lp_buffer: *mut c_void = &mut process_information as *mut _ as *mut c_void;
        let return_length: *mut u32 = std::ptr::null_mut();
        
        let status = NtQueryInformationProcess(
                process_handle.clone().unwrap(),    //  [in] HANDLE ProcessHandle,
                process_info_class,                 //  [in] PROCESSINFOCLASS ProcessInformationClass,
                lp_buffer,                          //  [out] PVOID ProcessInformation,
                mem_len as u32,   //  [in] ULONG ProcessInformationLength,
                return_length,                      //  [out, optional] PULONG ReturnLength
        );

        match status.is_ok() {
            true => {
                println!("Location of PEB: {:?}", &process_information.PebBaseAddress);
        },
            false => eprintln!("Failure: {:?}", status)
        }
       
        // Reading PEB
        let peb_addr: *const c_void = process_information.PebBaseAddress as *const _ as *const c_void;
        let mut peb = PEB::default();
        let mut buffer_ptr = &mut peb as *mut _ as *mut c_void;
        let peb_len = std::mem::size_of::<PEB>();
        let mut bytes_read: usize = 0;
        
        
        let peb_content = read_process_memory(process_handle.clone().unwrap(),
                                                 peb_addr,
                                                 buffer_ptr,
                                                 peb_len,
                                                 &mut bytes_read); 
        match peb_content {
            Ok(_) => println!("Success."),
            Err(_) => eprintln!("Failure")
        }


 

        
    }
}
