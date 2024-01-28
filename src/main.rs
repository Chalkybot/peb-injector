use windows::Win32::System::Threading::{CreateProcessA, 
                                        PROCESS_CREATION_FLAGS,
                                        STARTUPINFOA,
                                        PROCESS_INFORMATION,
                                        OpenProcess,
                                        PROCESS_ACCESS_RIGHTS,
                                        PROCESS_BASIC_INFORMATION};
use windows::Wdk::System::Threading::{NtQueryInformationProcess,
                                      PROCESSINFOCLASS,
                                      };
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::BOOL;
use windows::core::{PSTR, PCSTR};
use core::ffi::c_void;




fn main() {
    const SUSPENDED: u32 = 0x00000004;
    const PROCESS_VM_READ: u32 = 0xFFFF; // placeholder, correct rights are 0x0020 + whatever ntquery requires.
    let process_access_rights = PROCESS_ACCESS_RIGHTS(PROCESS_VM_READ);
    let mem_block = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
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
        let process_info_class = PROCESSINFOCLASS(0); // Should return the location of the PEB block.
        let mut process_information = vec![0u8; mem_block]; 

        let lp_buffer = process_information.as_mut_ptr() as *mut c_void;
        let return_length: *mut u32 = std::ptr::null_mut();
        
        let status = NtQueryInformationProcess(
                process_handle.clone().unwrap(),    //  [in] HANDLE ProcessHandle,
                process_info_class,                 //  [in] PROCESSINFOCLASS ProcessInformationClass,
                lp_buffer,                          //  [out] PVOID ProcessInformation,
                process_information.len() as u32,   //  [in] ULONG ProcessInformationLength,
                return_length,                      //  [out, optional] PULONG ReturnLength
        );

        match status.is_ok() {
            true => {
                let _x = PROCESS_BASIC_INFORMATION(lp_buffer);
                println!("Process basic information: {:?}", _x);
                println!("Location of PEB: 0x{:?}", &process_information[1]);
                println!("Returned block: \n{:?}", &process_information);

        },
            false => eprintln!("Failure: {:?}", status)
        }
        let peb_loc = process_information[1] as *const c_void;
        
        
        let base_address = lp_buffer;
        let mut buffer: [u8; 512] = [0; 512]; 
        let memory_buffer = buffer.as_mut_ptr() as *mut c_void;
        let mut number_of_bytes_read: usize = 0;

        let process_memory = ReadProcessMemory(
                process_handle.unwrap(),
                base_address,
                memory_buffer,
                buffer.len(),
                Some(&mut number_of_bytes_read as *mut usize),
        );
        match process_memory.is_ok() {
            true => println!("Contents of PEB: {:?}", process_memory),
            false =>  {
                eprintln!("Requested {:?} bytes, got {:?} back.\nFailure: {:?}", buffer.len(), number_of_bytes_read, process_memory);
                //eprintln!("Buffer:\n{:?}", buffer);
            }
        }

        
    }
}
