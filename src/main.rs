use windows::Win32::System::Threading::{CreateProcessA, 
                                        PROCESS_CREATION_FLAGS,
                                        STARTUPINFOA,
                                        PROCESS_INFORMATION,
                                        OpenProcess,
                                        PROCESS_ACCESS_RIGHTS,
                                        PROCESS_BASIC_INFORMATION,
                                        PEB,
                                        RTL_USER_PROCESS_PARAMETERS,
                                        ResumeThread};
use windows::Wdk::System::Threading::{NtQueryInformationProcess,
                                      PROCESSINFOCLASS,
                                      };
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::{BOOL, HANDLE, UNICODE_STRING};
use windows::core::{PSTR, PCSTR, PWSTR};
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
            PROCESS_CREATION_FLAGS(0x00000004),                      // Creation flags -> 0x00000004 is suspended mode.
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


unsafe fn write_process_memory<T>(process_handle: HANDLE, address: *const c_void, 
                                buffer: &T, length: usize) -> Result<(),()> {
    let mut bytes_written: usize = 0;
    let buffer_ptr: *const c_void = buffer as *const _ as *const c_void;
    let process_memory = WriteProcessMemory(
        process_handle,
        address,
        buffer_ptr,
        length,
        Some(&mut bytes_written)
    );
    match process_memory.is_ok() {
            true  => return Ok(()),
            false => {
                println!("{:?}", process_memory);    
                return Err(())
            }                
    }       

}

unsafe fn read_process_memory(process_handle: HANDLE, address: *const c_void,
                              buffer_ptr: *mut c_void, length: usize) -> Result<(),()> {
    let mut bytes_read: usize = 0;
    let process_memory = ReadProcessMemory(
                process_handle,
                address,
                buffer_ptr,
                length,
                Some(&mut bytes_read),
    );

    match process_memory.is_ok() {
            true  => return Ok(()),
            false => {
                println!("{:?}", process_memory);    
                return Err(())
            }                
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
        start_powershell("powershell", "echo 0", &mut process_information, &startup_info);
        let thread_handle = process_information.hThread;
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
            false => panic!("Failure: {:?}", status)
        }
       
        // Reading PEB
        let peb_addr: *const c_void = process_information.PebBaseAddress as *const _ as *const c_void;
        let mut peb_buffer = PEB::default();
        let peb_ptr: *mut c_void = &mut peb_buffer as *mut _ as *mut c_void; 
        let peb_len = std::mem::size_of::<PEB>();
        let peb_content = read_process_memory(  process_handle.clone().unwrap(),
                                                peb_addr,
                                                peb_ptr,
                                                peb_len); 
        // Todo:
        // Match peb_content
        // If it's Ok() -> bytes_read should be assigned 

        println!("Location of commandline arguments: {:?}", &peb_buffer.ProcessParameters);
        
        let process_params_addr: *const c_void = peb_buffer.ProcessParameters as *const _ as *const c_void;
        let mut process_params_buffer = RTL_USER_PROCESS_PARAMETERS::default();
        let process_params_ptr: *mut c_void = &mut process_params_buffer as *mut _ as *mut c_void;
        let process_params_len = std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>();

        let commandline_arguments = read_process_memory(process_handle.clone().unwrap(),
                                                       process_params_addr,
                                                       process_params_ptr,
                                                       process_params_len);
         // Todo:
        // Match peb_content
        // If it's Ok() -> bytes_read should be assigned 

        let commandline_len = process_params_buffer.CommandLine.Length as usize;
        let commandline_addr: *const c_void = process_params_buffer.CommandLine
                                                                    .Buffer
                                                                    .0 as *const _ as *const c_void;
        let mut commandline_buffer = vec![0u16; commandline_len / 2 + 1 ]; // account for utf16 + \0
        let commandline_ptr: *mut c_void = &mut *commandline_buffer as *mut _ as *mut c_void; 
        println!("Location of string: {:?}", commandline_addr);
        let commandline_arguments = read_process_memory(process_handle.clone().unwrap(),
                                                       commandline_addr,
                                                       commandline_ptr,
                                                       commandline_len,); 
        let replacement_string = [112u16, 111u16, 119u16, 101u16, 114u16, 115u16, 104u16, 101u16, 108u16, 108u16, 32u16, 101u16, 99u16, 104u16, 111u16, 32u16, 49u16, 0u16];

        let overwriting_peb = write_process_memory(
                process_handle.clone().unwrap(),
                commandline_addr,
                &replacement_string,
                replacement_string.len() * 2,
        );
        println!("Return: {:?}", overwriting_peb); 
        let unsuspend = ResumeThread(thread_handle);


    }
}
