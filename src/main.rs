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
                                      PROCESSINFOCLASS,};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::core::{PSTR, PCSTR, Error};
use core::ffi::c_void;
use std::env;


trait AsCVoid {
    fn as_cvoid(&self) -> *const c_void; // This implementation does not work. The created pointer
                                         // points to the wrong address.
    fn as_mut_cvoid(&mut self) -> *mut c_void;
}

unsafe fn cast_to_cvoid<T: ?Sized>(arg: &T) -> *const c_void { arg as *const _ as *const c_void }

impl<T: ?Sized> AsCVoid for T {
    fn as_cvoid(&self) -> *const c_void {
        self as *const _ as *const c_void
    }

    fn as_mut_cvoid(&mut self) -> *mut c_void {
        self as *mut _ as *mut c_void
    }
}



fn start_process(binary_name: &str, commandline_args: &str, 
                        process_information: &mut PROCESS_INFORMATION, 
                        startup_information: &STARTUPINFOA ) -> Result<(), Error> {
    const SUSPENDED: u32 = 0x00000004;
    let process_name = format!("{binary_name} {commandline_args}\0");
    unsafe {
            CreateProcessA(
                    PCSTR::null(),      
                    PSTR(process_name.as_str().as_ptr() as _ ),
                    None,
                    None,
                    BOOL(0),
                    PROCESS_CREATION_FLAGS(SUSPENDED),
                    None,
                    None,
                    startup_information as *const _,
                    process_information as *mut _,
            )
    }
}



fn write_process_memory(process_handle: HANDLE, address: *const c_void, 
                                content: *const c_void, length: usize) -> Result<usize, Error> {
    let mut bytes_written: usize = 0;
    unsafe {
        let written_memory = WriteProcessMemory(
            process_handle,
            address,
            content, 
            //content_ptr,
            length,
            Some(&mut bytes_written)
        );
        match written_memory {
            Ok(_) => Ok(bytes_written),
            Err(e) => Err(e),
        }
    }
}

fn open_process_handle(access_flags: u32, inherit_handle: i32, process_id: u32) -> Result<HANDLE, Error> {
    unsafe {
        OpenProcess(
                PROCESS_ACCESS_RIGHTS(access_flags), 
                BOOL(inherit_handle),
                process_id,
        )
    }

}


fn read_process_memory(process_handle: HANDLE, address: *const c_void,
                              buffer_ptr: *mut c_void, length: usize) -> Result<usize, Error> {
    let mut bytes_read: usize = 0;
    unsafe {
        let read_memory = ReadProcessMemory(
                process_handle,
                address,
                buffer_ptr,
                length,
                Some(&mut bytes_read),
        );
        match read_memory {
            Ok(_) => Ok(bytes_read),
            Err(e) => Err(e),
        }
    }
}
 

fn manage_arguments(arguments: Vec<String>) -> (String, String, Vec<u16>){
    let process_name = &arguments[0];
    let replacement_string: Vec<u16> = (arguments.join(" ") + "\0").encode_utf16().collect();
    let startup_args = "1".repeat(replacement_string.len() - process_name.len());
    (process_name.to_string(), startup_args, replacement_string)
} 

fn main() {

    const ALL_RIGHTS: u32 = 0xFFFF;
    let args: Vec<String> = env::args().skip(1).collect();
    let (process_name, startup_arguments, replacement_arguments) = manage_arguments(args);
    
    let mem_len = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
    let startup_info = STARTUPINFOA::default();
    let mut process_information = PROCESS_INFORMATION::default();
    
    println!("Running \"{}\"\nAs: \"{} {}\"", String::from_utf16(&replacement_arguments).unwrap(), &process_name, &startup_arguments);
      
    start_process(process_name.as_str(),
                    startup_arguments.as_str(), 
                    &mut process_information, 
                    &startup_info)
                    .expect("Unable to launch a process!");
    
    let process_handle = open_process_handle(
                                    ALL_RIGHTS,
                                    0,
                                    process_information.dwProcessId);
    let mut nt_query_return = PROCESS_BASIC_INFORMATION::default();
    let lp_buffer = nt_query_return.as_mut_cvoid(); // Issue lies here. 
    let return_length: *mut u32 = std::ptr::null_mut();
   

    unsafe {
                let status = NtQueryInformationProcess(
                process_handle.clone().unwrap(),
                PROCESSINFOCLASS(0), // PEB block
                lp_buffer,
                mem_len as u32,
                return_length,
        );
        match status.is_ok() {
            true => {
                println!("Location of PEB: {:?}", &nt_query_return.PebBaseAddress);
        },
            false => panic!("Failure: {:?}", status)
        }
       
        // Reading PEB
        let peb_addr = cast_to_cvoid(&*nt_query_return.PebBaseAddress); //as *const _  as *const c_void;
        let mut peb_buffer = PEB::default();
        let peb_ptr = peb_buffer.as_mut_cvoid(); 
        let peb_len = std::mem::size_of::<PEB>();
        let peb_content = read_process_memory(  process_handle.clone().unwrap(),
                                                peb_addr,
                                                peb_ptr,
                                                peb_len); 
        println!("Location of command line arguments: {:?}", &peb_buffer.ProcessParameters);
        
        let process_params_addr = cast_to_cvoid(&*peb_buffer.ProcessParameters);// as *const _ as *const c_void;
        let mut process_params_buffer = RTL_USER_PROCESS_PARAMETERS::default();
        let process_params_ptr = process_params_buffer.as_mut_cvoid();
        let process_params_len = std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>();

        let commandline_arguments = read_process_memory(process_handle.clone().unwrap(),
                                                       process_params_addr,
                                                       process_params_ptr,
                                                       process_params_len);

        let commandline_len = process_params_buffer.CommandLine.Length as usize;
        let commandline_addr = cast_to_cvoid(&*process_params_buffer.CommandLine
                                                                    .Buffer
                                                                    .0);
        let mut commandline_buffer = vec![0u16; commandline_len / 2 + 1 ]; // account for utf16 + \0
        let commandline_ptr = (*commandline_buffer).as_mut_cvoid();// as *mut _ as *mut c_void; 
        println!("Location of string: {:?}", commandline_addr);
        let commandline_arguments = read_process_memory(process_handle.clone().unwrap(),
                                                       commandline_addr,
                                                       commandline_ptr,
                                                       commandline_len,); 

        let overwriting_peb = write_process_memory(
                process_handle.clone().unwrap(),
                commandline_addr,
                (&*replacement_arguments).as_cvoid(),
                replacement_arguments.len() * 2,
        );
        let unsuspend = ResumeThread(process_information.hThread);
    }
}
