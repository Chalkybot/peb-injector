use windows::Win32::System::Threading::{CreateProcessA, 
                                        PROCESS_CREATION_FLAGS,
                                        STARTUPINFOA,
                                        PROCESS_INFORMATION};
use windows::Win32::Foundation::BOOL;
use windows::core::{PSTR, PCSTR};


fn main() {
    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_information = PROCESS_INFORMATION::default();

        let result = CreateProcessA(
            PCSTR::null(),      // Use command line for application name
            PSTR("powershell\0".as_ptr() as _ ), // Command line
            None,       // Process security attributes
            None,       // Thread security attributes
            BOOL(0),    // Inherit handles
            PROCESS_CREATION_FLAGS(0), // Creation flags
            None,       // Environment
            None,       // Current directory
            &mut startup_info,
            &mut process_information,
        );
    }
}
