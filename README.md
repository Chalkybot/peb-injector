### PEB Injector

## Overview
This tool is designed to manipulate the command line arguments of Windows binaries in memory. It first starts a suspended process with bogus arguments, locates the PEB structure, modifies the arguments in memory with the Windows API and resumes execution.

## Features
- Create a new Windows process in a suspended state.
- Read the Process Environment Block (PEB) and RTL_USER_PROCESS_PARAMETERS to extract current command line arguments.
- Overwrite the command line arguments in memory with the desired values.
- Resume the process execution with the spoofed command line arguments.

## Usage
Just run the binary with the target process and the desired command line arguments.
   ```
   peb-injector.exe powershell.exe "whoami"
   ```
## Important Note
- Use this tool responsibly and ethically. It is meant for educational and testing purposes only.

## Disclaimer
This tool is provided "as is", without warranty of any kind, express or implied. The authors are not responsible for any damage caused by the misuse or unintended use of this tool. Always ensure you have permission to test target binaries in your environment.
