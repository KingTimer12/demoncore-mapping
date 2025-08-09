use autocxx::prelude::*;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
};

use crate::{embedding::load_embedded_dll, process::find_process, utils::pause_console};

include_cpp! {
    #include "Injection.h"
    safety!(unsafe)
    generate!("ManualMap")
}

mod embedding;
mod process;
mod utils;

const PROCESS_NAME: &str = "any_process.exe"; // Example process name, replace with the target process
const RESOURCE_NAME: &str = "MY_DLL";

fn main() {
    unsafe {
        let (dll_data, dll_size) = match load_embedded_dll(RESOURCE_NAME) {
            Ok(data) => data,
            Err(err) => {
                println!("Error loading DLL: {}", err);
                utils::pause_console();
                return;
            }
        };
        println!("DLL loaded successfully! Size: {} bytes", dll_size);
        println!("DLL Data: {:?}", dll_data);
        let process_id = find_process(PROCESS_NAME);
        println!("Process ID: {}", process_id);
        if process_id == 0 {
            println!("Process not found: {}", PROCESS_NAME);
            pause_console();
            return;
        }
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        if h_process == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            println!("CreateToolhelp32Snapshot failed. Error: {}", err);
            pause_console();
            return;
        }

        let result = ffi::ManualMap(
            h_process as *mut c_void,
            dll_data,
            dll_size,
        );
        if !result {
            println!("Something went wrong with ManualMap");
        }
        CloseHandle(h_process);
        pause_console();
    }
}
