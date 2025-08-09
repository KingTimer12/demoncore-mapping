use std::ffi::CString;

use autocxx::prelude::*;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

use crate::utils::pause_console;

include_cpp! {
    #include "Injection.h"
    safety!(unsafe)
    generate!("ManualMap")
}

mod utils;

const DLL_PATH: &str = r"D:\app\mapping-injection\target\release\bapbap.dll"; // Example DLL file, replace with
const PROCESS_NAME: &str = "bapbap.exe"; // Example process name, replace with the target process

unsafe fn find_process() -> u32 {
    unsafe {
        let mut pe32 = PROCESSENTRY32::default();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let h_snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snap == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            println!("CreateToolhelp32Snapshot failed. Error: {}", err);
            pause_console();
            return 0;
        }

        let mut p_id = 0;
        let mut b_ret = Process32First(h_snap, &mut pe32);
        while b_ret != 0 && p_id == 0 {
            let process_name_cstr = std::ffi::CString::new(PROCESS_NAME).unwrap();
            let process_bytes = process_name_cstr.as_bytes_with_nul();
            let pe_name = pe32
                .szExeFile
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect::<Vec<u8>>();

            if pe_name == process_bytes[..process_bytes.len() - 1] {
                p_id = pe32.th32ProcessID;
            }
            b_ret = Process32Next(h_snap, &mut pe32);
        }
        CloseHandle(h_snap);
        p_id
    }
}

fn main() {
    unsafe {
        let process_id = find_process();
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

        let dll_path_c = CString::new(DLL_PATH).expect("CString creation failed");
        let result = ffi::ManualMap(h_process as *mut c_void, dll_path_c.as_ptr() as *const i8);
        if !result {
            println!("Something went wrong with ManualMap");
        }
        CloseHandle(h_process);
        pause_console();
    }
}
