use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND},
        UI::WindowsAndMessaging::{MESSAGEBOX_STYLE, MessageBoxA},
    },
    core::PCSTR,
};

#[unsafe(no_mangle)]
extern "C" fn main() {
    unsafe {
        MessageBoxA(
            HWND(0),
            PCSTR("DLL Example\x00".as_ptr()),
            PCSTR("Uh oh\x00".as_ptr()),
            MESSAGEBOX_STYLE(0),
        );
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    _fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> windows::Win32::Foundation::BOOL {
    match _fdw_reason {
        1 => {
            main();
            println!("DLL loaded successfully!");
        }
        0 => {
            // DLL_PROCESS_DETACH
            println!("DLL unloaded.");
        }
        _ => {}
    }
    windows::Win32::Foundation::BOOL(1) // Return TRUE
}
