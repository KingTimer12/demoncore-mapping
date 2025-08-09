use windows_sys::Win32::Media::KernelStreaming::RT_RCDATA;
use windows_sys::Win32::System::LibraryLoader::{
    FindResourceA, GetModuleHandleA, LoadResource, LockResource, SizeofResource,
};

pub unsafe fn load_embedded_dll(resource_name: &str) -> Result<(*const i8, usize), &'static str> {
    unsafe {
        let h_module = GetModuleHandleA(std::ptr::null());
        if h_module.is_null() {
            return Err("Failed to get module handle");
        }

        // Find resource
        let resource_name_cstr =
            std::ffi::CString::new(resource_name).map_err(|_| "Invalid resource name")?;
        let h_res = FindResourceA(
            h_module,
            resource_name_cstr.as_ptr() as *const u8,
            RT_RCDATA as *const u8,
        );

        if h_res.is_null() {
            return Err("Resource not found");
        }

        // Load resource
        let h_global = LoadResource(h_module, h_res);
        if h_global.is_null() {
            return Err("Failed to load resource");
        }

        // Get pointer to data
        let dll_data = LockResource(h_global) as *const i8;
        if dll_data.is_null() {
            return Err("Failed to lock resource");
        }

        // Get size
        let dll_size = SizeofResource(h_module, h_res) as usize;
        if dll_size == 0 {
            return Err("Zero-sized resource");
        }

        Ok((dll_data, dll_size))
    }
}
