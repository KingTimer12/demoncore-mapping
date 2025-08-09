use std::path::Path;

fn main() -> miette::Result<()> {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_resource_file("resources.rc");
        res.set_manifest(
            r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
<security>
  <requestedPrivileges>
    <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
  </requestedPrivileges>
</security>
</trustInfo>
</assembly>
"#,
        );
        res.compile().unwrap();
    }
    let include_path = std::path::PathBuf::from("injector/include");

    // This assumes all your C++ bindings are in main.rs
    let mut b = autocxx_build::Builder::new("src/main.rs", &[&include_path]).build()?;
    b.flag_if_supported("-std=c++17")
        .cpp(true)
        .std("c++17")
        .file(std::path::PathBuf::from("injector/Injection.cpp"))
        .includes(Path::new("injector/include"))
        .compile("mapping-injector"); // arbitrary library name, pick anything
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=resources.rc"); // Ensure the resource file is checked for changes
    println!("cargo:rerun-if-changed=target/release/example_dll.dll"); // Ensure the DLL is built before running this script

    // Add instructions to link to any C++ libraries you need.

    Ok(())
}
