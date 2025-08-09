# Mapping Injection

A Rust and C++ project focused on DLL injection using manual mapping techniques with embedded DLLs.

## Description

This project demonstrates advanced DLL injection techniques in processes using manual mapping, an approach that allows loading dynamic libraries without registering them in the target process's PEB (Process Environment Block). The project utilizes embedded DLLs for enhanced portability and stealth, combining Rust and C++ through the autocxx library.

## Features

- **Manual Mapping**: DLL loading without using LoadLibrary
- **Embedded DLLs**: Libraries incorporated directly into the executable
- **Process Injection**: Techniques for injecting code into remote processes
- **Rust + C++ Implementation**: Leveraging autocxx for seamless interoperability
- **Memory Management**: Safe and efficient memory handling across languages

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd mapping-injection

# Build the project
cargo build --release --workspace
```

## Usage

To perform DLL injection, you need to run the compiled executable. The injection will target a specific process.

**DLL Configuration**:
- Use `resource.rc` to specify the path to your DLL that will be injected
- Alternatively, check the examples in the crates to create your own custom DLL

For detailed implementation examples, refer to the project's example crates.

## Key Capabilities

- DLL injection via manual mapping
- Embedded DLLs in executable
- LoadLibrary detection bypass
- Clean and modular architecture
- Cross-language integration with autocxx

## Requirements

- Rust (latest stable)
- C++ compiler

## Contributing

1. Fork the project
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Legal Notice

This project is for educational and research purposes only. Use responsibly and in compliance with local laws.
