#include "include/Injection.h"

// Macro to determine relocation type based on architecture
#ifdef _WIN64
#define RELOC_FLAG(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)
#else
#define RELOC_FLAG(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#endif

void __stdcall shell_code(MANUAL_MAPPING_DATA* data_ptr);

// Forward declarations for helper functions
bool ValidateFileExistence(const char* szDllFile);
std::unique_ptr<BYTE[]> ReadFileToBuffer(const char* szDllFile,
                                         std::streamsize& fileSize);
bool ValidatePEHeaders(BYTE* pFileData);
BYTE* AllocateTargetMemory(HANDLE hProcess, IMAGE_OPTIONAL_HEADER* pOptHeader);
bool MapSectionsToTarget(HANDLE hProcess, BYTE* pTargetBase, BYTE* pFileData,
                         IMAGE_NT_HEADERS* pOldNtHeader);
bool ExecuteRemoteShellcode(HANDLE hProcess, BYTE* pTargetBase);

// Forward declarations for shellcode helper functions
void ApplyRelocations(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader,
                      BYTE* pLocationDelta);
void ResolveImports(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader,
                    f_LoadLibraryA pLoadLibraryA,
                    f_GetProcAddress pGetProcAddress);
void ExecuteTLSCallbacks(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader);

/// @brief Manually maps a DLL into a target process
/// @param hProcess Handle to the target process
/// @param szDllFile Path to the DLL file
/// @return True on success, false on failure
bool ManualMap(HANDLE hProcess, const char* dllData, size_t dllSize) {
  BYTE* src_data_ptr = new BYTE[static_cast<UINT_PTR>(dllSize)];

  ::memcpy(src_data_ptr, dllData, dllSize);

  // Step 3: Validate PE headers
  if (!ValidatePEHeaders(src_data_ptr)) {
    return false;
  }

  // Get PE headers from file data
  IMAGE_DOS_HEADER* pDosHeader =
      reinterpret_cast<IMAGE_DOS_HEADER*>(src_data_ptr);
  IMAGE_NT_HEADERS* pOldNtHeader =
      reinterpret_cast<IMAGE_NT_HEADERS*>(src_data_ptr + pDosHeader->e_lfanew);
  IMAGE_OPTIONAL_HEADER* pOptHeader = &pOldNtHeader->OptionalHeader;

  // Step 4: Allocate memory in target process
  BYTE* pTargetBase = AllocateTargetMemory(hProcess, pOptHeader);
  if (!pTargetBase) {
    return false;
  }

  // Step 5: Map DLL sections to target process
  if (!MapSectionsToTarget(hProcess, pTargetBase, src_data_ptr, pOldNtHeader)) {
    VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
    return false;
  }

  // Step 6: Execute shellcode in remote process
  if (!ExecuteRemoteShellcode(hProcess, pTargetBase)) {
    VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
    return false;
  }

  // Cleanup and return success
  VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
  return true;
}

//-----------------------------------------------------------------------------
// Helper function implementations
//-----------------------------------------------------------------------------

/// @brief Checks if target file exists
bool ValidateFileExistence(const char* szDllFile) {
  if (GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES) {
    printf("[!] File not found: %s\n", szDllFile);
    return false;
  }
  return true;
}

/// @brief Reads file content into memory buffer
std::unique_ptr<BYTE[]> ReadFileToBuffer(const char* szDllFile,
                                         std::streamsize& fileSize) {
  std::ifstream file(szDllFile, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    printf("[!] Failed to open file: %s (Error: %lu)\n", szDllFile,
           GetLastError());
    return nullptr;
  }

  fileSize = file.tellg();
  if (fileSize < 0x1000) {
    printf("[!] Invalid file size: %s\n", szDllFile);
    return std::unique_ptr<BYTE[]>();
  }

  auto buffer = std::make_unique<BYTE[]>(static_cast<size_t>(fileSize));
  file.seekg(0, std::ios::beg);
  file.read(reinterpret_cast<char*>(buffer.get()), fileSize);
  return buffer;
}

/// @brief Validates PE file structure and architecture
bool ValidatePEHeaders(BYTE* pFileData) {
  // Check DOS header signature
  IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pFileData);
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("[!] Invalid DOS header.\n");
    return false;
  }

  // Check NT headers signature
  IMAGE_NT_HEADERS* pNtHeader =
      reinterpret_cast<IMAGE_NT_HEADERS*>(pFileData + pDosHeader->e_lfanew);
  if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
    printf("[!] Invalid NT header.\n");
    return false;
  }

  // Check architecture compatibility
  IMAGE_FILE_HEADER* pFileHeader = &pNtHeader->FileHeader;
#ifdef _WIN64
  const bool bValidArch = (pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
  const char* szArch = "x64";
#else
  const bool bValidArch = (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386);
  const char* szArch = "x86";
#endif
  if (!bValidArch) {
    printf("[!] Architecture mismatch. Expected %s.\n", szArch);
    return false;
  }

  return true;
}

/// @brief Allocates memory in target process for DLL
BYTE* AllocateTargetMemory(HANDLE hProcess, IMAGE_OPTIONAL_HEADER* pOptHeader) {
  // Try to allocate at preferred base address
  BYTE* pAllocatedMem = reinterpret_cast<BYTE*>(
      VirtualAllocEx(hProcess, reinterpret_cast<void*>(pOptHeader->ImageBase),
                     pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE));

  // Fallback to any available address
  if (!pAllocatedMem) {
    pAllocatedMem = reinterpret_cast<BYTE*>(
        VirtualAllocEx(hProcess, nullptr, pOptHeader->SizeOfImage,
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  }

  if (!pAllocatedMem) {
    printf("[!] Memory allocation failed (Error: %lu)\n", GetLastError());
  }

  return pAllocatedMem;
}

/// @brief Writes DLL sections to target process memory
bool MapSectionsToTarget(HANDLE hProcess, BYTE* pTargetBase, BYTE* pFileData,
                         IMAGE_NT_HEADERS* pOldNtHeader) {
  // Prepare manual mapping data structure
  MANUAL_MAPPING_DATA mmData{};
  mmData.pLoadLibraryA = LoadLibraryA;
  mmData.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

  // Copy headers to target process
  if (!WriteProcessMemory(hProcess, pTargetBase, pFileData, 0x1000, nullptr)) {
    printf("[!] Header copy failed (Error: %lu)\n", GetLastError());
    return false;
  }

  // Process each section
  IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
  for (UINT i = 0; i < pOldNtHeader->FileHeader.NumberOfSections;
       ++i, ++pSectionHeader) {
    if (pSectionHeader->SizeOfRawData == 0) continue;

    BYTE* pTargetSection = pTargetBase + pSectionHeader->VirtualAddress;
    BYTE* pSourceSection = pFileData + pSectionHeader->PointerToRawData;

    if (!WriteProcessMemory(hProcess, pTargetSection, pSourceSection,
                            pSectionHeader->SizeOfRawData, nullptr)) {
      printf("[!] Section mapping failed: %s (Error: %lu)\n",
             pSectionHeader->Name, GetLastError());
      return false;
    }
  }

  // Write manual mapping data to target headers
  memcpy(pFileData, &mmData, sizeof(mmData));
  if (!WriteProcessMemory(hProcess, pTargetBase, pFileData, 0x1000, nullptr)) {
    printf("[!] Mapping data write failed (Error: %lu)\n", GetLastError());
    return false;
  }

  return true;
}

/// @brief Executes shellcode in remote process
bool ExecuteRemoteShellcode(HANDLE hProcess, BYTE* pTargetBase) {
  // Allocate memory for shellcode
  void* pShellcode =
      VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);

  if (!pShellcode) {
    printf("[!] Shellcode allocation failed (Error: %lu)\n", GetLastError());
    return false;
  }

  // Write shellcode to target
  if (!WriteProcessMemory(hProcess, pShellcode, shell_code, 0x1000, nullptr)) {
    printf("[!] Shellcode write failed (Error: %lu)\n", GetLastError());
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    return false;
  }

  // Create remote thread
  HANDLE hThread =
      CreateRemoteThread(hProcess, nullptr, 0,
                         reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode),
                         pTargetBase, 0, nullptr);

  if (!hThread) {
    printf("[!] Thread creation failed (Error: %lu)\n", GetLastError());
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    return false;
  }

  // Wait for module initialization
  HINSTANCE hModule = nullptr;
  while (!hModule) {
    MANUAL_MAPPING_DATA mmData{};
    if (ReadProcessMemory(hProcess, pTargetBase, &mmData, sizeof(mmData),
                          nullptr)) {
      hModule = mmData.hModule;
    }
    Sleep(10);
  }

  // Cleanup resources
  CloseHandle(hThread);
  VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
  return true;
}

//-----------------------------------------------------------------------------
// Shellcode implementation (runs in target process)
//-----------------------------------------------------------------------------

/// @brief Shellcode executed in target process to complete DLL loading
/// @param data_ptr Pointer to manual mapping data structure
void __stdcall shell_code(MANUAL_MAPPING_DATA* data_ptr) {
  if (!data_ptr) return;

  // Get base pointer and PE headers
  BYTE* pBase = reinterpret_cast<BYTE*>(data_ptr);
  IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(data_ptr);
  IMAGE_NT_HEADERS* pNtHeader =
      reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
  IMAGE_OPTIONAL_HEADER* pOptHeader = &pNtHeader->OptionalHeader;

  // Get critical function pointers
  auto pLoadLibraryA = data_ptr->pLoadLibraryA;
  auto pGetProcAddress = data_ptr->pGetProcAddress;
  auto pDllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(
      pBase + pOptHeader->AddressOfEntryPoint);

  // Process relocations if needed
  BYTE* pLocationDelta = pBase - pOptHeader->ImageBase;
  if (pLocationDelta) {
    ApplyRelocations(pBase, pOptHeader, pLocationDelta);
  }

  // Resolve imports
  ResolveImports(pBase, pOptHeader, pLoadLibraryA, pGetProcAddress);

  // Execute TLS callbacks
  ExecuteTLSCallbacks(pBase, pOptHeader);

  // Call DLL entry point
  if (pDllMain) {
    pDllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);
  }

  // Signal successful loading
  data_ptr->hModule = reinterpret_cast<HINSTANCE>(pBase);
}

//-----------------------------------------------------------------------------
// Shellcode helper functions
//-----------------------------------------------------------------------------

/// @brief Applies memory relocations
void ApplyRelocations(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader,
                      BYTE* pLocationDelta) {
  if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

  auto* pRelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
      pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                  .VirtualAddress);

  while (pRelocBlock->VirtualAddress) {
    const UINT numEntries =
        (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(WORD);
    WORD* pRelocInfo = reinterpret_cast<WORD*>(pRelocBlock + 1);

    for (UINT i = 0; i < numEntries; ++i, ++pRelocInfo) {
      if (RELOC_FLAG(*pRelocInfo)) {
        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(
            pBase + pRelocBlock->VirtualAddress + (*pRelocInfo & 0xFFF));
        *pPatch += reinterpret_cast<UINT_PTR>(pLocationDelta);
      }
    }

    pRelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        reinterpret_cast<BYTE*>(pRelocBlock) + pRelocBlock->SizeOfBlock);
  }
}

/// @brief Resolves imported functions
void ResolveImports(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader,
                    f_LoadLibraryA pLoadLibraryA,
                    f_GetProcAddress pGetProcAddress) {
  if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return;

  auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
      pBase +
      pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  while (pImportDesc->Name) {
    const char* szModule =
        reinterpret_cast<const char*>(pBase + pImportDesc->Name);
    HINSTANCE hModule = pLoadLibraryA(szModule);

    // Process function imports
    auto pThunkRef =
        reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
    auto pFuncRef =
        reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);
    pThunkRef = pThunkRef ? pThunkRef : pFuncRef;

    for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
      if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
        *pFuncRef = pGetProcAddress(
            hModule, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
      } else {
        auto pImport =
            reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
        *pFuncRef = pGetProcAddress(hModule, pImport->Name);
      }
    }
    ++pImportDesc;
  }
}

/// @brief Executes TLS callbacks
void ExecuteTLSCallbacks(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOptHeader) {
  if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) return;

  auto* pTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
      pBase +
      pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

  auto pCallback =
      reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
  for (; pCallback && *pCallback; ++pCallback) {
    (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
  }
}
