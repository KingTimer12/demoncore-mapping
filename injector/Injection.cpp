#include "include/Injection.h"

void __stdcall shell_code(MANUAL_MAPPING_DATA* data_ptr);

bool ManualMap(HANDLE hProcess, const char* szDllFile) {
  BYTE* src_data_ptr = nullptr;
  IMAGE_NT_HEADERS* old_nt_headers_ptr = nullptr;
  IMAGE_OPTIONAL_HEADER* old_optional_header_ptr = nullptr;
  IMAGE_FILE_HEADER* old_file_header_ptr = nullptr;
  BYTE* dest_data_ptr = nullptr;  // target_base

  DWORD dw_check = 0;
  if (GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES) {
    printf("File %s doesn't exist.\n", szDllFile);
    return false;
  }

  std::ifstream file(szDllFile, std::ios::binary | std::ios::ate);
  if (file.fail()) {
    printf("Failed to open file %s. Failed: %X\n", szDllFile,
           (DWORD)file.rdstate());
    file.close();
    return false;
  }

  auto file_size = file.tellg();
  if (file_size < 0x1000) {
    printf("File %s is too small.\n", szDllFile);
    file.close();
    return false;
  }

  src_data_ptr = new BYTE[static_cast<UINT_PTR>(file_size)];
  if (!src_data_ptr) {
    printf("Failed to allocate memory for file %s.\n", szDllFile);
    file.close();
    return false;
  }

  file.seekg(0, std::ios::beg);
  file.read(reinterpret_cast<char*>(src_data_ptr), file_size);
  file.close();

  // https://en.wikipedia.org/wiki/DOS_MZ_executable
  if (reinterpret_cast<IMAGE_DOS_HEADER*>(src_data_ptr)->e_magic !=
      IMAGE_DOS_SIGNATURE) {
    printf("File %s is not a valid PE file.\n", szDllFile);
    delete[] src_data_ptr;
    return false;
  }

  old_nt_headers_ptr = reinterpret_cast<IMAGE_NT_HEADERS*>(
      src_data_ptr +
      reinterpret_cast<IMAGE_DOS_HEADER*>(src_data_ptr)->e_lfanew);

  old_optional_header_ptr = &old_nt_headers_ptr->OptionalHeader;
  old_file_header_ptr = &old_nt_headers_ptr->FileHeader;

#ifdef _WIN64
  if (old_file_header_ptr->Machine != IMAGE_FILE_MACHINE_AMD64) {
    printf("File %s is not a valid PE file for x86-64 architecture.\n",
           szDllFile);
    delete[] src_data_ptr;
    return false;
  }
#else
  if (old_file_header_ptr->Machine != IMAGE_FILE_MACHINE_I386) {
    printf("File %s is not a valid PE file for x86 architecture.\n", szDllFile);
    delete[] src_data_ptr;
    return false;
  }
#endif

  dest_data_ptr = reinterpret_cast<BYTE*>(VirtualAllocEx(
      hProcess, reinterpret_cast<void*>(old_optional_header_ptr->ImageBase),
      old_optional_header_ptr->SizeOfImage, MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE));
  if (!dest_data_ptr) {
    dest_data_ptr = reinterpret_cast<BYTE*>(
        VirtualAllocEx(hProcess, nullptr, old_optional_header_ptr->SizeOfImage,
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!dest_data_ptr) {
      printf("VirtualAllocEx failed. Error: %X\n", GetLastError());
      delete[] src_data_ptr;
      return false;
    }
  }

  MANUAL_MAPPING_DATA data{0};
  data.pLoadLibraryA = LoadLibraryA;
  data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);
  auto* section_header_ptr = IMAGE_FIRST_SECTION(old_nt_headers_ptr);
  for (UINT i = 0; i < old_nt_headers_ptr->FileHeader.NumberOfSections;
       i++, section_header_ptr++) {
    if (section_header_ptr->SizeOfRawData == 0) continue;
    if (!WriteProcessMemory(hProcess,
                            dest_data_ptr + section_header_ptr->VirtualAddress,
                            src_data_ptr + section_header_ptr->PointerToRawData,
                            section_header_ptr->SizeOfRawData, nullptr)) {
      printf("Can't map section %s. Error: %X\n", section_header_ptr->Name,
             GetLastError());
      delete[] src_data_ptr;
      VirtualFreeEx(hProcess, dest_data_ptr, 0, MEM_RELEASE);
      return false;
    }
  }

  memcpy(src_data_ptr, &data, sizeof(data));
  WriteProcessMemory(hProcess, dest_data_ptr, src_data_ptr, 0x1000, nullptr);

  delete[] src_data_ptr;

  void* shellcode_ptr =
      VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);
  if (!shellcode_ptr) {
    printf("VirtualAllocEx for shellcode failed. Error: %X\n", GetLastError());
    VirtualFreeEx(hProcess, dest_data_ptr, 0, MEM_RELEASE);
    return false;
  }

  WriteProcessMemory(hProcess, shellcode_ptr,
                     reinterpret_cast<void*>(shell_code), 0x1000, nullptr);

  HANDLE h_thread = CreateRemoteThread(
      hProcess, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_ptr), dest_data_ptr, 0,
      nullptr);
  if (!h_thread) {
    printf("CreateRemoteThread failed. Error: %X\n", GetLastError());
    VirtualFreeEx(hProcess, shellcode_ptr, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, dest_data_ptr, 0, MEM_RELEASE);
    return false;
  }

  CloseHandle(h_thread);

  HINSTANCE h_check = NULL;
  while (!h_check) {
    MANUAL_MAPPING_DATA data_checked{0};
    ReadProcessMemory(hProcess, dest_data_ptr, &data_checked, sizeof(data_checked),
                      nullptr);
    h_check = data_checked.hModule;
    Sleep(10);
  }

  VirtualFreeEx(hProcess, shellcode_ptr, 0, MEM_RELEASE);

  return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall shell_code(MANUAL_MAPPING_DATA* data_ptr) {
  if (!data_ptr) return;
  BYTE* base_ptr = reinterpret_cast<BYTE*>(data_ptr);

  auto* option_ptr =
      &reinterpret_cast<IMAGE_NT_HEADERS*>(
           base_ptr + reinterpret_cast<IMAGE_DOS_HEADER*>(data_ptr)->e_lfanew)
           ->OptionalHeader;

  auto _LoadLibraryA = data_ptr->pLoadLibraryA;
  auto _GetProcAddress = data_ptr->pGetProcAddress;
  auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(
      base_ptr + option_ptr->AddressOfEntryPoint);

  BYTE* location_delta = base_ptr - option_ptr->ImageBase;
  if (location_delta) {
    if (!option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
      return;

    auto* reloc_data_ptr = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        base_ptr + option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                       .VirtualAddress);

    while (reloc_data_ptr->VirtualAddress) {
      UINT amount_of_entries =
          (reloc_data_ptr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
          sizeof(WORD);

      WORD* relative_info_ptr = reinterpret_cast<WORD*>(reloc_data_ptr + 1);

      for (UINT i = 0; i < amount_of_entries; i++, relative_info_ptr++) {
        if (RELOC_FLAG(*relative_info_ptr)) {
          UINT_PTR* patch_ptr = reinterpret_cast<UINT_PTR*>(
              base_ptr + reloc_data_ptr->VirtualAddress +
              ((*relative_info_ptr) & 0xFFF));
          *patch_ptr += reinterpret_cast<UINT_PTR>(location_delta);
        }
      }

      reloc_data_ptr = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
          reinterpret_cast<BYTE*>(reloc_data_ptr) +
          reloc_data_ptr->SizeOfBlock);
    }
  }

  if (option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    auto* import_desc_ptr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        base_ptr +
        option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (import_desc_ptr->Name) {
      char* module_name =
          reinterpret_cast<char*>(base_ptr + import_desc_ptr->Name);
      HINSTANCE h_dll = _LoadLibraryA(module_name);

      ULONG_PTR* thunk_ref_ptr = reinterpret_cast<ULONG_PTR*>(
          base_ptr + import_desc_ptr->OriginalFirstThunk);
      ULONG_PTR* func_ref_ptr =
          reinterpret_cast<ULONG_PTR*>(base_ptr + import_desc_ptr->FirstThunk);

      if (!thunk_ref_ptr) thunk_ref_ptr = func_ref_ptr;
      for (; *thunk_ref_ptr; thunk_ref_ptr++, func_ref_ptr++) {
        if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref_ptr)) {
          *func_ref_ptr = _GetProcAddress(
              h_dll, reinterpret_cast<char*>(*thunk_ref_ptr & 0xFFFF));
        } else {
          auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
              base_ptr + (*thunk_ref_ptr));
          *func_ref_ptr = _GetProcAddress(h_dll, import_by_name->Name);
        }
      }

      import_desc_ptr++;
    }
  }

  if (option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
    auto* tls_ptr = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
        base_ptr +
        option_ptr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* callback_ptr =
        reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_ptr->AddressOfCallBacks);
    for (; callback_ptr && *callback_ptr; callback_ptr++) {
      (*callback_ptr)(base_ptr, DLL_PROCESS_ATTACH, nullptr);
    }
  }

  if (_DllMain) {
    _DllMain(reinterpret_cast<HINSTANCE>(base_ptr), DLL_PROCESS_ATTACH,
             nullptr);
  }

  data_ptr->hModule = reinterpret_cast<HINSTANCE>(base_ptr);
}
