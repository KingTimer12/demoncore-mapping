#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <fstream>
#include <iostream>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFileName);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule,
                                           const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDLL, DWORD dwReason,
                                        void* pReserved);

struct MANUAL_MAPPING_DATA {
  f_LoadLibraryA pLoadLibraryA;
  f_GetProcAddress pGetProcAddress;
  HINSTANCE hModule;
};

bool ManualMap(HANDLE hProcess, const char* szDllFile);
